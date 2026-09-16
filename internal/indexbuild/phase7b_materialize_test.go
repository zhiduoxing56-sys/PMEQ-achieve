package indexbuild

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/gtank/ristretto255"
	"pmeq/internal/targetcrypto"
)

type auditPosting struct {
	ID       uint64
	Position uint32
}
type auditIdentity struct {
	Join uint64
	Word string
}
type slotReference struct{ B, G, S int }

func TestPhase7BMaterialize(t *testing.T) {
	dir := os.Getenv("PMEQ_7B_ARTIFACT")
	if dir == "" {
		t.Skip("explicit final materialization")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	_, kt := phase7bKeys(t)
	aliases := phase7bAliases(t)
	runtime.GC()
	var peak atomic.Uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak.Load() {
				peak.Store(m.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()
	started := time.Now()
	meta, a, b, stats, e := BuildFinalTarget(aliases, kt)
	wall := time.Since(started)
	buildProcStatus, eStatus := os.ReadFile("/proc/self/status")
	if eStatus != nil {
		t.Fatal(eStatus)
	}
	close(stop)
	<-done
	if e != nil {
		t.Fatal(e)
	}
	if stats.Target.LogicalGroups != 310331 || stats.Target.RealSlots != 480945 || stats.Target.PaddedSlots != 1317260 {
		t.Fatal("counts", stats.Target)
	}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		t.Fatal(e)
	}
	m, e := NewTargetManifest(id, meta, stats.Target)
	if e != nil {
		t.Fatal(e)
	}
	for party, p := range []PartyIndex{a, b} {
		path := filepath.Join(dir, fmt.Sprintf("cs%d.psmj.bin", party))
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		hash := sha256.New()
		if e = WriteTargetParty(io.MultiWriter(f, hash), m, uint8(party), p); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
		st, e := os.Stat(path)
		if e != nil {
			t.Fatal(e)
		}
		m.PartyBytes[party] = uint64(st.Size())
		m.PartySHA256[party] = hex.EncodeToString(hash.Sum(nil))
		if m.PartyBytes[party] != TargetEncodedBytes(uint64(m.NonemptyBuckets), m.LogicalGroups, m.PaddedSlots) {
			t.Fatal("size")
		}
		f, e = os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		decoded, e := ReadTargetParty(f, m, uint8(party))
		f.Close()
		if e != nil || !reflect.DeepEqual(decoded, p) {
			t.Fatal("full file roundtrip", e)
		}
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	if e = os.WriteFile(filepath.Join(dir, "manifest.json"), append(raw, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	diskWall := time.Since(started)
	// Independent trusted logical oracle; never serialized into a cloud artifact.
	logical := map[auditIdentity][]auditPosting{}
	for _, alias := range aliases {
		VisitQGrams(alias.Name, func(w string, pos uint32) {
			key := auditIdentity{alias.Area, w}
			logical[key] = append(logical[key], auditPosting{alias.ID, pos})
		})
	}
	byPoint := map[[32]byte]auditIdentity{}
	for key := range logical {
		p, e := targetcrypto.DeriveTargetGroupPoint(kt, key.Join, key.Word)
		if e != nil {
			t.Fatal(e)
		}
		var enc [32]byte
		copy(enc[:], p.Bytes())
		if _, ok := byPoint[enc]; ok {
			t.Fatal("collision")
		}
		byPoint[enc] = key
	}
	real, dummy := []slotReference{}, []slotReference{}
	points := []slotReference{}
	checkGroup := func(bi, gi int) auditIdentity {
		g, h := a.TargetBuckets[bi].Groups[gi], b.TargetBuckets[bi].Groups[gi]
		p, e := ristretto255.NewElement().SetCanonicalBytes(g.TargetKeyShare[:])
		if e != nil {
			t.Fatal(e)
		}
		q, e := ristretto255.NewElement().SetCanonicalBytes(h.TargetKeyShare[:])
		if e != nil {
			t.Fatal(e)
		}
		var enc [32]byte
		copy(enc[:], ristretto255.NewElement().Add(p, q).Bytes())
		key, ok := byPoint[enc]
		if !ok {
			t.Fatal("point absent")
		}
		jb, e := targetcrypto.JoinBucketComponent(kt, key.Join, TargetBucketBits)
		if e != nil {
			t.Fatal(e)
		}
		wb, e := targetcrypto.WordBucketComponent(kt, key.Word, TargetBucketBits)
		if e != nil {
			t.Fatal(e)
		}
		if a.TargetBuckets[bi].BucketID != uint16(targetcrypto.CombineBucketComponents(jb, wb)) {
			t.Fatal("bucket")
		}
		width, e := TierWidth(len(logical[key]))
		if e != nil || int(g.PadWidth) != width {
			t.Fatal("tier")
		}
		return key
	}
	checkSlot := func(ref slotReference, key auditIdentity) {
		x, y := a.TargetBuckets[ref.B].Groups[ref.G].Slots[ref.S], b.TargetBuckets[ref.B].Groups[ref.G].Slots[ref.S]
		id := uint64(x.RecordIDShare.Value() + y.RecordIDShare.Value())
		pos := uint32(x.PositionShare.Value() + y.PositionShare.Value())
		valid := bool(x.ValidityShare.Value().Add(y.ValidityShare.Value()))
		posts := logical[key]
		if ref.S < len(posts) {
			if !valid || id != posts[ref.S].ID || pos != posts[ref.S].Position {
				t.Fatal("real slot")
			}
		} else if valid || id != 0 || pos != 0 {
			t.Fatal("dummy")
		}
	}
	maxGroup := 0
	seen := map[auditIdentity]bool{}
	for bi, bucket := range a.TargetBuckets {
		for gi, g := range bucket.Groups {
			key := checkGroup(bi, gi)
			if seen[key] {
				t.Fatal("duplicate group")
			}
			seen[key] = true
			if len(logical[key]) > maxGroup {
				maxGroup = len(logical[key])
			}
			points = append(points, slotReference{bi, gi, 0})
			for si := range g.Slots {
				ref := slotReference{bi, gi, si}
				checkSlot(ref, key)
				if si < len(logical[key]) {
					real = append(real, ref)
				} else {
					dummy = append(dummy, ref)
				}
			}
		}
	}
	rng := mathrand.New(mathrand.NewSource(708))
	for _, refs := range [][]slotReference{real, dummy, points} {
		for _, at := range rng.Perm(len(refs))[:10000] {
			ref := refs[at]
			key := checkGroup(ref.B, ref.G)
			checkSlot(ref, key)
		}
	}
	if len(real) != 480945 || len(dummy) != 836315 || len(points) != 310331 {
		t.Fatal("audited counts")
	}
	// Exact public/local schema allow-list, including nested types.
	want := map[reflect.Type][]string{reflect.TypeOf(TargetPartySlot{}): {"RecordIDShare", "PositionShare", "ValidityShare"}, reflect.TypeOf(TargetPartyGroup{}): {"TargetKeyShare", "PadWidth", "Slots"}, reflect.TypeOf(TargetPartyBucket{}): {"BucketID", "Groups"}}
	for typ, fields := range want {
		if typ.NumField() != len(fields) {
			t.Fatal("schema", typ)
		}
		for i, f := range fields {
			if typ.Field(i).Name != f {
				t.Fatal("schema", typ)
			}
		}
	}
	memory := uint64(unsafe.Sizeof(a))
	for _, bucket := range a.TargetBuckets {
		memory += uint64(unsafe.Sizeof(bucket)) + uint64(cap(bucket.Groups))*uint64(unsafe.Sizeof(TargetPartyGroup{}))
		for _, g := range bucket.Groups {
			memory += uint64(cap(g.Slots)) * uint64(unsafe.Sizeof(TargetPartySlot{}))
		}
	}
	report := map[string]any{"BuildStats": stats, "BuildWallSeconds": wall.Seconds(), "MaterializeAndEncodeSeconds": diskWall.Seconds(), "BuildProcStatus": string(buildProcStatus), "BuildHeapPeakSampled10ms": peak.Load(), "RetainedPartyIndexBytesApprox": memory, "MaxRealGroup": maxGroup, "AllPoints": len(points), "AllRealSlots": len(real), "AllDummySlots": len(dummy), "RandomRealSlots": 10000, "RandomDummySlots": 10000, "RandomGroupPoints": 10000, "Errors": 0, "PartySchema": "PASS"}
	raw, _ = json.MarshalIndent(report, "", "  ")
	if e = os.WriteFile(filepath.Join(dir, "build-audit.json"), append(raw, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	t.Logf("FINAL PSMJ bits=%d groups=%d real=%d padded=%d dummy=%d max_group=%d logical=%s sharing_padding=%s wall=%s sampled_heap_peak=%d bytes/party=%d random_real/dummy/points=10000/10000/10000 all_reconstruction_errors=0 schema=PASS", TargetBucketBits, len(points), len(real), stats.Target.PaddedSlots, len(dummy), maxGroup, stats.LogicalBuildTime, stats.SharingPadTime, wall, peak.Load(), m.PartyBytes[0])
}
