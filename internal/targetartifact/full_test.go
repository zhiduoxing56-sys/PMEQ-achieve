package targetartifact

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gtank/ristretto255"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetquery"
	"pmeq/internal/targetrouting"
)

type workloadQuery struct {
	Query        int
	Anchor       string
	Tau          int
	Target       string
	Positive     bool
	CompactionID [16]byte
	Joins        []uint64
	Words        []anchorfilter.QueryChunk
}

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func fullPoint(t *testing.T, a, b targetcrypto.PointShare) [32]byte {
	t.Helper()
	p, e := ristretto255.NewElement().SetCanonicalBytes(a[:])
	must(t, e)
	q, e := ristretto255.NewElement().SetCanonicalBytes(b[:])
	must(t, e)
	var out [32]byte
	copy(out[:], ristretto255.NewElement().Add(p, q).Bytes())
	return out
}
func TestFinalPayloadAndRoutes(t *testing.T) {
	dir, trace := os.Getenv("PMEQ_7B_ROUTE_ARTIFACT"), os.Getenv("PMEQ_7B_WORKLOAD")
	if dir == "" || trace == "" {
		t.Skip("explicit full regression")
	}
	raw, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	must(t, e)
	m, e := indexbuild.ReadTargetManifest(bytes.NewReader(raw))
	must(t, e)
	bound, e := targetrouting.LoadIndex(bytes.NewReader(raw))
	must(t, e)
	var indexes [2]indexbuild.PartyIndex
	for u := 0; u < 2; u++ {
		f, e := os.Open(filepath.Join(dir, fmt.Sprintf("cs%d.psmj.bin", u)))
		must(t, e)
		hash := sha256.New()
		indexes[u], e = indexbuild.ReadTargetParty(io.TeeReader(f, hash), m, uint8(u))
		must(t, e)
		must(t, f.Close())
		if hex.EncodeToString(hash.Sum(nil)) != m.PartySHA256[u] {
			t.Fatal("artifact hash")
		}
	}
	stored := map[[32]byte]uint32{}
	for bi, b := range indexes[0].TargetBuckets {
		for gi, g := range b.Groups {
			p := fullPoint(t, g.TargetKeyShare, indexes[1].TargetBuckets[bi].Groups[gi].TargetKeyShare)
			if _, ok := stored[p]; ok {
				t.Fatal("duplicate point")
			}
			stored[p] = b.BucketID
		}
	}
	f, e := os.Open("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area")
	must(t, e)
	areas, e := indexbuild.LoadArea(f, 0)
	must(t, e)
	must(t, f.Close())
	ids := make([]uint64, len(areas))
	for i, a := range areas {
		ids[i] = a.ID
	}
	var key [32]byte
	for i := range key {
		key[i] = byte(255 - i)
	}
	kt, e := targetcrypto.NewMasterKey(key)
	must(t, e)
	// A new offline LayoutID is provisioned through the existing PHASE5 API.
	// It is never relabelled as an old alignment. KJoin and all protocols unchanged.
	_, p0, p1, e := aggregation.GeneratePayload(ids, kt, int(m.TargetBucketBits))
	must(t, e)
	byID := map[uint64]int{}
	d, e := targetcrypto.NewBucketDomain(int(m.TargetBucketBits))
	must(t, e)
	for i, a := range p0.Slots {
		b := p1.Slots[i]
		id := uint64(a.RecordIDShare.Value() + b.RecordIDShare.Value())
		if _, ok := byID[id]; ok {
			t.Fatal("duplicate payload")
		}
		byID[id] = i
		x, e := ristretto255.NewScalar().SetCanonicalBytes(a.KappaJoinShare[:])
		must(t, e)
		y, e := ristretto255.NewScalar().SetCanonicalBytes(b.KappaJoinShare[:])
		must(t, e)
		want, e := targetcrypto.KJoin(kt, id)
		must(t, e)
		if ristretto255.NewScalar().Add(x, y).Equal(want) != 1 {
			t.Fatal("kappa changed")
		}
		beta, e := d.Open(a.BucketJoinShare, b.BucketJoinShare)
		must(t, e)
		expected, e := targetcrypto.JoinBucketComponent(kt, id, int(m.TargetBucketBits))
		must(t, e)
		if beta != expected {
			t.Fatal("global payload bucket")
		}
	}
	for _, id := range ids {
		if _, ok := byID[id]; !ok {
			t.Fatal("missing global ID")
		}
	}
	payloadManifest := struct {
		IndexID, LayoutID [16]byte
		TargetBucketBits  uint8
		N                 int
		Bytes             [2]int64
		SHA256            [2]string
	}{IndexID: m.IndexID, LayoutID: p0.LayoutID, TargetBucketBits: m.TargetBucketBits, N: len(ids)}
	for u, p := range []aggregation.PartyPayload{p0, p1} {
		path := filepath.Join(dir, fmt.Sprintf("cs%d.payload.bin", u))
		f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		must(t, e)
		hash := sha256.New()
		must(t, WritePayload(io.MultiWriter(f, hash), m, uint8(u), p))
		must(t, f.Close())
		st, e := os.Stat(path)
		must(t, e)
		payloadManifest.Bytes[u] = st.Size()
		payloadManifest.SHA256[u] = hex.EncodeToString(hash.Sum(nil))
		if st.Size() != int64(PayloadHeaderBytes+42*len(ids)) {
			t.Fatal("payload bytes")
		}
		f, e = os.Open(path)
		must(t, e)
		loaded, e := ReadPayload(f, m, uint8(u), p.LayoutID, uint32(len(ids)))
		must(t, e)
		must(t, f.Close())
		if !reflect.DeepEqual(p, loaded) {
			t.Fatal("payload roundtrip")
		}
	}
	raw, e = json.MarshalIndent(payloadManifest, "", "  ")
	must(t, e)
	must(t, os.WriteFile(filepath.Join(dir, "payload-manifest.json"), append(raw, '\n'), 0600))
	f, e = os.Open(trace)
	must(t, e)
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 65536), 4<<20)
	queries, pairs, present, positive, repeats := 0, 0, 0, 0, 0
	var stats []map[string]int
	for scan.Scan() {
		var q workloadQuery
		must(t, json.Unmarshal(scan.Bytes(), &q))
		if q.Query != queries || !reflect.DeepEqual(q.Words, anchorfilter.QueryChunks(q.Target)) {
			t.Fatal("workload occurrence")
		}
		if q.Positive {
			positive++
		}
		seenWords := map[string]bool{}
		repeat := false
		for _, w := range q.Words {
			if seenWords[w.QGram] {
				repeat = true
			}
			seenWords[w.QGram] = true
		}
		if repeat {
			repeats++
		}
		var c [2]targetrouting.Candidates
		for u, p := range []aggregation.PartyPayload{p0, p1} {
			c[u] = targetrouting.Candidates{LayoutID: p.LayoutID, CompactionID: q.CompactionID, TargetBucketBits: m.TargetBucketBits, K: len(q.Joins)}
			for _, j := range q.Joins {
				at, ok := byID[j]
				if !ok {
					t.Fatal("candidate absent")
				}
				v := p.Slots[at]
				c[u].RecordIDShare = append(c[u].RecordIDShare, v.RecordIDShare)
				c[u].KappaJoinShare = append(c[u].KappaJoinShare, v.KappaJoinShare)
				c[u].BucketJoinShare = append(c[u].BucketJoinShare, v.BucketJoinShare)
			}
		}
		t0, t1, e := targetquery.GenerateTokens(bound.TokenManifest(), kt, q.Target)
		must(t, e)
		a, ma, e := bound.Prepare(0, c[0], t0, 16)
		must(t, e)
		b, mb, e := bound.Prepare(1, c[1], t1, 16)
		must(t, e)
		r0, e := a.Finish(mb)
		must(t, e)
		r1, e := b.Finish(ma)
		must(t, e)
		for ci, j := range q.Joins {
			for h, w := range q.Words {
				at := ci*len(q.Words) + h
				x, y := r0.Routes[at], r1.Routes[at]
				jb, e := targetcrypto.JoinBucketComponent(kt, j, int(m.TargetBucketBits))
				must(t, e)
				wb, e := targetcrypto.WordBucketComponent(kt, w.QGram, int(m.TargetBucketBits))
				must(t, e)
				beta := uint32(targetcrypto.CombineBucketComponents(jb, wb))
				if x.BucketID != beta || y.BucketID != beta || x.CandidateIndex != uint32(ci) || x.OccurrenceID != uint32(h) {
					t.Fatal("route binding/bucket")
				}
				p := fullPoint(t, x.Y, y.Y)
				want, e := targetcrypto.DeriveTargetGroupPoint(kt, j, w.QGram)
				must(t, e)
				if !bytes.Equal(p[:], want.Bytes()) {
					t.Fatal("Y oracle")
				}
				if actual, ok := stored[p]; ok {
					if actual != beta {
						t.Fatal("materialized bucket")
					}
					present++
				}
				pairs++
			}
		}
		stats = append(stats, map[string]int{"Query": queries, "K": len(q.Joins), "Occurrences": len(q.Words), "Routes": len(r0.Routes)})
		queries++
		if queries%100 == 0 {
			t.Logf("final routing %d queries %d routes", queries, pairs)
		}
	}
	must(t, scan.Err())
	if queries != 1003 || pairs != 466105 || present != 2554 || positive != 248 || repeats != 59 {
		t.Fatal("PHASE7 workload mismatch", queries, pairs, present, positive, repeats)
	}
	raw, e = json.MarshalIndent(map[string]any{"Queries": queries, "Routes": pairs, "PresentPairs": present, "Positive": positive, "Repeated": repeats, "GlobalPayloadRecords": len(ids), "Errors": 0}, "", "  ")
	must(t, e)
	must(t, os.WriteFile(filepath.Join(dir, "route-audit.json"), append(raw, '\n'), 0600))
	t.Logf("FINAL_ROUTE_REGRESSION queries=%d routes=%d present=%d payload_records=%d errors=0", queries, pairs, present, len(ids))
	// Empty candidates create no dummy access; mismatched width rejected.
	var cid [16]byte
	_, e = rand.Read(cid[:])
	must(t, e)
	empty := targetrouting.Candidates{LayoutID: p0.LayoutID, CompactionID: cid, TargetBucketBits: m.TargetBucketBits}
	u, v, e := targetquery.GenerateTokens(bound.TokenManifest(), kt, "test")
	must(t, e)
	a, ma, e := bound.Prepare(0, empty, u, 1)
	must(t, e)
	b, mb, e := bound.Prepare(1, empty, v, 1)
	must(t, e)
	ra, e := a.Finish(mb)
	must(t, e)
	_, e = b.Finish(ma)
	must(t, e)
	if len(ma)+len(mb)+len(ra.Routes) != 0 {
		t.Fatal("empty")
	}
	empty.TargetBucketBits = 8
	if _, _, e = bound.Prepare(0, empty, u, 1); e == nil {
		t.Fatal("old width accepted")
	}
}
