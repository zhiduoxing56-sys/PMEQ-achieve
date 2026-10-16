package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"pmeq/internal/candidatequery"
	"pmeq/internal/domain"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/share"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetaggregation/gen"
	"pmeq/internal/targetartifact"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetpe"
	"pmeq/internal/zeroagg"
)

// This backend is an insecure unit-test oracle, never a performance backend.
type domainBackend struct{}

func (domainBackend) KeyGen(_ uint8, x, y uint32, o domain.Bit) (anchorfilter.SCMPKeyShare, anchorfilter.SCMPKeyShare, error) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, x)
	binary.LittleEndian.PutUint32(b[4:], y)
	return anchorfilter.NewSCMPKeyShare(b, share.NewBitShare(o)), anchorfilter.NewSCMPKeyShare(b, share.NewBitShare(false)), nil
}
func (domainBackend) Eval(p uint8, k anchorfilter.SCMPKeyShare, x, y uint32) (share.BitShare, error) {
	v := false
	if p == 0 {
		b := k.Opaque()
		v = ((x-binary.LittleEndian.Uint32(b))-(y-binary.LittleEndian.Uint32(b[4:])))&127 < 64
	}
	return share.LocalAddBit(share.NewBitShare(domain.Bit(v)), k.OutputMaskShare()), nil
}
func domainMust(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func domainJSON(t *testing.T, x any) []byte {
	t.Helper()
	b, e := json.Marshal(x)
	domainMust(t, e)
	return b
}
func domainHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type domainFixture struct {
	keys    UserKeys
	st      [2]*Static
	buckets []uint32
	shape   targetaggregation.Shape
	cap     []int
	q       Query
}

// All inputs and sealed artifacts are independently synthesized in memory.
// This constructs no MusicBrainz subset and writes no experimental results.
func newDomainFixture(t *testing.T, n int, present bool) domainFixture {
	return newDomainFixtureWithBits(t, n, present, 16)
}

func newDomainFixtureWithBits(t *testing.T, n int, present bool, bits int, extraAliases ...indexbuild.AreaAliasRecord) domainFixture {
	return newDomainFixtureWithBitsAndD(t, n, present, bits, 26, extraAliases...)
}

func newDomainFixtureWithBitsAndD(t *testing.T, n int, present bool, bits, dTarget int, extraAliases ...indexbuild.AreaAliasRecord) domainFixture {
	t.Helper()
	f := domainFixture{q: Query{Anchor: "abcd", Target: "efgh"}}
	if !present {
		f.q.Anchor = "zzzz"
	}
	var e error
	f.keys.Anchor, e = anchorindex.NewKey([32]byte{1})
	domainMust(t, e)
	f.keys.Target, e = targetcrypto.NewMasterKey([32]byte{2})
	domainMust(t, e)
	areas := make([]indexbuild.AreaRecord, n)
	ids := make([]uint64, n)
	for i := range areas {
		ids[i] = 1001 + uint64(i)*17
		areas[i] = indexbuild.AreaRecord{ID: ids[i], Name: "x"}
	}
	areas[0].Name = "abcd"
	aliases := []indexbuild.AreaAliasRecord{{ID: 901, Name: "efgh", Area: ids[0]}}
	if dTarget != 1 {
		aliases = append([]indexbuild.AreaAliasRecord{{ID: 900, Name: "x", Area: ids[0]}}, aliases...)
	}
	aliases = append(aliases, extraAliases...)
	_, a0, a1, _, e := indexbuild.Build(areas, nil, f.keys.Anchor, f.keys.Target, bits, bits)
	domainMust(t, e)
	meta, t0, t1, stats, e := indexbuild.BuildFinalTargetWithBits(aliases, f.keys.Target, bits)
	domainMust(t, e)
	m, e := indexbuild.NewTargetManifest([16]byte{1}, meta, stats.Target)
	domainMust(t, e)
	var files [2][]byte
	for u, p := range []indexbuild.PartyIndex{t0, t1} {
		var b bytes.Buffer
		domainMust(t, indexbuild.WriteTargetParty(&b, m, uint8(u), p))
		files[u] = b.Bytes()
		m.PartyBytes[u] = uint64(b.Len())
		m.PartySHA256[u] = domainHash(b.Bytes())
	}
	mr := domainJSON(t, m)
	layout, p0, p1, e := aggregation.GeneratePayload(ids, f.keys.Target, bits)
	domainMust(t, e)
	payloads := [2]aggregation.PartyPayload{p0, p1}
	pm := targetpe.PayloadManifest{IndexID: m.IndexID, LayoutID: layout.LayoutID, TargetBucketBits: uint8(bits), N: n}
	var pb [2][]byte
	for u, p := range payloads {
		var b bytes.Buffer
		domainMust(t, targetartifact.WritePayload(&b, m, uint8(u), p))
		pb[u] = b.Bytes()
		pm.Bytes[u] = int64(b.Len())
		pm.SHA256[u] = domainHash(b.Bytes())
	}
	pr := domainJSON(t, pm)
	var sb [2]bytes.Buffer
	sm, _, e := gen.BuildWithCapacity(mr, files, aliases, [2]io.Writer{&sb[0], &sb[1]}, dTarget)
	domainMust(t, e)
	z, e := anchorindex.Encode(f.keys.Anchor, f.q.Anchor)
	domainMust(t, e)
	id, e := indexbuild.AnchorBucket(z, bits)
	domainMust(t, e)
	f.buckets = []uint32{id}
	bs := [2]indexbuild.AnchorPartyBucket{{BucketID: id}, {BucketID: id}}
	for u, p := range []indexbuild.PartyIndex{a0, a1} {
		for _, b := range p.AnchorBuckets {
			if b.BucketID == id {
				bs[u] = b
			}
		}
	}
	var posts []incidence.Posting
	for _, g := range bs[0].Groups {
		if g.Z != z {
			t.Fatal("unexpected synthetic bucket collision")
		}
		posts = append(posts, incidence.Posting{RecordID: ids[0], Real: true})
		for i := 1; i < len(g.Slots); i++ {
			posts = append(posts, incidence.Posting{})
		}
	}
	loc, e := incidence.PrepareLayout(posts)
	domainMust(t, e)
	i0, i1, e := zeroagg.ShareCoordinates(loc.Coordinates, loc.D)
	domainMust(t, e)
	s0, s1, e := layout.Alignment(id, loc, posts)
	domainMust(t, e)
	anchors := [2]map[uint32]AnchorStatic{{id: {Bucket: bs[0], D: loc.D, T: len(posts), Labels: i0, LabelID: "01000000000000000000000000000000", Stage0: s0}}, {id: {Bucket: bs[1], D: loc.D, T: len(posts), Labels: i1, LabelID: "01000000000000000000000000000000", Stage1: s1}}}
	for u := 0; u < 2; u++ {
		idx, e := targetpe.Load(bytes.NewReader(mr), bytes.NewReader(pr), bytes.NewReader(files[u]), bytes.NewReader(pb[u]), uint8(u), targetpe.AlignmentLineage{IndexID: m.IndexID, LayoutID: layout.LayoutID, N: n})
		domainMust(t, e)
		payload, e := targetartifact.ReadPayload(bytes.NewReader(pb[u]), m, uint8(u), layout.LayoutID, uint32(n))
		domainMust(t, e)
		side, e := targetaggregation.LoadSidecar(sm, mr, idx, bytes.NewReader(sb[u].Bytes()))
		domainMust(t, e)
		f.st[u], e = NewStatic(uint8(u), anchors[u], payload, idx, side)
		domainMust(t, e)
	}
	f.shape = targetaggregation.Shape{R: 1, D: dTarget}
	f.cap = []int{0}
	if present {
		j, e := targetcrypto.JoinBucketComponent(f.keys.Target, ids[0], bits)
		domainMust(t, e)
		w, e := targetcrypto.WordBucketComponent(f.keys.Target, "efgh", bits)
		domainMust(t, e)
		groups := f.st[0].target.PositionGroups(uint32(j) ^ uint32(w))
		f.shape.K = 1
		f.shape.G = len(groups)
		for _, g := range groups {
			f.shape.S += int(g.PadWidth)
		}
		f.cap[0] = f.shape.S
	}
	return f
}

func runDomainFixture(t *testing.T, f domainFixture, backend anchorfilter.SCMPBackend) Metrics {
	t.Helper()
	n := len(f.st[0].payload.Slots)
	u, p0, p1, cost, e := Provision(f.st[0], f.st[1], f.buckets, f.cap, f.shape, backend)
	domainMust(t, e)
	_, e = PersistReservation(t.TempDir(), t.TempDir(), u, p0, p1, f.st[0], f.st[1])
	domainMust(t, e)
	compactionBytes := 266
	if f.st[0].target.Manifest().TargetBucketBits > 16 {
		compactionBytes = 278
	}
	if cost.Compaction != uint64(compactionBytes*n) {
		t.Fatal("compaction capacity", n, cost.Compaction)
	}
	// The comparison API itself rejects a vector from a different global domain.
	if _, e := p0.keep.Prepare(make([]incidence.Share, n+1)); e == nil {
		t.Fatal("Keep material domain")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, m, e := RunLocal(ctx, f.q, f.keys, u, f.st, [2]*PartyPacket{p0, p1}, backend)
	domainMust(t, e)
	if m.K != f.shape.K || m.Groups != f.shape.G || m.Slots != f.shape.S || m.Routes != f.shape.K {
		t.Fatal("workload", m)
	}
	if len(out.Pairs) != f.shape.K {
		t.Fatal("pair count", out)
	}
	if f.shape.K == 1 && out.Pairs[0] != (candidatequery.Pair{AnchorRecordID: 1001, TargetRecordID: 901}) {
		t.Fatal("pair IDs", out)
	}
	if m.CloudToUser != ([2]uint64{uint64(86 + 442*m.K), uint64(86 + 442*m.K)}) {
		t.Fatal("output bytes")
	}
	if m.AnchorParts.Total() != m.Anchor || m.AnchorParts.Other < 0 {
		t.Fatal("timing partition")
	}
	if _, _, e := RunLocal(ctx, f.q, f.keys, u, f.st, [2]*PartyPacket{p0, p1}, backend); e == nil {
		t.Fatal("reused packet")
	}
	return m
}

func TestIntegratedActualDomain(t *testing.T) {
	for _, present := range []bool{false, true} {
		var previous Metrics
		prevN := 0
		for _, n := range []int{1, 7, 65} {
			t.Run(fmt.Sprintf("N%d/present%t", n, present), func(t *testing.T) {
				m := runDomainFixture(t, newDomainFixture(t, n, present), domainBackend{})
				// One Anchor occurrence: two alignment vectors, Keep vector,
				// two 43-byte shuffle tuples and two opening bits per record.
				// Alignment contributes 2N; Keep contributes 2N; compaction 88N.
				if prevN > 0 {
					if m.ServerBytes-previous.ServerBytes != uint64(92*(n-prevN)) {
						t.Fatal("global wire domain", previous.ServerBytes, m.ServerBytes)
					}
					if m.UserToCloud != previous.UserToCloud || m.CloudToUser != previous.CloudToUser {
						t.Fatal("token/output format changed")
					}
				}
				previous = m
				prevN = n
			})
		}
	}
}

func TestBucketWidthsCompleteProtocol(t *testing.T) {
	for _, bits := range []int{14, 15, 16, 17} {
		t.Run(fmt.Sprintf("B2^%d", bits), func(t *testing.T) {
			runDomainFixture(t, newDomainFixtureWithBits(t, 2, true, bits), domainBackend{})
		})
	}
}

func TestStaticDomainMismatch(t *testing.T) {
	f := newDomainFixture(t, 7, true)
	for u, st := range f.st {
		p := st.payload
		p.Slots = p.Slots[:6]
		if _, e := NewStatic(uint8(u), st.anchor, p, st.target, st.sidecar); e == nil {
			t.Fatal("payload mismatch")
		}
	}
	b := *f.st[1]
	b.payload.Slots = b.payload.Slots[:6]
	if _, _, _, _, e := Provision(f.st[0], &b, f.buckets, f.cap, f.shape, domainBackend{}); e == nil {
		t.Fatal("party domain mismatch")
	}
	id := f.buckets[0]
	a := f.st[1].anchor[id]
	pi := make([]uint32, 8)
	for i := range pi {
		pi[i] = uint32(i)
	}
	_, bad, e := aggregation.SplitPermutation(f.st[1].payload.LayoutID, id, pi)
	domainMust(t, e)
	a.Stage1 = bad
	if _, e := NewStatic(1, map[uint32]AnchorStatic{id: a}, f.st[1].payload, f.st[1].target, f.st[1].sidecar); e == nil {
		t.Fatal("alignment mismatch")
	}
	b = *f.st[1]
	b.anchor = map[uint32]AnchorStatic{id: a}
	if _, _, _, _, e := Provision(f.st[0], &b, f.buckets, f.cap, f.shape, domainBackend{}); e == nil {
		t.Fatal("offline alignment mismatch")
	}
}
