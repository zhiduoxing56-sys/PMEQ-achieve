package targetpe

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"github.com/gtank/ristretto255"
	"os"
	"path/filepath"
	"pmeq/internal/f2beaver"
	"pmeq/internal/indexbuild"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetrouting"
	"testing"
)

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func syntheticIndex() (*PartyIndex, *PartyIndex) {
	m := indexbuild.TargetManifest{IndexID: [16]byte{1}, TargetBucketBits: 16, Q: 4}
	l := AlignmentLineage{m.IndexID, [16]byte{2}, 120071}
	return &PartyIndex{manifest: m, lineage: l, party: 0, buckets: make([][]indexbuild.TargetPartyGroup, 1<<m.TargetBucketBits)}, &PartyIndex{manifest: m, lineage: l, party: 1, buckets: make([][]indexbuild.TargetPartyGroup, 1<<m.TargetBucketBits)}
}
func run(t *testing.T, a, b *Session) (TargetGroupMatches, TargetGroupMatches) {
	t.Helper()
	if a.g > 0 {
		for round := 0; round < 8; round++ {
			x, e := a.Next()
			must(t, e)
			y, e := b.Next()
			must(t, e)
			must(t, a.Accept(y))
			must(t, b.Accept(x))
		}
	}
	x, e := a.Output()
	must(t, e)
	y, e := b.Output()
	must(t, e)
	return x, y
}

// Tests-only access to encoded private inputs for 200k differential cases.
func encodedSession(t *testing.T, party uint8, enc [][32]byte, p Packet, workers int) *Session {
	t.Helper()
	p.state.Lock()
	defer p.state.Unlock()
	if p.state.used {
		t.Fatal("reused test packet")
	}
	p.state.used = true
	s := &Session{party: party, workers: workers, g: len(enc), w: Words(len(enc)), packetID: p.ID, triples: p.state.triples}
	p.state.triples = f2beaver.PackedBatch{}
	s.initialize(enc)
	return s
}
func TestOption4PrivateEquality100k(t *testing.T) {
	const n = 200000
	a, b := make([][32]byte, n), make([][32]byte, n)
	var random [64]byte
	// Independent random group shares. Equal cases choose Y=T; unequal uses
	// a distinct full point. All full-point construction is trusted test only.
	for i := 0; i < n; i++ {
		_, e := rand.Read(random[:])
		must(t, e)
		full, e := ristretto255.NewElement().SetUniformBytes(random[:])
		must(t, e)
		t0, t1, e := targetcrypto.SplitPoint(full)
		must(t, e)
		if i >= 100000 {
			full = ristretto255.NewElement().Add(full, targetcrypto.TargetBasePoint())
		}
		y0, y1, e := targetcrypto.SplitPoint(full)
		must(t, e)
		a[i], e = DifferenceEncoding(0, y0, t0)
		must(t, e)
		b[i], e = DifferenceEncoding(1, y1, t1)
		must(t, e)
		if (a[i] == b[i]) != (i < 100000) {
			t.Fatal("Option4 identity")
		}
	}
	p, q, e := Preprocess(AlignmentLineage{IndexID: [16]byte{1}, LayoutID: [16]byte{2}}, n)
	must(t, e)
	s0, s1 := encodedSession(t, 0, a, p, 1), encodedSession(t, 1, b, q, 1)
	x, y := run(t, s0, s1)
	for i := range a {
		hit := bool(x.MatchShares[i].Value().Add(y.MatchShares[i].Value()))
		if hit != (i < 100000) {
			t.Fatal("PE", i)
		}
	}
	if s0.Metrics().PayloadBytes+s1.Metrics().PayloadBytes != uint64(8160*Words(n)) {
		t.Fatal("bytes")
	}
	t.Log("Option4+PE equal=100000 unequal=100000 false_negative=0 false_positive=0")
}
func TestEdgesBindingsAndWorkers(t *testing.T) {
	for _, n := range []int{0, 1, 63, 64, 65, 129} {
		for _, workers := range []int{1, 4, 8, 16} {
			a, b := make([][32]byte, n), make([][32]byte, n)
			for i := range a {
				if i%2 == 1 {
					b[i][31] = 128
				}
			}
			p, q, e := Preprocess(AlignmentLineage{IndexID: [16]byte{1}, LayoutID: [16]byte{2}}, n)
			must(t, e)
			s0, s1 := encodedSession(t, 0, a, p, workers), encodedSession(t, 1, b, q, workers)
			x, y := run(t, s0, s1)
			if len(x.MatchShares) != n {
				t.Fatal("padding")
			}
			for i := range a {
				if bool(x.MatchShares[i].Value().Add(y.MatchShares[i].Value())) != (i%2 == 0) {
					t.Fatal("last byte/lane")
				}
			}
			if _, e = s0.Output(); e == nil {
				t.Fatal("output reuse")
			}
		}
	}
	z := targetcrypto.PointShare{}
	for _, party := range []uint8{0, 1} {
		enc, e := DifferenceEncoding(party, z, z)
		must(t, e)
		if enc != [32]byte{} {
			t.Fatal("identity")
		}
	}
	scalar := targetcrypto.ScalarShare{}
	p, e := targetcrypto.PartEval(scalar)
	must(t, e)
	if !bytes.Equal(p.Bytes(), make([]byte, 32)) {
		t.Fatal("zero scalar")
	}
	var malformed targetcrypto.PointShare
	for i := range malformed {
		malformed[i] = 255
	}
	if _, e = DifferenceEncoding(0, malformed, z); e == nil {
		t.Fatal("noncanonical")
	}
	for _, n := range []int{0, 31, 33} {
		if _, e = ristretto255.NewElement().SetCanonicalBytes(make([]byte, n)); e == nil {
			t.Fatal("length")
		}
	}
	for i := 0; i < 100; i++ {
		var r [64]byte
		rand.Read(r[:])
		p, e := ristretto255.NewElement().SetUniformBytes(r[:])
		must(t, e)
		var raw [32]byte
		copy(raw[:], p.Bytes())
		s, e := targetcrypto.NewPointShare(raw)
		must(t, e)
		if s.CanonicalBytes() != raw {
			t.Fatal("roundtrip")
		}
	}
}
func fixture(t *testing.T, n int) (*PartyIndex, *PartyIndex, targetrouting.RoutedCandidates, targetrouting.RoutedCandidates) {
	t.Helper()
	a, b := syntheticIndex()
	zero := targetcrypto.PointShare{}
	for i := 0; i < n; i++ {
		a.buckets[0] = append(a.buckets[0], indexbuild.TargetPartyGroup{TargetKeyShare: zero, PadWidth: 4})
		b.buckets[0] = append(b.buckets[0], indexbuild.TargetPartyGroup{TargetKeyShare: zero, PadWidth: 4})
	}
	r := targetrouting.RoutedCandidates{Manifest: a.Manifest(), LayoutID: a.lineage.LayoutID, CompactionID: [16]byte{3}, QueryID: [16]byte{4}, K: 1, AnchorRecordIDShare: make([]share.Ring64Share, 1), Occurrences: []targetrouting.Occurrence{{OccurrenceID: 0, Position: 0}}, Routes: []targetrouting.Route{{CandidateIndex: 0, OccurrenceID: 0, BucketID: 0, Y: zero}}}
	return a, b, r, r
}
func TestSessionGuards(t *testing.T) {
	a, b, r, u := fixture(t, 65)
	p, q, e := Preprocess(a.lineage, 65)
	must(t, e)
	wrong := r
	wrong.LayoutID = [16]byte{9}
	if _, e = a.Begin(wrong, p, 1); e == nil {
		t.Fatal("lineage")
	}
	wrong = r
	wrong.Manifest.TargetBucketBits = 8
	if _, e = a.Begin(wrong, p, 1); e == nil {
		t.Fatal("manifest")
	}
	s0, e := a.Begin(r, p, 1)
	must(t, e)
	if _, e = a.Begin(r, p, 1); e == nil {
		t.Fatal("packet reuse")
	}
	s1, e := b.Begin(u, q, 1)
	must(t, e)
	m0, e := s0.Next()
	must(t, e)
	m1, e := s1.Next()
	must(t, e)
	if _, e = s0.Next(); e == nil {
		t.Fatal("round twice")
	}
	bad := append([]byte(nil), m1...)
	bad[57]++
	if e = s0.Accept(bad); e == nil {
		t.Fatal("round")
	}
	bad = append([]byte(nil), m1...)
	bad[8]++
	if e = s0.Accept(bad); e == nil {
		t.Fatal("binding")
	}
	if e = s0.Accept(m0); e == nil {
		t.Fatal("same party")
	}
	must(t, s0.Accept(m1))
	must(t, s1.Accept(m0))
	if e = s0.Accept(m1); e == nil {
		t.Fatal("round replay")
	}
	for round := 1; round < 8; round++ {
		m0, e = s0.Next()
		must(t, e)
		m1, e = s1.Next()
		must(t, e)
		must(t, s0.Accept(m1))
		must(t, s1.Accept(m0))
	}
	x, e := s0.Output()
	must(t, e)
	y, e := s1.Output()
	must(t, e)
	for i := range x.MatchShares {
		if !bool(x.MatchShares[i].Value().Add(y.MatchShares[i].Value())) {
			t.Fatal("identity equality")
		}
	}
}
func TestSealedManifestLineageAndStructure(t *testing.T) {
	dir := "../../artifacts/phase7b"
	raw, e := os.ReadFile(filepath.Join(dir, "payload-manifest.json"))
	must(t, e)
	var pm PayloadManifest
	must(t, json.Unmarshal(raw, &pm))
	l := AlignmentLineage{pm.IndexID, pm.LayoutID, pm.N}
	var idx [2]*PartyIndex
	load := func(u int, lineage AlignmentLineage) (*PartyIndex, error) {
		name := "cs0"
		if u == 1 {
			name = "cs1"
		}
		a, e := os.Open(filepath.Join(dir, "manifest.json"))
		if e != nil {
			return nil, e
		}
		defer a.Close()
		b, e := os.Open(filepath.Join(dir, "payload-manifest.json"))
		if e != nil {
			return nil, e
		}
		defer b.Close()
		c, e := os.Open(filepath.Join(dir, name+".psmj.bin"))
		if e != nil {
			return nil, e
		}
		defer c.Close()
		d, e := os.Open(filepath.Join(dir, name+".payload.bin"))
		if e != nil {
			return nil, e
		}
		defer d.Close()
		return Load(a, b, c, d, uint8(u), lineage)
	}
	for i := range idx {
		idx[i], e = load(i, l)
		must(t, e)
	}
	if idx[0].StructureDigest() != idx[1].StructureDigest() {
		t.Fatal("structure")
	}
	for i := 0; i < 65536; i++ {
		a, b := idx[0].buckets[i], idx[1].buckets[i]
		if len(a) != len(b) {
			t.Fatal("count")
		}
		for j := range a {
			if a[j].PadWidth != b[j].PadWidth {
				t.Fatal("ordinal")
			}
		}
	}
	l.LayoutID[0] ^= 1
	if _, e = load(0, l); e == nil {
		t.Fatal("wrong alignment")
	}
}

func TestLogicalUnequalCategories(t *testing.T) {
	key, e := targetcrypto.NewMasterKey([32]byte{8})
	must(t, e)
	ref, e := targetcrypto.DeriveTargetGroupPoint(key, 1, "abcd")
	must(t, e)
	t0, t1, e := targetcrypto.SplitPoint(ref)
	must(t, e)
	var a, b [][32]byte
	for _, v := range []struct {
		j uint64
		w string
	}{{1, "wxyz"}, {2, "abcd"}, {2, "wxyz"}, {1, "abcd"}, {1, "abcd"}} {
		point, e := targetcrypto.DeriveTargetGroupPoint(key, v.j, v.w)
		must(t, e)
		y0, y1, e := targetcrypto.SplitPoint(point)
		must(t, e)
		x, e := DifferenceEncoding(0, y0, t0)
		must(t, e)
		y, e := DifferenceEncoding(1, y1, t1)
		must(t, e)
		a = append(a, x)
		b = append(b, y)
	}
	p, q, e := Preprocess(AlignmentLineage{IndexID: [16]byte{1}, LayoutID: [16]byte{2}}, len(a))
	must(t, e)
	x, y := run(t, encodedSession(t, 0, a, p, 1), encodedSession(t, 1, b, q, 1))
	for i := range a {
		if bool(x.MatchShares[i].Value().Add(y.MatchShares[i].Value())) != (i >= 3) {
			t.Fatal("logical unequal/repeated", i)
		}
	}
}

func TestHashCorruption(t *testing.T) {
	dir := "../../artifacts/phase7b"
	mr, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	must(t, e)
	pr, e := os.ReadFile(filepath.Join(dir, "payload-manifest.json"))
	must(t, e)
	sr, e := os.ReadFile(filepath.Join(dir, "cs0.psmj.bin"))
	must(t, e)
	gr, e := os.ReadFile(filepath.Join(dir, "cs0.payload.bin"))
	must(t, e)
	var pm PayloadManifest
	must(t, json.Unmarshal(pr, &pm))
	l := AlignmentLineage{pm.IndexID, pm.LayoutID, pm.N}
	gr[len(gr)-1] ^= 1
	if _, e = Load(bytes.NewReader(mr), bytes.NewReader(pr), bytes.NewReader(sr), bytes.NewReader(gr), 0, l); e == nil {
		t.Fatal("payload hash")
	}
	gr[len(gr)-1] ^= 1
	sr[len(sr)-1] ^= 1
	if _, e = Load(bytes.NewReader(mr), bytes.NewReader(pr), bytes.NewReader(sr), bytes.NewReader(gr), 0, l); e == nil {
		t.Fatal("PSMJ hash")
	}
}

func TestEmptyRouting(t *testing.T) {
	a, b := syntheticIndex()
	r := targetrouting.RoutedCandidates{Manifest: a.Manifest(), LayoutID: a.lineage.LayoutID, CompactionID: [16]byte{3}, QueryID: [16]byte{4}, Occurrences: []targetrouting.Occurrence{{OccurrenceID: 0, Position: 0}}}
	p, q, e := Preprocess(a.lineage, 0)
	must(t, e)
	s, e := a.Begin(r, p, 1)
	must(t, e)
	v, e := b.Begin(r, q, 1)
	must(t, e)
	x, y := run(t, s, v)
	if x.K != 0 || len(x.Routes) != 0 || len(y.MatchShares) != 0 || s.Metrics().PayloadBytes != 0 || s.Metrics().FramingBytes != 0 {
		t.Fatal("empty routes")
	}
}

func TestOfflineCapacityPacket(t *testing.T) {
	a, b, r, u := fixture(t, 3)
	p, q, e := Preprocess(a.lineage, 129)
	must(t, e)
	s, e := a.Begin(r, p, 1)
	must(t, e)
	v, e := b.Begin(u, q, 1)
	must(t, e)
	x, y := run(t, s, v)
	for i := range x.MatchShares {
		if !bool(x.MatchShares[i].Value().Add(y.MatchShares[i].Value())) {
			t.Fatal("capacity prefix")
		}
	}
	if s.usedTriples != 255*Words(3) || s.Metrics().PayloadBytes+v.Metrics().PayloadBytes != 8160 {
		t.Fatal("actual consumption")
	}
	if _, e = a.Begin(r, p, 1); e == nil {
		t.Fatal("unused capacity cannot be reused")
	}
}
