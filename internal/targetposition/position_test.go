package targetposition

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/share"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetrouting"
	"testing"
)

// OracleBackend is deliberately test-only and insecure. Never benchmark it.
type oracleBackend struct{}

func (oracleBackend) KeyGen(bin uint8, x, y uint32, o domain.Bit) (anchorfilter.SCMPKeyShare, anchorfilter.SCMPKeyShare, error) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, x)
	binary.LittleEndian.PutUint32(b[4:], y)
	return anchorfilter.NewSCMPKeyShare(b, share.NewBitShare(o)), anchorfilter.NewSCMPKeyShare(b, share.NewBitShare(domain.BitZero)), nil
}
func (oracleBackend) Eval(p uint8, k anchorfilter.SCMPKeyShare, x, y uint32) (share.BitShare, error) {
	v := false
	if p == 0 {
		b := k.Opaque()
		d := ((x - binary.LittleEndian.Uint32(b)) - (y - binary.LittleEndian.Uint32(b[4:]))) & 127
		v = d < 64
	}
	return share.LocalAddBit(share.NewBitShare(domain.Bit(v)), k.OutputMaskShare()), nil
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func loadIndexes(t *testing.T) [2]*targetpe.PartyIndex {
	t.Helper()
	dir := "../../artifacts/phase7b"
	mr, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	must(t, e)
	pr, e := os.ReadFile(filepath.Join(dir, "payload-manifest.json"))
	must(t, e)
	var pm targetpe.PayloadManifest
	must(t, json.Unmarshal(pr, &pm))
	var out [2]*targetpe.PartyIndex
	for u := 0; u < 2; u++ {
		name := "cs0"
		if u == 1 {
			name = "cs1"
		}
		f, e := os.Open(filepath.Join(dir, name+".psmj.bin"))
		must(t, e)
		p, e := os.Open(filepath.Join(dir, name+".payload.bin"))
		must(t, e)
		out[u], e = targetpe.Load(bytes.NewReader(mr), bytes.NewReader(pr), f, p, uint8(u), targetpe.AlignmentLineage{IndexID: pm.IndexID, LayoutID: pm.LayoutID, N: pm.N})
		must(t, e)
		f.Close()
		p.Close()
	}
	return out
}
func testBounds(t *testing.T, backend anchorfilter.SCMPBackend) {
	for _, tau := range []uint32{0, 1, 2, 62, ^uint32(0)} {
		for _, pq := range []uint32{0, 4, 60, 62} {
			u, a, b, e := anchorfilter.Preprocess(63, 7, backend)
			must(t, e)
			pid, l, r, e := u.ConsumeBounds(pq, tau, 62)
			must(t, e)
			q := anchorfilter.PartyQuery{PID: pid, Ltilde: l, RplusTilde: r}
			opened := anchorfilter.OpenedPositions{PL: make([]uint32, 63), PR: make([]uint32, 63)}
			for p := uint32(0); p <= 62; p++ {
				opened.PL[p] = (p + a.RhoL[p] + b.RhoL[p]) & 127
				opened.PR[p] = (p + a.RhoR[p] + b.RhoR[p]) & 127
			}
			x, e := anchorfilter.EvalPosition(0, q, a, opened, backend)
			must(t, e)
			y, e := anchorfilter.EvalPosition(1, q, b, opened, backend)
			must(t, e)
			for p := uint32(0); p <= 62; p++ {
				d := int(p) - int(pq)
				if d < 0 {
					d = -d
				}
				if bool(x[p].Value().Add(y[p].Value())) != (uint64(d) <= uint64(tau)) {
					t.Fatal("position boundary", p, pq, tau)
				}
			}
		}
	}
}
func TestBoundsOracle(t *testing.T)                      { testBounds(t, oracleBackend{}) }
func TestSealedPostingCompositionAndGuards(t *testing.T) { testComposition(t, oracleBackend{}) }
func testComposition(t *testing.T, backend anchorfilter.SCMPBackend) {
	idx := loadIndexes(t)
	bucket := uint32(0)
	for len(idx[0].PositionGroups(bucket)) < 2 {
		bucket++
	}
	gs := idx[0].PositionGroups(bucket)
	n := 0
	for _, g := range gs {
		n += int(g.PadWidth)
	}
	for _, tau := range []uint32{0, 2, ^uint32(0)} {
		users, p0, p1, _, e := Preprocess(idx[0].Lineage(), []int{n + 1, n}, backend)
		must(t, e)
		packets := [2]Packet{p0, p1}
		var tok [2]targetrouting.QueryToken
		var matches [2]targetpe.TargetGroupMatches
		for h := 0; h < 2; h++ {
			pid, l, r, e := users[h].ConsumeBounds(uint32(h*4), tau, 62)
			must(t, e)
			for u := 0; u < 2; u++ {
				tok[u].Position = append(tok[u].Position, anchorfilter.PositionToken{PID: pid, Ltilde: l, RplusTilde: r})
				tok[u].Words = append(tok[u].Words, targetrouting.WordToken{Occurrence: targetrouting.Occurrence{OccurrenceID: uint32(h), Position: uint32(4 * h)}})
			}
		}
		for u := 0; u < 2; u++ {
			tok[u].Manifest = idx[u].Manifest()
			tok[u].QueryID = [16]byte{3}
			tok[u].Party = uint8(u)
			matches[u] = targetpe.TargetGroupMatches{Manifest: idx[u].Manifest(), LayoutID: idx[u].Lineage().LayoutID, CompactionID: [16]byte{4}, QueryID: tok[u].QueryID, K: 1, AnchorRecordIDShare: make([]share.Ring64Share, 1)}
			for h := 0; h < 2; h++ {
				matches[u].Occurrences = append(matches[u].Occurrences, tok[u].Words[h].Occurrence)
				matches[u].Routes = append(matches[u].Routes, targetpe.Route{CandidateIndex: 0, OccurrenceID: uint32(h), BucketID: bucket, MatchOffset: h * len(gs), GroupCount: len(gs)})
				for gi := range gs {
					matches[u].MatchShares = append(matches[u].MatchShares, share.NewBitShare(domain.Bit(u == 0 && gi%2 == 0)))
				}
			}
		}
		bad := matches[0]
		bad.LayoutID = [16]byte{9}
		if _, e := Begin(idx[0], bad, tok[0], p0, backend); e == nil {
			t.Fatal("lineage accepted")
		}
		a, e := Begin(idx[0], matches[0], tok[0], packets[0], backend)
		must(t, e)
		b, e := Begin(idx[1], matches[1], tok[1], packets[1], backend)
		must(t, e)
		if _, e := Begin(idx[0], matches[0], tok[0], p0, backend); e == nil {
			t.Fatal("reused packet")
		}
		for !a.Done() {
			x, e := a.Next()
			must(t, e)
			y, e := b.Next()
			must(t, e)
			if _, e := a.Next(); e == nil {
				t.Fatal("duplicate Next")
			}
			wrong := append([]byte(nil), y...)
			wrong[41] ^= 1
			if e := a.Accept(wrong); e == nil {
				t.Fatal("wrong round")
			}
			must(t, a.Accept(y))
			must(t, b.Accept(x))
		}
		x, e := a.Output()
		must(t, e)
		y, e := b.Output()
		must(t, e)
		if _, e := a.Output(); e == nil {
			t.Fatal("repeat output")
		}
		for h, r := range x.Routes {
			at := r.SlotOffset
			for gi, g := range gs {
				for si := 0; si < int(g.PadWidth); si++ {
					p0, v0 := idx[0].PositionSlot(bucket, gi, si)
					p1, v1 := idx[1].PositionSlot(bucket, gi, si)
					p := int(uint32(p0.Value() + p1.Value()))
					d := p - 4*h
					if d < 0 {
						d = -d
					}
					want := gi%2 == 0 && uint64(d) <= uint64(tau) && bool(v0.Value().Add(v1.Value()))
					if bool(x.HitShares[at].Value().Add(y.HitShares[at].Value())) != want {
						t.Fatal("slot hit", h, gi, si)
					}
					at++
				}
			}
		}
		if a.Metrics().SCMPBytes+b.Metrics().SCMPBytes != uint64(16*2*n) || a.Metrics().ANDBytes+b.Metrics().ANDBytes != uint64(8*2*n) {
			t.Fatal("codec accounting")
		}
	}
	users, p0, p1, _, e := Preprocess(idx[0].Lineage(), nil, backend)
	must(t, e)
	_ = users
	for u, p := range []Packet{p0, p1} {
		m := targetpe.TargetGroupMatches{Manifest: idx[u].Manifest(), LayoutID: idx[u].Lineage().LayoutID, QueryID: [16]byte{1}, CompactionID: [16]byte{2}}
		tok := targetrouting.QueryToken{Manifest: m.Manifest, QueryID: m.QueryID, Party: uint8(u)}
		s, e := Begin(idx[u], m, tok, p, backend)
		must(t, e)
		o, e := s.Output()
		must(t, e)
		if len(o.HitShares) != 0 {
			t.Fatal("dummy zero route")
		}
	}
}

func TestFrozenDomainProof(t *testing.T) {
	bin, e := anchorfilter.DeriveBin(62)
	must(t, e)
	if bin != 7 {
		t.Fatal("Bin")
	}
	for p := uint32(0); p <= 62; p++ {
		for pq := uint32(0); pq <= 62; pq++ {
			for tau := uint32(0); tau <= 64; tau++ {
				l, r := anchorfilter.Bounds(pq, tau, 62)
				for _, b := range []uint32{l, r + 1} {
					d := int(p) - int(b)
					if d < -63 || d > 62 {
						t.Fatal("signed input bound")
					}
				}
			}
		}
	}
	var user anchorfilter.UserPreprocessing
	if _, _, _, e := user.ConsumeBounds(64, 0, 62); e == nil {
		t.Fatal("out of range query")
	}
}
