package candidatequery

import (
	"pmeq/internal/domain"
	"pmeq/internal/preprocess"
	"pmeq/internal/share"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetrouting"
	"testing"
)

func fixture(t *testing.T, k int) (Binding, [2]targetaggregation.CandidatePairShares) {
	t.Helper()
	w := Binding{Manifest: targetrouting.Manifest{IndexID: [16]byte{1}, TargetBucketBits: 16, Q: 4}, LayoutID: [16]byte{2}, CompactionID: [16]byte{3}, QueryID: [16]byte{4}}
	var s [2]targetaggregation.CandidatePairShares
	for u := range s {
		s[u] = targetaggregation.CandidatePairShares{Manifest: w.Manifest, LayoutID: w.LayoutID, CompactionID: w.CompactionID, QueryID: w.QueryID, K: k, DTarget: 26, PairKeepShares: make([]share.BitShare, 26*k), AnchorIDShares: make([]share.Ring64Share, 26*k), TargetIDShares: make([]share.Ring64Share, 26*k)}
	}
	for i := 0; i < 26*k; i++ {
		setSlot(t, &s, i, false, 0, 0)
	}
	return w, s
}
func setSlot(t *testing.T, s *[2]targetaggregation.CandidatePairShares, i int, keep bool, a, b uint64) {
	t.Helper()
	var e error
	s[0].PairKeepShares[i], s[1].PairKeepShares[i], e = preprocess.SplitBit(domain.Bit(keep))
	if e != nil {
		t.Fatal(e)
	}
	s[0].AnchorIDShares[i], s[1].AnchorIDShares[i], e = preprocess.SplitRing64(domain.Ring64(a))
	if e != nil {
		t.Fatal(e)
	}
	s[0].TargetIDShares[i], s[1].TargetIDShares[i], e = preprocess.SplitRing64(domain.Ring64(b))
	if e != nil {
		t.Fatal(e)
	}
}
func encode(t *testing.T, s [2]targetaggregation.CandidatePairShares) [2][]byte {
	t.Helper()
	var b [2][]byte
	for u := range b {
		var e error
		b[u], e = EncodeShares(uint8(u), s[u])
		if e != nil {
			t.Fatal(e)
		}
		if len(b[u]) != HeaderBytes+17*26*s[u].K {
			t.Fatal("fixed bytes")
		}
	}
	return b
}
func TestRecoveryBoundary(t *testing.T) {
	for _, k := range []int{0, 1, 3} {
		w, s := fixture(t, k)
		want := []Pair{}
		if k > 0 {
			setSlot(t, &s, 0, true, ^uint64(0), 1<<63|9)
			want = append(want, Pair{^uint64(0), 1<<63 | 9})
		}
		b := encode(t, s)
		out, e := Recover(w, b[0], b[1])
		if e != nil || out.QueryID != w.QueryID || len(out.Pairs) != len(want) {
			t.Fatal(e, out)
		}
		if k > 0 && out.Pairs[0] != want[0] {
			t.Fatal("Ring64")
		}
		if _, e = Recover(w, b[1], b[0]); e == nil {
			t.Fatal("swapped parties")
		}
		w.QueryID[0] ^= 1
		if _, e = Recover(w, b[0], b[1]); e == nil {
			t.Fatal("query mix")
		}
	}
}
func TestRecoveryRejectsMalformed(t *testing.T) {
	w, s := fixture(t, 1)
	setSlot(t, &s, 2, false, 1, 0)
	b := encode(t, s)
	if _, e := Recover(w, b[0], b[1]); e == nil {
		t.Fatal("nonzero masked ID")
	}
	setSlot(t, &s, 2, true, 7, 8)
	setSlot(t, &s, 9, true, 7, 8)
	b = encode(t, s)
	if _, e := Recover(w, b[0], b[1]); e == nil {
		t.Fatal("duplicate")
	}
	setSlot(t, &s, 9, false, 0, 0)
	b = encode(t, s)
	for _, bad := range [][]byte{b[0][:len(b[0])-1], append(append([]byte(nil), b[0]...), 0), []byte{1}} {
		if _, e := Recover(w, bad, b[1]); e == nil {
			t.Fatal("length")
		}
	}
	b[0][HeaderBytes] = 2
	if _, e := Recover(w, b[0], b[1]); e == nil {
		t.Fatal("noncanonical bit")
	}
}

func TestRecoveryD1AndDimensionBinding(t *testing.T) {
	w, s := fixture(t, 1)
	w.DTarget = 1
	for i := range s {
		s[i].DTarget = 1
		s[i].PairKeepShares = s[i].PairKeepShares[:1]
		s[i].AnchorIDShares = s[i].AnchorIDShares[:1]
		s[i].TargetIDShares = s[i].TargetIDShares[:1]
	}
	setSlot(t, &s, 0, true, 71, 901)
	var wire [2][]byte
	for i := range wire {
		var err error
		wire[i], err = EncodeShares(uint8(i), s[i])
		if err != nil || len(wire[i]) != HeaderBytes+17 {
			t.Fatalf("D=1 encode: %v", err)
		}
	}
	got, err := Recover(w, wire[0], wire[1])
	if err != nil || len(got.Pairs) != 1 || got.Pairs[0] != (Pair{71, 901}) {
		t.Fatalf("D=1 recover: %v %+v", err, got)
	}
	w.DTarget = 26
	if _, err = Recover(w, wire[0], wire[1]); err == nil {
		t.Fatal("D=1 shares accepted under D=26 binding")
	}
}
