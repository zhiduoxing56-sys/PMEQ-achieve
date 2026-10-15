package candidatequery

import (
	"pmeq/internal/aggregation"
	"pmeq/internal/share"
	"pmeq/internal/targetrouting"
	"testing"
)

func TestSelected(t *testing.T) {
	w := Binding{Manifest: targetrouting.Manifest{IndexID: [16]byte{1}, TargetBucketBits: 16, Q: 4}, LayoutID: [16]byte{2}, CompactionID: [16]byte{3}, QueryID: [16]byte{4}}
	for _, m := range []int{0, 1, 31} {
		s := aggregation.PairSelection{ShuffleID: [16]byte{5}, OrderDigest: [32]byte{6}, Anchor: make([]share.Ring64Share, m), Target: make([]share.Ring64Share, m)}
		b, e := EncodeSelected(0, w, s)
		if e != nil {
			t.Fatal(e)
		}
		if len(b) != SelectedHeaderBytes+16*m {
			t.Fatal("not M pairs")
		}
		d, e := DecodeSelected(0, w, b, 2)
		if e != nil || len(d.Anchor) != m {
			t.Fatal(e)
		}
		if _, e = DecodeSelected(1, w, b, 2); e == nil {
			t.Fatal("wrong party accepted")
		}
		b[62] ^= 1
		if _, e = DecodeSelected(0, w, b, 2); e == nil {
			t.Fatal("wrong query accepted")
		}
	}
}
