package aggregation

import (
	"crypto/sha256"
	"pmeq/internal/domain"
	"pmeq/internal/preprocess"
	"pmeq/internal/share"
	"testing"
)

func TestPairPermutation(t *testing.T) {
	for _, active := range []int{0, 1, 7, 16} {
		p, q, e := PreprocessPairPermutation([16]byte{1}, [32]byte{2}, 32)
		if e != nil {
			t.Fatal(e)
		}
		sealed0, e := p.Seal()
		if e != nil {
			t.Fatal(e)
		}
		sealed1, e := q.Seal()
		if e != nil {
			t.Fatal(e)
		}
		p, e = LoadPairPermutation(sealed0, sha256.Sum256(sealed0), 0, [16]byte{1}, 32)
		if e != nil {
			t.Fatal(e)
		}
		q, e = LoadPairPermutation(sealed1, sha256.Sum256(sealed1), 1, [16]byte{1}, 32)
		if e != nil {
			t.Fatal(e)
		}
		dir := t.TempDir()
		if e = p.BindLedger(dir); e != nil {
			t.Fatal(e)
		}
		keep := [2][]share.BitShare{make([]share.BitShare, active), make([]share.BitShare, active)}
		a := [2][]share.Ring64Share{make([]share.Ring64Share, active), make([]share.Ring64Share, active)}
		b := [2][]share.Ring64Share{make([]share.Ring64Share, active), make([]share.Ring64Share, active)}
		for i := 0; i < active; i++ {
			keep[0][i], keep[1][i], e = preprocess.SplitBit(domain.Bit(i%3 != 0))
			if e != nil {
				t.Fatal(e)
			}
			a[0][i], a[1][i], e = preprocess.SplitRing64(77)
			if e != nil {
				t.Fatal(e)
			}
			b[0][i], b[1][i], e = preprocess.SplitRing64(domain.Ring64(i + 100))
			if e != nil {
				t.Fatal(e)
			}
		}
		ch := [2]chan []byte{make(chan []byte, 1), make(chan []byte, 1)}
		done := make(chan error, 2)
		out := [2]PairSelection{}
		for party, packet := range []*PairPermutation{p, q} {
			go func(party int, packet *PairPermutation) {
				var err error
				out[party], err = packet.Select([16]byte{3}, keep[party], a[party], b[party], func(v []byte) ([]byte, error) { ch[party] <- v; return <-ch[1-party], nil })
				done <- err
			}(party, packet)
		}
		for i := 0; i < 2; i++ {
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		}
		if out[0].ShuffleID != out[1].ShuffleID || out[0].OrderDigest != out[1].OrderDigest || len(out[0].Anchor) != active-(active+2)/3 {
			t.Fatal("binding/count", active)
		}
		seen := map[uint64]bool{}
		local := map[uint64]bool{}
		for i := range out[0].Anchor {
			aa := uint64(out[0].Anchor[i].Value() + out[1].Anchor[i].Value())
			bb := uint64(out[0].Target[i].Value() + out[1].Target[i].Value())
			if aa != 77 || bb < 100 || bb >= uint64(100+active) || (bb-100)%3 == 0 || seen[bb] {
				t.Fatal("missing/extra/duplicate/padding/misalignment", aa, bb)
			}
			seen[bb] = true
			if local[uint64(out[0].Anchor[i].Value())] {
				t.Fatal("old repeated anchor share reused")
			}
			local[uint64(out[0].Anchor[i].Value())] = true
		}
		if _, e := p.Select([16]byte{3}, nil, nil, nil, func([]byte) ([]byte, error) { t.Fatal("reuse exchanged"); return nil, nil }); e == nil {
			t.Fatal("reuse accepted")
		}
		copy, e := LoadPairPermutation(sealed0, sha256.Sum256(sealed0), 0, [16]byte{1}, 32)
		if e != nil {
			t.Fatal(e)
		}
		if e = copy.BindLedger(dir); e != nil {
			t.Fatal(e)
		}
		if _, e = copy.Select([16]byte{4}, nil, nil, nil, func([]byte) ([]byte, error) { t.Fatal("persisted reuse exchanged"); return nil, nil }); e == nil {
			t.Fatal("loaded masks reused")
		}
	}
}
