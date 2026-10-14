package ring64beaver

import (
	"math/rand"
	"pmeq/internal/domain"
	"pmeq/internal/share"
	"testing"
)

func TestProductsAndB2A(t *testing.T) {
	r := rand.New(rand.NewSource(1010))
	const n = 10000
	var x, y [2][]share.Ring64Share
	var bits [2][]share.BitShare
	for u := 0; u < 2; u++ {
		x[u] = make([]share.Ring64Share, n)
		y[u] = make([]share.Ring64Share, n)
		bits[u] = make([]share.BitShare, n)
	}
	want := make([]uint64, n)
	for i := 0; i < n; i++ {
		a, b := r.Uint64(), r.Uint64()
		if i < 4 {
			a = uint64(i)
			b = ^uint64(0)
		}
		p, q := r.Uint64(), r.Uint64()
		x[0][i] = share.NewRing64Share(domain.Ring64(p))
		x[1][i] = share.NewRing64Share(domain.Ring64(a - p))
		y[0][i] = share.NewRing64Share(domain.Ring64(q))
		y[1][i] = share.NewRing64Share(domain.Ring64(b - q))
		want[i] = a * b
		bits[0][i] = share.NewBitShare(domain.Bit(i&1 != 0))
		bits[1][i] = share.NewBitShare(domain.Bit(i&2 != 0))
	}
	a, b, e := Preprocess(n)
	if e != nil {
		t.Fatal(e)
	}
	copyA := a
	s, m, e := Begin(a, x[0], y[0])
	if e != nil {
		t.Fatal(e)
	}
	v, w, e := Begin(b, x[1], y[1])
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = Begin(copyA, x[0], y[0]); e == nil {
		t.Fatal("copied packet reused")
	}
	o, e := s.Finish(w)
	if e != nil {
		t.Fatal(e)
	}
	p, e := v.Finish(m)
	if e != nil {
		t.Fatal(e)
	}
	for i := range o {
		if uint64(o[i].Value()+p[i].Value()) != want[i] {
			t.Fatal("product", i)
		}
	}
	if _, e = s.Finish(w); e == nil {
		t.Fatal("finish reused")
	}
	a, b, e = Preprocess(n)
	if e != nil {
		t.Fatal(e)
	}
	s, m, e = BeginB2A(a, bits[0])
	if e != nil {
		t.Fatal(e)
	}
	v, w, e = BeginB2A(b, bits[1])
	if e != nil {
		t.Fatal(e)
	}
	o, e = s.Finish(w)
	if e != nil {
		t.Fatal(e)
	}
	p, e = v.Finish(m)
	if e != nil {
		t.Fatal(e)
	}
	for i := range o {
		want := uint64(0)
		if (i&1 != 0) != (i&2 != 0) {
			want = 1
		}
		if uint64(o[i].Value()+p[i].Value()) != want {
			t.Fatal("B2A", i)
		}
	}
}

func TestRejectShapes(t *testing.T) {
	a, _, e := Preprocess(1)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = Begin(a, nil, nil); e == nil {
		t.Fatal("length accepted")
	}
	s, _, e := Begin(a, make([]share.Ring64Share, 1), make([]share.Ring64Share, 1))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Finish(Message{}); e == nil {
		t.Fatal("bad message accepted")
	}
	if _, _, e = Preprocess(-1); e == nil {
		t.Fatal("negative size")
	}
}
