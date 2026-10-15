package f2beaver

import (
	"math/rand"
	"pmeq/internal/domain"
	"pmeq/internal/preprocess"
	"pmeq/internal/share"
	"testing"
)

func TestBatchANDExhaustiveAndRandom(t *testing.T) {
	const n = 100000
	x0 := make([]share.BitShare, n)
	x1 := make([]share.BitShare, n)
	y0 := make([]share.BitShare, n)
	y1 := make([]share.BitShare, n)
	r := rand.New(rand.NewSource(4))
	want := make([]domain.Bit, n)
	for i := 0; i < n; i++ {
		x := domain.Bit(i < 4 && i&2 != 0 || i >= 4 && r.Intn(2) == 1)
		y := domain.Bit(i < 4 && i&1 != 0 || i >= 4 && r.Intn(2) == 1)
		var err error
		x0[i], x1[i], err = preprocess.SplitBit(x)
		if err != nil {
			t.Fatal(err)
		}
		y0[i], y1[i], err = preprocess.SplitBit(y)
		if err != nil {
			t.Fatal(err)
		}
		want[i] = domain.Bit(bool(x) && bool(y))
	}
	z0, z1, err := BatchAND(x0, x1, y0, y1)
	if err != nil {
		t.Fatal(err)
	}
	for i := range z0 {
		if z0[i].Value().Add(z1[i].Value()) != want[i] {
			t.Fatalf("case %d", i)
		}
	}
}
