package reconstruct

import (
	"math"
	"testing"

	"pmeq/internal/domain"
	"pmeq/internal/share"
)

func TestRecoverBitExhaustiveAllSharePairs(t *testing.T) {
	bits := []domain.Bit{domain.BitZero, domain.BitOne}
	for _, x := range bits {
		for _, y := range bits {
			got := RecoverBit(share.NewBitShare(x), share.NewBitShare(y))
			if want := x.Add(y); got != want {
				t.Fatalf("recover(%v,%v) = %v, want %v", x, y, got, want)
			}
		}
	}
}

func TestRecoverRing32Boundaries(t *testing.T) {
	tests := []struct {
		x, y, want domain.Ring32
	}{
		{0, 0, 0},
		{1, 0, 1},
		{domain.Ring32(math.MaxUint32), 0, domain.Ring32(math.MaxUint32)},
		{domain.Ring32(math.MaxUint32), 1, 0},
	}
	for _, tc := range tests {
		got := RecoverRing32(share.NewRing32Share(tc.x), share.NewRing32Share(tc.y))
		if got != tc.want {
			t.Fatalf("recover(%d,%d) = %d, want %d", tc.x, tc.y, got, tc.want)
		}
	}
}

func TestRecoverRing64Boundaries(t *testing.T) {
	tests := []struct {
		x, y, want domain.Ring64
	}{
		{0, 0, 0},
		{1, 0, 1},
		{domain.Ring64(math.MaxUint64), 0, domain.Ring64(math.MaxUint64)},
		{domain.Ring64(math.MaxUint64), 1, 0},
	}
	for _, tc := range tests {
		got := RecoverRing64(share.NewRing64Share(tc.x), share.NewRing64Share(tc.y))
		if got != tc.want {
			t.Fatalf("recover(%d,%d) = %d, want %d", tc.x, tc.y, got, tc.want)
		}
	}
}
