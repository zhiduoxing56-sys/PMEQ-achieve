package share

import (
	"math"
	"testing"

	"pmeq/internal/domain"
)

func TestBitShareLocalAddSubTruthTable(t *testing.T) {
	bits := []domain.Bit{domain.BitZero, domain.BitOne}
	for _, x := range bits {
		for _, y := range bits {
			sx, sy := NewBitShare(x), NewBitShare(y)
			want := domain.Bit(x != y)
			if got := LocalAddBit(sx, sy).Value(); got != want {
				t.Fatalf("add(%v,%v) = %v, want %v", x, y, got, want)
			}
			if got := LocalSubBit(sx, sy).Value(); got != want {
				t.Fatalf("sub(%v,%v) = %v, want %v", x, y, got, want)
			}
		}
	}
}

func TestRing32ShareLocalBoundaries(t *testing.T) {
	max := NewRing32Share(domain.Ring32(math.MaxUint32))
	one := NewRing32Share(1)
	zero := NewRing32Share(0)
	if got := LocalAddRing32(max, one).Value(); got != 0 {
		t.Fatalf("overflow = %d, want 0", got)
	}
	if got := LocalSubRing32(zero, one).Value(); got != domain.Ring32(math.MaxUint32) {
		t.Fatalf("underflow = %d", got)
	}
}

func TestRing64ShareLocalBoundaries(t *testing.T) {
	max := NewRing64Share(domain.Ring64(math.MaxUint64))
	one := NewRing64Share(1)
	zero := NewRing64Share(0)
	if got := LocalAddRing64(max, one).Value(); got != 0 {
		t.Fatalf("overflow = %d, want 0", got)
	}
	if got := LocalSubRing64(zero, one).Value(); got != domain.Ring64(math.MaxUint64) {
		t.Fatalf("underflow = %d", got)
	}
}
