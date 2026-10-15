package domain

import (
	"math"
	"testing"
)

func TestBitDomainExhaustive(t *testing.T) {
	bits := []Bit{BitZero, BitOne}
	for _, x := range bits {
		for _, y := range bits {
			want := Bit(x != y)
			if got := x.Add(y); got != want {
				t.Fatalf("%v + %v = %v, want %v", x, y, got, want)
			}
			if got := x.Sub(y); got != want {
				t.Fatalf("%v - %v = %v, want %v", x, y, got, want)
			}
		}
	}
}

func TestRing32Wrapping(t *testing.T) {
	if got := Ring32(math.MaxUint32).Add(1); got != 0 {
		t.Fatalf("overflow = %d, want 0", got)
	}
	if got := Ring32(0).Sub(1); got != Ring32(math.MaxUint32) {
		t.Fatalf("underflow = %d, want %d", got, uint32(math.MaxUint32))
	}
}

func TestRing64Wrapping(t *testing.T) {
	if got := Ring64(math.MaxUint64).Add(1); got != 0 {
		t.Fatalf("overflow = %d, want 0", got)
	}
	if got := Ring64(0).Sub(1); got != Ring64(math.MaxUint64) {
		t.Fatalf("underflow = %d, want %d", got, uint64(math.MaxUint64))
	}
}
