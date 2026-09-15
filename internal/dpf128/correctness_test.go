package dpf128_test

import (
	"testing"

	"pmeq/internal/domain"
	"pmeq/internal/dpf128"
	"pmeq/internal/dpf128/gen"
)

func reconstruct(t *testing.T, key0, key1 dpf128.Key, point dpf128.Point) domain.Bit {
	t.Helper()
	return dpf128.Eval(key0, point).Value().Add(dpf128.Eval(key1, point).Value())
}

func generatedKeys(t *testing.T, alpha dpf128.Point) (dpf128.Key, dpf128.Key) {
	t.Helper()
	key0, key1, err := gen.Gen(alpha)
	if err != nil {
		t.Fatal(err)
	}
	return key0, key1
}

func TestDPFMatch(t *testing.T) {
	alpha := dpf128.Point{0x12, 0x34, 0x56}
	key0, key1 := generatedKeys(t, alpha)
	if got := reconstruct(t, key0, key1, alpha); got != domain.BitOne {
		t.Fatalf("match = %v, want 1", got)
	}
}

func TestDPFNonMatch(t *testing.T) {
	alpha := dpf128.Point{0x12, 0x34, 0x56}
	key0, key1 := generatedKeys(t, alpha)
	point := alpha
	point[7] ^= 0x04
	if got := reconstruct(t, key0, key1, point); got != domain.BitZero {
		t.Fatalf("non-match = %v, want 0", got)
	}
}

func TestDPFZeroAndMaxPoints(t *testing.T) {
	var zero dpf128.Point
	var max dpf128.Point
	for i := range max {
		max[i] = 0xff
	}
	for _, alpha := range []dpf128.Point{zero, max} {
		key0, key1 := generatedKeys(t, alpha)
		if got := reconstruct(t, key0, key1, alpha); got != domain.BitOne {
			t.Fatalf("edge match for %x = %v", alpha, got)
		}
		other := alpha
		other[8] ^= 0x80
		if got := reconstruct(t, key0, key1, other); got != domain.BitZero {
			t.Fatalf("edge non-match for %x = %v", alpha, got)
		}
	}
}

func TestDPFOnlyMSBDiffers(t *testing.T) {
	assertSingleDifference(t, 0, 0x80)
}

func TestDPFOnlyLSBDiffers(t *testing.T) {
	assertSingleDifference(t, 15, 0x01)
}

func TestDPFHigh64DiffersLow64Equal(t *testing.T) {
	assertSingleDifference(t, 3, 0x20)
}

func TestDPFLow64DiffersHigh64Equal(t *testing.T) {
	assertSingleDifference(t, 12, 0x08)
}

func assertSingleDifference(t *testing.T, byteIndex int, mask byte) {
	t.Helper()
	alpha := dpf128.Point{0xa5, 0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	key0, key1 := generatedKeys(t, alpha)
	point := alpha
	point[byteIndex] ^= mask
	if got := reconstruct(t, key0, key1, point); got != domain.BitZero {
		t.Fatalf("single-bit non-match = %v, want 0", got)
	}
}

func TestIndependentPartyEvaluation(t *testing.T) {
	alpha := dpf128.Point{0xde, 0xad, 0xbe, 0xef}
	key0, key1 := generatedKeys(t, alpha)
	share0 := dpf128.Eval(key0, alpha)
	share1 := dpf128.Eval(key1, alpha)
	if share0.Value().Add(share1.Value()) != domain.BitOne {
		t.Fatal("independently evaluated shares do not reconstruct")
	}
}

func TestF2OutputTruthTable(t *testing.T) {
	alpha := dpf128.Point{0x42}
	key0, key1 := generatedKeys(t, alpha)
	points := []struct {
		point dpf128.Point
		want  domain.Bit
	}{
		{alpha, domain.BitOne},
		{dpf128.Point{0x43}, domain.BitZero},
	}
	for _, tc := range points {
		left := dpf128.Eval(key0, tc.point).Value()
		right := dpf128.Eval(key1, tc.point).Value()
		if got := left.Add(right); got != tc.want {
			t.Fatalf("F_2 reconstruction = %v, want %v", got, tc.want)
		}
	}
}
