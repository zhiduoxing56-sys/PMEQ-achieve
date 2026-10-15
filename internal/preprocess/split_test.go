package preprocess

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"pmeq/internal/domain"
	"pmeq/internal/reconstruct"
	"pmeq/internal/share"
)

type failureReader struct{}

func (failureReader) Read([]byte) (int, error) { return 0, errors.New("injected failure") }

func TestSplitBitExhaustive(t *testing.T) {
	for _, secret := range []domain.Bit{domain.BitZero, domain.BitOne} {
		for i := 0; i < 64; i++ {
			a, b, err := SplitBit(secret)
			if err != nil {
				t.Fatal(err)
			}
			if got := reconstruct.RecoverBit(a, b); got != secret {
				t.Fatalf("recover = %v, want %v", got, secret)
			}
		}
	}
}

func TestSplitRing32Boundaries(t *testing.T) {
	values := []domain.Ring32{0, 1, domain.Ring32(math.MaxUint32), domain.Ring32(math.MaxUint32 - 1)}
	for _, secret := range values {
		a, b, err := SplitRing32(secret)
		if err != nil {
			t.Fatal(err)
		}
		if got := reconstruct.RecoverRing32(a, b); got != secret {
			t.Fatalf("recover = %d, want %d", got, secret)
		}
	}
}

func TestSplitRing64Boundaries(t *testing.T) {
	values := []domain.Ring64{0, 1, domain.Ring64(math.MaxUint64), domain.Ring64(math.MaxUint64 - 1)}
	for _, secret := range values {
		a, b, err := SplitRing64(secret)
		if err != nil {
			t.Fatal(err)
		}
		if got := reconstruct.RecoverRing64(a, b); got != secret {
			t.Fatalf("recover = %d, want %d", got, secret)
		}
	}
}

func TestRandomizedRing32RoundTripsAndHomomorphism(t *testing.T) {
	for i := 0; i < 10_000; i++ {
		x := domain.Ring32(uint32(i)*0x9e3779b1 + uint32(i>>3))
		y := domain.Ring32(uint32(i)*0x85ebca6b + 0x7f4a7c15)
		x0, x1, err := SplitRing32(x)
		if err != nil {
			t.Fatal(err)
		}
		y0, y1, err := SplitRing32(y)
		if err != nil {
			t.Fatal(err)
		}
		if reconstruct.RecoverRing32(x0, x1) != x {
			t.Fatal("round trip failed")
		}
		add := reconstruct.RecoverRing32(share.LocalAddRing32(x0, y0), share.LocalAddRing32(x1, y1))
		if add != x.Add(y) {
			t.Fatal("additive homomorphism failed")
		}
		sub := reconstruct.RecoverRing32(share.LocalSubRing32(x0, y0), share.LocalSubRing32(x1, y1))
		if sub != x.Sub(y) {
			t.Fatal("subtractive homomorphism failed")
		}
	}
}

func TestRandomizedRing64RoundTripsAndHomomorphism(t *testing.T) {
	for i := uint64(0); i < 10_000; i++ {
		x := domain.Ring64(i*0x9e3779b97f4a7c15 + (i >> 3))
		y := domain.Ring64(i*0xbf58476d1ce4e5b9 + 0x94d049bb133111eb)
		x0, x1, err := SplitRing64(x)
		if err != nil {
			t.Fatal(err)
		}
		y0, y1, err := SplitRing64(y)
		if err != nil {
			t.Fatal(err)
		}
		if reconstruct.RecoverRing64(x0, x1) != x {
			t.Fatal("round trip failed")
		}
		add := reconstruct.RecoverRing64(share.LocalAddRing64(x0, y0), share.LocalAddRing64(x1, y1))
		if add != x.Add(y) {
			t.Fatal("additive homomorphism failed")
		}
		sub := reconstruct.RecoverRing64(share.LocalSubRing64(x0, y0), share.LocalSubRing64(x1, y1))
		if sub != x.Sub(y) {
			t.Fatal("subtractive homomorphism failed")
		}
	}
}

func TestSplitImmediateReaderFailure(t *testing.T) {
	if _, _, err := splitBitWithReader(failureReader{}, domain.BitOne); err == nil {
		t.Fatal("Bit split accepted failed entropy read")
	}
	if _, _, err := splitRing32WithReader(failureReader{}, 1); err == nil {
		t.Fatal("Ring32 split accepted failed entropy read")
	}
	if _, _, err := splitRing64WithReader(failureReader{}, 1); err == nil {
		t.Fatal("Ring64 split accepted failed entropy read")
	}
}

func TestSplitShortReaderFailure(t *testing.T) {
	if _, _, err := splitBitWithReader(bytes.NewReader(nil), domain.BitOne); err == nil {
		t.Fatal("Bit split accepted a short entropy read")
	}
	if _, _, err := splitRing32WithReader(bytes.NewReader([]byte{1, 2, 3}), 1); err == nil {
		t.Fatal("Ring32 split accepted a short entropy read")
	}
	if _, _, err := splitRing64WithReader(bytes.NewReader(make([]byte, 7)), 1); err == nil {
		t.Fatal("Ring64 split accepted a short entropy read")
	}
}

func TestSplitFreshnessWiringRegression(t *testing.T) {
	bitFirst, _, err := SplitBit(domain.BitOne)
	if err != nil {
		t.Fatal(err)
	}
	bitChanged := false
	for i := 0; i < 64; i++ {
		next, _, err := SplitBit(domain.BitOne)
		if err != nil {
			t.Fatal(err)
		}
		bitChanged = bitChanged || next != bitFirst
	}
	if !bitChanged {
		t.Fatal("Bit split output was fixed across all attempts")
	}

	ringFirst, _, err := SplitRing64(42)
	if err != nil {
		t.Fatal(err)
	}
	ringChanged := false
	for i := 0; i < 8; i++ {
		next, _, err := SplitRing64(42)
		if err != nil {
			t.Fatal(err)
		}
		ringChanged = ringChanged || next != ringFirst
	}
	if !ringChanged {
		t.Fatal("Ring64 split output was fixed across all attempts")
	}
	// This is an RNG wiring regression only, not a statistical security proof.
}
