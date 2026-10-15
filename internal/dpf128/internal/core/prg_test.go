package core

import (
	"encoding/hex"
	"testing"

	"pmeq/internal/domain"
)

func mustSeed(t *testing.T, value string) Seed {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(Seed{}) {
		t.Fatalf("invalid seed fixture %q", value)
	}
	var seed Seed
	copy(seed[:], decoded)
	return seed
}

func TestPRGKnownAnswer(t *testing.T) {
	seed := mustSeed(t, "000102030405060708090a0b0c0d0e0f")
	wantLeft := mustSeed(t, "c6a13b37878f5b826f4f8162a1c8d879")
	wantRight := mustSeed(t, "7346139595c0b41e497bbde365f42d0a")
	wantControl := mustSeed(t, "49d68753999ba68ce3897a686081b09d")
	wantValue := mustSeed(t, "b9ad2b2e346ac238505d365e9cb7fc56")

	left, leftControl, right, rightControl := Expand(seed)
	if left != wantLeft || right != wantRight {
		t.Fatalf("child seeds do not match independent OpenSSL vectors")
	}
	if got := encrypt(seed, domainControl); got != wantControl {
		t.Fatalf("control block = %x, want %x", got, wantControl)
	}
	if got := encrypt(seed, domainValue); got != wantValue {
		t.Fatalf("value block = %x, want %x", got, wantValue)
	}
	if leftControl != domain.BitZero || rightControl != domain.BitOne {
		t.Fatalf("control bits = %v,%v, want 0,1", leftControl, rightControl)
	}
	if got := Convert(seed); got != domain.BitOne {
		t.Fatalf("Convert = %v, want 1", got)
	}
}

func TestPRGDomainBlocks(t *testing.T) {
	want := [][16]byte{
		{},
		{15: 1},
		{15: 2},
		{15: 3},
	}
	got := [][16]byte{domainLeft, domainRight, domainControl, domainValue}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("domain block %d = %x, want %x", i, got[i], want[i])
		}
	}
}
