package core

import (
	"encoding/hex"
	"testing"

	"pmeq/internal/domain"
)

func mustPointBytes(t *testing.T, value string) [16]byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 16 {
		t.Fatalf("invalid point fixture %q", value)
	}
	var point [16]byte
	copy(point[:], decoded)
	return point
}

func TestLayerCorrectionInvariants(t *testing.T) {
	alpha := mustPointBytes(t, "00112233445566778899aabbccddeeff")
	root0 := mustSeed(t, "000102030405060708090a0b0c0d0e0f")
	root1 := mustSeed(t, "f0e0d0c0b0a090807060504030201000")
	_, _, trace := generateWithTrace(root0, root1, alpha)
	for level, state := range trace {
		if state.keepControl0.Add(state.keepControl1) != domain.BitOne {
			t.Fatalf("level %d keep control difference is not one", level)
		}
		if state.loseSeed0 != state.loseSeed1 {
			t.Fatalf("level %d lose seeds do not cancel", level)
		}
		if state.loseControl0 != state.loseControl1 {
			t.Fatalf("level %d lose controls do not cancel", level)
		}
	}
}

func TestDeterministicRootSeedKAT(t *testing.T) {
	alpha := mustPointBytes(t, "00112233445566778899aabbccddeeff")
	root0 := mustSeed(t, "000102030405060708090a0b0c0d0e0f")
	root1 := mustSeed(t, "f0e0d0c0b0a090807060504030201000")
	key0, key1 := Generate(root0, root1, alpha)

	want := map[int]correctionWord{
		0: {
			seedCW:   mustSeed(t, "b587b0a34c5e16fdcb9a85d141fa7ffa"),
			tcwLeft:  domain.BitZero,
			tcwRight: domain.BitZero,
		},
		1: {
			seedCW:   mustSeed(t, "9086fed4eeb1d606dd30c5614144ca2a"),
			tcwLeft:  domain.BitOne,
			tcwRight: domain.BitZero,
		},
		127: {
			seedCW:   mustSeed(t, "3c3b5ea915c647258e5b02f9e1e2b0c2"),
			tcwLeft:  domain.BitZero,
			tcwRight: domain.BitOne,
		},
	}
	for level, expected := range want {
		if got := key0.corrections[level]; got != expected {
			t.Fatalf("correction %d = %#v, want %#v", level, got, expected)
		}
	}
	if key0.finalCW != domain.BitZero || key1.finalCW != domain.BitZero {
		t.Fatalf("final correction is not fixed-vector zero")
	}

	if got0, got1 := Evaluate(key0, alpha), Evaluate(key1, alpha); got0 != domain.BitOne || got1 != domain.BitZero {
		t.Fatalf("alpha outputs = %v,%v, want 1,0", got0, got1)
	}
	off := alpha
	off[15] ^= 1
	if got0, got1 := Evaluate(key0, off), Evaluate(key1, off); got0 != domain.BitZero || got1 != domain.BitZero {
		t.Fatalf("off-point outputs = %v,%v, want 0,0", got0, got1)
	}
}
