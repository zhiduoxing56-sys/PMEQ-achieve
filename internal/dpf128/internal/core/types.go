// Package core contains DPF key material and tree mechanics. Its nested
// internal location makes it compiler-inaccessible outside the dpf128 subtree.
package core

import "pmeq/internal/domain"

const Depth = 128

type Seed [16]byte

type correctionWord struct {
	seedCW   Seed
	tcwLeft  domain.Bit
	tcwRight domain.Bit
}

// Key is one party's opaque DPF evaluation key. All protocol fields are
// deliberately unexported.
type Key struct {
	rootSeed    Seed
	rootControl domain.Bit
	corrections [Depth]correctionWord
	finalCW     domain.Bit
}

func newKey(root Seed, control domain.Bit, corrections [Depth]correctionWord, final domain.Bit) Key {
	return Key{
		rootSeed:    root,
		rootControl: control,
		corrections: corrections,
		finalCW:     final,
	}
}
