// Package gen is the policy-separated trusted DPF key generator. Future cloud
// packages are forbidden by project policy from importing it.
package gen

import (
	"crypto/rand"
	"io"

	"pmeq/internal/dpf128"
	"pmeq/internal/dpf128/internal/core"
)

// Gen creates independent keys for CS0 and CS1 using the operating system's
// cryptographic random source.
func Gen(alpha dpf128.Point) (dpf128.Key, dpf128.Key, error) {
	return genWithReader(alpha, rand.Reader)
}

func genWithReader(alpha dpf128.Point, random io.Reader) (dpf128.Key, dpf128.Key, error) {
	var root0, root1 core.Seed
	if _, err := io.ReadFull(random, root0[:]); err != nil {
		return dpf128.Key{}, dpf128.Key{}, err
	}
	if _, err := io.ReadFull(random, root1[:]); err != nil {
		return dpf128.Key{}, dpf128.Key{}, err
	}
	return genWithRootSeeds(alpha, root0, root1)
}

func genWithRootSeeds(alpha dpf128.Point, root0, root1 core.Seed) (dpf128.Key, dpf128.Key, error) {
	key0, key1 := core.Generate(root0, root1, [16]byte(alpha))
	return key0, key1, nil
}
