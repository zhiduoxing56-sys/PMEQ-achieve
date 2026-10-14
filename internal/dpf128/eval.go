package dpf128

import (
	"pmeq/internal/dpf128/internal/core"
	"pmeq/internal/share"
)

// Eval evaluates one party's key at a public point without communication or
// randomness. The result is that party's F_2 share, not a plaintext match bit.
func Eval(key Key, point Point) share.BitShare {
	return share.NewBitShare(core.Evaluate(key, [16]byte(point)))
}
