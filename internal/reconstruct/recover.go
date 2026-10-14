// Package reconstruct provides the explicit authorized reconstruction
// boundary. Cloud-facing packages must not import this package.
package reconstruct

import (
	"pmeq/internal/domain"
	"pmeq/internal/share"
)

func RecoverBit(x, y share.BitShare) domain.Bit {
	return x.Value().Add(y.Value())
}

func RecoverRing32(x, y share.Ring32Share) domain.Ring32 {
	return x.Value().Add(y.Value())
}

func RecoverRing64(x, y share.Ring64Share) domain.Ring64 {
	return x.Value().Add(y.Value())
}
