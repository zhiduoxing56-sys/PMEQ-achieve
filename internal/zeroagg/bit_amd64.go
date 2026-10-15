//go:build amd64

package zeroagg

import "pmeq/internal/domain"

// CanonicalBit embeds the existing canonical Go bool into GF16 without a
// secret-dependent branch or table lookup. The supported target is amd64.
func CanonicalBit(v domain.Bit) F
