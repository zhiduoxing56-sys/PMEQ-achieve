//go:build !amd64

package zeroagg

import "pmeq/internal/domain"

func CanonicalBit(v domain.Bit) F {
	panic("zeroagg validation adapter requires audited amd64 bool ABI")
}
