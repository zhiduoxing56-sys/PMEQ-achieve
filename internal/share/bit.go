// Package share defines party-local mathematical shares and local linear
// operations. A value of any type in this package contains one party's share
// only.
package share

import "pmeq/internal/domain"

type BitShare struct {
	value domain.Bit
}

func NewBitShare(value domain.Bit) BitShare { return BitShare{value: value} }
func (s BitShare) Value() domain.Bit        { return s.value }

func LocalAddBit(x, y BitShare) BitShare {
	return NewBitShare(x.value.Add(y.value))
}

func LocalSubBit(x, y BitShare) BitShare {
	return NewBitShare(x.value.Sub(y.value))
}
