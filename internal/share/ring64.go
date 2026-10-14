package share

import "pmeq/internal/domain"

type Ring64Share struct {
	value domain.Ring64
}

func NewRing64Share(value domain.Ring64) Ring64Share { return Ring64Share{value: value} }
func (s Ring64Share) Value() domain.Ring64           { return s.value }

func LocalAddRing64(x, y Ring64Share) Ring64Share {
	return NewRing64Share(x.value.Add(y.value))
}

func LocalSubRing64(x, y Ring64Share) Ring64Share {
	return NewRing64Share(x.value.Sub(y.value))
}
