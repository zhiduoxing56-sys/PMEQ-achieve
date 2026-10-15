package share

import "pmeq/internal/domain"

type Ring32Share struct {
	value domain.Ring32
}

func NewRing32Share(value domain.Ring32) Ring32Share { return Ring32Share{value: value} }
func (s Ring32Share) Value() domain.Ring32           { return s.value }

func LocalAddRing32(x, y Ring32Share) Ring32Share {
	return NewRing32Share(x.value.Add(y.value))
}

func LocalSubRing32(x, y Ring32Share) Ring32Share {
	return NewRing32Share(x.value.Sub(y.value))
}
