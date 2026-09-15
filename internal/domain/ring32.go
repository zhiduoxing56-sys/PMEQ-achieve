package domain

// Ring32 is an element of Z/(2^32). Go's unsigned arithmetic supplies the
// required modular wrapping semantics.
type Ring32 uint32

func (x Ring32) Add(y Ring32) Ring32 { return x + y }
func (x Ring32) Sub(y Ring32) Ring32 { return x - y }
