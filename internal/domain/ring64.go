package domain

// Ring64 is an element of Z/(2^64). It is currently only the linear sharing
// domain for record, candidate, and count values. Before any future secure
// comparison consumes such a value, that stage must prove that every legal
// clear value stays within a bound that cannot wrap modulo 2^64. PHASE 1B
// intentionally provides no comparison operation.
type Ring64 uint64

func (x Ring64) Add(y Ring64) Ring64 { return x + y }
func (x Ring64) Sub(y Ring64) Ring64 { return x - y }
