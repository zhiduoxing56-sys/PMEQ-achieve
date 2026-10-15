package zeroagg

import "fmt"

// LimitInput burns unused public capacity before binding or any opening.
// t is an already public routed bucket size, never a secret hit/object count.
func (p *Party) LimitInput(t int) error {
	if p == nil || t < 1 || t > p.inputT || p.started.Load() || p.sealed.Load() || p.exchange != nil || !p.limited.CompareAndSwap(false, true) {
		return fmt.Errorf("invalid or consumed public GF capacity")
	}
	tp, n, g := Gates(t, p.d)
	clear(p.triples[g:])
	p.triples = p.triples[:g]
	p.inputT, p.t, p.n = t, tp, n
	return nil
}
