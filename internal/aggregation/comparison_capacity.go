package aggregation

// Limit consumes a public prefix of a previously provisioned comparison class.
// The enclosing one-use query packet burns the unused capacity. No mask/key is
// regenerated, and the existing Prepare/Finish equations are unchanged.
func (p *ComparisonParty) Limit(n int) error {
	if p == nil || p.begun || p.finished || n < 0 || n > len(p.keys) {
		return ErrShape
	}
	clear(p.keys[n:])
	p.keys = p.keys[:n:n]
	p.masks = p.masks[:n:n]
	return nil
}
