// Validation-only own-share encoding; no peer state is serialized.
package f2beaver

import (
	"fmt"
	"pmeq/internal/domain"
	"pmeq/internal/share"
)

func (p *PartyBatch) EncodeOwn() []byte {
	out := make([]byte, 3*len(p.a))
	for i := range p.a {
		out[3*i] = byte(ownBit(p.a[i].Value()))
		out[3*i+1] = byte(ownBit(p.b[i].Value()))
		out[3*i+2] = byte(ownBit(p.c[i].Value()))
	}
	return out
}
func DecodeOwn(raw []byte, n int) (*PartyBatch, error) {
	if len(raw) != 3*n {
		return nil, fmt.Errorf("boolean material shape")
	}
	p := &PartyBatch{a: make([]share.BitShare, n), b: make([]share.BitShare, n), c: make([]share.BitShare, n)}
	for i := range p.a {
		for _, v := range raw[3*i : 3*i+3] {
			if v > 1 {
				return nil, fmt.Errorf("noncanonical boolean material")
			}
		}
		p.a[i] = share.NewBitShare(domain.Bit(raw[3*i] != 0))
		p.b[i] = share.NewBitShare(domain.Bit(raw[3*i+1] != 0))
		p.c[i] = share.NewBitShare(domain.Bit(raw[3*i+2] != 0))
	}
	return p, nil
}

func ownBit(v domain.Bit) uint64 {
	if v {
		return 1
	}
	return 0
}

// DiscardOwn is used only after trusted offline serialization.
func (p PartyBatch) DiscardOwn() { clear(p.a); clear(p.b); clear(p.c) }
