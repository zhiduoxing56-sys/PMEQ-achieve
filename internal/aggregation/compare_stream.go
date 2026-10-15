package aggregation

import (
	"pmeq/internal/anchorfilter"
	"pmeq/internal/incidence"
	"pmeq/internal/material"
)

func (u *BoundMask) WriteOwn(e *material.StreamEncoder) {
	if u == nil || u.use == nil {
		e.Err = material.ErrEncoding
		return
	}
	e.U8(1)
	e.U8(u.eta)
}

func ReadBoundOwn(d *material.StreamDecoder) (*BoundMask, error) {
	if d.U8() != 1 {
		return nil, material.ErrEncoding
	}
	eta := d.U8()
	if d.Err != nil || eta > 127 {
		return nil, material.ErrEncoding
	}
	return &BoundMask{eta: eta, use: material.NewUseGuard()}, nil
}

func (p *ComparisonParty) WriteOwn(e *material.StreamEncoder) {
	if p == nil || p.use == nil || p.party > 1 || len(p.masks) != len(p.keys) {
		e.Err = material.ErrEncoding
		return
	}
	e.U8(1)
	e.U8(p.party)
	e.U32(uint32(len(p.masks)))
	for i := range p.masks {
		e.U8(uint8(p.masks[i].Value()))
		anchorfilter.WriteKeyOwn(e, p.keys[i])
	}
}

func ReadComparisonOwn(d *material.StreamDecoder, party uint8, n int) (*ComparisonParty, error) {
	if party > 1 || n < 0 || d.U8() != 1 || d.U8() != party || d.U32() != uint32(n) || d.Err != nil {
		return nil, material.ErrEncoding
	}
	p := &ComparisonParty{party: party, masks: make([]incidence.Share, n), keys: make([]anchorfilter.SCMPKeyShare, n), use: material.NewUseGuard()}
	for i := 0; i < n; i++ {
		v := d.U8()
		k, err := anchorfilter.ReadKeyOwn(d)
		if err != nil || v > 127 {
			return nil, material.ErrEncoding
		}
		p.masks[i] = incidence.NewShare(incidence.Z128(v))
		p.keys[i] = k
	}
	return p, nil
}
