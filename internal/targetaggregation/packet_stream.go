package targetaggregation

import (
	"pmeq/internal/aggregation"
	"pmeq/internal/f2beaver"
	"pmeq/internal/incidence"
	"pmeq/internal/material"
	"pmeq/internal/ring64beaver"
	"pmeq/internal/targetpe"
	"pmeq/internal/zeroagg"
)

func (u *UserMaterial) WriteOwn(e *material.StreamEncoder) {
	if u == nil || u.f == nil || u.k == nil || u.id == [16]byte{} {
		e.Err = material.ErrEncoding
		return
	}
	e.U8(1)
	e.Bytes(u.id[:])
	writeShape(e, u.shape)
	u.f.WriteOwn(e)
	u.k.WriteOwn(e)
}
func ReadUserOwn(d *material.StreamDecoder, expected Shape) (*UserMaterial, error) {
	if d.U8() != 1 {
		return nil, material.ErrEncoding
	}
	u := &UserMaterial{shape: expected}
	d.Bytes(u.id[:])
	if u.id == [16]byte{} || readShape(d) != expected || d.Err != nil {
		return nil, material.ErrEncoding
	}
	var err error
	u.f, err = aggregation.ReadBoundOwn(d)
	if err != nil {
		return nil, err
	}
	u.k, err = aggregation.ReadBoundOwn(d)
	if err != nil {
		return nil, err
	}
	return u, nil
}
func writeShape(e *material.StreamEncoder, s Shape) {
	for _, v := range []int{s.K, s.R, s.S, s.G, s.Capacity()} {
		e.U32(uint32(v))
	}
}
func readShape(d *material.StreamDecoder) Shape {
	return Shape{K: int(d.U32()), R: int(d.U32()), S: int(d.U32()), G: int(d.U32()), D: int(d.U32())}
}
func (p Packet) WriteOwn(e *material.StreamEncoder) {
	if p.state == nil || p.party > 1 || p.id == [16]byte{} || p.shape.validate(p.lineage.N) != nil {
		e.Err = material.ErrEncoding
		return
	}
	p.state.Lock()
	defer p.state.Unlock()
	if p.state.used {
		e.Err = material.ErrEncoding
		return
	}
	version := uint8(1)
	if p.zeroT > 0 {
		version = 2
	}
	e.U8(version)
	e.U8(p.party)
	e.Bytes(p.id[:])
	e.Bytes(p.lineage.IndexID[:])
	e.Bytes(p.lineage.LayoutID[:])
	e.U32(uint32(p.lineage.N))
	writeShape(e, p.shape)
	if version == 2 {
		e.U32(uint32(p.zeroT))
		e.Blob([]byte(p.labelID))
	}
	p.hit.WriteOwn(e)
	p.inc.WriteOwn(e)
	p.z.WriteOwn(e)
	p.f.WriteOwn(e)
	p.keep.WriteOwn(e)
	for _, ring := range p.ring {
		ring.WriteOwn(e)
	}
	p.rep.WriteOwn(e)
	if version == 2 {
		if len(p.zero) != p.shape.K*p.shape.R {
			e.Err = material.ErrEncoding
			return
		}
		for _, q := range p.zero {
			q.WriteTargetOwn(e)
		}
	}
}
func ReadPacketOwn(d *material.StreamDecoder, party uint8, lineage targetpe.AlignmentLineage, shape Shape) (Packet, error) {
	if party > 1 || shape.validate(lineage.N) != nil {
		return Packet{}, material.ErrEncoding
	}
	version := d.U8()
	if (version != 1 && version != 2) || d.U8() != party {
		return Packet{}, material.ErrEncoding
	}
	p := Packet{state: &packetState{}, party: party, lineage: lineage, shape: shape}
	d.Bytes(p.id[:])
	var index, layout [16]byte
	d.Bytes(index[:])
	d.Bytes(layout[:])
	if d.U32() != uint32(lineage.N) || readShape(d) != shape || d.Err != nil || p.id == [16]byte{} || index != lineage.IndexID || layout != lineage.LayoutID {
		return Packet{}, material.ErrEncoding
	}
	inputS, compareN := shape.S, shape.K*shape.R*shape.Capacity()
	if version == 2 {
		p.zeroT = int(d.U32())
		p.labelID = string(d.Blob(64))
		if d.Err != nil || p.zeroT < 1 || p.zeroT > 65536 || p.labelID == "" {
			return Packet{}, material.ErrEncoding
		}
		inputS, compareN = 0, 0
	}
	var err error
	p.hit, err = incidence.ReadTriplesOwn(d, party, inputS, 1)
	if err != nil {
		return Packet{}, err
	}
	p.inc, err = incidence.ReadTriplesOwn(d, party, inputS, shape.Capacity())
	if err != nil {
		return Packet{}, err
	}
	z, m := shape.K*shape.R*shape.Capacity(), shape.K*shape.Capacity()
	p.z, err = incidence.ReadTriplesOwn(d, party, z, 1)
	if err != nil {
		return Packet{}, err
	}
	p.f, err = aggregation.ReadComparisonOwn(d, party, compareN)
	if err != nil {
		return Packet{}, err
	}
	p.keep, err = aggregation.ReadComparisonOwn(d, party, m)
	if err != nil {
		return Packet{}, err
	}
	sizes := [7]int{shape.G, shape.Capacity() * shape.G, z, z, m, m, m}
	for i, n := range sizes {
		p.ring[i], err = ring64beaver.ReadOwn(d, party, n)
		if err != nil {
			return Packet{}, err
		}
	}
	p.rep, err = f2beaver.ReadBatchOwn(d, z)
	if err != nil {
		return Packet{}, err
	}
	if version == 2 {
		capacity := 1
		for capacity < shape.Capacity() {
			capacity *= 2
		}
		p.zero = make([]*zeroagg.Party, shape.K*shape.R)
		for i := range p.zero {
			p.zero[i], err = zeroagg.ReadTargetOwn(d, party, p.zeroT, capacity)
			if err != nil {
				return Packet{}, err
			}
		}
	}
	return p, nil
}
