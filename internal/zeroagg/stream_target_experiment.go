package zeroagg

import (
	"encoding/binary"
	"pmeq/internal/material"
)

// Target experiment packets contain only one party's fresh GF triples.
func (p *Party) WriteTargetOwn(e *material.StreamEncoder) {
	if p == nil || p.started.Load() || p.sealed.Load() || p.used != 0 || p.id < 0 || p.id > 1 {
		e.Err = material.ErrEncoding
		return
	}
	_, _, gates := Gates(p.inputT, p.d)
	if len(p.triples) != gates {
		e.Err = material.ErrEncoding
		return
	}
	e.U8(uint8(p.id))
	e.U32(uint32(p.inputT))
	e.U32(uint32(p.d))
	var raw [6]byte
	for _, q := range p.triples {
		binary.LittleEndian.PutUint16(raw[:2], uint16(q.a))
		binary.LittleEndian.PutUint16(raw[2:4], uint16(q.b))
		binary.LittleEndian.PutUint16(raw[4:6], uint16(q.c))
		e.Bytes(raw[:])
	}
}

func ReadTargetOwn(d *material.StreamDecoder, party uint8, t, capacity int) (*Party, error) {
	if party > 1 || t < 1 || t > 65536 || capacity < 1 {
		return nil, material.ErrEncoding
	}
	if d.U8() != party || d.U32() != uint32(t) || d.U32() != uint32(capacity) || d.Err != nil {
		return nil, material.ErrEncoding
	}
	tp, n, gates := Gates(t, capacity)
	p := &Party{inputT: t, t: tp, d: capacity, n: n, id: int(party), triples: make([]LocalTriple, gates)}
	var raw [6]byte
	for i := range p.triples {
		d.Bytes(raw[:])
		if d.Err != nil {
			return nil, material.ErrEncoding
		}
		p.triples[i] = LocalTriple{F(binary.LittleEndian.Uint16(raw[:2])), F(binary.LittleEndian.Uint16(raw[2:4])), F(binary.LittleEndian.Uint16(raw[4:6]))}
	}
	return p, nil
}
