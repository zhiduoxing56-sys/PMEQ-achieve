package targetpe

import (
	"pmeq/internal/f2beaver"
	"pmeq/internal/material"
)

func (p Packet) WriteOwn(e *material.StreamEncoder) {
	if p.state == nil || p.party > 1 || p.ID == [16]byte{} || p.G < 0 {
		e.Err = material.ErrEncoding
		return
	}
	p.state.Lock()
	defer p.state.Unlock()
	if p.state.used || p.state.triples.Len() != TripleWords(p.G) {
		e.Err = material.ErrEncoding
		return
	}
	e.U8(1)
	e.U8(p.party)
	e.Bytes(p.ID[:])
	e.Bytes(p.lineage.IndexID[:])
	e.Bytes(p.lineage.LayoutID[:])
	e.U32(uint32(p.lineage.N))
	e.U32(uint32(p.G))
	p.state.triples.WriteOwn(e)
}

func ReadPacketOwn(d *material.StreamDecoder, party uint8, lineage AlignmentLineage, g int) (Packet, error) {
	if party > 1 || g < 0 || d.U8() != 1 || d.U8() != party {
		return Packet{}, material.ErrEncoding
	}
	p := Packet{state: &packetState{}, party: party, lineage: lineage, G: g}
	d.Bytes(p.ID[:])
	var index, layout [16]byte
	d.Bytes(index[:])
	d.Bytes(layout[:])
	if d.U32() != uint32(lineage.N) || d.U32() != uint32(g) || d.Err != nil || p.ID == [16]byte{} || index != lineage.IndexID || layout != lineage.LayoutID {
		return Packet{}, material.ErrEncoding
	}
	triples, err := f2beaver.ReadPackedOwn(d, TripleWords(g))
	if err != nil {
		return Packet{}, err
	}
	p.state.triples = triples
	return p, nil
}
