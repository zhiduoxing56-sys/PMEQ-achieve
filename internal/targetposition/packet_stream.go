package targetposition

import (
	"pmeq/internal/anchorfilter"
	"pmeq/internal/f2beaver"
	matcodec "pmeq/internal/material"
	"pmeq/internal/targetpe"
)

func (p Packet) WriteOwn(e *matcodec.StreamEncoder) {
	if p.state == nil || p.party > 1 {
		e.Err = matcodec.ErrEncoding
		return
	}
	p.state.Lock()
	defer p.state.Unlock()
	if p.state.used {
		e.Err = matcodec.ErrEncoding
		return
	}
	e.U8(1)
	e.U8(p.party)
	e.Bytes(p.lineage.IndexID[:])
	e.Bytes(p.lineage.LayoutID[:])
	e.U32(uint32(p.lineage.N))
	e.U8(p.bin)
	e.U32(p.maxPosition)
	e.U32(uint32(len(p.state.materials)))
	for _, m := range p.state.materials {
		m.prep.WriteOwn(e)
		m.first.WriteOwn(e)
		m.second.WriteOwn(e)
	}
}

func ReadPacketOwn(d *matcodec.StreamDecoder, party uint8, lineage targetpe.AlignmentLineage, capacities []int, bin uint8, maxPosition uint32) (Packet, error) {
	if party > 1 || d.U8() != 1 || d.U8() != party {
		return Packet{}, matcodec.ErrEncoding
	}
	var index, layout [16]byte
	d.Bytes(index[:])
	d.Bytes(layout[:])
	if d.U32() != uint32(lineage.N) || d.U8() != bin || d.U32() != maxPosition || d.U32() != uint32(len(capacities)) || d.Err != nil || index != lineage.IndexID || layout != lineage.LayoutID {
		return Packet{}, matcodec.ErrEncoding
	}
	p := Packet{state: &packetState{materials: make([]material, len(capacities))}, lineage: lineage, party: party, bin: bin, maxPosition: maxPosition}
	for i, n := range capacities {
		var err error
		p.state.materials[i].prep, err = anchorfilter.ReadPartyOwn(d, n, bin)
		if err != nil {
			return Packet{}, err
		}
		p.state.materials[i].first, err = f2beaver.ReadBatchOwn(d, n)
		if err != nil {
			return Packet{}, err
		}
		p.state.materials[i].second, err = f2beaver.ReadBatchOwn(d, n)
		if err != nil {
			return Packet{}, err
		}
	}
	return p, nil
}
