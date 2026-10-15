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

// Inventory packets deliberately contain no SCMP key or rho. Their own-share
// format cannot be parsed by the v1 target-position reader.
func (p Packet) WriteInventoryOwn(e *matcodec.StreamEncoder) {
	if p.state == nil || !p.inventory || p.party > 1 {
		e.Err = matcodec.ErrEncoding
		return
	}
	p.state.Lock()
	defer p.state.Unlock()
	if p.state.used {
		e.Err = matcodec.ErrEncoding
		return
	}
	e.U8(3)
	e.U8(p.party)
	e.Bytes(p.lineage.IndexID[:])
	e.Bytes(p.lineage.LayoutID[:])
	e.U32(uint32(p.lineage.N))
	e.U8(p.bin)
	e.U32(p.maxPosition)
	e.U32(uint32(len(p.state.materials)))
	for _, m := range p.state.materials {
		if len(m.prep.Lower) != 0 || len(m.prep.Upper) != 0 || len(m.prep.RhoL) != 0 || len(m.prep.RhoR) != 0 {
			e.Err = matcodec.ErrEncoding
			return
		}
		m.prep.WriteOwn(e)
		e.U32(m.etaShare[0])
		e.U32(m.etaShare[1])
		m.first.WriteOwn(e)
		m.second.WriteOwn(e)
	}
}

func ReadInventoryOwn(d *matcodec.StreamDecoder, party uint8, lineage targetpe.AlignmentLineage, capacities []int, bin uint8, maxPosition uint32) (Packet, error) {
	if party > 1 || d.U8() != 3 || d.U8() != party {
		return Packet{}, matcodec.ErrEncoding
	}
	var index, layout [16]byte
	d.Bytes(index[:])
	d.Bytes(layout[:])
	if d.U32() != uint32(lineage.N) || d.U8() != bin || d.U32() != maxPosition || d.U32() != uint32(len(capacities)) || d.Err != nil || index != lineage.IndexID || layout != lineage.LayoutID {
		return Packet{}, matcodec.ErrEncoding
	}
	p := Packet{state: &packetState{materials: make([]material, len(capacities))}, lineage: lineage, party: party, bin: bin, maxPosition: maxPosition, inventory: true}
	m := (uint32(1) << bin) - 1
	for i, n := range capacities {
		var e error
		p.state.materials[i].prep, e = anchorfilter.ReadPartyOwn(d, 0, bin)
		if e != nil {
			return Packet{}, e
		}
		p.state.materials[i].etaShare = [2]uint32{d.U32(), d.U32()}
		if d.Err != nil || p.state.materials[i].etaShare[0] > m || p.state.materials[i].etaShare[1] > m {
			return Packet{}, matcodec.ErrEncoding
		}
		p.state.materials[i].first, e = f2beaver.ReadBatchOwn(d, n)
		if e != nil {
			return Packet{}, e
		}
		p.state.materials[i].second, e = f2beaver.ReadBatchOwn(d, n)
		if e != nil {
			return Packet{}, e
		}
		p.state.materials[i].capacity = n
	}
	return p, nil
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
