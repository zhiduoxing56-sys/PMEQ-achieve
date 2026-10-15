package ring64beaver

import (
	"encoding/binary"
	"pmeq/internal/material"
)

func (p Packet) WriteOwn(e *material.StreamEncoder) {
	if p.party > 1 || p.state == nil {
		e.Err = material.ErrEncoding
		return
	}
	s := p.state
	s.Lock()
	defer s.Unlock()
	n := len(s.a)
	if s.used || s.next != 0 || len(s.b) != n || len(s.c) != n {
		e.Err = material.ErrEncoding
		return
	}
	e.U8(1)
	e.U8(p.party)
	e.U32(uint32(n))
	var buf [24 * 256]byte
	for lo := 0; lo < n; lo += 256 {
		count := min(256, n-lo)
		for j := 0; j < count; j++ {
			i := lo + j
			binary.LittleEndian.PutUint64(buf[24*j:], s.a[i])
			binary.LittleEndian.PutUint64(buf[24*j+8:], s.b[i])
			binary.LittleEndian.PutUint64(buf[24*j+16:], s.c[i])
		}
		e.Bytes(buf[:24*count])
	}
}

func ReadOwn(d *material.StreamDecoder, party uint8, n int) (Packet, error) {
	if party > 1 || n < 0 || d.U8() != 1 || d.U8() != party || d.U32() != uint32(n) || d.Err != nil {
		return Packet{}, material.ErrEncoding
	}
	p := Packet{party: party, state: &state{a: make([]uint64, n), b: make([]uint64, n), c: make([]uint64, n)}}
	var buf [24 * 256]byte
	for lo := 0; lo < n; lo += 256 {
		count := min(256, n-lo)
		d.Bytes(buf[:24*count])
		if d.Err != nil {
			return Packet{}, material.ErrEncoding
		}
		for j := 0; j < count; j++ {
			i := lo + j
			p.state.a[i] = binary.LittleEndian.Uint64(buf[24*j:])
			p.state.b[i] = binary.LittleEndian.Uint64(buf[24*j+8:])
			p.state.c[i] = binary.LittleEndian.Uint64(buf[24*j+16:])
		}
	}
	return p, nil
}
