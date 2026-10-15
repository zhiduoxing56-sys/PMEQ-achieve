package incidence

import "pmeq/internal/material"

func (p *PartyTriples) WriteOwn(e *material.StreamEncoder) {
	if p == nil || p.used || p.party > 1 || p.N < 0 || p.D < 1 || len(p.a) != p.N || len(p.b) != p.N*p.D || len(p.c) != p.N*p.D {
		e.Err = material.ErrEncoding
		return
	}
	e.U8(1)
	e.U8(p.party)
	e.U32(uint32(p.N))
	e.U32(uint32(p.D))
	for _, values := range [][]Z128{p.a, p.b, p.c} {
		var buf [4096]byte
		for lo := 0; lo < len(values); lo += len(buf) {
			count := min(len(buf), len(values)-lo)
			for j := 0; j < count; j++ {
				buf[j] = byte(values[lo+j])
			}
			e.Bytes(buf[:count])
		}
	}
}

func ReadTriplesOwn(d *material.StreamDecoder, party uint8, n, width int) (*PartyTriples, error) {
	if party > 1 || n < 0 || width < 1 || n > int(^uint(0)>>1)/width || d.U8() != 1 || d.U8() != party || d.U32() != uint32(n) || d.U32() != uint32(width) || d.Err != nil {
		return nil, material.ErrEncoding
	}
	p := &PartyTriples{party: party, N: n, D: width, a: make([]Z128, n), b: make([]Z128, n*width), c: make([]Z128, n*width)}
	for _, values := range [][]Z128{p.a, p.b, p.c} {
		var buf [4096]byte
		for lo := 0; lo < len(values); lo += len(buf) {
			count := min(len(buf), len(values)-lo)
			d.Bytes(buf[:count])
			if d.Err != nil {
				return nil, material.ErrEncoding
			}
			for j := 0; j < count; j++ {
				if buf[j] > 127 {
					return nil, material.ErrEncoding
				}
				values[lo+j] = Z128(buf[j])
			}
		}
	}
	return p, nil
}
