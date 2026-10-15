package aggregation

import (
	"encoding/binary"
	"pmeq/internal/domain"
	"pmeq/internal/material"
	"pmeq/internal/targetcrypto"
)

func writeCompaction(e *material.StreamEncoder, s *compactState, party uint8) {
	if s == nil || party > 1 || s.phase != 0 || s.query == [16]byte{} || s.layout == [16]byte{} || len(s.perm) != s.n || len(s.c) != s.n || len(s.t) != s.n || len(s.r) != s.n {
		e.Err = material.ErrEncoding
		return
	}
	e.U8(1)
	e.U8(party)
	e.Bytes(s.layout[:])
	e.Bytes(s.query[:])
	e.U32(uint32(s.n))
	e.U8(s.bucketBits)
	for _, v := range s.perm {
		e.U32(v)
	}
	var buf [45 * 64]byte
	for _, tuples := range [][]compactTuple{s.c, s.t, s.r} {
		for lo := 0; lo < len(tuples); lo += 64 {
			count := min(64, len(tuples)-lo)
			for j := 0; j < count; j++ {
				v := tuples[lo+j]
				o := buf[45*j:]
				if v.keep {
					o[0] = 1
				} else {
					o[0] = 0
				}
				binary.LittleEndian.PutUint64(o[1:9], v.id)
				copy(o[9:41], v.scalar.Bytes())
				binary.LittleEndian.PutUint32(o[41:45], v.bucket)
			}
			e.Bytes(buf[:45*count])
		}
	}
}

func (p *Compaction0) WriteOwn(e *material.StreamEncoder) {
	if p == nil || p.state == nil {
		e.Err = material.ErrEncoding
		return
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	writeCompaction(e, p.state, 0)
}
func (p *Compaction1) WriteOwn(e *material.StreamEncoder) {
	if p == nil || p.state == nil {
		e.Err = material.ErrEncoding
		return
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	writeCompaction(e, p.state, 1)
}

func readCompaction(d *material.StreamDecoder, party uint8, layout [16]byte, n int, bits uint8) (*compactState, error) {
	if n < 0 || party > 1 || d.U8() != 1 || d.U8() != party {
		return nil, material.ErrEncoding
	}
	s := &compactState{n: n, bucketBits: bits}
	d.Bytes(s.layout[:])
	d.Bytes(s.query[:])
	if d.U32() != uint32(n) || d.U8() != bits || d.Err != nil || s.layout != layout || s.query == [16]byte{} {
		return nil, material.ErrEncoding
	}
	if _, err := targetcrypto.NewBucketDomain(int(bits)); err != nil {
		return nil, material.ErrEncoding
	}
	s.perm = make([]uint32, n)
	seen := make([]bool, n)
	for i := range s.perm {
		v := d.U32()
		if d.Err != nil || v >= uint32(n) || seen[v] {
			return nil, material.ErrEncoding
		}
		seen[v] = true
		s.perm[i] = v
	}
	s.c, s.t, s.r = make([]compactTuple, n), make([]compactTuple, n), make([]compactTuple, n)
	var buf [45 * 64]byte
	for _, tuples := range [][]compactTuple{s.c, s.t, s.r} {
		for lo := 0; lo < len(tuples); lo += 64 {
			count := min(64, len(tuples)-lo)
			d.Bytes(buf[:45*count])
			if d.Err != nil {
				return nil, material.ErrEncoding
			}
			for j := 0; j < count; j++ {
				o := buf[45*j : 45*j+45]
				if o[0] > 1 {
					return nil, material.ErrEncoding
				}
				v := &tuples[lo+j]
				v.keep = domain.Bit(o[0] == 1)
				v.id = binary.LittleEndian.Uint64(o[1:9])
				if _, err := v.scalar.SetCanonicalBytes(o[9:41]); err != nil {
					return nil, material.ErrEncoding
				}
				v.bucket = binary.LittleEndian.Uint32(o[41:45])
				if v.bucket >= uint32(1)<<bits {
					return nil, material.ErrEncoding
				}
			}
		}
	}
	return s, nil
}

func ReadCompaction0Own(d *material.StreamDecoder, layout [16]byte, n int, bits uint8) (*Compaction0, error) {
	s, err := readCompaction(d, 0, layout, n, bits)
	if err != nil {
		return nil, err
	}
	return &Compaction0{state: s}, nil
}
func ReadCompaction1Own(d *material.StreamDecoder, layout [16]byte, n int, bits uint8) (*Compaction1, error) {
	s, err := readCompaction(d, 1, layout, n, bits)
	if err != nil {
		return nil, err
	}
	return &Compaction1{state: s}, nil
}
