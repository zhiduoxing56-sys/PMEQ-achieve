package f2beaver

import (
	"encoding/binary"
	"pmeq/internal/domain"
	"pmeq/internal/material"
	"pmeq/internal/share"
)

func (p PartyBatch) WriteOwn(e *material.StreamEncoder) {
	n := len(p.a)
	if len(p.b) != n || len(p.c) != n {
		e.Err = material.ErrEncoding
		return
	}
	e.U32(uint32(n))
	var buf [3 * 1024]byte
	for lo := 0; lo < n; lo += 1024 {
		count := min(1024, n-lo)
		for j := 0; j < count; j++ {
			i := lo + j
			buf[3*j], buf[3*j+1], buf[3*j+2] = byte(ownBit(p.a[i].Value())), byte(ownBit(p.b[i].Value())), byte(ownBit(p.c[i].Value()))
		}
		e.Bytes(buf[:3*count])
	}
}

func ReadBatchOwn(d *material.StreamDecoder, n int) (PartyBatch, error) {
	if n < 0 || d.U32() != uint32(n) || d.Err != nil {
		return PartyBatch{}, material.ErrEncoding
	}
	p := PartyBatch{a: make([]share.BitShare, n), b: make([]share.BitShare, n), c: make([]share.BitShare, n)}
	var buf [3 * 1024]byte
	for lo := 0; lo < n; lo += 1024 {
		count := min(1024, n-lo)
		d.Bytes(buf[:3*count])
		if d.Err != nil {
			return PartyBatch{}, material.ErrEncoding
		}
		for j := 0; j < count; j++ {
			v := buf[3*j : 3*j+3]
			if v[0] > 1 || v[1] > 1 || v[2] > 1 {
				return PartyBatch{}, material.ErrEncoding
			}
			i := lo + j
			p.a[i] = share.NewBitShare(domain.Bit(v[0] == 1))
			p.b[i] = share.NewBitShare(domain.Bit(v[1] == 1))
			p.c[i] = share.NewBitShare(domain.Bit(v[2] == 1))
		}
	}
	return p, nil
}

func (p PackedBatch) WriteOwn(e *material.StreamEncoder) {
	n := len(p.a)
	if len(p.b) != n || len(p.c) != n {
		e.Err = material.ErrEncoding
		return
	}
	e.U32(uint32(n))
	var buf [24 * 256]byte
	for lo := 0; lo < n; lo += 256 {
		count := min(256, n-lo)
		for j := 0; j < count; j++ {
			i := lo + j
			binary.LittleEndian.PutUint64(buf[24*j:], p.a[i])
			binary.LittleEndian.PutUint64(buf[24*j+8:], p.b[i])
			binary.LittleEndian.PutUint64(buf[24*j+16:], p.c[i])
		}
		e.Bytes(buf[:24*count])
	}
}

func ReadPackedOwn(d *material.StreamDecoder, n int) (PackedBatch, error) {
	if n < 0 || d.U32() != uint32(n) || d.Err != nil {
		return PackedBatch{}, material.ErrEncoding
	}
	p := PackedBatch{a: make([]uint64, n), b: make([]uint64, n), c: make([]uint64, n)}
	var buf [24 * 256]byte
	for lo := 0; lo < n; lo += 256 {
		count := min(256, n-lo)
		d.Bytes(buf[:24*count])
		if d.Err != nil {
			return PackedBatch{}, material.ErrEncoding
		}
		for j := 0; j < count; j++ {
			i := lo + j
			p.a[i] = binary.LittleEndian.Uint64(buf[24*j:])
			p.b[i] = binary.LittleEndian.Uint64(buf[24*j+8:])
			p.c[i] = binary.LittleEndian.Uint64(buf[24*j+16:])
		}
	}
	return p, nil
}
