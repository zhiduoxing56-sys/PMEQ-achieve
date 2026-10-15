package aggregation

import (
	"pmeq/internal/incidence"
	"pmeq/internal/material"
)

func writeZ128(e *material.StreamEncoder, values []incidence.Z128) {
	var buf [4096]byte
	for lo := 0; lo < len(values); lo += len(buf) {
		count := min(len(buf), len(values)-lo)
		for j := 0; j < count; j++ {
			buf[j] = byte(values[lo+j])
		}
		e.Bytes(buf[:count])
	}
}
func readZ128(d *material.StreamDecoder, n int) ([]incidence.Z128, error) {
	v := make([]incidence.Z128, n)
	var buf [4096]byte
	for lo := 0; lo < n; lo += len(buf) {
		count := min(len(buf), n-lo)
		d.Bytes(buf[:count])
		if d.Err != nil {
			return nil, material.ErrEncoding
		}
		for j := 0; j < count; j++ {
			if buf[j] > 127 {
				return nil, material.ErrEncoding
			}
			v[lo+j] = incidence.Z128(buf[j])
		}
	}
	return v, nil
}

func (p *PermPrep0) WriteOwn(e *material.StreamEncoder) {
	if p == nil || p.stage == nil || p.use == nil || len(p.c1) != len(p.a2) || len(p.c1) != len(p.b2) {
		e.Err = material.ErrEncoding
		return
	}
	e.U8(1)
	e.Bytes(p.stage.LayoutID[:])
	e.U32(p.stage.BucketID)
	e.U32(uint32(len(p.c1)))
	writeZ128(e, p.c1)
	writeZ128(e, p.a2)
	writeZ128(e, p.b2)
}
func ReadPermPrep0Own(d *material.StreamDecoder, stage *Stage0, n int) (*PermPrep0, error) {
	if stage == nil || n < 0 || d.U8() != 1 {
		return nil, material.ErrEncoding
	}
	var layout [16]byte
	d.Bytes(layout[:])
	if d.U32() != stage.BucketID || d.U32() != uint32(n) || d.Err != nil || layout != stage.LayoutID {
		return nil, material.ErrEncoding
	}
	a, e := readZ128(d, n)
	if e != nil {
		return nil, e
	}
	b, e := readZ128(d, n)
	if e != nil {
		return nil, e
	}
	c, e := readZ128(d, n)
	if e != nil {
		return nil, e
	}
	return &PermPrep0{c1: a, a2: b, b2: c, use: material.NewUseGuard(), stage: stage}, nil
}

func (p *PermPrep1) WriteOwn(e *material.StreamEncoder) {
	if p == nil || p.use == nil || len(p.a1) != len(p.b1) || len(p.a1) != len(p.c2) {
		e.Err = material.ErrEncoding
		return
	}
	e.U8(1)
	e.Bytes(p.stage[:])
	e.U32(uint32(len(p.a1)))
	writeZ128(e, p.a1)
	writeZ128(e, p.b1)
	writeZ128(e, p.c2)
}
func ReadPermPrep1Own(d *material.StreamDecoder, stage *Stage1, n int) (*PermPrep1, error) {
	if stage == nil || n < 0 || d.U8() != 1 {
		return nil, material.ErrEncoding
	}
	var digest [32]byte
	d.Bytes(digest[:])
	if d.U32() != uint32(n) || d.Err != nil || digest != stage.digest() {
		return nil, material.ErrEncoding
	}
	a, e := readZ128(d, n)
	if e != nil {
		return nil, e
	}
	b, e := readZ128(d, n)
	if e != nil {
		return nil, e
	}
	c, e := readZ128(d, n)
	if e != nil {
		return nil, e
	}
	return &PermPrep1{a1: a, b1: b, c2: c, use: material.NewUseGuard(), stage: digest}, nil
}
