package anchorfilter

import (
	"pmeq/internal/domain"
	"pmeq/internal/material"
	"pmeq/internal/share"
)

// Own-share codecs are used only by the trusted offline ticket store. The
// enclosing ticket authenticates the file and burns its ID before query use.
func (u UserPreprocessing) WriteOwn(e *material.StreamEncoder) {
	e.U8(1)
	e.Bytes(u.PID[:])
	e.U8(u.bin)
	e.U32(u.EtaL)
	e.U32(u.EtaR)
}

func ReadUserOwn(d *material.StreamDecoder, bin uint8) (UserPreprocessing, error) {
	var u UserPreprocessing
	if d.U8() != 1 {
		return u, material.ErrEncoding
	}
	d.Bytes(u.PID[:])
	u.bin = d.U8()
	u.EtaL, u.EtaR = d.U32(), d.U32()
	if d.Err != nil || u.PID == [16]byte{} || u.bin != bin || u.EtaL > mask(bin) || u.EtaR > mask(bin) {
		return UserPreprocessing{}, material.ErrEncoding
	}
	u.use = material.NewUseGuard()
	return u, nil
}

func (p PartyPreprocessing) WriteOwn(e *material.StreamEncoder) {
	e.U8(1)
	e.Bytes(p.PID[:])
	e.U8(p.Bin)
	n := len(p.Lower)
	e.U32(uint32(n))
	if len(p.Upper) != n || len(p.RhoL) != n || len(p.RhoR) != n {
		e.Err = material.ErrEncoding
		return
	}
	for i := 0; i < n; i++ {
		e.U32(p.RhoL[i])
		e.U32(p.RhoR[i])
		WriteKeyOwn(e, p.Lower[i])
		WriteKeyOwn(e, p.Upper[i])
	}
}

func ReadPartyOwn(d *material.StreamDecoder, n int, bin uint8) (PartyPreprocessing, error) {
	var p PartyPreprocessing
	if n < 0 || d.U8() != 1 {
		return p, material.ErrEncoding
	}
	d.Bytes(p.PID[:])
	p.Bin = d.U8()
	count := d.U32()
	if d.Err != nil || p.PID == [16]byte{} || p.Bin != bin || count != uint32(n) {
		return PartyPreprocessing{}, material.ErrEncoding
	}
	p.RhoL, p.RhoR = make([]uint32, n), make([]uint32, n)
	p.Lower, p.Upper = make([]SCMPKeyShare, n), make([]SCMPKeyShare, n)
	for i := 0; i < n; i++ {
		p.RhoL[i], p.RhoR[i] = d.U32(), d.U32()
		for j := 0; j < 2; j++ {
			k, err := ReadKeyOwn(d)
			if err != nil || p.RhoL[i] > mask(bin) || p.RhoR[i] > mask(bin) {
				return PartyPreprocessing{}, material.ErrEncoding
			}
			if j == 0 {
				p.Lower[i] = k
			} else {
				p.Upper[i] = k
			}
		}
	}
	return p, nil
}

func WriteKeyOwn(e *material.StreamEncoder, k SCMPKeyShare) {
	e.Blob(k.opaque)
	if k.rb.Value() {
		e.U8(1)
	} else {
		e.U8(0)
	}
}

func ReadKeyOwn(d *material.StreamDecoder) (SCMPKeyShare, error) {
	opaque := d.Blob(4096)
	bit := d.U8()
	if d.Err != nil || bit > 1 {
		return SCMPKeyShare{}, material.ErrEncoding
	}
	// Blob allocated a private, exact-length slice. Adopt it directly so a
	// production readback does not duplicate millions of opaque native keys.
	return SCMPKeyShare{opaque: opaque, rb: share.NewBitShare(domain.Bit(bit == 1)), use: material.NewUseGuard()}, nil
}
