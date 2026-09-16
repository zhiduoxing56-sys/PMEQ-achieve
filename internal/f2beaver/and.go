// Package f2beaver implements batched two-party Beaver multiplication in F2.
package f2beaver

import (
	"crypto/rand"
	"errors"
	"io"

	"pmeq/internal/domain"
	"pmeq/internal/preprocess"
	"pmeq/internal/share"
)

// PartyBatch is one party's local share of a one-time batch of Beaver triples.
type PartyBatch struct {
	a, b, c []share.BitShare
}

// Opened contains the public masked differences opened once for a whole layer.
type Opened struct {
	D, E []domain.Bit
}

// Preprocess generates one fresh triple per multiplication inside the trusted
// preprocessing boundary. Neither returned object contains the peer's shares.
func Preprocess(n int) (PartyBatch, PartyBatch, error) {
	if n < 0 {
		return PartyBatch{}, PartyBatch{}, errors.New("f2beaver: negative batch size")
	}
	p0 := PartyBatch{a: make([]share.BitShare, n), b: make([]share.BitShare, n), c: make([]share.BitShare, n)}
	p1 := PartyBatch{a: make([]share.BitShare, n), b: make([]share.BitShare, n), c: make([]share.BitShare, n)}
	for i := 0; i < n; i++ {
		a, err := randomBit(rand.Reader)
		if err != nil {
			return PartyBatch{}, PartyBatch{}, err
		}
		b, err := randomBit(rand.Reader)
		if err != nil {
			return PartyBatch{}, PartyBatch{}, err
		}
		a0, a1, err := preprocess.SplitBit(a)
		if err != nil {
			return PartyBatch{}, PartyBatch{}, err
		}
		b0, b1, err := preprocess.SplitBit(b)
		if err != nil {
			return PartyBatch{}, PartyBatch{}, err
		}
		c := domain.Bit(bool(a) && bool(b))
		c0, c1, err := preprocess.SplitBit(c)
		if err != nil {
			return PartyBatch{}, PartyBatch{}, err
		}
		p0.a[i], p1.a[i], p0.b[i], p1.b[i], p0.c[i], p1.c[i] = a0, a1, b0, b1, c0, c1
	}
	return p0, p1, nil
}

func randomBit(r io.Reader) (domain.Bit, error) {
	var b [1]byte
	_, err := io.ReadFull(r, b[:])
	return domain.Bit(b[0]&1 == 1), err
}

// Mask computes one party's local opening shares for an entire multiplication layer.
func Mask(x, y []share.BitShare, triples PartyBatch) ([]share.BitShare, []share.BitShare, error) {
	if len(x) != len(y) || len(x) != len(triples.a) {
		return nil, nil, errors.New("f2beaver: batch length mismatch")
	}
	d, e := make([]share.BitShare, len(x)), make([]share.BitShare, len(x))
	for i := range x {
		d[i] = share.LocalSubBit(x[i], triples.a[i])
		e[i] = share.LocalSubBit(y[i], triples.b[i])
	}
	return d, e, nil
}

// Open reconstructs only the masked d/e values in one logical batch opening.
func Open(d0, e0, d1, e1 []share.BitShare) (Opened, error) {
	if len(d0) != len(e0) || len(d0) != len(d1) || len(d0) != len(e1) {
		return Opened{}, errors.New("f2beaver: opening length mismatch")
	}
	o := Opened{D: make([]domain.Bit, len(d0)), E: make([]domain.Bit, len(d0))}
	for i := range d0 {
		o.D[i] = d0[i].Value().Add(d1[i].Value())
		o.E[i] = e0[i].Value().Add(e1[i].Value())
	}
	return o, nil
}

// Finish returns one party's product shares. Party 0 alone adds public d*e.
func Finish(party uint8, triples PartyBatch, opened Opened) ([]share.BitShare, error) {
	if party > 1 || len(triples.a) != len(opened.D) || len(opened.D) != len(opened.E) {
		return nil, errors.New("f2beaver: invalid party or batch")
	}
	z := make([]share.BitShare, len(opened.D))
	for i := range z {
		v := triples.c[i].Value()
		v = v.Add(domain.Bit(bool(opened.D[i]) && bool(triples.b[i].Value())))
		v = v.Add(domain.Bit(bool(opened.E[i]) && bool(triples.a[i].Value())))
		if party == 0 {
			v = v.Add(domain.Bit(bool(opened.D[i]) && bool(opened.E[i])))
		}
		z[i] = share.NewBitShare(v)
	}
	return z, nil
}

// BatchAND is a test/harness coordinator for two party-local batch calls. It
// models two batched openings; it is not a per-slot communication interface.
func BatchAND(x0, x1, y0, y1 []share.BitShare) ([]share.BitShare, []share.BitShare, error) {
	t0, t1, err := Preprocess(len(x0))
	if err != nil {
		return nil, nil, err
	}
	d0, e0, err := Mask(x0, y0, t0)
	if err != nil {
		return nil, nil, err
	}
	d1, e1, err := Mask(x1, y1, t1)
	if err != nil {
		return nil, nil, err
	}
	o, err := Open(d0, e0, d1, e1)
	if err != nil {
		return nil, nil, err
	}
	z0, err := Finish(0, t0, o)
	if err != nil {
		return nil, nil, err
	}
	z1, err := Finish(1, t1, o)
	return z0, z1, err
}
