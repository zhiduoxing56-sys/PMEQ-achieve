package aggregation

// This is compaction.go's two masked scatter stages over F2 x Ring64 x
// Ring64. Each party owns one independent factor; masks in all three fields
// are independent, including padding. Only the final globally shuffled bits
// are opened. No per-candidate count is opened.
import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"pmeq/internal/domain"
	"pmeq/internal/material"
	"pmeq/internal/share"
)

type pairTuple struct {
	keep           domain.Bit
	anchor, target uint64
}

func pairAdd(a, b pairTuple) pairTuple {
	return pairTuple{a.keep.Add(b.keep), a.anchor + b.anchor, a.target + b.target}
}
func pairSub(a, b pairTuple) pairTuple {
	return pairTuple{a.keep.Sub(b.keep), a.anchor - b.anchor, a.target - b.target}
}
func pairRandom(n int) ([]pairTuple, error) {
	v := make([]pairTuple, n)
	buf := make([]byte, 17*n)
	if _, e := rand.Read(buf); e != nil {
		return nil, e
	}
	for i := range v {
		at := 17 * i
		v[i] = pairTuple{domain.Bit(buf[at]&1 == 1), binary.LittleEndian.Uint64(buf[at+1:]), binary.LittleEndian.Uint64(buf[at+9:])}
	}
	clear(buf)
	return v, nil
}

type PairPermutation struct {
	party      uint8
	layout, id [16]byte
	binding    [32]byte
	n          int
	perm       []uint32
	c, t, r    []pairTuple
	use        *material.UseGuard
	ledger     string
}
type PairSelection struct {
	ShuffleID      [16]byte
	OrderDigest    [32]byte
	Anchor, Target []share.Ring64Share
}

// PreprocessPairPermutation is owner-offline only. n must be D*C, never D*K.
// binding includes the sealed index, layout, shape and sharing domains.
func PreprocessPairPermutation(layout [16]byte, binding [32]byte, n int) (*PairPermutation, *PairPermutation, error) {
	if layout == [16]byte{} || binding == [32]byte{} || n < 0 || uint64(n) > uint64(^uint32(0)) || n > int(^uint(0)>>1)/55 {
		return nil, nil, ErrCompaction
	}
	p, e := permutation(n)
	if e != nil {
		return nil, nil, e
	}
	q, e := permutation(n)
	if e != nil {
		return nil, nil, e
	}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return nil, nil, e
	}
	t0, e := pairRandom(n)
	if e != nil {
		return nil, nil, e
	}
	r0, e := pairRandom(n)
	if e != nil {
		return nil, nil, e
	}
	t1, e := pairRandom(n)
	if e != nil {
		return nil, nil, e
	}
	r1, e := pairRandom(n)
	if e != nil {
		return nil, nil, e
	}
	c0, c1 := make([]pairTuple, n), make([]pairTuple, n)
	for i, j := range p {
		c0[j] = pairSub(t0[i], r0[j])
	}
	for i, j := range q {
		c1[j] = pairSub(t1[i], r1[j])
	}
	return &PairPermutation{party: 0, layout: layout, id: id, binding: binding, n: n, perm: p, c: c0, t: t1, r: r1, use: material.NewUseGuard()}, &PairPermutation{party: 1, layout: layout, id: id, binding: binding, n: n, perm: q, c: c1, t: t0, r: r0, use: material.NewUseGuard()}, nil
}

func (p *PairPermutation) message(stage byte, query [16]byte, v []pairTuple) []byte {
	b := make([]byte, 85+17*len(v))
	copy(b, p.layout[:])
	copy(b[16:], p.id[:])
	copy(b[32:], p.binding[:])
	copy(b[64:], query[:])
	b[80] = stage
	binary.LittleEndian.PutUint32(b[81:], uint32(len(v)))
	for i, x := range v {
		at := 85 + 17*i
		if x.keep {
			b[at] = 1
		}
		binary.LittleEndian.PutUint64(b[at+1:], x.anchor)
		binary.LittleEndian.PutUint64(b[at+9:], x.target)
	}
	return b
}
func (p *PairPermutation) parse(stage byte, query [16]byte, b []byte) ([]pairTuple, error) {
	if len(b) != 85+17*p.n || string(b[:16]) != string(p.layout[:]) || string(b[16:32]) != string(p.id[:]) || string(b[32:64]) != string(p.binding[:]) || string(b[64:80]) != string(query[:]) || b[80] != stage || int(binary.LittleEndian.Uint32(b[81:])) != p.n {
		return nil, ErrCompaction
	}
	v := make([]pairTuple, p.n)
	for i := range v {
		at := 85 + 17*i
		if b[at] > 1 {
			return nil, ErrCompaction
		}
		v[i] = pairTuple{domain.Bit(b[at] == 1), binary.LittleEndian.Uint64(b[at+1:]), binary.LittleEndian.Uint64(b[at+9:])}
	}
	return v, nil
}

// Select runs one cloud. exchange accepts only serialized masked messages.
// All positions beyond the D*K prefix are secret zeros before permutation.
func (p *PairPermutation) Select(query [16]byte, keep []share.BitShare, anchor, target []share.Ring64Share, exchange func([]byte) ([]byte, error)) (PairSelection, error) {
	if p == nil || query == [16]byte{} || exchange == nil || len(keep) > p.n || len(anchor) != len(keep) || len(target) != len(keep) || !p.use.Claim(0) {
		return PairSelection{}, ErrCompaction
	}
	if p.ledger != "" {
		if e := material.ClaimPersistent(p.ledger, p.id); e != nil {
			return PairSelection{}, e
		}
	}
	x := make([]pairTuple, p.n)
	for i := range keep {
		x[i] = pairTuple{keep[i].Value(), uint64(anchor[i].Value()), uint64(target[i].Value())}
	}
	var msg []byte
	if p.party == 1 {
		v := make([]pairTuple, p.n)
		for i := range v {
			v[i] = pairSub(x[i], p.t[i])
		}
		msg = p.message(1, query, v)
		clear(p.t)
		p.t = nil
	}
	peer, e := exchange(msg)
	if e != nil {
		return PairSelection{}, e
	}
	var own []pairTuple
	msg = nil
	if p.party == 0 {
		v, e := p.parse(1, query, peer)
		if e != nil {
			return PairSelection{}, e
		}
		w := make([]pairTuple, p.n)
		for i, j := range p.perm {
			w[j] = pairAdd(pairAdd(x[i], v[i]), p.c[j])
		}
		for i := range w {
			w[i] = pairSub(w[i], p.t[i])
		}
		msg = p.message(2, query, w)
		own = p.r
		p.r = nil
		clear(p.c)
		clear(p.t)
		clear(p.perm)
		p.c = nil
		p.t = nil
		p.perm = nil
	}
	clear(x)
	peer, e = exchange(msg)
	if e != nil {
		return PairSelection{}, e
	}
	if p.party == 1 {
		v, e := p.parse(2, query, peer)
		if e != nil {
			return PairSelection{}, e
		}
		own = make([]pairTuple, p.n)
		for i, j := range p.perm {
			own[j] = pairAdd(pairAdd(p.r[i], v[i]), p.c[j])
		}
		clear(p.r)
		clear(p.c)
		clear(p.perm)
		p.r = nil
		p.c = nil
		p.perm = nil
	}
	bits := make([]byte, p.n)
	for i, v := range own {
		if v.keep {
			bits[i] = 1
		}
	}
	peer, e = exchange(bits)
	if e != nil {
		return PairSelection{}, e
	}
	if len(peer) != p.n {
		return PairSelection{}, ErrCompaction
	}
	opened := make([]byte, p.n)
	out := PairSelection{ShuffleID: p.id, Anchor: make([]share.Ring64Share, 0), Target: make([]share.Ring64Share, 0)}
	for i, v := range own {
		if peer[i] > 1 {
			return PairSelection{}, ErrCompaction
		}
		opened[i] = bits[i] ^ peer[i]
		if opened[i] == 1 {
			out.Anchor = append(out.Anchor, share.NewRing64Share(domain.Ring64(v.anchor)))
			out.Target = append(out.Target, share.NewRing64Share(domain.Ring64(v.target)))
		}
	}
	out.OrderDigest = sha256.Sum256(opened)
	clear(own)
	return out, nil
}

// BindLedger attaches a party-local offline lifecycle guard. Persisted copies
// of the same ShuffleID burn the same durable marker before masked exchange.
func (p *PairPermutation) BindLedger(dir string) error {
	if p == nil || dir == "" || !p.use.Fresh() {
		return ErrCompaction
	}
	p.ledger = dir
	return nil
}

// Seal is a party-local offline codec. Its hash is recorded by the enclosing
// offline reservation. It contains only this party's factor and masks.
func (p *PairPermutation) Seal() ([]byte, error) {
	if p == nil || !p.use.Fresh() {
		return nil, ErrCompaction
	}
	b := make([]byte, 85+55*p.n)
	copy(b, "PMEQPP01")
	b[8] = p.party
	copy(b[9:], p.layout[:])
	copy(b[25:], p.id[:])
	copy(b[41:], p.binding[:])
	binary.LittleEndian.PutUint32(b[73:], uint32(p.n))
	at := 85
	for i, j := range p.perm {
		binary.LittleEndian.PutUint32(b[at:], j)
		at += 4
		for _, v := range []pairTuple{p.c[i], p.t[i], p.r[i]} {
			if v.keep {
				b[at] = 1
			}
			binary.LittleEndian.PutUint64(b[at+1:], v.anchor)
			binary.LittleEndian.PutUint64(b[at+9:], v.target)
			at += 17
		}
	}
	return b, nil
}

// LoadPairPermutation is a party-local offline loader. expectedHash comes from
// the authenticated reservation metadata, never from an online peer message.
// The enclosing durable reservation must be claimed before Select.
func LoadPairPermutation(b []byte, expectedHash [32]byte, party uint8, layout [16]byte, n int) (*PairPermutation, error) {
	if party > 1 || n < 0 || n > (int(^uint(0)>>1)-85)/55 || len(b) != 85+55*n || sha256.Sum256(b) != expectedHash || string(b[:8]) != "PMEQPP01" || b[8] != party || string(b[9:25]) != string(layout[:]) || int(binary.LittleEndian.Uint32(b[73:])) != n {
		return nil, ErrCompaction
	}
	p := &PairPermutation{party: party, layout: layout, n: n, perm: make([]uint32, n), c: make([]pairTuple, n), t: make([]pairTuple, n), r: make([]pairTuple, n), use: material.NewUseGuard()}
	copy(p.id[:], b[25:41])
	copy(p.binding[:], b[41:73])
	if p.id == [16]byte{} || p.binding == [32]byte{} {
		return nil, ErrCompaction
	}
	at := 85
	for i := range p.perm {
		p.perm[i] = binary.LittleEndian.Uint32(b[at:])
		at += 4
		for _, v := range []*pairTuple{&p.c[i], &p.t[i], &p.r[i]} {
			if b[at] > 1 {
				return nil, ErrCompaction
			}
			*v = pairTuple{domain.Bit(b[at] == 1), binary.LittleEndian.Uint64(b[at+1:]), binary.LittleEndian.Uint64(b[at+9:])}
			at += 17
		}
	}
	if !validPermutation(p.perm) {
		return nil, ErrCompaction
	}
	return p, nil
}
