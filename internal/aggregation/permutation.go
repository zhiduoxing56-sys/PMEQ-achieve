package aggregation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"pmeq/internal/incidence"
	"pmeq/internal/material"
)

func permutation(n int) ([]uint32, error) {
	if n < 0 || uint64(n) > uint64(^uint32(0)) {
		return nil, ErrShape
	}
	p := make([]uint32, n)
	for i := range p {
		p[i] = uint32(i)
	}
	for i := n - 1; i > 0; i-- {
		j, e := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if e != nil {
			return nil, e
		}
		p[i], p[int(j.Int64())] = p[int(j.Int64())], p[i]
	}
	return p, nil
}
func validPermutation(p []uint32) bool {
	seen := make([]bool, len(p))
	for _, j := range p {
		if uint64(j) >= uint64(len(p)) || seen[int(j)] {
			return false
		}
		seen[int(j)] = true
	}
	return true
}

// ExpandRho defines version 1 of the party-local representation: AES-256-CTR
// keyed by seed, IV ASCII "PMEQ-RHO-PRG-V1!", LE uint32 stream words, descending
// Fisher-Yates. Rejection before modulo removes sampling bias. The seed is
// never shared with CS1. This is computational pseudorandomness, not a claim
// that 256 seed bits enumerate every member of S_N uniformly.
func ExpandRho(seed [32]byte, n int) ([]uint32, error) {
	if n < 0 || uint64(n) > uint64(^uint32(0)) {
		return nil, ErrShape
	}
	block, e := aes.NewCipher(seed[:])
	if e != nil {
		return nil, e
	}
	stream := cipher.NewCTR(block, []byte("PMEQ-RHO-PRG-V1!"))
	var buffer [4096]byte
	off := len(buffer)
	next := func() uint32 {
		if off == len(buffer) {
			clear(buffer[:])
			stream.XORKeyStream(buffer[:], buffer[:])
			off = 0
		}
		v := binary.LittleEndian.Uint32(buffer[off : off+4])
		off += 4
		return v
	}
	rho := make([]uint32, n)
	for i := range rho {
		rho[i] = uint32(i)
	}
	for i := n - 1; i > 0; i-- {
		bound := uint32(i + 1)
		threshold := (-bound) % bound
		v := next()
		for v < threshold {
			v = next()
		}
		j := int(v % bound)
		rho[i], rho[j] = rho[j], rho[i]
	}
	return rho, nil
}

// Stage0/Stage1 have distinct types: neither contains the peer permutation.
type Stage0 struct {
	LayoutID [16]byte
	BucketID uint32
	RhoSeed  [32]byte
}
type Stage1 struct {
	LayoutID [16]byte
	BucketID uint32
	sigma    []uint32
}

// digest binds an offline CS1 mask to the exact bucket permutation without
// retaining another 400 KB sigma in every reserved query packet.
func (s *Stage1) digest() [32]byte {
	h := sha256.New()
	h.Write([]byte("PMEQ-SIGMA-v1"))
	h.Write(s.LayoutID[:])
	var b [4096]byte
	binary.LittleEndian.PutUint32(b[:4], s.BucketID)
	binary.LittleEndian.PutUint64(b[4:12], uint64(len(s.sigma)))
	h.Write(b[:12])
	for at := 0; at < len(s.sigma); {
		n := min(len(b)/4, len(s.sigma)-at)
		for i := 0; i < n; i++ {
			binary.LittleEndian.PutUint32(b[4*i:], s.sigma[at+i])
		}
		h.Write(b[:4*n])
		at += n
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// GlobalRecords returns the public domain length without exposing sigma.
func (s *Stage1) GlobalRecords() int { return len(s.sigma) }

// Discard is called by the trusted owner after a bucket is durably sealed.
// Cloud callers discard only after their final use of the loaded state.
func (s *Stage1) Discard() {
	if s != nil {
		clear(s.sigma)
		s.sigma = nil
	}
}

// SplitPermutation is DO-only. pi is never retained in either party object.
func SplitPermutation(id [16]byte, bucket uint32, pi []uint32) (*Stage0, *Stage1, error) {
	if !validPermutation(pi) {
		return nil, nil, ErrShape
	}
	var seed [32]byte
	if _, e := rand.Read(seed[:]); e != nil {
		return nil, nil, e
	}
	rho, e := ExpandRho(seed, len(pi))
	if e != nil {
		return nil, nil, e
	}
	sigma := make([]uint32, len(pi))
	for i, j := range rho {
		sigma[int(j)] = pi[i]
	}
	clear(rho)
	return &Stage0{id, bucket, seed}, &Stage1{id, bucket, sigma}, nil
}

// ExpandedStage0 is invocation-local scratch, NOT static bucket state.
// Callers may release it after Message2; no all-bucket expansion/cache exists.
type ExpandedStage0 struct {
	rho   []uint32
	owner *Stage0
}

func (s *Stage0) Expand(n int) (*ExpandedStage0, error) {
	rho, e := ExpandRho(s.RhoSeed, n)
	if e != nil {
		return nil, e
	}
	return &ExpandedStage0{rho: rho, owner: s}, nil
}

type PermPrep0 struct {
	c1, a2, b2 []incidence.Z128
	use        *material.UseGuard
	stage      *Stage0
}
type PermPrep1 struct {
	a1, b1, c2 []incidence.Z128
	use        *material.UseGuard
	stage      [32]byte
}

// PreprocessPermutation reuses the old masked-scatter equations with fresh
// correlated randomness per invocation, including repeated query chunks.
func PreprocessPermutation(p *Stage0, q *Stage1) (*PermPrep0, *PermPrep1, error) {
	if p == nil || q == nil {
		return nil, nil, ErrShape
	}
	n := len(q.sigma)
	if p.LayoutID != q.LayoutID || p.BucketID != q.BucketID {
		return nil, nil, ErrShape
	}
	rho, e := ExpandRho(p.RhoSeed, n)
	if e != nil {
		return nil, nil, e
	}
	b, e := randomBytes(4 * n)
	if e != nil {
		return nil, nil, e
	}
	a1, c1, a2, c2 := make([]incidence.Z128, n), make([]incidence.Z128, n), make([]incidence.Z128, n), make([]incidence.Z128, n)
	for i := 0; i < n; i++ {
		a1[i] = incidence.Z128(b[i] & 127)
		c1[i] = incidence.Z128(b[n+i] & 127)
		a2[i] = incidence.Z128(b[2*n+i] & 127)
		c2[i] = incidence.Z128(b[3*n+i] & 127)
	}
	b1, b2 := make([]incidence.Z128, n), make([]incidence.Z128, n)
	for i, coordinate := range rho {
		j := int(coordinate)
		b1[j] = a1[i].Sub(c1[j])
	}
	for i, coordinate := range q.sigma {
		j := int(coordinate)
		b2[j] = a2[i].Sub(c2[j])
	}
	clear(rho)
	clear(b)
	return &PermPrep0{c1: c1, a2: a2, b2: b2, use: material.NewUseGuard(), stage: p}, &PermPrep1{a1: a1, b1: b1, c2: c2, use: material.NewUseGuard(), stage: q.digest()}, nil
}

// Message1 travels CS1 -> CS0. Local inputs beyond D are public zero shares.
func (p *PermPrep1) Message1(x []incidence.Share) ([]incidence.Z128, error) {
	if p == nil || len(x) > len(p.a1) || !p.use.Claim(0) {
		return nil, ErrShape
	}
	d := make([]incidence.Z128, len(p.a1))
	for i := range d {
		v := incidence.Z128(0)
		if i < len(x) {
			v = x[i].Value()
		}
		d[i] = v.Sub(p.a1[i])
	}
	return d, nil
}

// Message2 travels CS0 -> CS1; CS0's final share is independently masked b2.
func (s *Stage0) Message2(p *PermPrep0, x []incidence.Share, d1 []incidence.Z128) ([]incidence.Z128, []incidence.Share, error) {
	if s == nil || p == nil || p.stage != s {
		return nil, nil, ErrShape
	}
	expanded, e := s.Expand(len(d1))
	if e != nil {
		return nil, nil, e
	}
	return expanded.Message2(p, x, d1)
}

func (s *ExpandedStage0) Message2(p *PermPrep0, x []incidence.Share, d1 []incidence.Z128) ([]incidence.Z128, []incidence.Share, error) {
	if s == nil {
		return nil, nil, ErrShape
	}
	n := len(s.rho)
	if p == nil || p.stage != s.owner || len(x) > n || len(d1) != n || len(p.a2) != n || !p.use.Claim(0) {
		return nil, nil, ErrShape
	}
	d2 := make([]incidence.Z128, n)
	for i, coordinate := range s.rho {
		j := int(coordinate)
		v := incidence.Z128(0)
		if i < len(x) {
			v = x[i].Value()
		}
		d2[j] = v.Add(d1[i]).Add(p.c1[j]).Sub(p.a2[j])
	}
	out := make([]incidence.Share, n)
	for i := range out {
		out[i] = incidence.NewShare(p.b2[i])
	}
	return d2, out, nil
}
func (s *Stage1) Finish(p *PermPrep1, d2 []incidence.Z128) ([]incidence.Share, error) {
	if s == nil {
		return nil, ErrShape
	}
	n := len(s.sigma)
	if p == nil || p.stage != s.digest() || len(d2) != n || len(p.b1) != n || !p.use.Claim(1) {
		return nil, ErrShape
	}
	out := make([]incidence.Share, n)
	for i, coordinate := range s.sigma {
		j := int(coordinate)
		out[j] = incidence.NewShare(p.b1[i].Add(d2[i]).Add(p.c2[j]))
	}
	return out, nil
}
