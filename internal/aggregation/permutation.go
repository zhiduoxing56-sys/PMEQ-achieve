package aggregation

import (
	"crypto/rand"
	"math/big"
	"pmeq/internal/incidence"
)

func permutation(n int) ([]int, error) {
	p := make([]int, n)
	for i := range p {
		p[i] = i
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
func validPermutation(p []int) bool {
	seen := make([]bool, len(p))
	for _, j := range p {
		if j < 0 || j >= len(p) || seen[j] {
			return false
		}
		seen[j] = true
	}
	return true
}

// Stage0/Stage1 have distinct types: neither contains the peer permutation.
type Stage0 struct {
	LayoutID [16]byte
	rho      []int
}
type Stage1 struct {
	LayoutID [16]byte
	sigma    []int
}

// SplitPermutation is DO-only. pi is never retained in either party object.
func SplitPermutation(id [16]byte, pi []int) (*Stage0, *Stage1, error) {
	if !validPermutation(pi) {
		return nil, nil, ErrShape
	}
	rho, e := permutation(len(pi))
	if e != nil {
		return nil, nil, e
	}
	sigma := make([]int, len(pi))
	for i, j := range rho {
		sigma[j] = pi[i]
	}
	return &Stage0{id, rho}, &Stage1{id, sigma}, nil
}

type PermPrep0 struct {
	c1, a2, b2   []incidence.Z128
	done1, done2 bool
}
type PermPrep1 struct {
	a1, b1, c2   []incidence.Z128
	done1, done2 bool
}

// PreprocessPermutation reuses the old masked-scatter equations with fresh
// correlated randomness per invocation, including repeated query chunks.
func PreprocessPermutation(p *Stage0, q *Stage1) (*PermPrep0, *PermPrep1, error) {
	n := len(p.rho)
	if n != len(q.sigma) || p.LayoutID != q.LayoutID {
		return nil, nil, ErrShape
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
	for i, j := range p.rho {
		b1[j] = a1[i].Sub(c1[j])
	}
	for i, j := range q.sigma {
		b2[j] = a2[i].Sub(c2[j])
	}
	return &PermPrep0{c1: c1, a2: a2, b2: b2}, &PermPrep1{a1: a1, b1: b1, c2: c2}, nil
}

// Message1 travels CS1 -> CS0. Local inputs beyond D are public zero shares.
func (p *PermPrep1) Message1(x []incidence.Share) ([]incidence.Z128, error) {
	if p.done1 || len(x) > len(p.a1) {
		return nil, ErrShape
	}
	p.done1 = true
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
	n := len(s.rho)
	if p.done1 || len(x) > n || len(d1) != n || len(p.a2) != n {
		return nil, nil, ErrShape
	}
	p.done1 = true
	d2 := make([]incidence.Z128, n)
	for i, j := range s.rho {
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
	n := len(s.sigma)
	if !p.done1 || p.done2 || len(d2) != n || len(p.b1) != n {
		return nil, ErrShape
	}
	p.done2 = true
	out := make([]incidence.Share, n)
	for i, j := range s.sigma {
		out[j] = incidence.NewShare(p.b1[i].Add(d2[i]).Add(p.c2[j]))
	}
	return out, nil
}
