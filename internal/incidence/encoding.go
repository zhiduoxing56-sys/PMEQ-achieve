package incidence

import (
	"io"
	"sync"
)

// WriteCoefficients persists the original dense one-party representation.
func (p *PartyMatrix) WriteCoefficients(w io.Writer) error {
	if p == nil {
		return ErrShape
	}
	var b [65536]byte
	for at := 0; at < len(p.coefficients); {
		n := min(len(b), len(p.coefficients)-at)
		for i := 0; i < n; i++ {
			b[i] = byte(p.coefficients[at+i])
		}
		written, e := w.Write(b[:n])
		if e != nil {
			return e
		}
		if written != n {
			return io.ErrShortWrite
		}
		at += n
	}
	return nil
}

// ReadCoefficients loads into the same dense representation without a second
// complete temporary coefficient array. The caller authenticates its artifact.
func ReadCoefficients(r io.Reader, d, t int) (*PartyMatrix, error) {
	n, e := cells(t, d)
	if e != nil || d < 0 || (d == 0 && t != 0) {
		return nil, ErrShape
	}
	p := &PartyMatrix{D: d, T: t, coefficients: make([]Z128, n)}
	var b [65536]byte
	for at := 0; at < n; {
		m := min(len(b), n-at)
		if _, e = io.ReadFull(r, b[:m]); e != nil {
			return nil, e
		}
		for i := 0; i < m; i++ {
			if b[i] > 127 {
				return nil, ErrShape
			}
			p.coefficients[at+i] = Z128(b[i])
		}
		at += m
	}
	return p, nil
}

// FromLocalCoefficients loads one party's dense column-major coefficients.
// The caller must authenticate the source artifact. Unlike PrepareLayout,
// this decoder does not choose or disclose record coordinates; fixed domains
// such as PHASE10's 26 are supported by the existing multiplication kernel.
func FromLocalCoefficients(d, t int, encoded []byte) (*PartyMatrix, error) {
	n, err := cells(t, d)
	if err != nil || d < 1 || len(encoded) != n {
		return nil, ErrShape
	}
	p := &PartyMatrix{D: d, T: t, coefficients: make([]Z128, n)}
	for i, v := range encoded {
		if v > 127 {
			return nil, ErrShape
		}
		p.coefficients[i] = Z128(v)
	}
	return p, nil
}

// TripleStream claims a complete packet once, then hands out disjoint posting
// ranges. This supports public route boundaries without copying vector masks.
type TripleStream struct {
	sync.Mutex
	p    *PartyTriples
	next int
}

func ClaimTriples(p *PartyTriples) (*TripleStream, error) {
	if p == nil || p.used {
		return nil, ErrConsumed
	}
	p.used = true
	return &TripleStream{p: p}, nil
}

func (s *TripleStream) Take(n int) (*PartyTriples, error) {
	s.Lock()
	defer s.Unlock()
	if n < 0 || s.p == nil || n > s.p.N-s.next {
		return nil, ErrShape
	}
	lo, hi := s.next, s.next+n
	s.next = hi
	p := s.p
	return &PartyTriples{party: p.party, N: n, D: p.D, a: p.a[lo:hi], b: p.b[lo*p.D : hi*p.D], c: p.c[lo*p.D : hi*p.D]}, nil
}
