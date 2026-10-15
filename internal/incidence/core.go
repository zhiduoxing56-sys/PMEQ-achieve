// Package incidence implements PHASE 5B1 with party-local online state.
// Z128 means Z/128Z, not a 128-bit integer. Preprocessing functions are trusted DO code.
package incidence

import (
	"crypto/rand"
	"errors"
	"math/big"

	"pmeq/internal/share"
)

type Z128 uint8

func (x Z128) Add(y Z128) Z128 { return (x + y) & 127 }
func (x Z128) Sub(y Z128) Z128 { return (x - y) & 127 }
func (x Z128) Mul(y Z128) Z128 { return (x * y) & 127 }

type Share struct{ value Z128 }

func NewShare(x Z128) Share { return Share{x & 127} }
func (x Share) Value() Z128 { return x.value }
func Add(x, y Share) Share  { return NewShare(x.value.Add(y.value)) }
func Sub(x, y Share) Share  { return NewShare(x.value.Sub(y.value)) }
func Split(x Z128) (Share, Share, error) {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Share{}, Share{}, err
	}
	a := Z128(b[0] & 127)
	return NewShare(a), NewShare(x.Sub(a)), nil
}

var ErrShape = errors.New("incidence: invalid party, dimensions, or opening")
var ErrConsumed = errors.New("incidence: one-time material consumed or operation out of order")

// DefaultChunkSize was selected by the PHASE 5B1 local component benchmark.
// Callers can choose a different public limit; it is not a protocol parameter.
const DefaultChunkSize = 64

// PartyMatrix is static column-major A[:,s]. Every byte is a local share,
// including shares of zero. It never contains IDs or sparse coordinates.
type PartyMatrix struct {
	D, T         int
	coefficients []Z128
}

func (p *PartyMatrix) StorageBytes() int { return len(p.coefficients) }

// Posting and DealerLayout are DO-only build inputs/provenance. Neither is
// reachable from PartyMatrix, triples, B2A, or Aggregator.
type Posting struct {
	RecordID uint64
	Real     bool
}
type DealerLayout struct {
	D           int
	Coordinates []int
}

func RecordCapacity(m int) (int, error) {
	if m < 0 {
		return 0, ErrShape
	}
	if m == 0 {
		return 0, nil
	}
	d := 1
	for d < m {
		if d > int(^uint(0)>>1)/2 {
			return 0, ErrShape
		}
		d *= 2
	}
	return d, nil
}

// PrepareLayout randomly injects real records into a public power-of-two domain.
// Dummy columns have coordinate -1 only in this DO-owned object.
func PrepareLayout(slots []Posting) (DealerLayout, error) {
	ids := map[uint64]int{}
	for _, s := range slots {
		if s.Real {
			if _, ok := ids[s.RecordID]; !ok {
				ids[s.RecordID] = len(ids)
			}
		}
	}
	d, err := RecordCapacity(len(ids))
	if err != nil {
		return DealerLayout{}, err
	}
	perm := make([]int, d)
	for i := range perm {
		perm[i] = i
	}
	for i := d - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return DealerLayout{}, err
		}
		k := int(j.Int64())
		perm[i], perm[k] = perm[k], perm[i]
	}
	layout := DealerLayout{D: d, Coordinates: make([]int, len(slots))}
	for i, s := range slots {
		layout.Coordinates[i] = -1
		if s.Real {
			layout.Coordinates[i] = perm[ids[s.RecordID]]
		}
	}
	return layout, nil
}

func cells(n, d int) (int, error) {
	if n < 0 || d < 0 || (d != 0 && n > int(^uint(0)>>1)/d) {
		return 0, ErrShape
	}
	return n * d, nil
}

// ShareIncidence generates independent random masks for EVERY coefficient.
func ShareIncidence(layout DealerLayout) (*PartyMatrix, *PartyMatrix, error) {
	n := len(layout.Coordinates)
	p, err := cells(n, layout.D)
	if err != nil {
		return nil, nil, err
	}
	if layout.D < 0 || (layout.D > 0 && layout.D&(layout.D-1) != 0) {
		return nil, nil, ErrShape
	}
	for _, j := range layout.Coordinates {
		if j < -1 || j >= layout.D {
			return nil, nil, ErrShape
		}
	}
	a := &PartyMatrix{D: layout.D, T: n, coefficients: make([]Z128, p)}
	b := &PartyMatrix{D: layout.D, T: n, coefficients: make([]Z128, p)}
	// Bound entropy scratch independently of bucket size.
	buf := make([]byte, 65536)
	for start := 0; start < p; {
		end := min(p, start+len(buf))
		if _, err := rand.Read(buf[:end-start]); err != nil {
			return nil, nil, err
		}
		for k := start; k < end; k++ {
			v := Z128(0)
			if layout.Coordinates[k/layout.D] == k%layout.D {
				v = 1
			}
			r := Z128(buf[k-start] & 127)
			a.coefficients[k] = r
			b.coefficients[k] = v.Sub(r)
		}
		start = end
	}
	return a, b, nil
}

// PartyTriples has one scalar a per posting and contiguous vector b,c shares.
// It is one-use. No per-coefficient scalar triple objects are constructed.
type PartyTriples struct {
	party   uint8
	N, D    int
	a, b, c []Z128
	used    bool
}

func (p *PartyTriples) StorageBytes() int { return len(p.a) + len(p.b) + len(p.c) }
func Preprocess(n, d int) (*PartyTriples, *PartyTriples, error) {
	p, err := cells(n, d)
	if err != nil || d < 1 {
		return nil, nil, ErrShape
	}
	out := [2]*PartyTriples{}
	for i := range out {
		out[i] = &PartyTriples{party: uint8(i), N: n, D: d, a: make([]Z128, n), b: make([]Z128, p), c: make([]Z128, p)}
	}
	// One reusable row-sized buffer: clear a,a0; then clear b,b0,c0 per coordinate.
	if d > (int(^uint(0)>>1)-2)/3 {
		return nil, nil, ErrShape
	}
	buf := make([]byte, 2+3*d)
	for s := 0; s < n; s++ {
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, err
		}
		a, a0 := Z128(buf[0]&127), Z128(buf[1]&127)
		out[0].a[s] = a0
		out[1].a[s] = a.Sub(a0)
		for j := 0; j < d; j++ {
			k := s*d + j
			b, b0, c0 := Z128(buf[2+3*j]&127), Z128(buf[3+3*j]&127), Z128(buf[4+3*j]&127)
			out[0].b[k] = b0
			out[1].b[k] = b.Sub(b0)
			out[0].c[k] = c0
			out[1].c[k] = a.Mul(b).Sub(c0)
		}
	}
	return out[0], out[1], nil
}

// Masked is a party's outgoing masked differences, never an input share vector.
type Masked struct{ D, E []Z128 }
type Opened struct{ D, E []Z128 }

// OpenMasked models one batched exchange. Only masked messages reach it.
func OpenMasked(a, b Masked) (Opened, error) {
	if len(a.D) != len(b.D) || len(a.E) != len(b.E) {
		return Opened{}, ErrShape
	}
	o := Opened{D: make([]Z128, len(a.D)), E: make([]Z128, len(a.E))}
	for i := range o.D {
		o.D[i] = a.D[i].Add(b.D[i])
	}
	for i := range o.E {
		o.E[i] = a.E[i].Add(b.E[i])
	}
	return o, nil
}

type B2A struct {
	triples *PartyTriples
	bits    []Z128
	done    bool
}

func BeginB2A(bits []share.BitShare, p *PartyTriples) (*B2A, Masked, error) {
	if p == nil || p.D != 1 || p.N != len(bits) {
		return nil, Masked{}, ErrShape
	}
	if p.used {
		return nil, Masked{}, ErrConsumed
	}
	p.used = true
	b := &B2A{triples: p, bits: make([]Z128, len(bits))}
	m := Masked{D: make([]Z128, len(bits)), E: make([]Z128, len(bits))}
	for i, s := range bits {
		v := Z128(0)
		if s.Value() {
			v = 1
		}
		b.bits[i] = v
		x, y := Z128(0), Z128(0)
		if p.party == 0 {
			x = v
		} else {
			y = v
		}
		m.D[i] = x.Sub(p.a[i])
		m.E[i] = y.Sub(p.b[i])
	}
	return b, m, nil
}
func product(p *PartyTriples, s, k int, d, e Z128) Z128 {
	z := p.c[k].Add(d.Mul(p.b[k])).Add(e.Mul(p.a[s]))
	if p.party == 0 {
		z = z.Add(d.Mul(e))
	}
	return z
}
func (b *B2A) Finish(o Opened) ([]Share, error) {
	if b.done {
		return nil, ErrConsumed
	}
	if len(o.D) != len(b.bits) || len(o.E) != len(b.bits) {
		return nil, ErrShape
	}
	b.done = true
	out := make([]Share, len(b.bits))
	for i, v := range b.bits {
		p := product(b.triples, i, i, o.D[i], o.E[i])
		out[i] = NewShare(v.Sub(p.Add(p)))
	}
	b.triples = nil
	b.bits = nil
	return out, nil
}

// Aggregator is ONE cloud's streaming invocation. F is accumulated directly;
// intermediate product vectors are never materialized. Chunks are sequential.
type Aggregator struct {
	party           uint8
	matrix          *PartyMatrix
	f               []Share
	next, chunkSize int
	pending         *PartyTriples
}

func NewAggregator(party uint8, m *PartyMatrix, chunkSize int) (*Aggregator, error) {
	if party > 1 || m == nil || chunkSize < 1 {
		return nil, ErrShape
	}
	p, err := cells(m.T, m.D)
	if err != nil || p != len(m.coefficients) {
		return nil, ErrShape
	}
	return &Aggregator{party: party, matrix: m, f: make([]Share, m.D), chunkSize: chunkSize}, nil
}
func (a *Aggregator) BeginChunk(x []Share, p *PartyTriples) (Masked, error) {
	if p == nil || p.party != a.party || p.D != a.matrix.D || p.N != len(x) || len(x) == 0 || len(x) > a.chunkSize || len(x) > a.matrix.T-a.next {
		return Masked{}, ErrShape
	}
	if a.pending != nil || p.used {
		return Masked{}, ErrConsumed
	}
	p.used = true
	a.pending = p
	m := Masked{D: make([]Z128, p.N), E: make([]Z128, len(p.b))}
	for s, v := range x {
		m.D[s] = v.value.Sub(p.a[s])
		for j := 0; j < p.D; j++ {
			k := s*p.D + j
			m.E[k] = a.matrix.coefficients[(a.next+s)*p.D+j].Sub(p.b[k])
		}
	}
	return m, nil
}
func (a *Aggregator) FinishChunk(o Opened) error {
	p := a.pending
	if p == nil {
		return ErrConsumed
	}
	if len(o.D) != p.N || len(o.E) != len(p.b) {
		return ErrShape
	}
	for s, d := range o.D {
		for j := 0; j < p.D; j++ {
			k := s*p.D + j
			a.f[j] = Add(a.f[j], NewShare(product(p, s, k, d, o.E[k])))
		}
	}
	a.next += p.N
	a.pending = nil
	return nil
}
func (a *Aggregator) Result() ([]Share, error) {
	if a.pending != nil || (a.matrix.D != 0 && a.next != a.matrix.T) {
		return nil, ErrConsumed
	}
	return append([]Share(nil), a.f...), nil
}
