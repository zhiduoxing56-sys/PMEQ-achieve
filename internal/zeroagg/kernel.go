// Exact anchor OR using a fixed public additive-FFT circuit over GF(2^16).
package zeroagg

import (
	"crypto/rand"
	"encoding/binary"
	"sync/atomic"
	"time"
)

type LocalTriple struct{ a, b, c F }
type Party struct {
	t, d, n          int
	inputT           int
	started          atomic.Bool
	sealed           atomic.Bool
	id               int
	triples          []LocalTriple
	used             int
	exchange         func([]byte) []byte
	plan             *Plan
	MulTime, FFTTime time.Duration
	Rounds           int
}

func Gates(t, d int) (tp, n, g int) {
	if t < 0 || t > 65536 || d < 0 || d > 65535 || (t == 0 && d != 0) {
		panic("invalid public shape")
	}
	if t == 0 {
		return 0, 0, 0
	}
	tp = 1
	for tp < t {
		tp *= 2
	}
	n = 1
	for n < d+1 {
		n *= 2
	}
	if n > 65536 {
		panic("GF16 capacity")
	}
	g = tp + 4*d
	for b := 2; b <= tp; b *= 2 {
		g += (tp / b) * min(2*b, n)
	}
	return
}
func Prepare(t, d int) (*Party, *Party, int) {
	tp, n, g := Gates(t, d)
	a := &Party{inputT: t, t: tp, d: d, n: n, id: 0, triples: make([]LocalTriple, g)}
	b := &Party{inputT: t, t: tp, d: d, n: n, id: 1, triples: make([]LocalTriple, g)}
	raw := make([]byte, 10*g)
	defer clear(raw)
	_, e := rand.Read(raw)
	if e != nil {
		panic(e)
	}
	for i := 0; i < g; i++ {
		v := raw[10*i:]
		x, y, r, s, z := F(binary.LittleEndian.Uint16(v)), F(binary.LittleEndian.Uint16(v[2:])), F(binary.LittleEndian.Uint16(v[4:])), F(binary.LittleEndian.Uint16(v[6:])), F(binary.LittleEndian.Uint16(v[8:]))
		a.triples[i] = LocalTriple{r, s, z}
		b.triples[i] = LocalTriple{x ^ r, y ^ s, mul(x, y) ^ z}
	}
	return a, b, 12 * g
}
func (p *Party) Bind(exchange func([]byte) []byte) {
	p.exchange = exchange
	if p.d > 0 {
		p.plan = newPlan(p.n)
	}
}
func (p *Party) batch(x, y []F) []F {
	begin := time.Now()
	if len(x) != len(y) || p.used+len(x) > len(p.triples) {
		panic("triple shape/exhaustion")
	}
	data := make([]byte, 4*len(x))
	start := p.used
	// Reserve and erase BEFORE the first opening. Any failed exchange burns this batch.
	local := append([]LocalTriple(nil), p.triples[start:start+len(x)]...)
	defer clear(local)
	clear(p.triples[start : start+len(x)])
	p.used += len(x)
	for i := range x {
		q := local[i]
		binary.LittleEndian.PutUint16(data[4*i:], uint16(x[i]^q.a))
		binary.LittleEndian.PutUint16(data[4*i+2:], uint16(y[i]^q.b))
	}
	peer := p.exchange(data)
	if len(peer) != len(data) {
		panic("peer public shape mismatch")
	}
	out := make([]F, len(x))
	for i := range out {
		q := local[i]
		d := F(binary.LittleEndian.Uint16(data[4*i:]) ^ binary.LittleEndian.Uint16(peer[4*i:]))
		e := F(binary.LittleEndian.Uint16(data[4*i+2:]) ^ binary.LittleEndian.Uint16(peer[4*i+2:]))
		z := q.c ^ mul(d, q.b) ^ mul(e, q.a)
		if p.id == 0 {
			z ^= mul(d, e)
		}
		out[i] = z
	}
	p.Rounds++

	p.MulTime += time.Since(begin)
	return out
}
func (p *Party) forward(a []F) {
	start := time.Now()
	p.plan.forward(a, 0)
	p.FFTTime += time.Since(start)
}
func (p *Party) inverse(a []F) {
	start := time.Now()
	p.plan.inverse(a, 0)
	p.FFTTime += time.Since(start)
}
func (p *Party) Aggregate(x, labels []F) []byte {
	if p.sealed.Load() || !p.started.CompareAndSwap(false, true) {
		panic("aggregate material already claimed")
	}
	if len(x) != p.inputT || len(labels) != p.inputT {
		panic("input public shape mismatch")
	}
	if p.d > 0 && (p.exchange == nil || p.plan == nil) {
		panic("unbound party")
	}
	if p.d == 0 {
		return nil
	}
	if len(x) < p.t {
		x = append(x, make([]F, p.t-len(x))...)
		labels = append(labels, make([]F, p.t-len(labels))...)
	}
	xa := p.batch(x, labels)
	polys := make([][]F, p.t)
	for i := range polys {
		c := x[i] ^ xa[i]
		if p.id == 0 {
			c ^= 1
		}
		polys[i] = []F{c, x[i]}
	}
	for degree := 2; len(polys) > 1; degree *= 2 {
		points := 2 * degree
		if points > p.n {
			points = p.n
		}
		nodes := len(polys) / 2
		left, right := make([]F, nodes*points), make([]F, nodes*points)
		for j := 0; j < nodes; j++ {
			a, b := left[j*points:(j+1)*points], right[j*points:(j+1)*points]
			copy(a, polys[2*j])
			copy(b, polys[2*j+1])
			p.forward(a)
			p.forward(b)
		}
		products := p.batch(left, right)
		next := make([][]F, nodes)
		keep := degree + 1
		if keep > p.n {
			keep = p.n
		}
		for j := 0; j < nodes; j++ {
			a := products[j*points : (j+1)*points]
			p.inverse(a)
			next[j] = a[:keep:keep]
		}
		polys = next
	}
	values := make([]F, p.n)
	copy(values, polys[0])
	p.forward(values)
	z := append([]F(nil), values[1:p.d+1]...)
	for k := 1; k < 16; k *= 2 {
		q := append([]F(nil), z...)
		for i := range q {
			for j := 0; j < k; j++ {
				q[i] = mul(q[i], q[i])
			}
		}
		z = p.batch(q, z)
	}
	out := make([]byte, (p.d+7)/8)
	for j, v := range z {
		if p.id == 0 {
			v ^= 1
		}
		out[j/8] |= byte(v&1) << uint(j%8)
	}
	if p.used != len(p.triples) {
		panic("unexpected gate count")
	}
	return out
}

func (p *Party) GatesUsed() int { return p.used }

func (p *Party) TotalGates() int { return len(p.triples) }
