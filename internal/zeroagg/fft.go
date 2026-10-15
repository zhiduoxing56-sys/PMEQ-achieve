package zeroagg

// GF(2^16), polynomial basis, irreducible X^16+X^12+X^3+X+1.
type F uint16

func mul(a, b F) F {
	var z uint16
	x, y := uint16(a), uint16(b)
	for i := 0; i < 16; i++ {
		z ^= x & (0 - (y & 1))
		hi := x >> 15
		x = (x << 1) ^ (0x100b & (0 - hi))
		y >>= 1
	}
	return F(z)
}
func pow(a F, n uint32) F {
	v := F(1)
	for n > 0 {
		if n&1 != 0 {
			v = mul(v, a)
		}
		a = mul(a, a)
		n >>= 1
	}
	return v
}
func eval(p []F, x F) F {
	var v F
	for i := len(p) - 1; i >= 0; i-- {
		v = mul(v, x) ^ p[i]
	}
	return v
}
func polynomialProduct(a, b []F) []F {
	p := make([]F, len(a)+len(b)-1)
	for i, x := range a {
		for j, y := range b {
			p[i+j] ^= mul(x, y)
		}
	}
	return p
}

// Unnormalized novel basis B_j(Z)=product_k S_k(Z)^bit_k(j), deg B_j=j.
// S_k vanishes on span(1,2,...,2^(k-1)); S_0=Z.
// All twiddles and basis polynomials are public, independent of private labels.
type Plan struct {
	subspaces                  [][]F
	twiddle                    [][]F
	den, inv                   []F
	forwardCalls, inverseCalls int
}

func newPlan(n int) *Plan {
	levels := log2(n)
	p := &Plan{subspaces: [][]F{{0, 1}}, twiddle: make([][]F, levels), den: make([]F, levels), inv: make([]F, levels)}
	for k := 0; k < levels; k++ {
		s := p.subspaces[k]
		d := eval(s, F(1<<k))
		if d == 0 {
			panic("invalid subspace basis")
		}
		p.den[k] = d
		p.inv[k] = pow(d, 65534)
		p.twiddle[k] = make([]F, n)
		// Public S_k is F_2-linear: evaluate on public basis vectors, then
		// fill all twiddles by XOR. Avoid the previous quadratic plan setup.
		images := make([]F, levels)
		for bit := range images {
			images[bit] = eval(s, F(1<<bit))
		}
		for a := 1; a < n; a++ {
			low := a & (-a)
			bit := 0
			for (1 << bit) != low {
				bit++
			}
			p.twiddle[k][a] = p.twiddle[k][a^low] ^ images[bit]
		}
		next := make([]F, 2*(len(s)-1)+1)
		for i, c := range s {
			next[2*i] ^= mul(c, c)
			next[i] ^= mul(d, c)
		}
		p.subspaces = append(p.subspaces, next)
	}
	return p
}

// Actual radix-2 additive FFT, in-place. a is in the novel basis; outputs
// evaluate at shift XOR 0..len(a)-1. This is O(n log n) butterflies.
func (p *Plan) forward(a []F, shift int) { p.forwardCalls++; p.fwd(a, shift) }
func (p *Plan) fwd(a []F, shift int) {
	if len(a) == 1 {
		return
	}
	half := len(a) / 2
	k := 0
	for 1<<k < half {
		k++
	}
	s, d := p.twiddle[k][shift], p.den[k]
	for i := 0; i < half; i++ {
		hi := a[i+half]
		lo := a[i] ^ mul(hi, s)
		a[i] = lo
		a[i+half] = lo ^ mul(hi, d)
	}
	p.fwd(a[:half], shift)
	p.fwd(a[half:], shift^half)
}
func (p *Plan) inverse(a []F, shift int) { p.inverseCalls++; p.invFFT(a, shift) }
func (p *Plan) invFFT(a []F, shift int) {
	if len(a) == 1 {
		return
	}
	half := len(a) / 2
	k := 0
	for 1<<k < half {
		k++
	}
	p.invFFT(a[:half], shift)
	p.invFFT(a[half:], shift^half)
	s, v := p.twiddle[k][shift], p.inv[k]
	for i := 0; i < half; i++ {
		lo := a[i]
		hi := mul(lo^a[i+half], v)
		a[i] = lo ^ mul(hi, s)
		a[i+half] = hi
	}
}
func novelToMonomial(a []F, p *Plan) []F {
	out := make([]F, len(a))
	for j, c := range a {
		b := []F{1}
		for k := 0; 1<<k <= j; k++ {
			if j&(1<<k) != 0 {
				b = polynomialProduct(b, p.subspaces[k])
			}
		}
		for i, v := range b {
			out[i] ^= mul(c, v)
		}
	}
	return out
}

func log2(x int) int {
	n := 0
	for 1<<n < x {
		n++
	}
	return n
}
