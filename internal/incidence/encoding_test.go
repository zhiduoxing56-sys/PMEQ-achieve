package incidence

import "testing"

func TestFixedDomainDecoderAndStream(t *testing.T) {
	data := make([]byte, 26*3)
	for i := range data {
		data[i] = byte(i & 127)
	}
	m, e := FromLocalCoefficients(26, 3, data)
	if e != nil || m.D != 26 || m.T != 3 {
		t.Fatal(e)
	}
	data[0] = 127
	if m.coefficients[0] != 0 {
		t.Fatal("decoder aliases input")
	}
	data[1] = 128
	if _, e = FromLocalCoefficients(26, 3, data); e == nil {
		t.Fatal("noncanonical byte")
	}
	if _, e = FromLocalCoefficients(26, 2, data); e == nil {
		t.Fatal("length")
	}
	p, _, e := Preprocess(3, 26)
	if e != nil {
		t.Fatal(e)
	}
	s, e := ClaimTriples(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ClaimTriples(p); e == nil {
		t.Fatal("packet reclaimed")
	}
	for _, n := range []int{1, 2} {
		q, e := s.Take(n)
		if e != nil || q.N != n || q.D != 26 {
			t.Fatal(e)
		}
	}
	if _, e = s.Take(1); e == nil {
		t.Fatal("exhaustion")
	}
	// The sealed Anchor layout constructor remains power-of-two only.
	if _, _, e = ShareIncidence(DealerLayout{D: 26, Coordinates: []int{0}}); e == nil {
		t.Fatal("Anchor constructor changed")
	}
}
