package aggregation

import (
	"pmeq/internal/incidence"
	"pmeq/internal/material"
	"testing"
)

func TestPermutationFreshMaterialsCopiesAndBinding(t *testing.T) {
	pi := []uint32{2, 0, 4, 1, 3}
	s0, s1, e := SplitPermutation([16]byte{1}, 17, pi)
	must(t, e)
	p, q, e := PreprocessPermutation(s0, s1)
	must(t, e)
	pCopy, qCopy := *p, *q
	x0, x1 := make([]incidence.Share, len(pi)), make([]incidence.Share, len(pi))
	for i := range x0 {
		x0[i], x1[i], e = incidence.Split(incidence.Z128(i * 31))
		must(t, e)
	}
	d1, e := q.Message1(x1)
	must(t, e)
	if _, e = qCopy.Message1(x1); e == nil {
		t.Fatal("copied mask reused")
	}
	d2, y0, e := s0.Message2(p, x0, d1)
	must(t, e)
	if _, _, e = s0.Message2(&pCopy, x0, d1); e == nil {
		t.Fatal("copied mask reused")
	}
	y1, e := s1.Finish(q, d2)
	must(t, e)
	for i, j := range pi {
		if y0[j].Value().Add(y1[j].Value()) != incidence.Z128(i*31) {
			t.Fatal("permutation payload", i)
		}
	}
	if _, e = s1.Finish(&qCopy, d2); e == nil {
		t.Fatal("copied finish reused")
	}
	a, b, e := PreprocessPermutation(s0, s1)
	must(t, e)
	other0, other1, e := SplitPermutation([16]byte{1}, 17, pi)
	must(t, e)
	op, e := b.Message1(x1)
	must(t, e)
	if _, _, e = other0.Message2(a, x0, op); e == nil {
		t.Fatal("material applied to wrong factor")
	}
	msg, _, e := s0.Message2(a, x0, op)
	must(t, e)
	if _, e = other1.Finish(b, msg); e == nil {
		t.Fatal("material applied to wrong factor")
	}
	_, e = s1.Finish(b, msg)
	must(t, e)
	if _, _, e = PreprocessPermutation(nil, s1); e == nil {
		t.Fatal("nil factor")
	}
}

// Enumerate the full ring's pad values while invoking the real Message1 path.
// For any fixed other input, the received message has exactly the same histogram.
// This checks the first masking equation; it is not a whole-protocol security proof.
func TestPermutationSinglePartyMaskDistribution(t *testing.T) {
	s0, s1, e := SplitPermutation([16]byte{1}, 0, []uint32{0})
	must(t, e)
	for _, secret := range []incidence.Z128{0, 1, 63, 127} {
		var histogram [128]int
		for pad := 0; pad < 128; pad++ {
			_, p, e := PreprocessPermutation(s0, s1)
			must(t, e)
			// Trusted test enumerates the missing mask while preserving b1=rho(a1)-c1.
			old := p.a1[0]
			p.a1[0] = incidence.Z128(pad)
			p.b1[0] = p.b1[0].Add(p.a1[0]).Sub(old)
			m, e := p.Message1([]incidence.Share{incidence.NewShare(secret)})
			must(t, e)
			histogram[m[0]]++
		}
		for _, n := range histogram {
			if n != 1 {
				t.Fatal("input-dependent mask distribution", secret)
			}
		}
	}
	// For CS2 the second message is independently masked by the missing a2.
	// Hold CS2's a1/b1/c2 and its permutation fixed; enumerate the fresh a2.
	for _, secret := range []incidence.Z128{0, 1, 63, 127} {
		p, q, e := PreprocessPermutation(s0, s1)
		must(t, e)
		d1, e := q.Message1([]incidence.Share{incidence.NewShare(0)})
		must(t, e)
		var histogram [128]int
		for pad := 0; pad < 128; pad++ {
			trial := *p
			trial.use = material.NewUseGuard()
			trial.a2 = []incidence.Z128{incidence.Z128(pad)}
			trial.b2 = []incidence.Z128{incidence.Z128(pad).Sub(q.c2[0])}
			d2, _, e := s0.Message2(&trial, []incidence.Share{incidence.NewShare(secret)}, d1)
			must(t, e)
			histogram[d2[0]]++
		}
		for _, n := range histogram {
			if n != 1 {
				t.Fatal("second message leaks input", secret)
			}
		}
	}
}
