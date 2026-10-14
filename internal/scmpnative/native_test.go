//go:build phase6native

package scmpnative_test

import (
	"bytes"
	"crypto/rand"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/incidence"
	"pmeq/internal/scmpnative"
	"pmeq/internal/share"
	"sync"
	"testing"
)

func TestNativeExhaustiveComparison(t *testing.T) {
	b := scmpnative.Backend{}
	// All 4096 plaintext pairs in the unsigned half-domain. Each pair has fresh
	// native keys and masks; masked inputs cover the full Z_128 domain.
	for y := 0; y < 64; y++ {
		u, p, q, e := aggregation.PreprocessComparison(64, b)
		if e != nil {
			t.Fatal(e)
		}
		bound, e := u.Mask(y)
		if e != nil {
			t.Fatal(e)
		}
		x0, x1 := make([]incidence.Share, 64), make([]incidence.Share, 64)
		for x := range x0 {
			x0[x], x1[x], e = incidence.Split(incidence.Z128(x))
			if e != nil {
				t.Fatal(e)
			}
		}
		m0, e := p.Prepare(x0)
		if e != nil {
			t.Fatal(e)
		}
		m1, e := q.Prepare(x1)
		if e != nil {
			t.Fatal(e)
		}
		opened, e := aggregation.OpenComparison(m0, m1)
		if e != nil {
			t.Fatal(e)
		}
		a, e := p.Finish(opened, bound, b)
		if e != nil {
			t.Fatal(e)
		}
		c, e := q.Finish(opened, bound, b)
		if e != nil {
			t.Fatal(e)
		}
		for x := range a {
			if bool(a[x].Value()) != bool(c[x].Value()) != (x >= y) {
				t.Fatalf("x=%d y=%d", x, y)
			}
		}
		if _, e = p.Prepare(x0); e == nil {
			t.Fatal("comparison mask reused")
		}
		if _, e = q.Finish(opened, bound, b); e == nil {
			t.Fatal("comparison key reused")
		}
	}
}

func TestNativeDomainAndFreshness(t *testing.T) {
	b := scmpnative.Backend{}
	for _, v := range []struct {
		bin  uint8
		x, y uint32
	}{{6, 0, 0}, {8, 0, 0}, {7, 128, 0}, {7, 0, 128}} {
		if _, _, e := b.KeyGen(v.bin, v.x, v.y, domain.BitZero); e == nil {
			t.Fatal("invalid domain accepted", v)
		}
	}
	a, c, e := b.KeyGen(7, 127, 127, domain.BitOne)
	if e != nil {
		t.Fatal(e)
	}
	a2, c2, e := b.KeyGen(7, 127, 127, domain.BitOne)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(a.Opaque(), a2.Opaque()) || bytes.Equal(c.Opaque(), c2.Opaque()) {
		t.Fatal("repeated keys")
	}
	for _, v := range []struct {
		p    uint8
		x, y uint32
	}{{2, 0, 0}, {0, 128, 0}, {1, 0, 128}} {
		if _, e = b.Eval(v.p, a, v.x, v.y); e == nil {
			t.Fatal("invalid evaluation accepted", v)
		}
	}
	if _, e = b.Eval(0, anchorfilter.NewSCMPKeyShare([]byte{1}, share.BitShare{}), 0, 0); e == nil {
		t.Fatal("short key")
	}
	bad := a.Opaque()
	bad[0] = 8
	if _, e = b.Eval(0, anchorfilter.NewSCMPKeyShare(bad, share.BitShare{}), 0, 0); e == nil {
		t.Fatal("wrong native key shape")
	}
	u, p, q, e := aggregation.PreprocessComparison(1, b)
	if e != nil {
		t.Fatal(e)
	}
	uCopy, pCopy, qCopy := *u, *p, *q
	bound, e := u.Mask(63)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = uCopy.Mask(63); e == nil {
		t.Fatal("copied user mask reused")
	}
	x0, x1, e := incidence.Split(63)
	if e != nil {
		t.Fatal(e)
	}
	m0, e := p.Prepare([]incidence.Share{x0})
	if e != nil {
		t.Fatal(e)
	}
	m1, e := q.Prepare([]incidence.Share{x1})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pCopy.Prepare([]incidence.Share{x0}); e == nil {
		t.Fatal("copied comparison reused")
	}
	op, e := aggregation.OpenComparison(m0, m1)
	if e != nil {
		t.Fatal(e)
	}
	r0, e := p.Finish(op, bound, b)
	if e != nil {
		t.Fatal(e)
	}
	r1, e := q.Finish(op, bound, b)
	if e != nil {
		t.Fatal(e)
	}
	if bool(r0[0].Value()) == bool(r1[0].Value()) {
		t.Fatal("equality boundary")
	}
	if _, e = qCopy.Finish(op, bound, b); e == nil {
		t.Fatal("copied key reused")
	}
}

func TestNativeConcurrentDealer(t *testing.T) {
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := scmpnative.Backend{}
			for i := 0; i < 64; i++ {
				var r [2]byte
				if _, e := rand.Read(r[:]); e != nil {
					t.Error(e)
					return
				}
				rx, ry := uint32(r[0]&127), uint32(r[1]&127)
				a, c, e := b.KeyGen(7, rx, ry, domain.BitOne)
				if e != nil {
					t.Error(e)
					return
				}
				x, y := uint32(i), uint32(63-i)
				u, e := b.Eval(0, a, (x+rx)&127, (y+ry)&127)
				if e != nil {
					t.Error(e)
					return
				}
				v, e := b.Eval(1, c, (x+rx)&127, (y+ry)&127)
				if e != nil {
					t.Error(e)
					return
				}
				// Raw result includes the one-bit output mask.
				if (bool(u.Value()) != bool(v.Value())) == (x >= y) {
					t.Errorf("concurrent keygen x=%d y=%d", x, y)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestNativePositionBatchSingleUse(t *testing.T) {
	backend := scmpnative.Backend{}
	u, a, b, e := anchorfilter.Preprocess(63, 7, backend)
	if e != nil {
		t.Fatal(e)
	}
	_, l, r, e := u.ConsumeBounds(12, 1, 62)
	if e != nil {
		t.Fatal(e)
	}
	q := anchorfilter.PartyQuery{PID: u.PID, Ltilde: l, RplusTilde: r}
	opened := anchorfilter.OpenedPositions{PL: make([]uint32, 63), PR: make([]uint32, 63)}
	for i := range opened.PL {
		opened.PL[i] = (uint32(i) + a.RhoL[i] + b.RhoL[i]) & 127
		opened.PR[i] = (uint32(i) + a.RhoR[i] + b.RhoR[i]) & 127
	}
	x, e := anchorfilter.EvalPosition(0, q, a, opened, backend)
	if e != nil {
		t.Fatal(e)
	}
	y, e := anchorfilter.EvalPosition(1, q, b, opened, backend)
	if e != nil {
		t.Fatal(e)
	}
	for i := range x {
		if (bool(x[i].Value()) != bool(y[i].Value())) != (i >= 11 && i <= 13) {
			t.Fatal("position boundary", i)
		}
	}
	if _, e = anchorfilter.EvalPosition(0, q, a, opened, backend); e == nil {
		t.Fatal("position keys reused")
	}
}
