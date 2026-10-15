//go:build phase6native

package scmpnative_test

import (
	"crypto/rand"
	"encoding/binary"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/scmpnative"
	"pmeq/internal/share"
	"testing"
)

func TestIMDbNativeTenBitCompletePlaintextDomain(t *testing.T) {
	b := scmpnative.Backend{}
	// Includes every pair of legal stored positions and the inclusive upper-bound+1.
	for x := uint32(0); x <= 271; x++ {
		for y := uint32(0); y <= 271; y++ {
			var raw [8]byte
			if _, e := rand.Read(raw[:]); e != nil {
				t.Fatal(e)
			}
			rx := binary.LittleEndian.Uint32(raw[:4]) & 1023
			ry := binary.LittleEndian.Uint32(raw[4:]) & 1023
			mask := domain.Bit((x+y)%2 != 0)
			a, c, e := b.KeyGen(10, rx, ry, mask)
			if e != nil {
				t.Fatal(e)
			}
			if len(a.Opaque()) != 368 || len(c.Opaque()) != 368 {
				t.Fatal("wrong key size")
			}
			u, e := b.Eval(0, a, (x+rx)&1023, (y+ry)&1023)
			if e != nil {
				t.Fatal(e)
			}
			v, e := b.Eval(1, c, (x+rx)&1023, (y+ry)&1023)
			if e != nil {
				t.Fatal(e)
			}
			got := (bool(u.Value()) != bool(v.Value())) != bool(mask)
			if got != (x >= y) {
				t.Fatalf("Bin10 x=%d y=%d masks=%d/%d", x, y, rx, ry)
			}
		}
	}
	// Explicit wrap/extreme masks and the conservative signed half-domain boundary.
	for _, pair := range [][2]uint32{{0, 511}, {511, 0}, {511, 511}, {270, 271}, {271, 270}, {0, 0}} {
		for _, masks := range [][2]uint32{{0, 0}, {1023, 1023}, {1023, 0}, {0, 1023}, {511, 512}} {
			a, c, e := b.KeyGen(10, masks[0], masks[1], domain.BitOne)
			if e != nil {
				t.Fatal(e)
			}
			u, e := b.Eval(0, a, (pair[0]+masks[0])&1023, (pair[1]+masks[1])&1023)
			if e != nil {
				t.Fatal(e)
			}
			v, e := b.Eval(1, c, (pair[0]+masks[0])&1023, (pair[1]+masks[1])&1023)
			if e != nil {
				t.Fatal(e)
			}
			if (bool(u.Value()) == bool(v.Value())) != (pair[0] >= pair[1]) {
				t.Fatal("extreme mask boundary", pair, masks)
			}
		}
	}
	t.Log("73984 complete-domain comparisons and 30 extreme-mask comparisons passed")
}

func TestIMDbTenBitPositionIntervalsAndBinding(t *testing.T) {
	b := scmpnative.Backend{}
	for _, q := range []int{3, 4, 5, 6} {
		uPos := uint32(273 - q)
		bin, e := anchorfilter.DeriveBin(uPos)
		if e != nil || bin != 10 {
			t.Fatal("position capacity", q, bin, e)
		}
		for _, p := range []uint32{0, 1, 62, 127, 239, uPos} {
			for _, tau := range []uint32{0, 1, 3} {
				u, a, c, e := anchorfilter.Preprocess(int(uPos)+1, 10, b)
				if e != nil {
					t.Fatal(e)
				}
				if u.EtaL > 1023 || u.EtaR > 1023 {
					t.Fatal("bound mask overflow")
				}
				pid, l, r, e := u.ConsumeBounds(p, tau, uPos)
				if e != nil {
					t.Fatal(e)
				}
				token := anchorfilter.PartyQuery{PID: pid, Ltilde: l, RplusTilde: r}
				opened := anchorfilter.OpenedPositions{PL: make([]uint32, int(uPos)+1), PR: make([]uint32, int(uPos)+1)}
				for i := range opened.PL {
					// Force Ring32 wrap before reduction; reduction to Z1024 must commute.
					s0 := share.NewRing32Share(domain.Ring32(0xfffffffe))
					s1 := share.NewRing32Share(domain.Ring32(uint32(i) - 0xfffffffe))
					x0, _ := anchorfilter.ReducePosition(s0, 10)
					x1, _ := anchorfilter.ReducePosition(s1, 10)
					opened.PL[i] = (x0 + x1 + a.RhoL[i] + c.RhoL[i]) & 1023
					opened.PR[i] = (x0 + x1 + a.RhoR[i] + c.RhoR[i]) & 1023
				}
				x, e := anchorfilter.EvalPosition(0, token, a, opened, b)
				if e != nil {
					t.Fatal(e)
				}
				y, e := anchorfilter.EvalPosition(1, token, c, opened, b)
				if e != nil {
					t.Fatal(e)
				}
				lo, hi := anchorfilter.Bounds(p, tau, uPos)
				for i := range x {
					if (bool(x[i].Value()) != bool(y[i].Value())) != (uint32(i) >= lo && uint32(i) <= hi) {
						t.Fatal("interval", q, p, tau, i)
					}
				}
				if _, _, _, e := u.ConsumeBounds(p, tau, uPos); e == nil {
					t.Fatal("token reused")
				}
			}
		}
	}
	u, _, _, e := anchorfilter.Preprocess(1, 7, b)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = u.ConsumeBounds(0, 0, 270); e == nil {
		t.Fatal("mixed comparison domains accepted")
	}
	for _, mask := range [][2]uint32{{1024, 0}, {0, 1024}} {
		if _, _, e := b.KeyGen(10, mask[0], mask[1], domain.BitZero); e == nil {
			t.Fatal("mask overflow accepted")
		}
	}
	a, _, e := b.KeyGen(10, 1023, 1023, domain.BitZero)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := b.Eval(0, a, 1024, 0); e == nil {
		t.Fatal("C ABI silently narrowed input")
	}
	for _, q := range []int{3, 4, 5, 6} {
		chunks, e := anchorfilter.QueryChunksWithQ("电影🎥abcdefghijklmnopqrstuv", q, 4)
		if e != nil || len(chunks) != 4 || chunks[3].Position != uint32(3*q) {
			t.Fatal("explicit q signature", q, e)
		}
	}
}
