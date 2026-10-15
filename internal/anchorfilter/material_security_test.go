package anchorfilter

import (
	"pmeq/internal/material"
	"testing"
)

func TestCopiedUserMaskAndPositionKeysCannotRepeat(t *testing.T) {
	u, a, b, e := Preprocess(2, 7, referenceSCMP{})
	if e != nil {
		t.Fatal(e)
	}
	copyU := u
	_, l, r, e := u.ConsumeBounds(0, 0, 62)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = copyU.ConsumeBounds(0, 0, 62); e == nil {
		t.Fatal("copied query mask reused")
	}
	// Differential test backend here is only the unit oracle; native tests separately execute real keys.
	q := PartyQuery{PID: u.PID, Ltilde: l, RplusTilde: r}
	opened := OpenedPositions{PL: []uint32{0}, PR: []uint32{0}}
	first := a
	first.Lower = a.Lower[:1]
	first.Upper = a.Upper[:1]
	if _, e = EvalPosition(0, q, first, opened, referenceSCMP{}); e != nil {
		t.Fatal(e)
	}
	if _, e = EvalPosition(0, q, first, opened, referenceSCMP{}); e == nil {
		t.Fatal("copied position key reused")
	}
	next := a
	next.Lower = a.Lower[1:]
	next.Upper = a.Upper[1:]
	if _, e = EvalPosition(0, q, next, opened, referenceSCMP{}); e != nil {
		t.Fatal("fresh sliced keys rejected", e)
	}
	if b.Lower[0].use == a.Lower[0].use || b.Lower[0].use == (*material.UseGuard)(nil) {
		t.Fatal("peer use guard shared")
	}
}
