package f2beaver

import (
	"pmeq/internal/domain"
	"pmeq/internal/share"
	"testing"
)

func TestPackedScalarDifferential(t *testing.T) {
	const n = 1600
	a, b, e := PreprocessPacked(n)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < n; i++ {
		x0, x1, y0, y1 := uint64(i)*0x9e3779b97f4a7c15, uint64(i+1)*0x123456789abcdef, uint64(i+2)*0xd6e8feb86659fd93, ^uint64(i)
		d0, e0 := a.MaskAt(i, x0, y0)
		d1, e1 := b.MaskAt(i, x1, y1)
		d, e := d0^d1, e0^e1
		z0, z1 := a.FinishAt(0, i, d, e), b.FinishAt(1, i, d, e)
		if z0^z1 != (x0^x1)&(y0^y1) {
			t.Fatal("packed")
		}
		for lane := 0; lane < 64; lane++ {
			v := func(w uint64) share.BitShare { return share.NewBitShare(domain.Bit((w>>uint(lane))&1 == 1)) }
			p := PartyBatch{[]share.BitShare{v(a.a[i])}, []share.BitShare{v(a.b[i])}, []share.BitShare{v(a.c[i])}}
			q := PartyBatch{[]share.BitShare{v(b.a[i])}, []share.BitShare{v(b.b[i])}, []share.BitShare{v(b.c[i])}}
			o := Opened{[]domain.Bit{v(d).Value()}, []domain.Bit{v(e).Value()}}
			l, err := Finish(0, p, o)
			if err != nil {
				t.Fatal(err)
			}
			r, err := Finish(1, q, o)
			if err != nil {
				t.Fatal(err)
			}
			if l[0].Value() != v(z0).Value() || r[0].Value() != v(z1).Value() {
				t.Fatal("scalar differential")
			}
		}
	}
}
