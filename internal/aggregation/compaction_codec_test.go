package aggregation

import (
	"bytes"
	"pmeq/internal/targetcrypto"
	"testing"
)

func TestCompactionMessageCodecs(t *testing.T) {
	for _, n := range []int{0, 1, 37} {
		a, b := testCompactInput(t, n, n/2)
		p, q, e := PreprocessCompaction(a.LayoutID, n)
		must(t, e)
		m, e := q.Begin(b)
		must(t, e)
		raw := m.Encode()
		if len(raw) != 37+43*n {
			t.Fatal("shuffle bytes")
		}
		v, e := DecodeShuffle(raw)
		must(t, e)
		if !bytes.Equal(raw, v.Encode()) {
			t.Fatal("shuffle roundtrip")
		}
		must(t, p.Stage1(a, v))
		m, e = p.BeginStage2()
		must(t, e)
		v, e = DecodeShuffle(m.Encode())
		must(t, e)
		must(t, q.Stage2(v))
		k0, e := p.OpenKeep()
		must(t, e)
		k1, e := q.OpenKeep()
		must(t, e)
		x0, e := DecodeKeepOpening(k0.Encode())
		must(t, e)
		x1, e := DecodeKeepOpening(k1.Encode())
		must(t, e)
		out0, e := p.Extract(x1)
		must(t, e)
		out1, e := q.Extract(x0)
		must(t, e)
		verifyCompaction(t, a, b, out0, out1)
		if _, e = DecodeShuffle(raw[:len(raw)-1]); e == nil {
			t.Fatal("truncated")
		}
		bad := append([]byte(nil), raw...)
		bad[32] = 0
		if _, e = DecodeShuffle(bad); e == nil {
			t.Fatal("stage")
		}
		kb := k0.Encode()
		kb[32] = 2
		if _, e = DecodeKeepOpening(kb); e == nil {
			t.Fatal("party")
		}
	}
}

func TestCompactionMessageCodec17Bits(t *testing.T) {
	const n = 37
	a, b := testCompactInput(t, n, 18)
	for i := 0; i < n; i++ {
		var e error
		a.Payload[i].BucketJoinShare, b.Payload[i].BucketJoinShare, e = targetcrypto.SplitBucketComponent(targetcrypto.BucketComponent(0x10000+i*79), 17)
		must(t, e)
	}
	p, q, e := PreprocessCompactionWithBucketBits(a.LayoutID, n, 17)
	must(t, e)
	m, e := q.Begin(b)
	must(t, e)
	raw := m.Encode()
	if len(raw) != 37+45*n || raw[32] != 0x81 {
		t.Fatal("17-bit shuffle framing")
	}
	v, e := DecodeShuffleForDomain(raw, n)
	must(t, e)
	if !bytes.Equal(raw, v.Encode()) {
		t.Fatal("17-bit shuffle roundtrip")
	}
	must(t, p.Stage1(a, v))
	m, e = p.BeginStage2()
	must(t, e)
	v, e = DecodeShuffleForDomain(m.Encode(), n)
	must(t, e)
	must(t, q.Stage2(v))
	k0, e := p.OpenKeep()
	must(t, e)
	k1, e := q.OpenKeep()
	must(t, e)
	x, e := p.Extract(k1)
	must(t, e)
	y, e := q.Extract(k0)
	must(t, e)
	verifyCompaction(t, a, b, x, y)
}
