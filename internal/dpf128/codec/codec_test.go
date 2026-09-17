package codec_test

import (
	"bytes"
	"pmeq/internal/dpf128"
	"pmeq/internal/dpf128/codec"
	"pmeq/internal/dpf128/gen"
	"testing"
)

func TestKeyCodec(t *testing.T) {
	for n := 0; n < 10; n++ {
		var p dpf128.Point
		p[n] = byte(n + 1)
		a, b, e := gen.Gen(p)
		if e != nil {
			t.Fatal(e)
		}
		for _, k := range []dpf128.Key{a, b} {
			raw := codec.EncodeKey(k)
			q, e := codec.DecodeKey(raw)
			if e != nil || !bytes.Equal(raw, codec.EncodeKey(q)) {
				t.Fatal("roundtrip", e)
			}
			for i := 0; i < 10; i++ {
				var x dpf128.Point
				x[i] = byte(i + 1)
				if dpf128.Eval(k, x) != dpf128.Eval(q, x) {
					t.Fatal("evaluation")
				}
			}
			if _, e = codec.DecodeKey(raw[:len(raw)-1]); e == nil {
				t.Fatal("size")
			}
			raw[16] = 2
			if _, e = codec.DecodeKey(raw); e == nil {
				t.Fatal("bit")
			}
		}
	}
}
