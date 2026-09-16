package targetartifact

import (
	"bytes"
	"pmeq/internal/aggregation"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetcrypto"
	"reflect"
	"testing"
)

func TestPayloadCodecBinding(t *testing.T) {
	kt, e := targetcrypto.NewMasterKey([32]byte{1})
	must(t, e)
	_, a, b, e := aggregation.GeneratePayload([]uint64{1, 2, 3}, kt, 16)
	must(t, e)
	m := indexbuild.TargetManifest{Version: 1, IndexID: [16]byte{1}, Q: 4, AnchorBucketBits: 16, TargetBucketBits: 16, Tiers: [8]uint32{4, 16, 64, 256, 1024, 4096, 8192, 16384}}
	for u, p := range []aggregation.PartyPayload{a, b} {
		var buf bytes.Buffer
		must(t, WritePayload(&buf, m, uint8(u), p))
		raw := buf.Bytes()
		if len(raw) != PayloadHeaderBytes+42*3 {
			t.Fatal("bytes")
		}
		got, e := ReadPayload(bytes.NewReader(raw), m, uint8(u), p.LayoutID, 3)
		must(t, e)
		if !reflect.DeepEqual(got, p) {
			t.Fatal("roundtrip")
		}
		if _, e = ReadPayload(bytes.NewReader(raw), m, uint8(1-u), p.LayoutID, 3); e == nil {
			t.Fatal("party")
		}
		if _, e = ReadPayload(bytes.NewReader(raw), m, uint8(u), [16]byte{8}, 3); e == nil {
			t.Fatal("layout")
		}
		if _, e = ReadPayload(bytes.NewReader(raw), m, uint8(u), p.LayoutID, 4); e == nil {
			t.Fatal("count")
		}
		for _, v := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 0)} {
			if _, e = ReadPayload(bytes.NewReader(v), m, uint8(u), p.LayoutID, 3); e == nil {
				t.Fatal("malformed")
			}
		}
		bad := m
		bad.TargetBucketBits = 8
		if _, e = ReadPayload(bytes.NewReader(raw), bad, uint8(u), p.LayoutID, 3); e == nil {
			t.Fatal("width")
		}
	}
}
