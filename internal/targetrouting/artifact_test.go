package targetrouting

import (
	"bytes"
	"encoding/json"
	"pmeq/internal/indexbuild"
	"testing"
)

func TestProductionManifestWidth(t *testing.T) {
	m := indexbuild.TargetManifest{Version: 1, IndexID: [16]byte{3}, Q: 4, AnchorBucketBits: 16, TargetBucketBits: 16, Tiers: [8]uint32{4, 16, 64, 256, 1024, 4096, 8192, 16384}}
	raw, _ := json.Marshal(m)
	bound, e := LoadIndex(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	if bound.TokenManifest().TargetBucketBits != 16 {
		t.Fatal("width")
	}
	for _, bits := range []uint8{8, 10, 12, 14, 15} {
		m.TargetBucketBits = bits
		raw, _ = json.Marshal(m)
		if _, e = LoadIndex(bytes.NewReader(raw)); e == nil {
			t.Fatal("nonfinal manifest accepted", bits)
		}
	}
	if _, _, e = (BoundIndex{}).Prepare(0, Candidates{}, QueryToken{}, 1); e == nil {
		t.Fatal("zero binding")
	}
}
