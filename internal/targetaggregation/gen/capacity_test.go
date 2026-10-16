package gen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"pmeq/internal/anchorindex"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetcrypto"
	"testing"
)

func TestPublicCoordinateCapacity(t *testing.T) {
	ak, e := anchorindex.NewKey([32]byte{1})
	if e != nil {
		t.Fatal(e)
	}
	tk, e := targetcrypto.NewMasterKey([32]byte{2})
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ d, n int }{{1, 1}, {1, 2}, {16, 16}, {16, 17}} {
		n := tc.n
		aliases := make([]indexbuild.AreaAliasRecord, n)
		for i := range aliases {
			aliases[i] = indexbuild.AreaAliasRecord{ID: uint64(i + 1), Area: 99, Name: "abcdabcd"}
		}
		meta, a, b, stats, e := indexbuild.Build(nil, aliases, ak, tk, 16, 16)
		if e != nil {
			t.Fatal(e)
		}
		var out [2]bytes.Buffer
		m, e := indexbuild.NewTargetManifest([16]byte{1}, meta, stats.Target)
		if e != nil {
			t.Fatal(e)
		}
		for u, idx := range []indexbuild.PartyIndex{a, b} {
			if e = indexbuild.WriteTargetParty(&out[u], m, uint8(u), idx); e != nil {
				t.Fatal(e)
			}
			h := sha256.Sum256(out[u].Bytes())
			m.PartySHA256[u] = hex.EncodeToString(h[:])
			m.PartyBytes[u] = uint64(out[u].Len())
		}
		mr, e := json.Marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		sm, audit, e := BuildWithCapacity(mr, [2][]byte{out[0].Bytes(), out[1].Bytes()}, aliases, [2]io.Writer{io.Discard, io.Discard}, tc.d)
		if n > tc.d {
			if e == nil {
				t.Fatalf("D=%d overflow silently accepted", tc.d)
			}
		} else if e != nil || sm.DTarget != uint32(tc.d) || audit.MaxAliases != tc.d {
			t.Fatal(sm, audit, e)
		}
	}
}
