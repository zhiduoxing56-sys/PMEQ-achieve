package gen

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"pmeq/internal/indexbuild"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetcrypto"
)

func TestMovieMultiplicityAndD26Coordinates(t *testing.T) {
	tk, _ := targetcrypto.NewMasterKey([32]byte{2})
	for _, repetitions := range []int{4, 5} {
		aliases := []indexbuild.AreaAliasRecord{{ID: 1, Area: 99, Name: strings.Repeat("a", repetitions+3)}}
		meta, a, b, stats, err := indexbuild.BuildMovieTarget(aliases, tk)
		if err != nil {
			t.Fatal(err)
		}
		m, err := indexbuild.NewTargetManifest([16]byte{1}, meta, stats.Target)
		if err != nil {
			t.Fatal(err)
		}
		var files [2]bytes.Buffer
		for u, idx := range []indexbuild.PartyIndex{a, b} {
			if err = indexbuild.WriteTargetParty(&files[u], m, uint8(u), idx); err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(files[u].Bytes())
			m.PartySHA256[u], m.PartyBytes[u] = hex.EncodeToString(h[:]), uint64(files[u].Len())
		}
		manifest, _ := json.Marshal(m)
		var out [2]bytes.Buffer
		writers := [2]io.Writer{&out[0], &out[1]}
		sm, audit, err := BuildWithCapacity(manifest, [2][]byte{files[0].Bytes(), files[1].Bytes()}, aliases, writers, 26)
		if repetitions == 5 {
			if err == nil || audit.MaxMultiplicity != 5 {
				t.Fatalf("five repeats accepted: %+v %v", audit, err)
			}
			continue
		}
		if err != nil || audit.MaxMultiplicity != 4 || sm.MaxMultiplicity != 4 || sm.DTarget != 26 {
			t.Fatalf("four repeats rejected: %+v %+v %v", sm, audit, err)
		}
		read := func(raw []byte) ([]byte, []uint64) {
			r := bytes.NewReader(raw[57:])
			for bucket := 0; bucket < 1<<16; bucket++ {
				var n, width uint32
				if binary.Read(r, binary.LittleEndian, &n) != nil {
					t.Fatal("short sidecar")
				}
				if n == 0 {
					continue
				}
				if n != 1 || binary.Read(r, binary.LittleEndian, &width) != nil || width != 4 {
					t.Fatal("unexpected group layout")
				}
				coeff := make([]byte, 26*width)
				if _, err := io.ReadFull(r, coeff); err != nil {
					t.Fatal(err)
				}
				ids := make([]uint64, 26)
				for j := range ids {
					if binary.Read(r, binary.LittleEndian, &ids[j]) != nil {
						t.Fatal("short IDs")
					}
				}
				return coeff, ids
			}
			t.Fatal("missing target group")
			return nil, nil
		}
		c0, ids0 := read(out[0].Bytes())
		c1, ids1 := read(out[1].Bytes())
		for col := 0; col < 4; col++ {
			for row := 0; row < 26; row++ {
				want := byte(0)
				if row == 0 {
					want = 1
				}
				if (c0[col*26+row]+c1[col*26+row])&127 != want {
					t.Fatalf("matrix local coordinate col=%d row=%d", col, row)
				}
			}
		}
		for row := 0; row < 26; row++ {
			want := uint64(0)
			if row == 0 {
				want = 1
			}
			if ids0[row]+ids1[row] != want {
				t.Fatalf("target ordinal %d", row)
			}
		}
		if targetaggregation.MaxMultiplicity != 4 {
			t.Fatal("protocol multiplicity contract")
		}
	}
}
