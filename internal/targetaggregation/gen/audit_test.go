package gen

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"sort"
	"testing"

	"pmeq/internal/indexbuild"
)

// Independently read EVERY emitted coefficient and ID payload. This test
// reconstructs only inside the trusted offline oracle, never a party loader.
func TestEverySidecarCoefficientAndPayload(t *testing.T) {
	dir := "../../../artifacts/phase10b/"
	a, e := os.Open(dir + "cs0.aggregation.bin")
	if os.IsNotExist(e) {
		t.Skip("generate offline sidecars first")
	}
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := os.Open(dir + "cs1.aggregation.bin")
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	r := [2]*bufio.Reader{bufio.NewReader(a), bufio.NewReader(b)}
	for _, p := range r {
		if _, e = io.CopyN(io.Discard, p, 57); e != nil {
			t.Fatal(e)
		}
	}
	mr, e := os.ReadFile("../../../artifacts/phase7b/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	m, e := indexbuild.ReadTargetManifest(bytes.NewReader(mr))
	if e != nil {
		t.Fatal(e)
	}
	var idx [2]indexbuild.PartyIndex
	var bs [2][65536][]indexbuild.TargetPartyGroup
	for u, name := range []string{"cs0.psmj.bin", "cs1.psmj.bin"} {
		f, e := os.Open("../../../artifacts/phase7b/" + name)
		if e != nil {
			t.Fatal(e)
		}
		idx[u], e = indexbuild.ReadTargetParty(f, m, uint8(u))
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
		for _, b := range idx[u].TargetBuckets {
			bs[u][b.BucketID] = b.Groups
		}
	}
	f, e := os.Open("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area_alias")
	if e != nil {
		t.Fatal(e)
	}
	aliases, e := indexbuild.LoadAreaAlias(f, 0)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	joins := map[uint64][]uint64{}
	joinOf := map[uint64]uint64{}
	ord := map[uint64]int{}
	for _, a := range aliases {
		joins[a.Area] = append(joins[a.Area], a.ID)
		joinOf[a.ID] = a.Area
	}
	for _, ids := range joins {
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for i, id := range ids {
			ord[id] = i
		}
	}
	coeffs, payloads := 0, 0
	var hist [2][128]int
	for bi := 0; bi < 65536; bi++ {
		gs := bs[0][bi]
		nslots := 0
		for _, p := range r {
			var n uint32
			if e = binary.Read(p, binary.LittleEndian, &n); e != nil || int(n) != len(gs) {
				t.Fatal("group count", bi, e)
			}
			for _, g := range gs {
				var width uint32
				if e = binary.Read(p, binary.LittleEndian, &width); e != nil || width != g.PadWidth {
					t.Fatal("width", bi, e)
				}
			}
		}
		for _, g := range gs {
			nslots += int(g.PadWidth)
		}
		var local [2][]byte
		for u, p := range r {
			local[u] = make([]byte, nslots*26)
			if _, e = io.ReadFull(p, local[u]); e != nil {
				t.Fatal(e)
			}
		}
		slot := 0
		groupJoin := make([]uint64, len(gs))
		for gi, g := range gs {
			for si, s := range g.Slots {
				peer := bs[1][bi][gi].Slots[si]
				valid := bool(s.ValidityShare.Value().Add(peer.ValidityShare.Value()))
				id := uint64(s.RecordIDShare.Value() + peer.RecordIDShare.Value())
				if valid {
					groupJoin[gi] = joinOf[id]
				}
				for u := 0; u < 26; u++ {
					at := slot*26 + u
					want := byte(0)
					if valid && ord[id] == u {
						want = 1
					}
					x, y := local[0][at], local[1][at]
					if x > 127 || y > 127 || (x+y)&127 != want {
						t.Fatal("incidence", bi, gi, si, u)
					}
					hist[0][x]++
					hist[1][y]++
					coeffs++
				}
				slot++
			}
		}
		for gi := range gs {
			ids := joins[groupJoin[gi]]
			for u := 0; u < 26; u++ {
				var x, y uint64
				if e = binary.Read(r[0], binary.LittleEndian, &x); e != nil {
					t.Fatal(e)
				}
				if e = binary.Read(r[1], binary.LittleEndian, &y); e != nil {
					t.Fatal(e)
				}
				want := uint64(0)
				if u < len(ids) {
					want = ids[u]
				}
				if x+y != want {
					t.Fatal("payload", bi, gi, u)
				}
				payloads++
			}
		}
	}
	for _, p := range r {
		if _, e = p.ReadByte(); e != io.EOF {
			t.Fatal("trailing bytes")
		}
	}
	for _, h := range hist {
		for _, n := range h {
			if n == 0 {
				t.Fatal("missing mask marginal")
			}
		}
	}
	if coeffs != 34248760 || payloads != 8068606 {
		t.Fatal(coeffs, payloads)
	}
	t.Logf("all coefficients=%d all Ring64 payloads=%d reconstructed correctly; both parties all 128 marginals present", coeffs, payloads)
}
