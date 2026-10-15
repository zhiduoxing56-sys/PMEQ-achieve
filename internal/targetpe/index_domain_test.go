package targetpe

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"pmeq/internal/aggregation"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetartifact"
	"pmeq/internal/targetcrypto"
)

func TestLoadActualDomain(t *testing.T) {
	meta, a, _, stats, e := indexbuild.BuildFinalTarget(nil, targetcrypto.MasterKey{})
	must(t, e)
	m, e := indexbuild.NewTargetManifest([16]byte{1}, meta, stats.Target)
	must(t, e)
	var ps bytes.Buffer
	must(t, indexbuild.WriteTargetParty(&ps, m, 0, a))
	h := sha256.Sum256(ps.Bytes())
	m.PartyBytes[0], m.PartySHA256[0] = uint64(ps.Len()), hex.EncodeToString(h[:])
	mr, e := json.Marshal(m)
	must(t, e)
	for _, n := range []int{0, 1, 7, 120071} {
		payload := aggregation.PartyPayload{LayoutID: [16]byte{2}, Slots: make([]aggregation.PayloadShare, n)}
		var pb bytes.Buffer
		must(t, targetartifact.WritePayload(&pb, m, 0, payload))
		h := sha256.Sum256(pb.Bytes())
		pm := PayloadManifest{IndexID: m.IndexID, LayoutID: payload.LayoutID, TargetBucketBits: 16, N: n}
		pm.Bytes[0], pm.SHA256[0] = int64(pb.Len()), hex.EncodeToString(h[:])
		l := AlignmentLineage{pm.IndexID, pm.LayoutID, n}
		load := func(pm PayloadManifest, l AlignmentLineage, raw []byte) (*PartyIndex, error) {
			pr, e := json.Marshal(pm)
			must(t, e)
			return Load(bytes.NewReader(mr), bytes.NewReader(pr), bytes.NewReader(ps.Bytes()), bytes.NewReader(raw), 0, l)
		}
		idx, e := load(pm, l, pb.Bytes())
		must(t, e)
		if idx.Lineage().N != n || pb.Len() != 46+42*n {
			t.Fatal("N", n)
		}
		wrong := l
		wrong.N++
		if _, e := load(pm, wrong, pb.Bytes()); e == nil {
			t.Fatal("lineage mismatch")
		}
		bad := append([]byte(nil), pb.Bytes()...)
		binary.LittleEndian.PutUint32(bad[42:], uint32(n+1))
		badPM := pm
		hash := sha256.Sum256(bad)
		badPM.SHA256[0] = hex.EncodeToString(hash[:])
		if _, e := load(badPM, l, bad); e == nil {
			t.Fatal("header mismatch")
		}
		wrongPM := pm
		wrongPM.N++
		wrong = l
		wrong.N++
		if _, e := load(wrongPM, wrong, pb.Bytes()); e == nil {
			t.Fatal("manifest/header mismatch")
		}
		wrongPM = pm
		wrongPM.Bytes[0]++
		if _, e := load(wrongPM, l, pb.Bytes()); e == nil {
			t.Fatal("byte count")
		}
		if _, e := load(pm, l, pb.Bytes()[:pb.Len()-1]); e == nil {
			t.Fatal("truncated payload")
		}
	}
}
