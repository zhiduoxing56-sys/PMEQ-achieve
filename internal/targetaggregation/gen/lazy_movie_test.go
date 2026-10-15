package gen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"pmeq/internal/aggregation"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetartifact"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetpe"
)

func TestMovieTargetLazySidecarAndCorruption(t *testing.T) {
	key, err := targetcrypto.NewMasterKey([32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	movies := []indexbuild.AreaAliasRecord{{ID: 99, Area: 99, Name: "aaaaaaa"}}
	meta, p0, p1, stats, err := indexbuild.BuildMovieTarget(movies, key)
	if err != nil {
		t.Fatal(err)
	}
	m, err := indexbuild.NewTargetManifest([16]byte{1}, meta, stats.Target)
	if err != nil {
		t.Fatal(err)
	}
	var ps [2][]byte
	for i, p := range []indexbuild.PartyIndex{p0, p1} {
		var b bytes.Buffer
		if err = indexbuild.WriteTargetParty(&b, m, uint8(i), p); err != nil {
			t.Fatal(err)
		}
		ps[i] = b.Bytes()
		h := sha256.Sum256(ps[i])
		m.PartyBytes[i] = uint64(len(ps[i]))
		m.PartySHA256[i] = hex.EncodeToString(h[:])
	}
	mr, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	_, pa, pb, err := aggregation.GeneratePayloadWithJoins([]uint64{1}, []uint64{99}, key, 16)
	if err != nil {
		t.Fatal(err)
	}
	pm := targetpe.PayloadManifest{IndexID: m.IndexID, LayoutID: pa.LayoutID, TargetBucketBits: 16, N: 1}
	var payload [2][]byte
	for i, p := range []aggregation.PartyPayload{pa, pb} {
		var b bytes.Buffer
		if err = targetartifact.WritePayload(&b, m, uint8(i), p); err != nil {
			t.Fatal(err)
		}
		payload[i] = b.Bytes()
		h := sha256.Sum256(payload[i])
		pm.Bytes[i] = int64(len(payload[i]))
		pm.SHA256[i] = hex.EncodeToString(h[:])
	}
	pr, err := json.Marshal(pm)
	if err != nil {
		t.Fatal(err)
	}
	var side [2]bytes.Buffer
	sm, _, err := BuildWithCapacity(mr, ps, movies, [2]io.Writer{&side[0], &side[1]}, 26)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := targetpe.Load(bytes.NewReader(mr), bytes.NewReader(pr), bytes.NewReader(ps[0]), bytes.NewReader(payload[0]), 0, targetpe.AlignmentLineage{IndexID: m.IndexID, LayoutID: pa.LayoutID, N: 1})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cs0.aggregation.bin")
	if err = os.WriteFile(path, side[0].Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	lazy, err := targetaggregation.OpenSidecarLazy(sm, mr, idx, path)
	if err != nil {
		t.Fatal(err)
	}
	if lazy.Capacity() != 26 || lazy.Multiplicity() != 4 {
		t.Fatal("movie sidecar domain")
	}
	if err = lazy.Close(); err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), side[0].Bytes()...)
	raw[len(raw)-1] ^= 1
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = targetaggregation.OpenSidecarLazy(sm, mr, idx, path); err == nil {
		t.Fatal("corrupt sidecar accepted")
	}
}
