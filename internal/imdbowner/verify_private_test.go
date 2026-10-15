package imdbowner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"pmeq/internal/imdbkeys"
	"pmeq/internal/imdbprod"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetpe"
)

// This integration check is opt-in because it reads the ignored production
// target stage and copies one ciphertext share file to a temporary directory.
func TestPrivateTargetStageRoleAndCorruption(t *testing.T) {
	root := os.Getenv("PMEQ_IMDB_TARGET_STAGE")
	if root == "" {
		t.Skip("set PMEQ_IMDB_TARGET_STAGE to the local sealed target stage")
	}
	_, freeze, err := imdbprod.LoadFrozen("../../imdb_production_20261015")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := imdbkeys.Load("../../.private/imdb-production-keypair.json")
	if err != nil {
		t.Fatal(err)
	}
	seal, err := VerifyTargetStage(root, freeze, keys)
	if err != nil {
		t.Fatal(err)
	}
	badKeys := keys
	badKeys.Fingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := VerifyTargetStage(root, freeze, badKeys); err == nil {
		t.Fatal("wrong key identity accepted")
	}
	mRaw, err := os.ReadFile(filepath.Join(root, "target-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	pRaw, err := os.ReadFile(filepath.Join(root, "payload-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	index, err := os.Open(filepath.Join(root, "cs0.psmj.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()
	payload, err := os.Open(filepath.Join(root, "cs0.payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer payload.Close()
	idx, err := targetpe.Load(bytes.NewReader(mRaw), bytes.NewReader(pRaw), index, payload, 0,
		targetpe.AlignmentLineage{IndexID: seal.Binding.IndexID, LayoutID: seal.Binding.LayoutID, N: imdbprod.AnchorObjects})
	if err != nil {
		t.Fatal(err)
	}
	if side, err := targetaggregation.OpenSidecarLazy(seal.Sidecar, mRaw, idx, filepath.Join(root, "cs1.aggregation.bin")); err == nil {
		side.Close()
		t.Fatal("other party's matrix accepted")
	}
	badVersion := seal.Sidecar
	badVersion.MaxMultiplicity--
	if side, err := targetaggregation.OpenSidecarLazy(badVersion, mRaw, idx, filepath.Join(root, "cs0.aggregation.bin")); err == nil {
		side.Close()
		t.Fatal("old matrix multiplicity accepted")
	}
	source, err := os.ReadFile(filepath.Join(root, "cs0.aggregation.bin"))
	if err != nil {
		t.Fatal(err)
	}
	source[len(source)-1] ^= 1
	corrupt := filepath.Join(t.TempDir(), "corrupt.aggregation.bin")
	if err := os.WriteFile(corrupt, source, 0600); err != nil {
		t.Fatal(err)
	}
	if side, err := targetaggregation.OpenSidecarLazy(seal.Sidecar, mRaw, idx, corrupt); err == nil {
		side.Close()
		t.Fatal("damaged matrix accepted")
	}
}
