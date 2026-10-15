package imdbowner

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"pmeq/internal/aggregation"
	"pmeq/internal/discovery"
	"pmeq/internal/imdbkeys"
	"pmeq/internal/imdbprod"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetartifact"
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

func TestPrivateTargetAndRepresentativeAnchorCloudAssembly(t *testing.T) {
	targetRoot := os.Getenv("PMEQ_IMDB_TARGET_STAGE")
	if targetRoot == "" {
		t.Skip("set PMEQ_IMDB_TARGET_STAGE to the local sealed target stage")
	}
	gate, err := CheckProduction("../../imdb_production_20261015", "../../.private/imdb-production-keypair.json", "../../.private/imdb-key-backup-receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	seal, err := VerifyTargetStage(targetRoot, gate.Freeze, gate.Keys)
	if err != nil {
		t.Fatal(err)
	}
	areas, joins, _, err := gate.Mapping.IndexInputs()
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]uint64, len(areas))
	for i := range areas {
		ids[i] = areas[i].ID
	}
	var payloads [2]aggregation.PartyPayload
	for party := uint8(0); party < 2; party++ {
		f, err := os.Open(filepath.Join(targetRoot, "cs"+string(rune('0'+party))+".payload.bin"))
		if err != nil {
			t.Fatal(err)
		}
		payloads[party], err = targetartifact.ReadPayload(f, seal.Target, party, seal.Binding.LayoutID, imdbprod.AnchorObjects)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	dealer, err := aggregation.RestoreDealerLayoutFromPayload(ids, payloads[0], payloads[1])
	if err != nil {
		t.Fatal(err)
	}
	small := gate.Layout.Metadata.AnchorBuckets[0]
	for _, meta := range gate.Layout.Metadata.AnchorBuckets {
		if meta.TotalSlots < small.TotalSlots {
			small = meta
		}
	}
	root := t.TempDir()
	if err = os.Symlink(targetRoot, filepath.Join(root, "target")); err != nil {
		t.Fatal(err)
	}
	w, err := discovery.NewMovieAnchorWriter(filepath.Join(root, "anchor"), seal.Binding)
	if err != nil {
		t.Fatal(err)
	}
	n, err := discovery.WriteMovieAnchorBuckets(w, areas, joins, gate.Keys.Anchor, gate.Keys.Target, dealer,
		func(id uint32) bool { return id == small.BucketID }, nil)
	if err != nil || n != 1 {
		w.Close()
		t.Fatalf("representative bucket build: n=%d err=%v", n, err)
	}
	digest, err := w.Seal([]indexbuild.BucketMetadata{small})
	w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writeProductionSeal(root, seal, digest, 1); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "production-seal.json"))
	if err != nil {
		t.Fatal(err)
	}
	for party := uint8(0); party < 2; party++ {
		cloudRoot := filepath.Join(t.TempDir(), "cloud")
		if err = ExportParty(root, party, cloudRoot, sha256.Sum256(raw)); err != nil {
			t.Fatal(err)
		}
		prefix := "cs" + string(rune('0'+party))
		other := "cs" + string(rune('0'+1-party))
		if _, err = os.Lstat(filepath.Join(cloudRoot, "target", other+".psmj.bin")); !os.IsNotExist(err) {
			t.Fatal("peer target index was exported")
		}
		if _, err = os.Lstat(filepath.Join(cloudRoot, "anchor", other)); !os.IsNotExist(err) {
			t.Fatal("peer anchor directory was exported")
		}
		if _, err = os.Stat(filepath.Join(cloudRoot, "anchor", prefix)); err != nil {
			t.Fatal(err)
		}
		var packageBytes int64
		if err = filepath.WalkDir(cloudRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type().IsRegular() {
				info, e := entry.Info()
				if e != nil {
					return e
				}
				packageBytes += info.Size()
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		t.Logf("party=%d exported_bytes=%d", party, packageBytes)
		st, err := OpenParty(cloudRoot, party, sha256.Sum256(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err = st.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if st, err := OpenParty(root, 0, [32]byte{1}); err == nil {
		st.Close()
		t.Fatal("wrong publication hash accepted")
	}
}
