package imdbowner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"pmeq/internal/aggregation"
	"pmeq/internal/discovery"
	"pmeq/internal/imdbprod"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetartifact"
	"pmeq/internal/targetpe"
)

type ProductionSeal struct {
	Version             string           `json:"version"`
	Binding             imdbprod.Binding `json:"binding"`
	TargetSealSHA256    string           `json:"target_seal_sha256"`
	AnchorCatalogSHA256 string           `json:"anchor_catalog_sha256"`
	AnchorBuckets       int              `json:"anchor_buckets"`
}

// BuildAnchorStage resumes the committed BS02 catalog using the same PL01
// global permutation and target-stage binding. Call it only after the explicit
// full-build authorization and resource gate; it visits all 53k real buckets.
func BuildAnchorStage(root string, gate Preflight) (ProductionSeal, error) {
	return BuildAnchorStageGuarded(root, gate, nil)
}

// BuildAnchorStageGuarded checks the owner's resource gate before each new
// bucket. A failed check leaves only previously committed catalog entries;
// the next authorized run authenticates those entries before resuming.
func BuildAnchorStageGuarded(root string, gate Preflight, resourceCheck func() error) (ProductionSeal, error) {
	var out ProductionSeal
	if gate.Mapping == nil || gate.Keys.Fingerprint == "" {
		return out, ErrBuild
	}
	if resourceCheck != nil {
		if err := resourceCheck(); err != nil {
			return out, err
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "production-seal.json")); err == nil {
		return VerifyProduction(root, gate)
	} else if !os.IsNotExist(err) {
		return out, err
	}
	targetRoot := filepath.Join(root, "target")
	seal, err := VerifyTargetStage(targetRoot, gate.Freeze, gate.Keys)
	if err != nil {
		return out, err
	}
	// A crash may occur after the catalog's complete marker but before the
	// production seal. Authenticate all committed files before adopting it.
	if catalogRaw, e := os.ReadFile(filepath.Join(root, "anchor", "catalog.json")); e == nil {
		digest := sha256.Sum256(catalogRaw)
		if verifyAnchorCatalog(filepath.Join(root, "anchor"), seal.Binding, digest, gate.Layout.Metadata.AnchorBuckets) == nil {
			return writeProductionSeal(root, seal, digest, len(gate.Layout.Metadata.AnchorBuckets))
		}
	}
	var payloads [2]aggregation.PartyPayload
	for party := uint8(0); party < 2; party++ {
		f, e := os.Open(filepath.Join(targetRoot, "cs"+string(rune('0'+party))+".payload.bin"))
		if e != nil {
			return out, e
		}
		h := sha256.New()
		payloads[party], e = targetartifact.ReadPayload(io.TeeReader(f, h), seal.Target, party, seal.Binding.LayoutID, imdbprod.AnchorObjects)
		f.Close()
		if e != nil {
			return out, e
		}
		if hex.EncodeToString(h.Sum(nil)) != seal.Payload.SHA256[party] {
			return out, ErrBuild
		}
	}
	areas, joins, _, err := gate.Mapping.IndexInputs()
	if err != nil {
		return out, err
	}
	ids := make([]uint64, len(areas))
	for i := range areas {
		ids[i] = areas[i].ID
	}
	dealer, err := aggregation.RestoreDealerLayoutFromPayload(ids, payloads[0], payloads[1])
	if err != nil || dealer.LayoutID != seal.Binding.LayoutID {
		return out, ErrBuild
	}
	w, err := discovery.NewMovieAnchorWriter(filepath.Join(root, "anchor"), seal.Binding)
	if err != nil {
		return out, err
	}
	defer w.Close()
	var resourceErr error
	selected := func(uint32) bool {
		if resourceErr != nil {
			return false
		}
		if resourceCheck != nil {
			resourceErr = resourceCheck()
		}
		return resourceErr == nil
	}
	if _, err = discovery.WriteMovieAnchorBuckets(w, areas, joins, gate.Keys.Anchor, gate.Keys.Target, dealer, selected, nil); err != nil {
		return out, err
	}
	if resourceErr != nil {
		return out, resourceErr
	}
	catalogDigest, err := w.Seal(gate.Layout.Metadata.AnchorBuckets)
	if err != nil {
		return out, err
	}
	return writeProductionSeal(root, seal, catalogDigest, len(gate.Layout.Metadata.AnchorBuckets))
}

func writeProductionSeal(root string, target TargetSeal, catalogDigest [32]byte, anchorBuckets int) (ProductionSeal, error) {
	targetRaw, err := os.ReadFile(filepath.Join(root, "target", "target-seal.json"))
	if err != nil {
		return ProductionSeal{}, err
	}
	out := ProductionSeal{Version: imdbprod.Version, Binding: target.Binding,
		TargetSealSHA256: fileHash(targetRaw), AnchorCatalogSHA256: hex.EncodeToString(catalogDigest[:]),
		AnchorBuckets: anchorBuckets}
	raw, err := marshal(out)
	if err != nil {
		return ProductionSeal{}, err
	}
	if err = privateWrite(filepath.Join(root, "production-seal.json"), raw); err != nil {
		return ProductionSeal{}, err
	}
	return out, nil
}

func verifyAnchorCatalog(root string, binding imdbprod.Binding, digest [32]byte, expected []indexbuild.BucketMetadata) error {
	for party := uint8(0); party < 2; party++ {
		store, err := discovery.OpenMovieAnchorStore(root, party, digest, binding)
		if err != nil {
			return err
		}
		if store.BucketCount() != len(expected) {
			return ErrBuild
		}
		for _, meta := range expected {
			entry, ok := store.Meta(meta.BucketID)
			if !ok || entry.Groups != int(meta.GroupCount) || entry.T != int(meta.TotalSlots) {
				return ErrBuild
			}
			bucket, err := store.Load(meta.BucketID)
			if err != nil {
				return err
			}
			if bucket.Stage1 != nil {
				bucket.Stage1.Discard()
			}
		}
	}
	return nil
}

// VerifyProduction is the owner-only full recovery check. BuildAnchorStage
// adopts a completed catalog after a crash before production-seal writing.
func VerifyProduction(root string, gate Preflight) (ProductionSeal, error) {
	var out ProductionSeal
	seal, err := VerifyTargetStage(filepath.Join(root, "target"), gate.Freeze, gate.Keys)
	if err != nil {
		return out, err
	}
	raw, err := os.ReadFile(filepath.Join(root, "production-seal.json"))
	if err != nil {
		return out, err
	}
	if json.Unmarshal(raw, &out) != nil || out.Version != imdbprod.Version || out.Binding != seal.Binding ||
		out.AnchorBuckets != len(gate.Layout.Metadata.AnchorBuckets) {
		return ProductionSeal{}, ErrBuild
	}
	targetRaw, err := os.ReadFile(filepath.Join(root, "target", "target-seal.json"))
	if err != nil || out.TargetSealSHA256 != fileHash(targetRaw) {
		return ProductionSeal{}, ErrBuild
	}
	catalogRaw, err := os.ReadFile(filepath.Join(root, "anchor", "catalog.json"))
	if err != nil || out.AnchorCatalogSHA256 != fileHash(catalogRaw) {
		return ProductionSeal{}, ErrBuild
	}
	digest := sha256.Sum256(catalogRaw)
	if err = verifyAnchorCatalog(filepath.Join(root, "anchor"), out.Binding, digest, gate.Layout.Metadata.AnchorBuckets); err != nil {
		return ProductionSeal{}, err
	}
	return out, nil
}

// OpenParty loads only one cloud's secret files. expectedSealHash is supplied
// through the trusted publication channel; the cloud never opens either key.
func OpenParty(root string, party uint8, expectedSealHash [32]byte) (*discovery.Static, error) {
	if party > 1 || expectedSealHash == [32]byte{} {
		return nil, ErrBuild
	}
	raw, err := os.ReadFile(filepath.Join(root, "production-seal.json"))
	if err != nil || sha256.Sum256(raw) != expectedSealHash {
		return nil, ErrBuild
	}
	var prod ProductionSeal
	if json.Unmarshal(raw, &prod) != nil || prod.Version != imdbprod.Version || prod.AnchorBuckets < 1 {
		return nil, ErrBuild
	}
	if _, err = prod.Binding.Digest(); err != nil {
		return nil, err
	}
	targetRoot := filepath.Join(root, "target")
	tRaw, err := os.ReadFile(filepath.Join(targetRoot, "target-seal.json"))
	if err != nil || fileHash(tRaw) != prod.TargetSealSHA256 {
		return nil, ErrBuild
	}
	var target TargetSeal
	if json.Unmarshal(tRaw, &target) != nil || target.Version != imdbprod.Version || target.Binding != prod.Binding {
		return nil, ErrBuild
	}
	mRaw, err := os.ReadFile(filepath.Join(targetRoot, "target-manifest.json"))
	if err != nil {
		return nil, err
	}
	m, err := indexbuild.ReadTargetManifest(bytes.NewReader(mRaw))
	if err != nil || !reflect.DeepEqual(m, target.Target) || m.Version != indexbuild.TargetArtifactVersion {
		return nil, ErrBuild
	}
	pRaw, err := os.ReadFile(filepath.Join(targetRoot, "payload-manifest.json"))
	if err != nil {
		return nil, err
	}
	var pm targetpe.PayloadManifest
	if json.Unmarshal(pRaw, &pm) != nil || pm != target.Payload {
		return nil, ErrBuild
	}
	sRaw, err := os.ReadFile(filepath.Join(targetRoot, "sidecar-manifest.json"))
	if err != nil {
		return nil, err
	}
	var sm targetaggregation.SidecarManifest
	if json.Unmarshal(sRaw, &sm) != nil || sm != target.Sidecar {
		return nil, ErrBuild
	}
	prefix := "cs" + string(rune('0'+party))
	indexFile, err := os.Open(filepath.Join(targetRoot, prefix+".psmj.bin"))
	if err != nil {
		return nil, err
	}
	payloadFile, err := os.Open(filepath.Join(targetRoot, prefix+".payload.bin"))
	if err != nil {
		indexFile.Close()
		return nil, err
	}
	idx, loadErr := targetpe.Load(bytes.NewReader(mRaw), bytes.NewReader(pRaw), indexFile, payloadFile, party,
		targetpe.AlignmentLineage{IndexID: prod.Binding.IndexID, LayoutID: prod.Binding.LayoutID, N: imdbprod.AnchorObjects})
	indexFile.Close()
	if loadErr != nil {
		payloadFile.Close()
		return nil, loadErr
	}
	if _, err = payloadFile.Seek(0, io.SeekStart); err != nil {
		payloadFile.Close()
		return nil, err
	}
	payload, loadErr := targetartifact.ReadPayload(payloadFile, m, party, prod.Binding.LayoutID, imdbprod.AnchorObjects)
	payloadFile.Close()
	if loadErr != nil {
		return nil, loadErr
	}
	side, err := targetaggregation.OpenSidecarLazy(sm, mRaw, idx, filepath.Join(targetRoot, prefix+".aggregation.bin"))
	if err != nil {
		return nil, err
	}
	catalogRaw, err := os.ReadFile(filepath.Join(root, "anchor", "catalog.json"))
	if err != nil || fileHash(catalogRaw) != prod.AnchorCatalogSHA256 {
		side.Close()
		return nil, ErrBuild
	}
	catalogDigest := sha256.Sum256(catalogRaw)
	store, err := discovery.OpenMovieAnchorStore(filepath.Join(root, "anchor"), party, catalogDigest, prod.Binding)
	if err != nil {
		side.Close()
		return nil, err
	}
	if store.BucketCount() != prod.AnchorBuckets {
		side.Close()
		return nil, ErrBuild
	}
	static, err := discovery.NewMovieStaticFromStore(party, store, payload, idx, side, prod.Binding, expectedSealHash)
	if err != nil {
		side.Close()
		return nil, err
	}
	return static, nil
}
