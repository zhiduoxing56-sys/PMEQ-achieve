package imdbowner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"

	"pmeq/internal/imdbkeys"
	"pmeq/internal/imdbprod"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetpe"
)

// VerifyTargetStage is the resume gate for an already published target stage.
// Each role's index, payload and matrix are checked against the trusted seal.
// No opposite-party secret share is loaded into the returned value.
func VerifyTargetStage(root string, freeze imdbprod.FreezeManifest, keys imdbkeys.Pair) (TargetSeal, error) {
	var seal TargetSeal
	sealRaw, err := os.ReadFile(filepath.Join(root, "target-seal.json"))
	if err != nil || json.Unmarshal(sealRaw, &seal) != nil || seal.Version != imdbprod.Version {
		return TargetSeal{}, ErrBuild
	}
	expected, err := keys.Bind(freeze, seal.Binding.IndexID, seal.Binding.LayoutID)
	if err != nil || expected != seal.Binding || seal.Audit.Errors != 0 || seal.Audit.MaxMultiplicity > imdbprod.TargetMultiplicity {
		return TargetSeal{}, ErrBuild
	}
	mRaw, err := os.ReadFile(filepath.Join(root, "target-manifest.json"))
	if err != nil {
		return TargetSeal{}, err
	}
	m, err := indexbuild.ReadTargetManifest(bytes.NewReader(mRaw))
	if err != nil || !reflect.DeepEqual(m, seal.Target) || m.Version != indexbuild.TargetArtifactVersion || m.IndexID != seal.Binding.IndexID {
		return TargetSeal{}, ErrBuild
	}
	if seal.Audit.CheckedBuckets != 1<<imdbprod.BucketBits || seal.Audit.CheckedGroups != m.LogicalGroups ||
		seal.Audit.CheckedPhysicalSlots != m.PaddedSlots || seal.Audit.RealSlots != m.RealPostings {
		return TargetSeal{}, ErrBuild
	}
	pRaw, err := os.ReadFile(filepath.Join(root, "payload-manifest.json"))
	if err != nil {
		return TargetSeal{}, err
	}
	var pm targetpe.PayloadManifest
	if json.Unmarshal(pRaw, &pm) != nil || pm != seal.Payload || pm.LayoutID != seal.Binding.LayoutID || pm.N != imdbprod.AnchorObjects {
		return TargetSeal{}, ErrBuild
	}
	sRaw, err := os.ReadFile(filepath.Join(root, "sidecar-manifest.json"))
	if err != nil {
		return TargetSeal{}, err
	}
	var sm targetaggregation.SidecarManifest
	if json.Unmarshal(sRaw, &sm) != nil || sm != seal.Sidecar || sm.DTarget != imdbprod.TargetDimension || sm.MaxMultiplicity != imdbprod.TargetMultiplicity {
		return TargetSeal{}, ErrBuild
	}
	for party := uint8(0); party < 2; party++ {
		prefix := "cs" + string(rune('0'+party))
		indexFile, err := os.Open(filepath.Join(root, prefix+".psmj.bin"))
		if err != nil {
			return TargetSeal{}, err
		}
		payloadFile, err := os.Open(filepath.Join(root, prefix+".payload.bin"))
		if err != nil {
			indexFile.Close()
			return TargetSeal{}, err
		}
		idx, e := targetpe.Load(bytes.NewReader(mRaw), bytes.NewReader(pRaw), indexFile, payloadFile, party,
			targetpe.AlignmentLineage{IndexID: seal.Binding.IndexID, LayoutID: seal.Binding.LayoutID, N: imdbprod.AnchorObjects})
		indexFile.Close()
		payloadFile.Close()
		if e != nil {
			return TargetSeal{}, e
		}
		side, e := targetaggregation.OpenSidecarLazy(sm, mRaw, idx, filepath.Join(root, prefix+".aggregation.bin"))
		if e != nil {
			return TargetSeal{}, e
		}
		if e = side.Close(); e != nil {
			return TargetSeal{}, e
		}
	}
	return seal, nil
}
