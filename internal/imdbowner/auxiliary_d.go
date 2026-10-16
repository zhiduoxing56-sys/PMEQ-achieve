package imdbowner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"pmeq/internal/imdbprod"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpstock"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetaggregation/gen"
)

// TargetAuxiliaryD1 is an independent sealed target aggregation sidecar. Its
// base production index, payload and anchor catalog are referenced read-only.
// The published seal hash is also the D=1 ticket's index-state binding.
type TargetAuxiliaryD1 struct {
	Version                string                            `json:"version"`
	BaseProductionSealHash string                            `json:"base_production_seal_sha256"`
	IndexID                [16]byte                          `json:"index_id"`
	DTarget                int                               `json:"d_target"`
	MaxObjectsPerJoin      int                               `json:"max_objects_per_join"`
	Sidecar                targetaggregation.SidecarManifest `json:"sidecar"`
}

const targetAuxiliaryD1Version = "IMDB-TARGET-AUX-D1-v1"

// BuildTargetAuxiliaryD1 is trusted offline work. It never changes an already
// sealed production file and rejects a destination that already exists.
func BuildTargetAuxiliaryD1(root, productionRoot string, mapping *imdbprod.Mapping, baseSealHash [32]byte) (TargetAuxiliaryD1, [32]byte, error) {
	var out TargetAuxiliaryD1
	if root == "" || productionRoot == "" || mapping == nil || baseSealHash == [32]byte{} {
		return out, [32]byte{}, ErrBuild
	}
	if _, err := os.Lstat(root); err == nil || !os.IsNotExist(err) {
		return out, [32]byte{}, ErrBuild
	}
	_, _, movies, err := mapping.IndexInputs()
	if err != nil {
		return out, [32]byte{}, err
	}
	parent := filepath.Dir(root)
	if err = scmpstock.CheckBudget(parent, 128<<20); err != nil {
		return out, [32]byte{}, err
	}
	targetRoot := filepath.Join(productionRoot, "target")
	mRaw, err := os.ReadFile(filepath.Join(targetRoot, "target-manifest.json"))
	if err != nil {
		return out, [32]byte{}, err
	}
	m, err := indexbuild.ReadTargetManifest(bytes.NewReader(mRaw))
	if err != nil {
		return out, [32]byte{}, err
	}
	var ps [2][]byte
	for party := range ps {
		ps[party], err = os.ReadFile(filepath.Join(targetRoot, "cs"+string(rune('0'+party))+".psmj.bin"))
		if err != nil || uint64(len(ps[party])) != m.PartyBytes[party] || fileHash(ps[party]) != m.PartySHA256[party] {
			return out, [32]byte{}, ErrBuild
		}
	}
	var side [2]bytes.Buffer
	sm, audit, err := gen.BuildWithCapacity(mRaw, ps, movies, [2]io.Writer{&side[0], &side[1]}, 1)
	if err != nil || audit.Errors != 0 || audit.MaxAliases != 1 || sm.DTarget != 1 || sm.IndexID != m.IndexID {
		return out, [32]byte{}, ErrBuild
	}
	out = TargetAuxiliaryD1{Version: targetAuxiliaryD1Version, BaseProductionSealHash: hex.EncodeToString(baseSealHash[:]), IndexID: m.IndexID, DTarget: 1, MaxObjectsPerJoin: audit.MaxAliases, Sidecar: sm}
	tmp, err := os.MkdirTemp(parent, ".imdb-d1-aux-*")
	if err != nil {
		return out, [32]byte{}, err
	}
	defer os.RemoveAll(tmp)
	for party := range ps {
		if err = privateWrite(filepath.Join(tmp, "cs"+string(rune('0'+party))+".aggregation.bin"), side[party].Bytes()); err != nil {
			return out, [32]byte{}, err
		}
	}
	raw, err := marshal(out)
	if err != nil {
		return out, [32]byte{}, err
	}
	if err = privateWrite(filepath.Join(tmp, "auxiliary-seal.json"), raw); err != nil {
		return out, [32]byte{}, err
	}
	if err = os.Rename(tmp, root); err != nil {
		return out, [32]byte{}, err
	}
	return out, sha256.Sum256(raw), nil
}

// ReadTargetAuxiliaryD1 authenticates the public auxiliary seal against the
// already verified base production seal. Each cloud separately verifies its
// own sidecar bytes when it opens the role file.
func ReadTargetAuxiliaryD1(root string, baseSealHash [32]byte, expectedIndex [16]byte) (TargetAuxiliaryD1, [32]byte, error) {
	var out TargetAuxiliaryD1
	if baseSealHash == [32]byte{} || expectedIndex == [16]byte{} {
		return out, [32]byte{}, ErrBuild
	}
	raw, err := os.ReadFile(filepath.Join(root, "auxiliary-seal.json"))
	if err != nil || json.Unmarshal(raw, &out) != nil || out.Version != targetAuxiliaryD1Version || out.BaseProductionSealHash != hex.EncodeToString(baseSealHash[:]) || out.IndexID != expectedIndex || out.DTarget != 1 || out.MaxObjectsPerJoin != 1 || out.Sidecar.DTarget != 1 || out.Sidecar.IndexID != expectedIndex {
		return TargetAuxiliaryD1{}, [32]byte{}, ErrBuild
	}
	return out, sha256.Sum256(raw), nil
}
