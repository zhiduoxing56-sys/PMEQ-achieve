// Package imdbowner contains fixed-shape IMDb owner construction and sealed
// role loading. A cloud calls OpenParty with public manifests and only its own
// party files; owner keys are never included in an exported cloud package.
package imdbowner

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"pmeq/internal/aggregation"
	"pmeq/internal/imdbkeys"
	"pmeq/internal/imdbprod"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetaggregation/gen"
	"pmeq/internal/targetartifact"
	"pmeq/internal/targetpe"
)

var ErrBuild = errors.New("imdbowner: production build gate or artifact verification failed")

type TargetSeal struct {
	Version string                            `json:"version"`
	Binding imdbprod.Binding                  `json:"binding"`
	Target  indexbuild.TargetManifest         `json:"target_manifest"`
	Payload targetpe.PayloadManifest          `json:"payload_manifest"`
	Sidecar targetaggregation.SidecarManifest `json:"sidecar_manifest"`
	Audit   gen.Audit                         `json:"audit"`
}

func privateWrite(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func marshal(v any) ([]byte, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	return append(raw, '\n'), err
}

func fileHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// BuildTargetStage makes the sealed movie-domain PSMJ, PL01 payload and TG01
// matrix on a fresh trusted DO directory. This is a target-only stage; the
// full build launcher calls it only after backup, layout and resource gates.
func BuildTargetStage(root string, mapping *imdbprod.Mapping, freeze imdbprod.FreezeManifest, keys imdbkeys.Pair) (TargetSeal, error) {
	var seal TargetSeal
	if mapping == nil || keys.Fingerprint != imdbprod.KeyFingerprint([32]byte(keys.Anchor), [32]byte(keys.Target)) {
		return seal, ErrBuild
	}
	areas, joins, movies, err := mapping.IndexInputs()
	if err != nil {
		return seal, err
	}
	if len(areas) != imdbprod.AnchorObjects || len(movies) != imdbprod.TargetObjects {
		return seal, ErrBuild
	}
	if _, err = os.Lstat(root); !os.IsNotExist(err) {
		return seal, ErrBuild
	}
	finalRoot := root
	root, err = os.MkdirTemp(filepath.Dir(finalRoot), ".target-incomplete-")
	if err != nil {
		return seal, err
	}
	var indexID [16]byte
	if _, err = rand.Read(indexID[:]); err != nil {
		return seal, err
	}
	ids := make([]uint64, len(areas))
	for i, a := range areas {
		ids[i] = a.ID
	}
	dealer, p0, p1, err := aggregation.GeneratePayloadWithJoins(ids, joins, keys.Target, imdbprod.BucketBits)
	if err != nil {
		return seal, err
	}
	binding, err := keys.Bind(freeze, indexID, dealer.LayoutID)
	if err != nil {
		return seal, err
	}
	meta, t0, t1, stats, err := indexbuild.BuildMovieTarget(movies, keys.Target)
	if err != nil {
		return seal, err
	}
	for _, b := range meta.TargetBuckets {
		if b.GroupCount > imdbprod.TargetBucketGroups || b.TotalSlots > imdbprod.TargetBucketSlots {
			return seal, ErrBuild
		}
	}
	m, err := indexbuild.NewTargetManifest(indexID, meta, stats.Target)
	if err != nil {
		return seal, err
	}
	var ps [2][]byte
	for party, p := range []indexbuild.PartyIndex{t0, t1} {
		var buf bytes.Buffer
		if err = indexbuild.WriteTargetParty(&buf, m, uint8(party), p); err != nil {
			return seal, err
		}
		ps[party] = buf.Bytes()
		m.PartyBytes[party] = uint64(len(ps[party]))
		m.PartySHA256[party] = fileHash(ps[party])
		if err = privateWrite(filepath.Join(root, "cs"+string(rune('0'+party))+".psmj.bin"), ps[party]); err != nil {
			return seal, err
		}
	}
	mRaw, err := marshal(m)
	if err != nil {
		return seal, err
	}
	if err = privateWrite(filepath.Join(root, "target-manifest.json"), mRaw); err != nil {
		return seal, err
	}
	pm := targetpe.PayloadManifest{IndexID: indexID, LayoutID: dealer.LayoutID, TargetBucketBits: imdbprod.BucketBits, N: imdbprod.AnchorObjects}
	for party, p := range []aggregation.PartyPayload{p0, p1} {
		var buf bytes.Buffer
		if err = targetartifact.WritePayload(&buf, m, uint8(party), p); err != nil {
			return seal, err
		}
		raw := buf.Bytes()
		pm.Bytes[party] = int64(len(raw))
		pm.SHA256[party] = fileHash(raw)
		if err = privateWrite(filepath.Join(root, "cs"+string(rune('0'+party))+".payload.bin"), raw); err != nil {
			return seal, err
		}
	}
	pmRaw, err := marshal(pm)
	if err != nil {
		return seal, err
	}
	if err = privateWrite(filepath.Join(root, "payload-manifest.json"), pmRaw); err != nil {
		return seal, err
	}
	var side [2]bytes.Buffer
	sm, audit, err := gen.BuildWithCapacity(mRaw, ps, movies, [2]io.Writer{&side[0], &side[1]}, imdbprod.TargetDimension)
	if err != nil || audit.MaxMultiplicity > imdbprod.TargetMultiplicity || audit.Errors != 0 {
		return seal, ErrBuild
	}
	for party := 0; party < 2; party++ {
		if err = privateWrite(filepath.Join(root, "cs"+string(rune('0'+party))+".aggregation.bin"), side[party].Bytes()); err != nil {
			return seal, err
		}
	}
	smRaw, err := marshal(sm)
	if err != nil {
		return seal, err
	}
	if err = privateWrite(filepath.Join(root, "sidecar-manifest.json"), smRaw); err != nil {
		return seal, err
	}
	seal = TargetSeal{Version: imdbprod.Version, Binding: binding, Target: m, Payload: pm, Sidecar: sm, Audit: audit}
	for party := uint8(0); party < 2; party++ {
		psf, e := os.Open(filepath.Join(root, "cs"+string(rune('0'+party))+".psmj.bin"))
		if e != nil {
			return TargetSeal{}, e
		}
		plf, e := os.Open(filepath.Join(root, "cs"+string(rune('0'+party))+".payload.bin"))
		if e != nil {
			psf.Close()
			return TargetSeal{}, e
		}
		idx, e := targetpe.Load(bytes.NewReader(mRaw), bytes.NewReader(pmRaw), psf, plf, party, targetpe.AlignmentLineage{IndexID: indexID, LayoutID: dealer.LayoutID, N: imdbprod.AnchorObjects})
		psf.Close()
		plf.Close()
		if e != nil {
			return TargetSeal{}, e
		}
		sc, e := targetaggregation.OpenSidecarLazy(sm, mRaw, idx, filepath.Join(root, "cs"+string(rune('0'+party))+".aggregation.bin"))
		if e != nil {
			return TargetSeal{}, e
		}
		if e = sc.Close(); e != nil {
			return TargetSeal{}, e
		}
	}
	sealRaw, err := marshal(seal)
	if err != nil {
		return TargetSeal{}, err
	}
	if err = privateWrite(filepath.Join(root, "target-seal.json"), sealRaw); err != nil {
		return TargetSeal{}, err
	}
	if _, err = VerifyTargetStage(root, freeze, keys); err != nil {
		return TargetSeal{}, err
	}
	dir, err := os.Open(root)
	if err != nil {
		return TargetSeal{}, err
	}
	err = dir.Sync()
	dir.Close()
	if err != nil {
		return TargetSeal{}, err
	}
	if _, err = os.Lstat(finalRoot); !os.IsNotExist(err) {
		return TargetSeal{}, ErrBuild
	}
	if err = os.Rename(root, finalRoot); err != nil {
		return TargetSeal{}, err
	}
	parent, err := os.Open(filepath.Dir(finalRoot))
	if err != nil {
		return TargetSeal{}, err
	}
	err = parent.Sync()
	parent.Close()
	return seal, err
}
