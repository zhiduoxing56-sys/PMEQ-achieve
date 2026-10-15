package imdbowner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"pmeq/internal/discovery"
)

func copySealed(source, destination, expectedHash string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrBuild
	}
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), in)
	if err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if expectedHash != "" && hex.EncodeToString(h.Sum(nil)) != expectedHash {
		return ErrBuild
	}
	return nil
}

// ExportParty builds an atomic cloud package with public manifests and exactly
// one role's secret files. No owner key, peer share or orphan bucket is copied.
// The destination must be absent; an interrupted .export-incomplete directory
// is never treated as a published package.
func ExportParty(root string, party uint8, destination string, expectedSealHash [32]byte) error {
	if party > 1 || destination == "" || expectedSealHash == [32]byte{} {
		return ErrBuild
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return ErrBuild
	}
	static, err := OpenParty(root, party, expectedSealHash)
	if err != nil {
		return err
	}
	if err = static.Close(); err != nil {
		return err
	}
	sealRaw, err := os.ReadFile(filepath.Join(root, "production-seal.json"))
	if err != nil || sha256.Sum256(sealRaw) != expectedSealHash {
		return ErrBuild
	}
	var seal ProductionSeal
	if json.Unmarshal(sealRaw, &seal) != nil {
		return ErrBuild
	}
	catalogRaw, err := os.ReadFile(filepath.Join(root, "anchor", "catalog.json"))
	if err != nil || fileHash(catalogRaw) != seal.AnchorCatalogSHA256 {
		return ErrBuild
	}
	store, err := discovery.OpenMovieAnchorStore(filepath.Join(root, "anchor"), party, sha256.Sum256(catalogRaw), seal.Binding)
	if err != nil || store.BucketCount() != seal.AnchorBuckets {
		return ErrBuild
	}
	parent := filepath.Dir(destination)
	if _, err = os.Stat(parent); err != nil {
		return err
	}
	var required uint64
	for _, bucket := range store.Entries() {
		required += bucket.Bytes[party]
	}
	for _, name := range []string{"target-seal.json", "target-manifest.json", "payload-manifest.json", "sidecar-manifest.json",
		"cs" + string(rune('0'+party)) + ".psmj.bin", "cs" + string(rune('0'+party)) + ".payload.bin", "cs" + string(rune('0'+party)) + ".aggregation.bin"} {
		info, e := os.Stat(filepath.Join(root, "target", name))
		if e != nil || !info.Mode().IsRegular() {
			return ErrBuild
		}
		required += uint64(info.Size())
	}
	required += uint64(len(sealRaw) + len(catalogRaw))
	var disk syscall.Statfs_t
	if err = syscall.Statfs(parent, &disk); err != nil {
		return err
	}
	if uint64(disk.Bavail)*uint64(disk.Bsize) < required+required/20+(2<<30) {
		return ErrBuild
	}
	stage, err := os.MkdirTemp(parent, ".export-incomplete-")
	if err != nil {
		return err
	}
	targetStage := filepath.Join(stage, "target")
	anchorStage := filepath.Join(stage, "anchor")
	prefix := "cs" + string(rune('0'+party))
	for _, dir := range []string{targetStage, anchorStage, filepath.Join(anchorStage, prefix)} {
		if err = os.Mkdir(dir, 0700); err != nil {
			return err
		}
	}
	if err = copySealed(filepath.Join(root, "production-seal.json"), filepath.Join(stage, "production-seal.json"), hex.EncodeToString(expectedSealHash[:])); err != nil {
		return err
	}
	for _, name := range []string{"target-seal.json", "target-manifest.json", "payload-manifest.json", "sidecar-manifest.json",
		prefix + ".psmj.bin", prefix + ".payload.bin", prefix + ".aggregation.bin"} {
		if err = copySealed(filepath.Join(root, "target", name), filepath.Join(targetStage, name), ""); err != nil {
			return err
		}
	}
	if err = copySealed(filepath.Join(root, "anchor", "catalog.json"), filepath.Join(anchorStage, "catalog.json"), seal.AnchorCatalogSHA256); err != nil {
		return err
	}
	for _, bucket := range store.Entries() {
		name := fmt.Sprintf("%05d-%s.bs02", bucket.Bucket, bucket.SHA256[party])
		if err = copySealed(filepath.Join(root, "anchor", prefix, name), filepath.Join(anchorStage, prefix, name), bucket.SHA256[party]); err != nil {
			return err
		}
	}
	loaded, err := OpenParty(stage, party, expectedSealHash)
	if err != nil {
		return err
	}
	if err = loaded.Close(); err != nil {
		return err
	}
	for _, path := range []string{filepath.Join(anchorStage, prefix), anchorStage, targetStage, stage} {
		dir, err := os.Open(path)
		if err != nil {
			return err
		}
		err = dir.Sync()
		dir.Close()
		if err != nil {
			return err
		}
	}
	if _, err = os.Lstat(destination); !os.IsNotExist(err) {
		return ErrBuild
	}
	if err = os.Rename(stage, destination); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	err = dir.Sync()
	dir.Close()
	return err
}
