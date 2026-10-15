package imdbowner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"pmeq/internal/imdbkeys"
	"pmeq/internal/imdbprod"
	"pmeq/internal/indexbuild"
)

// Preflight holds trusted owner-only inputs. Never serialize this struct or
// pass it to a cloud role: Keys contains both full production master keys.
type Preflight struct {
	Mapping *imdbprod.Mapping
	Freeze  imdbprod.FreezeManifest
	Keys    imdbkeys.Pair
	Layout  indexbuild.LayoutAnalysis
}

type backupReceipt struct {
	SampleVersion           string `json:"sample_version"`
	KeyFingerprint          string `json:"key_fingerprint"`
	BackupPath              string `json:"backup_path"`
	BackupSHA256            string `json:"backup_sha256"`
	BackupBytes             int64  `json:"backup_bytes"`
	IsolatedRestoreVerified bool   `json:"isolated_restore_verified"`
}

// CheckBackup requires the user-created encrypted copy and the successful
// isolated restore receipt before any full production outsourcing starts.
func CheckBackup(receiptPath string, keys imdbkeys.Pair) error {
	info, err := os.Lstat(receiptPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return ErrBuild
	}
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		return err
	}
	var r backupReceipt
	if json.Unmarshal(raw, &r) != nil || r.SampleVersion != imdbprod.SampleVersion ||
		r.KeyFingerprint != keys.Fingerprint || !r.IsolatedRestoreVerified ||
		!filepath.IsAbs(r.BackupPath) || r.BackupBytes < 64 ||
		filepath.Ext(r.BackupPath) != ".gpg" ||
		filepath.Clean(r.BackupPath) == filepath.Clean(receiptPath) {
		return ErrBuild
	}
	backup, err := os.Open(r.BackupPath)
	if err != nil {
		return err
	}
	defer backup.Close()
	info, err = backup.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != r.BackupBytes {
		return ErrBuild
	}
	localStat, localOK := infoSysStat(receiptPath)
	backupStat, backupOK := info.Sys().(*syscall.Stat_t)
	if !localOK || !backupOK || localStat.Dev == backupStat.Dev {
		return ErrBuild
	}
	h := sha256.New()
	if _, err = io.Copy(h, backup); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != r.BackupSHA256 {
		return ErrBuild
	}
	return nil
}

func infoSysStat(path string) (*syscall.Stat_t, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

// CheckProduction reruns the actual keyed layout on the immutable frozen
// sample. The public 12-group/48-slot ceiling is checked before secret shares
// or long-lived index files can be generated.
func CheckProduction(sampleDir, keyPath, receiptPath string) (Preflight, error) {
	var out Preflight
	var err error
	out.Mapping, out.Freeze, err = imdbprod.LoadFrozen(sampleDir)
	if err != nil {
		return Preflight{}, err
	}
	out.Keys, err = imdbkeys.Load(keyPath)
	if err != nil {
		return Preflight{}, err
	}
	if err = CheckBackup(receiptPath, out.Keys); err != nil {
		return Preflight{}, err
	}
	areas, joins, movies, err := out.Mapping.IndexInputs()
	if err != nil {
		return Preflight{}, err
	}
	out.Layout, err = indexbuild.AnalyzeMovieTierLayout(areas, joins, movies, out.Keys.Anchor, out.Keys.Target)
	if err != nil {
		return Preflight{}, err
	}
	if out.Layout.Metadata.Q != imdbprod.Q ||
		out.Layout.Metadata.AnchorBucketBits != imdbprod.BucketBits ||
		out.Layout.Metadata.TargetBucketBits != imdbprod.BucketBits {
		return Preflight{}, ErrBuild
	}
	for _, bucket := range out.Layout.Metadata.TargetBuckets {
		if bucket.GroupCount > imdbprod.TargetBucketGroups || bucket.TotalSlots > imdbprod.TargetBucketSlots {
			return Preflight{}, ErrBuild
		}
	}
	return out, nil
}
