// Package imdbkeys is the trusted DO/query-user boundary for the one local
// production movie key pair. Cloud static state and tokens receive only its
// public identity digest, never either 256-bit key.
package imdbkeys

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"pmeq/internal/anchorindex"
	"pmeq/internal/imdbprod"
	"pmeq/internal/targetcrypto"
	"syscall"
)

type Pair struct {
	Anchor      anchorindex.Key
	Target      targetcrypto.MasterKey
	Fingerprint string
}

type fileBody struct {
	Version    string `json:"version"`
	CreatedUTC string `json:"created_utc"`
	AnchorHex  string `json:"anchor_key_hex"`
	TargetHex  string `json:"target_key_hex"`
}

var ErrKeyFile = errors.New("imdbkeys: invalid, unprotected or incompatible production key file")

// Load accepts only a 0700 local directory and 0600 regular file owned by
// this process's user. It never creates, rotates, exports or logs keys.
func Load(path string) (Pair, error) {
	var out Pair
	if path == "" {
		return out, ErrKeyFile
	}
	parent := filepath.Dir(path)
	dir, err := os.Lstat(parent)
	if err != nil || !dir.IsDir() || dir.Mode().Perm() != 0700 {
		return out, ErrKeyFile
	}
	file, err := os.Lstat(path)
	if err != nil || !file.Mode().IsRegular() || file.Mode().Perm() != 0600 {
		return out, ErrKeyFile
	}
	for _, info := range []os.FileInfo{dir, file} {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) {
			return out, ErrKeyFile
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	var body fileBody
	if json.Unmarshal(raw, &body) != nil || body.Version != imdbprod.SampleVersion || body.CreatedUTC == "" {
		return out, ErrKeyFile
	}
	a, e := hex.DecodeString(body.AnchorHex)
	if e != nil || len(a) != 32 {
		return out, ErrKeyFile
	}
	b, e := hex.DecodeString(body.TargetHex)
	if e != nil || len(b) != 32 {
		return out, ErrKeyFile
	}
	var aa, bb [32]byte
	copy(aa[:], a)
	copy(bb[:], b)
	out.Anchor, e = anchorindex.NewKey(aa)
	if e != nil {
		return Pair{}, ErrKeyFile
	}
	out.Target, e = targetcrypto.NewMasterKey(bb)
	if e != nil {
		return Pair{}, ErrKeyFile
	}
	out.Fingerprint = imdbprod.KeyFingerprint(aa, bb)
	return out, nil
}

// Bind ties the fixed sample, public config, key identity and fresh index and
// layout IDs into the digest used by BS02, offline packets and QU13 tokens.
func (p Pair) Bind(freeze imdbprod.FreezeManifest, indexID, layoutID [16]byte) (imdbprod.Binding, error) {
	if p.Fingerprint != imdbprod.KeyFingerprint([32]byte(p.Anchor), [32]byte(p.Target)) {
		return imdbprod.Binding{}, ErrKeyFile
	}
	return freeze.Bind(indexID, layoutID, p.Fingerprint)
}
