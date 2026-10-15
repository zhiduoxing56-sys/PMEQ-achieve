package imdbkeys

import (
	"encoding/json"
	"os"
	"path/filepath"
	"pmeq/internal/imdbprod"
	"testing"
)

func TestPrivateKeyLoadingAndBinding(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "keys.json")
	var a, b [32]byte
	a[0] = 1
	b[0] = 2
	raw, err := json.Marshal(fileBody{Version: imdbprod.SampleVersion, CreatedUTC: "2026-10-15T00:00:00Z", AnchorHex: "0100000000000000000000000000000000000000000000000000000000000000", TargetHex: "0200000000000000000000000000000000000000000000000000000000000000"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	pair, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if pair.Fingerprint != imdbprod.KeyFingerprint(a, b) {
		t.Fatal("key identity")
	}
	digest, err := imdbprod.Production().DigestHex()
	if err != nil {
		t.Fatal(err)
	}
	fm := imdbprod.FreezeManifest{Version: imdbprod.SampleVersion, AnchorSequenceSHA256: imdbprod.AnchorSequenceSHA256, TargetSequenceSHA256: imdbprod.TargetSequenceSHA256, SourceManifestSHA256: imdbprod.SourceManifestSHA256, MotherDatabaseSHA256: imdbprod.MotherDatabaseSHA256, Files: map[string]imdbprod.FileStamp{"identity_map.jsonl": {SHA256: imdbprod.IdentityMapSHA256}, "target_map.jsonl": {SHA256: imdbprod.TargetMapSHA256}}}
	binding, err := pair.Bind(fm, [16]byte{1}, [16]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if binding.ContractSHA256 != digest || binding.KeyFingerprint != pair.Fingerprint {
		t.Fatal("binding")
	}
	pair.Fingerprint = "bad"
	if _, err = pair.Bind(fm, [16]byte{1}, [16]byte{2}); err == nil {
		t.Fatal("forged key fingerprint")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(path); err == nil {
		t.Fatal("world-readable key accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(path); err == nil {
		t.Fatal("world-readable directory accepted")
	}
}
