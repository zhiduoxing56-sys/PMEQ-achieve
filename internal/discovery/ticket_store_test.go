package discovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"pmeq/internal/imdbprod"
	"pmeq/internal/material"
	"strings"
	"testing"
)

func syntheticBinding(t *testing.T) imdbprod.Binding {
	t.Helper()
	contract, e := imdbprod.Production().DigestHex()
	if e != nil {
		t.Fatal(e)
	}
	return imdbprod.Binding{Version: imdbprod.Version, ContractSHA256: contract,
		SourceManifestSHA256: imdbprod.SourceManifestSHA256, MotherDatabaseSHA256: imdbprod.MotherDatabaseSHA256,
		IdentityMapSHA256: imdbprod.IdentityMapSHA256, TargetMapSHA256: imdbprod.TargetMapSHA256,
		KeyFingerprint: strings.Repeat("01", 32), IndexID: [16]byte{1}, LayoutID: [16]byte{2}}
}

func TestTicketRoleCrossProcessHelper(t *testing.T) {
	dir := os.Getenv("PMEQ_TEST_TICKET_ROLE")
	if dir == "" {
		return
	}
	binding := syntheticBinding(t)
	var ticket [16]byte
	ticket[0] = 9
	var indexSeal, targetDigest [32]byte
	indexSeal[0] = 3
	targetDigest[0] = 4
	raw, e := hex.DecodeString(os.Getenv("PMEQ_TEST_MANIFEST_SHA"))
	if e != nil || len(raw) != 32 {
		t.Fatal("missing manifest identity")
	}
	var manifestSHA [32]byte
	copy(manifestSHA[:], raw)
	m, e := readRoleManifest(dir, manifestSHA, "user", binding, indexSeal, ticket, targetDigest)
	if e != nil {
		t.Fatal(e)
	}
	e = readMaterialFile(dir, m, func(d *material.StreamDecoder) error {
		blob := d.Blob(8192)
		if d.Err != nil || !bytes.Equal(blob, bytes.Repeat([]byte{0x5a}, 4096)) {
			return ErrBinding
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	e = material.ClaimPersistent(dir, ticket)
	if os.Getenv("PMEQ_TEST_EXPECT_REPLAY") == "1" {
		if e == nil {
			t.Fatal("replayed ticket accepted")
		}
	} else if e != nil {
		t.Fatal(e)
	}
}

func TestTicketRoleFileIntegrityAndRestartBurn(t *testing.T) {
	binding := syntheticBinding(t)
	bind, e := binding.Digest()
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(t.TempDir(), "user")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	bytesCount, sha, e := writeMaterialFile(dir, func(enc *material.StreamEncoder) { enc.Blob(bytes.Repeat([]byte{0x5a}, 4096)) })
	if e != nil {
		t.Fatal(e)
	}
	var ticket [16]byte
	ticket[0] = 9
	var indexSeal, targetDigest [32]byte
	indexSeal[0] = 3
	targetDigest[0] = 4
	m := TicketRoleManifest{Version: ticketStoreVersion, Role: "user", Ticket: hex.EncodeToString(ticket[:]), BindingSHA256: hex.EncodeToString(bind[:]), IndexSealSHA256: hex.EncodeToString(indexSeal[:]), LayoutID: hex.EncodeToString(binding.LayoutID[:]), KeyFingerprint: binding.KeyFingerprint, TargetManifestSHA256: hex.EncodeToString(targetDigest[:]), Buckets: []uint32{1, 2, 3, 4}, CandidateCapacity: imdbprod.CandidateCapacity, TargetRoutes: imdbprod.CandidateCapacity * imdbprod.TargetSignatures, TargetSlots: imdbprod.CandidateCapacity * imdbprod.TargetSignatures * imdbprod.TargetBucketSlots, TargetGroups: imdbprod.TargetGroupCapacity, Uses: 1, MaterialBytes: bytesCount, MaterialSHA256: sha}
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeReservation(filepath.Join(dir, "manifest.json"), raw); e != nil {
		t.Fatal(e)
	}
	manifestSHA := sha256.Sum256(raw)
	if _, e = readRoleManifest(dir, manifestSHA, "cs0", binding, indexSeal, ticket, targetDigest); e == nil {
		t.Fatal("cross-role manifest accepted")
	}
	bad := binding
	bad.LayoutID[0]++
	if _, e = readRoleManifest(dir, manifestSHA, "user", bad, indexSeal, ticket, targetDigest); e == nil {
		t.Fatal("wrong index layout accepted")
	}
	oldDir := filepath.Join(t.TempDir(), "user")
	if e = os.Mkdir(oldDir, 0700); e != nil {
		t.Fatal(e)
	}
	old := m
	old.Version = "IMDB-OFFLINE-TICKET-v0"
	oldRaw, e := json.Marshal(old)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(oldDir, "manifest.json"), oldRaw, 0600); e != nil {
		t.Fatal(e)
	}
	oldSHA := sha256.Sum256(oldRaw)
	if _, e = readRoleManifest(oldDir, oldSHA, "user", binding, indexSeal, ticket, targetDigest); e == nil {
		t.Fatal("old ticket version accepted")
	}
	if _, e = ReadTicketSeal(t.TempDir(), [32]byte{1}); e == nil {
		t.Fatal("incomplete ticket accepted")
	}
	for i := 0; i < 2; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestTicketRoleCrossProcessHelper$")
		cmd.Env = append(os.Environ(), "PMEQ_TEST_TICKET_ROLE="+dir, "PMEQ_TEST_MANIFEST_SHA="+hex.EncodeToString(manifestSHA[:]))
		if i == 1 {
			cmd.Env = append(cmd.Env, "PMEQ_TEST_EXPECT_REPLAY=1")
		}
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("fresh process %d: %v: %s", i, e, out)
		}
	}
	path := filepath.Join(dir, "material.bin")
	f, e := os.OpenFile(path, os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.WriteAt([]byte{0}, 20)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	e = readMaterialFile(dir, m, func(d *material.StreamDecoder) error { _ = d.Blob(8192); return d.Err })
	if e == nil {
		t.Fatal("corrupt role material accepted")
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = readMaterialFile(dir, m, func(*material.StreamDecoder) error { return nil }); e == nil {
		t.Fatal("missing role material accepted")
	}
}
