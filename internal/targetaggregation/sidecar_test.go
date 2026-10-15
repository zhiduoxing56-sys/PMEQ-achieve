package targetaggregation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"pmeq/internal/targetpe"
	"testing"
)

type rejectRead struct{ called bool }

func (r *rejectRead) Read([]byte) (int, error) {
	r.called = true
	return 0, errors.New("must reject manifest before reading sidecar")
}

func TestActualLoadedManifestBinding(t *testing.T) {
	mr, e := os.ReadFile("../../artifacts/phase7b/manifest.json")
	must(t, e)
	pr, e := os.ReadFile("../../artifacts/phase7b/payload-manifest.json")
	must(t, e)
	var pm targetpe.PayloadManifest
	must(t, json.Unmarshal(pr, &pm))
	f, e := os.Open("../../artifacts/phase7b/cs0.psmj.bin")
	must(t, e)
	defer f.Close()
	p, e := os.Open("../../artifacts/phase7b/cs0.payload.bin")
	must(t, e)
	defer p.Close()
	idx, e := targetpe.Load(bytes.NewReader(mr), bytes.NewReader(pr), f, p, 0, targetpe.AlignmentLineage{IndexID: pm.IndexID, LayoutID: pm.LayoutID, N: pm.N})
	must(t, e)
	if idx.ManifestDigest() != sha256.Sum256(mr) {
		t.Fatal("loaded manifest digest")
	}
	raw, e := os.ReadFile("../../artifacts/phase10b/manifest.json")
	if os.IsNotExist(e) {
		t.Skip("offline sidecar not provisioned")
	}
	must(t, e)
	var m SidecarManifest
	must(t, json.Unmarshal(raw, &m))
	if m.MaxMultiplicity != MaxMultiplicity {
		t.Skip("legacy sidecar with incompatible target multiplicity")
	}
	// Same IndexID, dimensions and parsed semantics, but different exact bytes.
	variant := append(append([]byte(nil), mr...), ' ')
	digest := sha256.Sum256(variant)
	bad := m
	bad.ManifestSHA256 = hex.EncodeToString(digest[:])
	reader := &rejectRead{}
	if _, e = LoadSidecar(bad, variant, idx, reader); e != ErrBinding || reader.called {
		t.Fatal("did not bind actual loaded manifest", e, reader.called)
	}
	// Positive path loads and checks every actual bucket/group/slot descriptor.
	sc, e := os.Open("../../artifacts/phase10b/cs0.aggregation.bin")
	must(t, e)
	defer sc.Close()
	_, e = LoadSidecar(m, mr, idx, sc)
	must(t, e)
}
