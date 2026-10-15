package discovery

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorindex"
	"pmeq/internal/imdbprod"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetrouting"
	"pmeq/internal/zeroagg"
	"testing"
	"time"
)

func TestMovieTokenRejectsDifferentProductionKeysBeforeTicketUse(t *testing.T) {
	u := &UserPacket{g: &guard{}, movieBinding: [32]byte{1}, keyFingerprint: imdbprod.KeyFingerprint([32]byte{1}, [32]byte{2})}
	_, err := generate(Query{}, UserKeys{Anchor: anchorindex.Key([32]byte{3})}, u, targetrouting.Manifest{})
	if err != ErrBinding || u.g.used {
		t.Fatal("wrong production key accepted or ticket burned", err)
	}
}

func movieTestBinding(t *testing.T) imdbprod.Binding {
	t.Helper()
	d, err := imdbprod.Production().DigestHex()
	if err != nil {
		t.Fatal(err)
	}
	return imdbprod.Binding{Version: imdbprod.Version, ContractSHA256: d,
		SourceManifestSHA256: imdbprod.SourceManifestSHA256, MotherDatabaseSHA256: imdbprod.MotherDatabaseSHA256,
		IdentityMapSHA256: imdbprod.IdentityMapSHA256, TargetMapSHA256: imdbprod.TargetMapSHA256,
		KeyFingerprint: imdbprod.KeyFingerprint([32]byte{1}, [32]byte{2}),
		IndexID:        [16]byte{1}, LayoutID: [16]byte{2}}
}

func movieTestPair(t *testing.T, bucket uint32, layout [16]byte, n int) (AnchorStatic, AnchorStatic, []uint32) {
	t.Helper()
	pi := make([]uint32, n)
	for i := range pi {
		pi[i] = uint32(i)
	}
	pi[0], pi[5] = pi[5], pi[0]
	s0, s1, err := aggregation.SplitPermutation(layout, bucket, pi)
	if err != nil {
		t.Fatal(err)
	}
	var z anchorindex.Value
	z[0], z[1] = byte(bucket>>8), byte(bucket)
	g0 := indexbuild.AnchorPartyGroup{Z: z, PadWidth: 4, Slots: make([]indexbuild.AnchorPartySlot, 4)}
	g1 := indexbuild.AnchorPartyGroup{Z: z, PadWidth: 4, Slots: make([]indexbuild.AnchorPartySlot, 4)}
	a := AnchorStatic{Bucket: indexbuild.AnchorPartyBucket{BucketID: bucket, Groups: []indexbuild.AnchorPartyGroup{g0}}, D: 4, T: 4, Labels: []zeroagg.F{1, 2, 3, 4}, LabelID: "00000000000000000000000000000001", Stage0: s0}
	b := AnchorStatic{Bucket: indexbuild.AnchorPartyBucket{BucketID: bucket, Groups: []indexbuild.AnchorPartyGroup{g1}}, D: 4, T: 4, Labels: []zeroagg.F{5, 6, 7, 8}, LabelID: a.LabelID, Stage1: s1}
	return a, b, pi
}

func TestMovieAnchorStoreResumeLazyAndPermutation(t *testing.T) {
	start := time.Now()
	binding := movieTestBinding(t)
	root := t.TempDir()
	w, err := NewMovieAnchorWriter(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	a, b, pi := movieTestPair(t, 17, binding.LayoutID, imdbprod.AnchorObjects)
	if err = w.PutPair(17, a, b); err != nil {
		t.Fatal(err)
	}
	incomplete, err := os.ReadFile(filepath.Join(root, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenMovieAnchorStore(root, 0, sha256.Sum256(incomplete), binding); err == nil {
		t.Fatal("incomplete catalog accepted")
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	w, err = NewMovieAnchorWriter(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !w.Has(17) || w.Has(18) {
		t.Fatal("resume list")
	}
	if err = w.PutPair(17, a, b); err == nil {
		t.Fatal("duplicate bucket regenerated")
	}
	a2, b2, _ := movieTestPair(t, 19, binding.LayoutID, imdbprod.AnchorObjects)
	if err = w.PutPair(19, a2, b2); err != nil {
		t.Fatal(err)
	}
	h, err := w.Seal([]indexbuild.BucketMetadata{{BucketID: 17, GroupCount: 1, TotalSlots: 4}, {BucketID: 19, GroupCount: 1, TotalSlots: 4}})
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = NewMovieAnchorWriter(root, binding); err == nil {
		t.Fatal("sealed catalog resumed")
	}
	s0, err := OpenMovieAnchorStore(root, 0, h, binding)
	if err != nil {
		t.Fatal(err)
	}
	s1, err := OpenMovieAnchorStore(root, 1, h, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s1.Meta(18); ok {
		t.Fatal("empty bucket claimed")
	}
	if _, err = s1.Load(18); err == nil {
		t.Fatal("empty bucket loaded")
	}
	if _, err = OpenMovieAnchorStore(root, 1, [32]byte{1}, binding); err == nil {
		t.Fatal("catalog hash ignored")
	}
	bad := binding
	bad.LayoutID[0]++
	if _, err = OpenMovieAnchorStore(root, 1, h, bad); err == nil {
		t.Fatal("wrong layout accepted")
	}
	loaded0, err := s0.Load(17)
	if err != nil {
		t.Fatal(err)
	}
	loaded1, err := s1.Load(17)
	if err != nil {
		t.Fatal(err)
	}
	p0, p1, err := aggregation.PreprocessPermutation(loaded0.Stage0, loaded1.Stage1)
	if err != nil {
		t.Fatal(err)
	}
	loaded1.Stage1.Discard() // offline packet must not retain the original sigma
	x := []incidence.Share{incidence.NewShare(1), incidence.NewShare(2), incidence.NewShare(3), incidence.NewShare(4)}
	d1, err := p1.Message1(nil)
	if err != nil {
		t.Fatal(err)
	}
	d2, y0, err := loaded0.Stage0.Message2(p0, x, d1)
	if err != nil {
		t.Fatal(err)
	}
	loaded1, err = s1.Load(17)
	if err != nil {
		t.Fatal(err)
	}
	y1, err := loaded1.Stage1.Finish(p1, d2)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range x {
		if y0[pi[i]].Value().Add(y1[pi[i]].Value()) != v.Value() {
			t.Fatal("permutation equation", i)
		}
	}
	if _, err = loaded1.Stage1.Finish(p1, d2); err == nil {
		t.Fatal("material reused")
	}
	loaded1.Stage1.Discard()
	if _, err = s1.Load(17); err != nil {
		t.Fatal("repeat independent read", err)
	}
	m, _ := s1.Meta(17)
	path := movieAnchorPath(root, 1, 17, m.SHA256[1])
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s1.Load(17); err == nil {
		t.Fatal("damaged BS02 accepted")
	}
	if _, err = s0.Load(17); err != nil {
		t.Fatal("peer file damaged by role test", err)
	}
	if _, err = readAnchorStaticFileAsWrongRole(root, m, binding); err == nil {
		t.Fatal("cross-role file accepted")
	}
	info, err := os.Stat(filepath.Join(root, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("bucket=17 party_bytes=%d,%d catalog_bytes=%d elapsed=%s", m.Bytes[0], m.Bytes[1], info.Size(), time.Since(start))
}

func readAnchorStaticFileAsWrongRole(root string, m AnchorArtifact, binding imdbprod.Binding) (AnchorStatic, error) {
	f, err := os.Open(movieAnchorPath(root, 0, m.Bucket, m.SHA256[0]))
	if err != nil {
		return AnchorStatic{}, err
	}
	defer f.Close()
	return ReadAnchorStatic(f, binding.IndexID, binding.LayoutID, 1, imdbprod.AnchorObjects, m)
}

func TestMovieAnchorCatalogRejectsLegacyVersion(t *testing.T) {
	binding := movieTestBinding(t)
	root := t.TempDir()
	w, err := NewMovieAnchorWriter(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	path := filepath.Join(root, "catalog.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A syntactically valid old format must not be resumed or loaded.
	var c movieAnchorCatalog
	if err = json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.Version = "IMDB-BS02-BUCKETS-v0"
	changed, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = NewMovieAnchorWriter(root, binding); err == nil {
		t.Fatal("legacy writer resume")
	}
	if _, err = OpenMovieAnchorStore(root, 0, sha256.Sum256(changed), binding); err == nil {
		t.Fatal("legacy loader")
	}
}

func TestMovieAnchorWriterRejectsCorruptCommittedBucketOnResume(t *testing.T) {
	binding := movieTestBinding(t)
	root := t.TempDir()
	w, err := NewMovieAnchorWriter(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	a, b, _ := movieTestPair(t, 17, binding.LayoutID, imdbprod.AnchorObjects)
	if err = w.PutPair(17, a, b); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog movieAnchorCatalog
	if err = json.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	path := movieAnchorPath(root, 1, 17, catalog.Buckets[0].SHA256[1])
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteAt([]byte{0xff}, 60); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if writer, err := NewMovieAnchorWriter(root, binding); err == nil {
		writer.Close()
		t.Fatal("corrupted committed bucket skipped on resume")
	}
}

func TestMovieAnchorWriterResumesAfterUncommittedPartyFile(t *testing.T) {
	binding := movieTestBinding(t)
	root := t.TempDir()
	w, err := NewMovieAnchorWriter(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	a, b, _ := movieTestPair(t, 23, binding.LayoutID, imdbprod.AnchorObjects)
	if _, _, _, err = w.writeOne(0, 23, a); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	w, err = NewMovieAnchorWriter(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	if w.Has(23) {
		t.Fatal("uncommitted party file treated as committed pair")
	}
	if err = w.PutPair(23, a, b); err != nil {
		t.Fatal(err)
	}
	h, err := w.Seal([]indexbuild.BucketMetadata{{BucketID: 23, GroupCount: 1, TotalSlots: 4}})
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	for party := uint8(0); party < 2; party++ {
		s, e := OpenMovieAnchorStore(root, party, h, binding)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = s.Load(23); e != nil {
			t.Fatal(e)
		}
	}
}
