package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gtank/ristretto255"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorindex"
	"pmeq/internal/discovery"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetaggregation/gen"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/zeroagg"
)

func TestReverseOfflineCryptoArtifacts(t *testing.T) {
	ak, e := anchorindex.GenerateKey()
	if e != nil {
		t.Fatal(e)
	}
	tk, e := targetcrypto.GenerateMasterKey()
	if e != nil {
		t.Fatal(e)
	}
	z0, e := anchorindex.EncodeMovie(ak, "aaaa")
	if e != nil {
		t.Fatal(e)
	}
	z1, e := anchorindex.EncodeMovieTitle(ak, "aaaa")
	if e != nil || z0 == z1 {
		t.Fatal("anchor table domains not distinct", e)
	}
	w0, e := targetcrypto.KMovieWord(tk, "aaaa")
	if e != nil {
		t.Fatal(e)
	}
	w1, e := targetcrypto.KMoviecastWord(tk, "aaaa")
	if e != nil || bytes.Equal(w0.Bytes(), w1.Bytes()) {
		t.Fatal("target table domains not distinct", e)
	}
	movies := []indexbuild.AreaRecord{{ID: 7, Name: "abcdefgh"}, {ID: 8, Name: "ijklmnop"}}
	joins := []uint64{7, 8}
	casts := []indexbuild.AreaAliasRecord{{ID: 1, Area: 7, Name: "aaaaaaaa"}, {ID: 2, Area: 7, Name: "bbbbbbbb"}, {ID: 3, Area: 8, Name: "cccccccc"}}
	d, mult, e := shape(casts)
	if e != nil || d != 2 || mult != 5 {
		t.Fatalf("shape %d %d %v", d, mult, e)
	}
	layout, e := indexbuild.AnalyzeReverseIMDbTierLayout(movies, joins, casts, ak, tk)
	if e != nil {
		t.Fatal(e)
	}
	var indexID [16]byte
	rand.Read(indexID[:])
	meta, p0, p1, stats, e := indexbuild.BuildMoviecastTarget(casts, tk)
	if e != nil {
		t.Fatal(e)
	}
	joinBucket, e := targetcrypto.JoinBucketComponent(tk, 7, 16)
	if e != nil {
		t.Fatal(e)
	}
	wordBucket, e := targetcrypto.MoviecastWordBucketComponent(tk, "aaaa", 16)
	if e != nil {
		t.Fatal(e)
	}
	wantBucket := uint32(targetcrypto.CombineBucketComponents(joinBucket, wordBucket))
	wantPoint, e := targetcrypto.DeriveMoviecastGroupPoint(tk, 7, "aaaa")
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for bi, b := range p0.TargetBuckets {
		if b.BucketID != wantBucket {
			continue
		}
		for gi, g := range b.Groups {
			peer := p1.TargetBuckets[bi].Groups[gi]
			left, e := ristretto255.NewElement().SetCanonicalBytes(g.TargetKeyShare[:])
			if e != nil {
				t.Fatal(e)
			}
			right, e := ristretto255.NewElement().SetCanonicalBytes(peer.TargetKeyShare[:])
			if e != nil {
				t.Fatal(e)
			}
			point := ristretto255.NewElement().Add(left, right)
			if !bytes.Equal(point.Bytes(), wantPoint.Bytes()) {
				continue
			}
			found = true
			valid := 0
			for si, s := range g.Slots {
				v := bool(s.ValidityShare.Value().Add(peer.Slots[si].ValidityShare.Value()))
				if !v {
					continue
				}
				valid++
				id := uint64(s.RecordIDShare.Value() + peer.Slots[si].RecordIDShare.Value())
				pos := uint32(s.PositionShare.Value() + peer.Slots[si].PositionShare.Value())
				if id != 1 || pos != uint32(valid-1) {
					t.Fatalf("bad posting id=%d pos=%d", id, pos)
				}
			}
			if valid != 5 {
				t.Fatalf("duplicate qgram postings=%d", valid)
			}
		}
	}
	if !found {
		t.Fatal("reverse target group absent")
	}
	if !sameBuckets(meta.TargetBuckets, layout.Metadata.TargetBuckets) {
		t.Fatal("layout mismatch")
	}
	manifest, e := indexbuild.NewTargetManifest(indexID, meta, stats.Target)
	if e != nil {
		t.Fatal(e)
	}
	var files [2][]byte
	for u, p := range []indexbuild.PartyIndex{p0, p1} {
		var b bytes.Buffer
		if e = indexbuild.WriteTargetParty(&b, manifest, uint8(u), p); e != nil {
			t.Fatal(e)
		}
		files[u] = b.Bytes()
		h := sha256.Sum256(files[u])
		manifest.PartyBytes[u] = uint64(len(files[u]))
		manifest.PartySHA256[u] = hex.EncodeToString(h[:])
		if _, e = indexbuild.ReadTargetParty(bytes.NewReader(files[u]), manifest, uint8(u)); e != nil {
			t.Fatal(e)
		}
	}
	raw, e := json.Marshal(manifest)
	if e != nil {
		t.Fatal(e)
	}
	var side [2]bytes.Buffer
	sm, audit, e := gen.BuildReverseOffline(raw, files, casts, [2]io.Writer{&side[0], &side[1]}, d, mult)
	if e != nil || sm.Version != 2 || sm.DTarget != 2 || sm.MaxMultiplicity != 5 || audit.MaxMultiplicity != 5 || audit.RealSlots != uint64(layout.Target.RealSlots) {
		t.Fatalf("matrix %+v %+v %v", sm, audit, e)
	}
	dealer, _, _, e := aggregation.GeneratePayloadWithJoins([]uint64{7, 8}, joins, tk, 16)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	e = indexbuild.VisitMovieTitleAnchorBuckets(movies, joins, ak, tk, nil, func(meta indexbuild.BucketMetadata, b0, b1 indexbuild.AnchorPartyBucket, posts []incidence.Posting) error {
		local, e := incidence.PrepareLayout(posts)
		if e != nil {
			return e
		}
		l0, l1, e := zeroagg.ShareCoordinates(local.Coordinates, local.D)
		if e != nil {
			return e
		}
		s0, s1, e := dealer.Alignment(meta.BucketID, local, posts)
		if e != nil {
			return e
		}
		defer s1.Discard()
		a0 := discovery.AnchorStatic{Bucket: b0, D: local.D, T: len(posts), Labels: l0, LabelID: "00000000000000000000000000000001", Stage0: s0}
		a1 := discovery.AnchorStatic{Bucket: b1, D: local.D, T: len(posts), Labels: l1, LabelID: a0.LabelID, Stage1: s1}
		entry := discovery.AnchorArtifact{Bucket: meta.BucketID, D: local.D, T: len(posts), Groups: int(meta.GroupCount)}
		for u, a := range []discovery.AnchorStatic{a0, a1} {
			var b bytes.Buffer
			var sections [3]uint64
			if e = discovery.WriteAnchorStatic(&b, indexID, dealer.LayoutID, uint8(u), len(movies), a, &sections); e != nil {
				return e
			}
			h := sha256.Sum256(b.Bytes())
			entry.Bytes[u] = uint64(b.Len())
			entry.SHA256[u] = hex.EncodeToString(h[:])
			entry.SectionBytes[u] = sections
			loaded, e := discovery.ReadAnchorStatic(bytes.NewReader(b.Bytes()), indexID, dealer.LayoutID, uint8(u), len(movies), entry)
			if e != nil {
				return e
			}
			if loaded.Stage1 != nil {
				loaded.Stage1.Discard()
			}
		}
		count++
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if count != len(layout.Metadata.AnchorBuckets) {
		t.Fatalf("buckets %d != %d", count, len(layout.Metadata.AnchorBuckets))
	}
}

func TestPublishedReverseArtifacts(t *testing.T) {
	root := os.Getenv("PMEQ_REVERSE_OUT")
	if root == "" {
		t.Skip("set PMEQ_REVERSE_OUT to the published offline-only index")
	}
	raw, e := os.ReadFile(filepath.Join(root, "build-report.json"))
	if e != nil {
		t.Fatal(e)
	}
	var report runReport
	if e = json.Unmarshal(raw, &report); e != nil {
		t.Fatal(e)
	}
	if report.Version != version || report.D != 531 || report.MaxMultiplicity != 5 || len(report.Anchor) != report.AnchorBuckets {
		t.Fatalf("bad report shape: %+v", report)
	}
	var indexID, layoutID [16]byte
	for _, p := range []struct {
		hex string
		dst *[16]byte
	}{{report.IndexID, &indexID}, {report.LayoutID, &layoutID}} {
		b, e := hex.DecodeString(p.hex)
		if e != nil || len(b) != 16 {
			t.Fatal("bad ID", e)
		}
		copy(p.dst[:], b)
	}
	for u := uint8(0); u < 2; u++ {
		f, e := os.Open(filepath.Join(root, fmt.Sprintf("cs%d/target.psmj.bin", u)))
		if e != nil {
			t.Fatal(e)
		}
		p, e := indexbuild.ReadTargetParty(f, report.TargetManifest, u)
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
		if len(p.TargetBuckets) != report.TargetBuckets {
			t.Fatal("target bucket count")
		}
	}
	indices := []int{0, len(report.Anchor) / 2, len(report.Anchor) - 1}
	for _, i := range indices {
		entry := report.Anchor[i]
		for u := uint8(0); u < 2; u++ {
			p := filepath.Join(root, fmt.Sprintf("cs%d/anchor-%05d.bs02", u, entry.Bucket))
			f, e := os.Open(p)
			if e != nil {
				t.Fatal(e)
			}
			a, e := discovery.ReadAnchorStatic(f, indexID, layoutID, u, report.AnchorObjects, entry)
			f.Close()
			if e != nil {
				t.Fatal(e)
			}
			if a.Bucket.BucketID != entry.Bucket || len(a.Bucket.Groups) != entry.Groups {
				t.Fatal("anchor bucket content")
			}
			if a.Stage1 != nil {
				a.Stage1.Discard()
			}
		}
	}
}
