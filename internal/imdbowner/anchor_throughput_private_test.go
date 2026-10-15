package imdbowner

import (
	"os"
	"path/filepath"
	"pmeq/internal/aggregation"
	"pmeq/internal/discovery"
	"pmeq/internal/imdbprod"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetartifact"
	"testing"
	"time"
)

// Opt-in owner-only 128-bucket probe of the real frozen keyed layout. It
// never adopts or seals the production anchor directory.
func TestPrivateAnchorBuildThroughput128(t *testing.T) {
	if os.Getenv("PMEQ_ANCHOR_THROUGHPUT") != "1" {
		t.Skip("opt-in real 128-bucket throughput probe")
	}
	targetRoot := os.Getenv("PMEQ_IMDB_TARGET_STAGE")
	if targetRoot == "" {
		t.Fatal("sealed target stage path required")
	}
	gate, err := CheckProduction("../../imdb_production_20261015", "../../.private/imdb-production-keypair.json", "../../.private/imdb-key-backup-receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	seal, err := VerifyTargetStage(targetRoot, gate.Freeze, gate.Keys)
	if err != nil {
		t.Fatal(err)
	}
	areas, joins, _, err := gate.Mapping.IndexInputs()
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]uint64, len(areas))
	for i := range areas {
		ids[i] = areas[i].ID
	}
	var payloads [2]aggregation.PartyPayload
	for party := uint8(0); party < 2; party++ {
		f, e := os.Open(filepath.Join(targetRoot, "cs"+string(rune('0'+party))+".payload.bin"))
		if e != nil {
			t.Fatal(e)
		}
		payloads[party], e = targetartifact.ReadPayload(f, seal.Target, party, seal.Binding.LayoutID, imdbprod.AnchorObjects)
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	dealer, err := aggregation.RestoreDealerLayoutFromPayload(ids, payloads[0], payloads[1])
	if err != nil {
		t.Fatal(err)
	}
	selected := make(map[uint32]bool, 128)
	expected := make([]indexbuild.BucketMetadata, 0, 128)
	for i := 0; i < 128; i++ {
		meta := gate.Layout.Metadata.AnchorBuckets[i*len(gate.Layout.Metadata.AnchorBuckets)/128]
		selected[meta.BucketID] = true
		expected = append(expected, meta)
	}
	w, err := discovery.NewMovieAnchorWriter(filepath.Join(t.TempDir(), "anchor"), seal.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	start := time.Now()
	n, err := discovery.WriteMovieAnchorBuckets(w, areas, joins, gate.Keys.Anchor, gate.Keys.Target, dealer, func(bucket uint32) bool { return selected[bucket] }, nil)
	if err != nil || n != 128 {
		t.Fatalf("real buckets built=%d err=%v", n, err)
	}
	if _, err = w.Seal(expected); err != nil {
		t.Fatal(err)
	}
	stats := w.Stats()
	t.Logf("real_anchor_buckets=%d wall=%s cs0_bytes=%d cs1_bytes=%d max_temporary=%d write_wall=%s", n, time.Since(start), stats.PartyBytes[0], stats.PartyBytes[1], stats.MaxTemporaryFileBytes, time.Duration(stats.WriteWallNS))
}
