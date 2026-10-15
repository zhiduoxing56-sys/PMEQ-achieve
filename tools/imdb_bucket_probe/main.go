// Command imdb_bucket_probe performs bounded real-crypto tests on two keyed
// buckets of the frozen production sample. It never builds the full index.
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"pmeq/internal/aggregation"
	"pmeq/internal/discovery"
	"pmeq/internal/imdbkeys"
	"pmeq/internal/imdbprod"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"runtime"
	"sort"
	"time"
)

type keyedLayout struct {
	Version               string                      `json:"version"`
	KeyFingerprint        string                      `json:"key_fingerprint"`
	SampleAnchorSHA256    string                      `json:"sample_anchor_sha256"`
	SampleTargetSHA256    string                      `json:"sample_target_sha256"`
	RepresentativeBuckets map[string]uint32           `json:"representative_buckets"`
	AnchorBuckets         []indexbuild.BucketMetadata `json:"anchor_buckets"`
}
type bucketCost struct {
	Kind       string    `json:"kind"`
	Groups     uint32    `json:"groups"`
	Slots      uint64    `json:"slots"`
	D          int       `json:"local_domain"`
	PartyBytes [2]uint64 `json:"party_bytes"`
	LoadNS     [2]int64  `json:"load_ns"`
	CryptoNS   int64     `json:"crypto_ns"`
}
type probeResult struct {
	Version             string                          `json:"version"`
	KeyFingerprint      string                          `json:"key_fingerprint"`
	BindingSHA256       string                          `json:"binding_sha256"`
	CatalogSHA256       string                          `json:"catalog_sha256"`
	BuildWallNS         int64                           `json:"build_wall_ns"`
	Writer              discovery.MovieAnchorWriteStats `json:"writer"`
	PeakHeapAllocBytes  uint64                          `json:"sampled_peak_heap_alloc_bytes"`
	PersistentDiskBytes int64                           `json:"persistent_disk_bytes"`
	Buckets             []bucketCost                    `json:"buckets"`
	EmptyBucketRejected bool                            `json:"empty_bucket_rejected"`
	PermutationCorrect  bool                            `json:"permutation_correct"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	keys := flag.String("keys", ".private/imdb-production-keypair.json", "local private key file")
	layoutFile := flag.String("layout", ".private/imdb-keyed-layout-v2.json", "local keyed layout")
	root := flag.String("root", ".private/imdb-bucket-probe-v1", "new private probe directory")
	flag.Parse()
	if filepath.Clean(filepath.Dir(*root)) != ".private" {
		panic("probe root must be in ignored local .private directory")
	}
	pair, err := imdbkeys.Load(*keys)
	must(err)
	raw, err := os.ReadFile(*layoutFile)
	must(err)
	var keyed keyedLayout
	must(json.Unmarshal(raw, &keyed))
	if keyed.Version != imdbprod.Version || keyed.KeyFingerprint != pair.Fingerprint || keyed.SampleAnchorSHA256 != imdbprod.AnchorSequenceSHA256 || keyed.SampleTargetSHA256 != imdbprod.TargetSequenceSHA256 {
		panic("keyed layout binding")
	}
	minID, maxID, emptyID := keyed.RepresentativeBuckets["small"], keyed.RepresentativeBuckets["high"], keyed.RepresentativeBuckets["empty"]
	if minID == maxID {
		panic("representative buckets collapsed")
	}
	selected := map[uint32]bool{minID: true, maxID: true}
	metadata := make([]indexbuild.BucketMetadata, 0, 2)
	for _, m := range keyed.AnchorBuckets {
		if selected[m.BucketID] {
			metadata = append(metadata, m)
		}
	}
	if len(metadata) != 2 {
		panic("missing representative metadata")
	}
	mapping, freeze, err := imdbprod.LoadFrozen("imdb_production_20261015")
	must(err)
	areas, joins, _, err := mapping.IndexInputs()
	must(err)
	ids := make([]uint64, len(areas))
	for i, a := range areas {
		ids[i] = a.ID
	}
	dealer, payload0, payload1, err := aggregation.GeneratePayloadWithJoins(ids, joins, pair.Target, imdbprod.BucketBits)
	must(err)
	// The trusted probe reconstructs gamma from fresh payload shares. It is
	// held only in this process, never persisted or sent to a cloud party.
	gamma := make(map[uint64]uint32, len(payload0.Slots))
	for j := range payload0.Slots {
		id := uint64(payload0.Slots[j].RecordIDShare.Value() + payload1.Slots[j].RecordIDShare.Value())
		gamma[id] = uint32(j)
	}
	var indexID [16]byte
	_, err = rand.Read(indexID[:])
	must(err)
	binding, err := pair.Bind(freeze, indexID, dealer.LayoutID)
	must(err)
	bindingDigest, err := binding.Digest()
	must(err)
	w, err := discovery.NewMovieAnchorWriter(*root, binding)
	must(err)
	started := time.Now()
	type doWitness struct {
		meta     indexbuild.BucketMetadata
		x        []incidence.Share
		expected []bool
		d        int
	}
	witnesses := make(map[uint32]doWitness, 2)
	written, err := discovery.WriteMovieAnchorBuckets(w, areas, joins, pair.Anchor, pair.Target, dealer, func(id uint32) bool { return selected[id] }, func(id uint32, local incidence.DealerLayout, posts []incidence.Posting) error {
		x := make([]incidence.Share, local.D)
		expected := make([]bool, len(ids))
		for i, p := range posts {
			if p.Real {
				x[local.Coordinates[i]] = incidence.NewShare(1)
				j, ok := gamma[p.RecordID]
				if !ok {
					return fmt.Errorf("foreign object in trusted witness")
				}
				expected[j] = true
			}
		}
		for _, m := range metadata {
			if m.BucketID == id {
				witnesses[id] = doWitness{m, x, expected, local.D}
				return nil
			}
		}
		return fmt.Errorf("missing selected metadata")
	})
	must(err)
	if written != 2 {
		panic("did not write both selected buckets")
	}
	buildNS := time.Since(started).Nanoseconds()
	catalogHash, err := w.Seal(metadata)
	must(err)
	stats := w.Stats()
	must(w.Close())
	s0, err := discovery.OpenMovieAnchorStore(*root, 0, catalogHash, binding)
	must(err)
	s1, err := discovery.OpenMovieAnchorStore(*root, 1, catalogHash, binding)
	must(err)
	_, emptyErr := s1.Load(emptyID)
	if emptyErr == nil {
		panic("empty bucket unexpectedly loaded")
	}
	result := probeResult{Version: imdbprod.Version, KeyFingerprint: pair.Fingerprint, BindingSHA256: fmt.Sprintf("%x", bindingDigest), CatalogSHA256: fmt.Sprintf("%x", catalogHash), BuildWallNS: buildNS, Writer: stats, EmptyBucketRejected: true, PermutationCorrect: true}
	var heap runtime.MemStats
	runtime.ReadMemStats(&heap)
	result.PeakHeapAllocBytes = heap.HeapAlloc
	for _, meta := range metadata {
		kind := "small"
		if meta.BucketID == maxID {
			kind = "high"
		}
		witness, ok := witnesses[meta.BucketID]
		if !ok || witness.meta != meta {
			panic("trusted witness missing")
		}
		cost := bucketCost{Kind: kind, Groups: meta.GroupCount, Slots: meta.TotalSlots, D: witness.d}
		start := time.Now()
		a0, e := s0.Load(meta.BucketID)
		must(e)
		cost.LoadNS[0] = time.Since(start).Nanoseconds()
		start = time.Now()
		a1, e := s1.Load(meta.BucketID)
		must(e)
		cost.LoadNS[1] = time.Since(start).Nanoseconds()
		m, _ := s0.Meta(meta.BucketID)
		cost.PartyBytes = m.Bytes
		start = time.Now()
		p0, p1, e := aggregation.PreprocessPermutation(a0.Stage0, a1.Stage1)
		must(e)
		a1.Stage1.Discard()
		d1, e := p1.Message1(nil)
		must(e)
		d2, y0, e := a0.Stage0.Message2(p0, witness.x, d1)
		must(e)
		a1, e = s1.Load(meta.BucketID)
		must(e)
		y1, e := a1.Stage1.Finish(p1, d2)
		must(e)
		for j := range witness.expected {
			want := incidence.Z128(0)
			if witness.expected[j] {
				want = 1
			}
			if got := y0[j].Value().Add(y1[j].Value()); got != want {
				panic(fmt.Sprintf("real bucket permutation mismatch: kind=%s position=%d got=%d want=%d D=%d", kind, j, got, want, witness.d))
			}
		}
		a1.Stage1.Discard()
		cost.CryptoNS = time.Since(start).Nanoseconds()
		result.Buckets = append(result.Buckets, cost)
		runtime.ReadMemStats(&heap)
		if heap.HeapAlloc > result.PeakHeapAllocBytes {
			result.PeakHeapAllocBytes = heap.HeapAlloc
		}
	}
	if len(result.Buckets) != 2 {
		panic("representative visit count")
	}
	err = filepath.Walk(*root, func(_ string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if info.Mode().IsRegular() {
			result.PersistentDiskBytes += info.Size()
		}
		return nil
	})
	must(err)
	sort.Slice(result.Buckets, func(i, j int) bool { return result.Buckets[i].Kind < result.Buckets[j].Kind })
	out, err := json.MarshalIndent(result, "", "  ")
	must(err)
	out = append(out, '\n')
	f, err := os.OpenFile(filepath.Join(*root, "probe-result.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(err)
	_, err = f.Write(out)
	must(err)
	must(f.Sync())
	must(f.Close())
	fmt.Printf("real bucket probe: %d buckets, empty rejected, permutation correct, build %.3fs, disk %d bytes\n", len(result.Buckets), float64(buildNS)/1e9, result.PersistentDiskBytes)
}
