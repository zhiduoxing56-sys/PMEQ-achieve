// Command imdb_keyed_layout performs a DO-only, no-sharing layout preflight.
// It writes keyed bucket IDs only to the ignored local output path.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"pmeq/internal/imdbkeys"
	"pmeq/internal/imdbprod"
	"pmeq/internal/indexbuild"
	"sort"
	"time"
)

type envelope struct {
	Version                 string                      `json:"version"`
	KeyFingerprint          string                      `json:"key_fingerprint"`
	SampleAnchorSHA256      string                      `json:"sample_anchor_sha256"`
	SampleTargetSHA256      string                      `json:"sample_target_sha256"`
	ElapsedSeconds          float64                     `json:"elapsed_seconds"`
	Anchor                  indexbuild.SideStats        `json:"anchor"`
	Target                  indexbuild.SideStats        `json:"target"`
	MaxTargetGroups         int                         `json:"max_target_groups"`
	MaxTargetSlots          int                         `json:"max_target_slots"`
	TargetWithinFixedBudget bool                        `json:"target_within_fixed_budget"`
	RepresentativeBuckets   map[string]uint32           `json:"representative_buckets"`
	AnchorBuckets           []indexbuild.BucketMetadata `json:"anchor_buckets"`
	TargetBuckets           []indexbuild.BucketMetadata `json:"target_buckets"`
}

func main() {
	keys := flag.String("keys", ".private/imdb-production-keypair.json", "private DO key file")
	sample := flag.String("sample", "imdb_production_20261015", "frozen sample directory")
	output := flag.String("output", ".private/imdb-keyed-layout-v3.json", "private output file, created exclusively")
	flag.Parse()
	if filepath.Clean(filepath.Dir(*output)) != ".private" {
		panic("output must remain in the ignored local .private directory")
	}
	start := time.Now()
	pair, err := imdbkeys.Load(*keys)
	if err != nil {
		panic(err)
	}
	m, _, err := imdbprod.LoadFrozen(*sample)
	if err != nil {
		panic(err)
	}
	areas, joins, movies, err := m.IndexInputs()
	if err != nil {
		panic(err)
	}
	analysis, err := indexbuild.AnalyzeMovieTierLayout(areas, joins, movies, pair.Anchor, pair.Target)
	if err != nil {
		panic(err)
	}
	a := analysis.Metadata.AnchorBuckets
	t := analysis.Metadata.TargetBuckets
	result := envelope{Version: imdbprod.Version, KeyFingerprint: pair.Fingerprint,
		SampleAnchorSHA256: imdbprod.AnchorSequenceSHA256, SampleTargetSHA256: imdbprod.TargetSequenceSHA256,
		ElapsedSeconds: time.Since(start).Seconds(), Anchor: analysis.Anchor, Target: analysis.Target,
		RepresentativeBuckets: map[string]uint32{}, AnchorBuckets: a, TargetBuckets: t}
	if len(a) > 0 {
		min, max := a[0], a[0]
		for _, v := range a {
			if v.TotalSlots < min.TotalSlots {
				min = v
			}
			if v.TotalSlots > max.TotalSlots {
				max = v
			}
		}
		result.RepresentativeBuckets["small"] = min.BucketID
		result.RepresentativeBuckets["high"] = max.BucketID
		for i := uint32(0); i < 1<<imdbprod.BucketBits; i++ {
			j := sort.Search(len(a), func(j int) bool { return a[j].BucketID >= i })
			if j == len(a) || a[j].BucketID != i {
				result.RepresentativeBuckets["empty"] = i
				break
			}
		}
	}
	for _, v := range t {
		if int(v.GroupCount) > result.MaxTargetGroups {
			result.MaxTargetGroups = int(v.GroupCount)
		}
		if int(v.TotalSlots) > result.MaxTargetSlots {
			result.MaxTargetSlots = int(v.TotalSlots)
		}
	}
	result.TargetWithinFixedBudget = result.MaxTargetGroups <= imdbprod.TargetBucketGroups && result.MaxTargetSlots <= imdbprod.TargetBucketSlots
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		panic(err)
	}
	raw = append(raw, '\n')
	f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		panic(err)
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		panic(err)
	}
	if closeErr != nil {
		panic(closeErr)
	}
	fmt.Printf("keyed layout complete: anchor buckets=%d target buckets=%d max target groups=%d slots=%d within fixed %d/%d=%t elapsed=%.3fs\n", len(a), len(t), result.MaxTargetGroups, result.MaxTargetSlots, imdbprod.TargetBucketGroups, imdbprod.TargetBucketSlots, result.TargetWithinFixedBudget, result.ElapsedSeconds)
	if !result.TargetWithinFixedBudget {
		os.Exit(3)
	}
}
