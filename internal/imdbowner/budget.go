package imdbowner

import (
	"pmeq/internal/imdbprod"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetpe"
)

// Budget gives deterministic byte counts for the current keyed layout and
// fixed public query envelope. OfflineFieldBytes is a lower bound on all-party
// serialized fields; it excludes Go object overhead, framing and anchor zero
// material, so it is never used as a memory-safe launch threshold by itself.
type Budget struct {
	AnchorCS0Bytes       uint64
	AnchorCS1Bytes       uint64
	MaxAnchorBucketBytes uint64
	OfflineFieldBytes    uint64
	TargetPositionBytes  uint64
	TargetAggregateBytes uint64
}

func Estimate(layout indexbuild.LayoutAnalysis) (Budget, error) {
	if len(layout.Metadata.AnchorBuckets) == 0 || len(layout.Metadata.TargetBuckets) == 0 ||
		layout.Metadata.AnchorBucketBits != imdbprod.BucketBits ||
		layout.Metadata.TargetBucketBits != imdbprod.BucketBits {
		return Budget{}, ErrBuild
	}
	buckets := uint64(len(layout.Metadata.AnchorBuckets))
	groups := uint64(layout.Anchor.LogicalGroups)
	slots := uint64(layout.Anchor.PaddedSlots)
	// BS02 header 65, Z/P 20 per group, each secret-shared slot 47,
	// GF16 label 2 per slot, label ID 16 per bucket.
	base := buckets*(65+16) + groups*20 + slots*(47+2)
	out := Budget{AnchorCS0Bytes: base + buckets*32,
		AnchorCS1Bytes: base + buckets*uint64(imdbprod.AnchorObjects)*4}
	for _, b := range layout.Metadata.AnchorBuckets {
		one := uint64(65+16+imdbprod.AnchorObjects*4) + uint64(b.GroupCount)*20 + uint64(b.TotalSlots)*49
		if one > out.MaxAnchorBucketBytes {
			out.MaxAnchorBucketBytes = one
		}
	}
	k, r, d := uint64(imdbprod.CandidateCapacity), uint64(imdbprod.TargetSignatures), uint64(imdbprod.TargetDimension)
	s, g := k*r*uint64(imdbprod.TargetBucketSlots), k*uint64(imdbprod.TargetBucketSlots)
	z, m := k*r*d, k*d
	// Two 368-byte Bin10 native keys per slot and party, masks and F2 triples.
	out.TargetPositionBytes = 2 * ((2*368+2+8)*s + 6*s)
	// Existing targetaggregation.Preprocess field accounting: Z128, Bin7
	// comparisons, seven Ring64 stages and F2 representative triples.
	out.TargetAggregateBytes = (6+2+4*d)*s + 6*z +
		(2*284+4)*(z+m) + 48*(g+d*g+2*z+3*m) + 6*z
	pe := uint64(12240 * targetpe.Words(int(g)))
	compaction := uint64((6*43 + 8) * imdbprod.AnchorObjects)
	anchorComparison := uint64((2*284 + 2 + 2) * imdbprod.AnchorObjects)
	out.OfflineFieldBytes = out.TargetPositionBytes + out.TargetAggregateBytes + pe + compaction + anchorComparison
	return out, nil
}
