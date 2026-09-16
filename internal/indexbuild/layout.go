package indexbuild

import (
	"sort"

	"pmeq/internal/anchorindex"
	"pmeq/internal/targetcrypto"
)

// AnchorMaxGroup is trusted analysis output. QGram must never be copied into
// PublicMetadata or either party index.
type AnchorMaxGroup struct {
	QGram        string
	Occurrences  int
	BucketID     uint16
	BucketGroups int
	BucketLPad   int
	BucketSlots  int
}

// TargetMaxGroup is trusted analysis output. JoinID and QGram must never be
// copied into PublicMetadata or either party index.
type TargetMaxGroup struct {
	JoinID       uint64
	QGram        string
	Occurrences  int
	BucketID     uint16
	BucketGroups int
	BucketLPad   int
	BucketSlots  int
}

// LayoutAnalysis contains layout-only counts. AnalyzeLayout performs the same
// q-gram extraction, group identity, keyed derivation, and bucket mapping as
// Build, but allocates no party shares, dummy slots, or point-share arrays.
type LayoutAnalysis struct {
	Metadata       PublicMetadata
	Anchor         SideStats
	Target         SideStats
	AnchorMaxGroup AnchorMaxGroup
	TargetMaxGroup TargetMaxGroup
}

// AnalyzeLayout evaluates one pair of bucket widths without materialization.
func AnalyzeLayout(areas []AreaRecord, aliases []AreaAliasRecord, kB anchorindex.Key, kT targetcrypto.MasterKey, anchorBits, targetBits int) (LayoutAnalysis, error) {
	if _, err := AnchorBucket(anchorindex.Value{}, anchorBits); err != nil {
		return LayoutAnalysis{}, err
	}
	if _, err := targetcrypto.JoinBucketComponent(kT, 0, targetBits); err != nil {
		return LayoutAnalysis{}, err
	}
	anchors, targets, stats, err := buildLogical(areas, aliases, kB, kT, anchorBits, targetBits)
	if err != nil {
		return LayoutAnalysis{}, err
	}
	metadata := PublicMetadata{Q: Q, AnchorBucketBits: uint8(anchorBits), TargetBucketBits: uint8(targetBits)}
	metadata.AnchorBuckets = anchorLayoutMetadata(anchors)
	metadata.TargetBuckets = targetLayoutMetadata(targets)
	stats.Anchor.RealSlots = stats.Anchor.QGramOccurrences
	stats.Target.RealSlots = stats.Target.QGramOccurrences
	finishStats(&stats.Anchor, metadata.AnchorBuckets)
	finishStats(&stats.Target, metadata.TargetBuckets)
	analysis := LayoutAnalysis{Metadata: metadata, Anchor: stats.Anchor, Target: stats.Target}
	analysis.AnchorMaxGroup = largestAnchorGroup(anchors, metadata.AnchorBuckets)
	analysis.TargetMaxGroup = largestTargetGroup(targets, metadata.TargetBuckets)
	return analysis, nil
}

func anchorLayoutMetadata(groups []anchorLogicalGroup) []BucketMetadata {
	byBucket := make(map[uint16]BucketMetadata)
	for _, group := range groups {
		metadata := byBucket[group.bucket]
		metadata.BucketID = group.bucket
		metadata.GroupCount++
		if uint32(len(group.postings)) > metadata.LPad {
			metadata.LPad = uint32(len(group.postings))
		}
		byBucket[group.bucket] = metadata
	}
	return sortedBucketMetadata(byBucket)
}

func targetLayoutMetadata(groups []targetLogicalGroup) []BucketMetadata {
	byBucket := make(map[uint16]BucketMetadata)
	for _, group := range groups {
		metadata := byBucket[group.bucket]
		metadata.BucketID = group.bucket
		metadata.GroupCount++
		if uint32(len(group.postings)) > metadata.LPad {
			metadata.LPad = uint32(len(group.postings))
		}
		byBucket[group.bucket] = metadata
	}
	return sortedBucketMetadata(byBucket)
}

func sortedBucketMetadata(byBucket map[uint16]BucketMetadata) []BucketMetadata {
	out := make([]BucketMetadata, 0, len(byBucket))
	for _, metadata := range byBucket {
		out = append(out, metadata)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BucketID < out[j].BucketID })
	return out
}

func largestAnchorGroup(groups []anchorLogicalGroup, buckets []BucketMetadata) AnchorMaxGroup {
	byBucket := metadataMap(buckets)
	var out AnchorMaxGroup
	for _, group := range groups {
		if len(group.postings) <= out.Occurrences {
			continue
		}
		bucket := byBucket[group.bucket]
		out = AnchorMaxGroup{group.qgram, len(group.postings), group.bucket, int(bucket.GroupCount), int(bucket.LPad), int(bucket.GroupCount * bucket.LPad)}
	}
	return out
}

func largestTargetGroup(groups []targetLogicalGroup, buckets []BucketMetadata) TargetMaxGroup {
	byBucket := metadataMap(buckets)
	var out TargetMaxGroup
	for _, group := range groups {
		if len(group.postings) <= out.Occurrences {
			continue
		}
		bucket := byBucket[group.bucket]
		out = TargetMaxGroup{group.joinID, group.qgram, len(group.postings), group.bucket, int(bucket.GroupCount), int(bucket.LPad), int(bucket.GroupCount * bucket.LPad)}
	}
	return out
}

func metadataMap(buckets []BucketMetadata) map[uint16]BucketMetadata {
	out := make(map[uint16]BucketMetadata, len(buckets))
	for _, bucket := range buckets {
		out[bucket.BucketID] = bucket
	}
	return out
}
