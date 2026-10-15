package indexbuild

import (
	"errors"
	"sort"

	"pmeq/internal/anchorindex"
	"pmeq/internal/targetcrypto"
)

type TierPopulation struct {
	PadWidth        int
	GroupCount      int
	GroupPercentage float64
	RealOccurrences int
	PaddedSlots     int
	PaddingOverhead int
}

// These are trusted analysis outputs; plaintext identities must never be
// copied into PublicMetadata or either party index.
type AnchorMaxGroup struct {
	QGram                                 string
	Occurrences, PadWidth                 int
	BucketID                              uint32
	BucketGroups, BucketLPad, BucketSlots int
}
type TargetMaxGroup struct {
	JoinID                                uint64
	QGram                                 string
	Occurrences, PadWidth                 int
	BucketID                              uint32
	BucketGroups, BucketLPad, BucketSlots int
}

type LayoutAnalysis struct {
	Metadata                 PublicMetadata
	Anchor, Target           SideStats
	AnchorTiers, TargetTiers []TierPopulation
	AnchorMaxGroup           AnchorMaxGroup
	TargetMaxGroup           TargetMaxGroup
}

// AnalyzeLayout retains the PHASE 3C2 per-bucket-maximum layout strictly as an
// experiment baseline. Production Build does not call this function.
func AnalyzeLayout(areas []AreaRecord, aliases []AreaAliasRecord, kB anchorindex.Key, kT targetcrypto.MasterKey, anchorBits, targetBits int) (LayoutAnalysis, error) {
	return AnalyzeUniformLayout(areas, aliases, kB, kT, anchorBits, targetBits)
}

func AnalyzeUniformLayout(areas []AreaRecord, aliases []AreaAliasRecord, kB anchorindex.Key, kT targetcrypto.MasterKey, anchorBits, targetBits int) (LayoutAnalysis, error) {
	anchors, targets, stats, err := layoutLogical(areas, aliases, kB, kT, anchorBits, targetBits)
	if err != nil {
		return LayoutAnalysis{}, err
	}
	return analyzeUniformFromLogical(anchors, targets, stats, anchorBits, targetBits)
}

// AnalyzeLayouts computes both layouts from one shared logical grouping pass.
func AnalyzeLayouts(areas []AreaRecord, aliases []AreaAliasRecord, kB anchorindex.Key, kT targetcrypto.MasterKey, anchorBits, targetBits int) (LayoutAnalysis, LayoutAnalysis, error) {
	anchors, targets, stats, err := layoutLogical(areas, aliases, kB, kT, anchorBits, targetBits)
	if err != nil {
		return LayoutAnalysis{}, LayoutAnalysis{}, err
	}
	uniform, err := analyzeUniformFromLogical(anchors, targets, stats, anchorBits, targetBits)
	if err != nil {
		return LayoutAnalysis{}, LayoutAnalysis{}, err
	}
	tier, err := analyzeTierFromLogical(anchors, targets, stats, anchorBits, targetBits)
	return uniform, tier, err
}

func analyzeUniformFromLogical(anchors []anchorLogicalGroup, targets []targetLogicalGroup, stats BuildStats, anchorBits, targetBits int) (LayoutAnalysis, error) {
	anchorMeta, anchorLPad := uniformAnchorMetadata(anchors)
	targetMeta, targetLPad := uniformTargetMetadata(targets)
	stats.Anchor.RealSlots, stats.Target.RealSlots = stats.Anchor.QGramOccurrences, stats.Target.QGramOccurrences
	finishUniformStats(&stats.Anchor, anchorMeta, anchorLPad)
	finishUniformStats(&stats.Target, targetMeta, targetLPad)
	analysis := LayoutAnalysis{Metadata: PublicMetadata{Q: Q, AnchorBucketBits: uint8(anchorBits), TargetBucketBits: uint8(targetBits), AnchorBuckets: anchorMeta, TargetBuckets: targetMeta}, Anchor: stats.Anchor, Target: stats.Target}
	analysis.AnchorMaxGroup = largestAnchorGroup(anchors, anchorMeta, anchorLPad, false)
	analysis.TargetMaxGroup = largestTargetGroup(targets, targetMeta, targetLPad, false)
	return analysis, nil
}

// AnalyzeTierLayout evaluates production per-group tiers without allocating
// shares, dummy slots, or point-share arrays.
func AnalyzeTierLayout(areas []AreaRecord, aliases []AreaAliasRecord, kB anchorindex.Key, kT targetcrypto.MasterKey, anchorBits, targetBits int) (LayoutAnalysis, error) {
	anchors, targets, stats, err := layoutLogical(areas, aliases, kB, kT, anchorBits, targetBits)
	if err != nil {
		return LayoutAnalysis{}, err
	}
	return analyzeTierFromLogical(anchors, targets, stats, anchorBits, targetBits)
}

// AnalyzeMovieTierLayout performs the production movie-domain keyed layout
// pass without making shares or generating the secret index. It is safe for a
// bounded-memory DO preflight and uses the same logical builder as BuildMovie.
func AnalyzeMovieTierLayout(areas []AreaRecord, joins []uint64, movies []AreaAliasRecord, kB anchorindex.Key, kT targetcrypto.MasterKey) (LayoutAnalysis, error) {
	if len(areas) != len(joins) {
		return LayoutAnalysis{}, errors.New("indexbuild: object/join input length mismatch")
	}
	anchors, targets, stats, err := buildLogicalProjectionMode(areas, movies, joins, kB, kT, 16, 16, true)
	if err != nil {
		return LayoutAnalysis{}, err
	}
	return analyzeTierFromLogical(anchors, targets, stats, 16, 16)
}

func analyzeTierFromLogical(anchors []anchorLogicalGroup, targets []targetLogicalGroup, stats BuildStats, anchorBits, targetBits int) (LayoutAnalysis, error) {
	anchorMeta, anchorWidths, anchorTiers, err := tierAnchorMetadata(anchors)
	if err != nil {
		return LayoutAnalysis{}, err
	}
	targetMeta, targetWidths, targetTiers, err := tierTargetMetadata(targets)
	if err != nil {
		return LayoutAnalysis{}, err
	}
	stats.Anchor.RealSlots, stats.Target.RealSlots = stats.Anchor.QGramOccurrences, stats.Target.QGramOccurrences
	finishTierStats(&stats.Anchor, anchorMeta, anchorWidths)
	finishTierStats(&stats.Target, targetMeta, targetWidths)
	analysis := LayoutAnalysis{Metadata: PublicMetadata{Q: Q, AnchorBucketBits: uint8(anchorBits), TargetBucketBits: uint8(targetBits), AnchorBuckets: anchorMeta, TargetBuckets: targetMeta}, Anchor: stats.Anchor, Target: stats.Target, AnchorTiers: anchorTiers, TargetTiers: targetTiers}
	analysis.AnchorMaxGroup = largestAnchorGroup(anchors, anchorMeta, nil, true)
	analysis.TargetMaxGroup = largestTargetGroup(targets, targetMeta, nil, true)
	return analysis, nil
}

func layoutLogical(areas []AreaRecord, aliases []AreaAliasRecord, kB anchorindex.Key, kT targetcrypto.MasterKey, anchorBits, targetBits int) ([]anchorLogicalGroup, []targetLogicalGroup, BuildStats, error) {
	if _, err := AnchorBucket(anchorindex.Value{}, anchorBits); err != nil {
		return nil, nil, BuildStats{}, err
	}
	if _, err := targetcrypto.JoinBucketComponent(kT, 0, targetBits); err != nil {
		return nil, nil, BuildStats{}, err
	}
	return buildLogical(areas, aliases, kB, kT, anchorBits, targetBits)
}

func uniformAnchorMetadata(groups []anchorLogicalGroup) ([]BucketMetadata, map[uint32]int) {
	counts, lpads := map[uint32]int{}, map[uint32]int{}
	for _, g := range groups {
		counts[g.bucket]++
		if len(g.postings) > lpads[g.bucket] {
			lpads[g.bucket] = len(g.postings)
		}
	}
	return uniformMetadata(counts, lpads), lpads
}
func uniformTargetMetadata(groups []targetLogicalGroup) ([]BucketMetadata, map[uint32]int) {
	counts, lpads := map[uint32]int{}, map[uint32]int{}
	for _, g := range groups {
		counts[g.bucket]++
		if len(g.postings) > lpads[g.bucket] {
			lpads[g.bucket] = len(g.postings)
		}
	}
	return uniformMetadata(counts, lpads), lpads
}
func uniformMetadata(counts, lpads map[uint32]int) []BucketMetadata {
	by := make(map[uint32]BucketMetadata, len(counts))
	for id, count := range counts {
		by[id] = BucketMetadata{BucketID: id, GroupCount: uint32(count), TotalSlots: uint64(count * lpads[id])}
	}
	return sortedBucketMetadata(by)
}

func tierAnchorMetadata(groups []anchorLogicalGroup) ([]BucketMetadata, []int, []TierPopulation, error) {
	by := map[uint32]BucketMetadata{}
	widths := make([]int, 0, len(groups))
	pop := newTierPopulation()
	for _, g := range groups {
		w, err := TierWidth(len(g.postings))
		if err != nil {
			return nil, nil, nil, err
		}
		widths = append(widths, w)
		addTierPopulation(pop, w, len(g.postings))
		m := by[g.bucket]
		m.BucketID = g.bucket
		m.GroupCount++
		m.TotalSlots += uint64(w)
		by[g.bucket] = m
	}
	return sortedBucketMetadata(by), widths, finishTierPopulation(pop, len(groups)), nil
}
func tierTargetMetadata(groups []targetLogicalGroup) ([]BucketMetadata, []int, []TierPopulation, error) {
	by := map[uint32]BucketMetadata{}
	widths := make([]int, 0, len(groups))
	pop := newTierPopulation()
	for _, g := range groups {
		w, err := TierWidth(len(g.postings))
		if err != nil {
			return nil, nil, nil, err
		}
		widths = append(widths, w)
		addTierPopulation(pop, w, len(g.postings))
		m := by[g.bucket]
		m.BucketID = g.bucket
		m.GroupCount++
		m.TotalSlots += uint64(w)
		by[g.bucket] = m
	}
	return sortedBucketMetadata(by), widths, finishTierPopulation(pop, len(groups)), nil
}

func newTierPopulation() map[int]*TierPopulation {
	out := make(map[int]*TierPopulation, len(tierLadder))
	for _, w := range tierLadder {
		out[w] = &TierPopulation{PadWidth: w}
	}
	return out
}
func addTierPopulation(p map[int]*TierPopulation, w, real int) {
	x := p[w]
	x.GroupCount++
	x.RealOccurrences += real
	x.PaddedSlots += w
}
func finishTierPopulation(p map[int]*TierPopulation, total int) []TierPopulation {
	out := make([]TierPopulation, 0, len(tierLadder))
	for _, w := range tierLadder {
		x := *p[w]
		x.GroupPercentage = 100 * float64(x.GroupCount) / float64(total)
		x.PaddingOverhead = x.PaddedSlots - x.RealOccurrences
		out = append(out, x)
	}
	return out
}

func finishUniformStats(stats *SideStats, buckets []BucketMetadata, lpads map[uint32]int) {
	stats.NonemptyBuckets = len(buckets)
	groups := make([]int, len(buckets))
	pads := make([]int, len(buckets))
	slots := make([]int, len(buckets))
	for i, b := range buckets {
		groups[i] = int(b.GroupCount)
		pads[i] = lpads[b.BucketID]
		slots[i] = int(b.TotalSlots)
		stats.PaddedSlots += slots[i]
	}
	stats.GroupCount = distribution(groups)
	stats.LPad = distribution(pads)
	stats.SlotsPerBucket = distribution(slots)
	if stats.RealSlots > 0 {
		stats.PaddingRatio = float64(stats.PaddedSlots) / float64(stats.RealSlots)
	}
}
func sortedBucketMetadata(by map[uint32]BucketMetadata) []BucketMetadata {
	out := make([]BucketMetadata, 0, len(by))
	for _, m := range by {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BucketID < out[j].BucketID })
	return out
}
func metadataMap(b []BucketMetadata) map[uint32]BucketMetadata {
	out := make(map[uint32]BucketMetadata, len(b))
	for _, x := range b {
		out[x.BucketID] = x
	}
	return out
}

func largestAnchorGroup(groups []anchorLogicalGroup, buckets []BucketMetadata, lpads map[uint32]int, tiered bool) AnchorMaxGroup {
	by := metadataMap(buckets)
	var out AnchorMaxGroup
	for _, g := range groups {
		if len(g.postings) <= out.Occurrences {
			continue
		}
		b := by[g.bucket]
		pad, lpad := lpads[g.bucket], lpads[g.bucket]
		if tiered {
			pad, _ = TierWidth(len(g.postings))
			lpad = 0
		}
		out = AnchorMaxGroup{g.qgram, len(g.postings), pad, g.bucket, int(b.GroupCount), lpad, int(b.TotalSlots)}
	}
	return out
}
func largestTargetGroup(groups []targetLogicalGroup, buckets []BucketMetadata, lpads map[uint32]int, tiered bool) TargetMaxGroup {
	by := metadataMap(buckets)
	var out TargetMaxGroup
	for _, g := range groups {
		if len(g.postings) <= out.Occurrences {
			continue
		}
		b := by[g.bucket]
		pad, lpad := lpads[g.bucket], lpads[g.bucket]
		if tiered {
			pad, _ = TierWidth(len(g.postings))
			lpad = 0
		}
		out = TargetMaxGroup{g.joinID, g.qgram, len(g.postings), pad, g.bucket, int(b.GroupCount), lpad, int(b.TotalSlots)}
	}
	return out
}
