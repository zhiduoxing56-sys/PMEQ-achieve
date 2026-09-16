package indexbuild

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/gtank/ristretto255"
	"pmeq/internal/anchorindex"
	"pmeq/internal/domain"
	"pmeq/internal/preprocess"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
)

const Q = 4

type AnchorPartySlot struct {
	RecordIDShare   share.Ring64Share
	PositionShare   share.Ring32Share
	ValidityShare   share.BitShare
	KappaJoinShare  targetcrypto.ScalarShare
	BucketJoinShare targetcrypto.BucketShare
}
type TargetPartySlot struct {
	RecordIDShare share.Ring64Share
	PositionShare share.Ring32Share
	ValidityShare share.BitShare
}
type AnchorPartyGroup struct {
	Z     anchorindex.Value
	Slots []AnchorPartySlot
}
type TargetPartyGroup struct {
	TargetKeyShare targetcrypto.PointShare
	Slots          []TargetPartySlot
}
type AnchorPartyBucket struct {
	BucketID uint16
	LPad     uint32
	Groups   []AnchorPartyGroup
}
type TargetPartyBucket struct {
	BucketID uint16
	LPad     uint32
	Groups   []TargetPartyGroup
}
type PartyIndex struct {
	AnchorBuckets []AnchorPartyBucket
	TargetBuckets []TargetPartyBucket
}
type BucketMetadata struct {
	BucketID   uint16
	LPad       uint32
	GroupCount uint32
}
type PublicMetadata struct {
	Q                uint32
	AnchorBucketBits uint8
	TargetBucketBits uint8
	AnchorBuckets    []BucketMetadata
	TargetBuckets    []BucketMetadata
}
type Distribution struct {
	Min int
	P50 int
	P95 int
	P99 int
	Max int
}
type SideStats struct {
	RawRecords       int
	ShortStrings     int
	QGramOccurrences int
	LogicalGroups    int
	NonemptyBuckets  int
	GroupCount       Distribution
	LPad             Distribution
	SlotsPerBucket   Distribution
	RealSlots        int
	PaddedSlots      int
	PaddingRatio     float64
}
type BuildStats struct {
	Anchor           SideStats
	Target           SideStats
	LogicalBuildTime time.Duration
	SharingPadTime   time.Duration
	TotalBuildTime   time.Duration
}

type anchorPosting struct {
	recordID uint64
	position uint32
}
type anchorLogicalGroup struct {
	qgram    string
	z        anchorindex.Value
	bucket   uint16
	postings []anchorPosting
}
type targetPosting struct {
	recordID uint64
	position uint32
}
type targetLogicalGroup struct {
	joinID   uint64
	qgram    string
	target   *ristretto255.Element
	bucket   uint16
	postings []targetPosting
}
type targetIdentity struct {
	joinID uint64
	qgram  string
}

var (
	splitRing64 = preprocess.SplitRing64
	splitRing32 = preprocess.SplitRing32
	splitBit    = preprocess.SplitBit
	splitScalar = targetcrypto.SplitScalar
	splitBucket = targetcrypto.SplitBucketComponent
	splitPoint  = targetcrypto.SplitPoint
)

// AnchorBucket takes the first k bits of z, most-significant bit first.
func AnchorBucket(z anchorindex.Value, k int) (uint16, error) {
	if k < targetcrypto.MinBucketBits || k > targetcrypto.MaxBucketBits {
		return 0, targetcrypto.ErrBucketBits
	}
	bytesNeeded := (k + 7) / 8
	var value uint32
	for i := 0; i < bytesNeeded; i++ {
		value = value<<8 | uint32(z[i])
	}
	return uint16(value >> uint(bytesNeeded*8-k)), nil
}

// VisitQGrams emits every q=4 Unicode-code-point occurrence, including repeats.
func VisitQGrams(s string, visit func(string, uint32)) bool {
	runes := []rune(s)
	if len(runes) < Q {
		return false
	}
	for i := 0; i+Q <= len(runes); i++ {
		visit(string(runes[i:i+Q]), uint32(i))
	}
	return true
}

// Build constructs both in-memory party indexes inside the trusted DO boundary.
func Build(areas []AreaRecord, aliases []AreaAliasRecord, kB anchorindex.Key, kT targetcrypto.MasterKey, anchorBits, targetBits int) (PublicMetadata, PartyIndex, PartyIndex, BuildStats, error) {
	started := time.Now()
	if _, err := AnchorBucket(anchorindex.Value{}, anchorBits); err != nil {
		return PublicMetadata{}, PartyIndex{}, PartyIndex{}, BuildStats{}, err
	}
	if _, err := targetcrypto.JoinBucketComponent(kT, 0, targetBits); err != nil {
		return PublicMetadata{}, PartyIndex{}, PartyIndex{}, BuildStats{}, err
	}
	anchorGroups, targetGroups, stats, err := buildLogical(areas, aliases, kB, kT, anchorBits, targetBits)
	if err != nil {
		return PublicMetadata{}, PartyIndex{}, PartyIndex{}, BuildStats{}, err
	}
	stats.LogicalBuildTime = time.Since(started)
	sharingStarted := time.Now()
	metadata, cs0, cs1, err := shareAndPad(anchorGroups, targetGroups, kT, anchorBits, targetBits, &stats)
	if err != nil {
		return PublicMetadata{}, PartyIndex{}, PartyIndex{}, BuildStats{}, err
	}
	stats.SharingPadTime = time.Since(sharingStarted)
	stats.TotalBuildTime = time.Since(started)
	return metadata, cs0, cs1, stats, nil
}

func buildLogical(areas []AreaRecord, aliases []AreaAliasRecord, kB anchorindex.Key, kT targetcrypto.MasterKey, anchorBits, targetBits int) ([]anchorLogicalGroup, []targetLogicalGroup, BuildStats, error) {
	stats := BuildStats{Anchor: SideStats{RawRecords: len(areas)}, Target: SideStats{RawRecords: len(aliases)}}
	am := make(map[string]*anchorLogicalGroup)
	for _, record := range areas {
		if !VisitQGrams(record.Name, func(qgram string, position uint32) {
			stats.Anchor.QGramOccurrences++
			group := am[qgram]
			if group == nil {
				group = &anchorLogicalGroup{qgram: qgram}
				am[qgram] = group
			}
			group.postings = append(group.postings, anchorPosting{record.ID, position})
		}) {
			stats.Anchor.ShortStrings++
		}
	}
	anchors := make([]anchorLogicalGroup, 0, len(am))
	zSeen := make(map[anchorindex.Value]string)
	for qgram, group := range am {
		z, err := anchorindex.Encode(kB, qgram)
		if err != nil {
			return nil, nil, stats, err
		}
		if old, ok := zSeen[z]; ok && old != qgram {
			return nil, nil, stats, fmt.Errorf("anchor value collision")
		}
		zSeen[z] = qgram
		bucket, err := AnchorBucket(z, anchorBits)
		if err != nil {
			return nil, nil, stats, err
		}
		group.z, group.bucket = z, bucket
		anchors = append(anchors, *group)
	}
	tm := make(map[targetIdentity]*targetLogicalGroup)
	for _, record := range aliases {
		if !VisitQGrams(record.Name, func(qgram string, position uint32) {
			stats.Target.QGramOccurrences++
			identity := targetIdentity{record.Area, qgram}
			group := tm[identity]
			if group == nil {
				group = &targetLogicalGroup{joinID: record.Area, qgram: qgram}
				tm[identity] = group
			}
			group.postings = append(group.postings, targetPosting{record.ID, position})
		}) {
			stats.Target.ShortStrings++
		}
	}
	targets := make([]targetLogicalGroup, 0, len(tm))
	tSeen := make(map[[32]byte]targetIdentity)
	for identity, group := range tm {
		target, err := targetcrypto.DeriveTargetGroupPoint(kT, identity.joinID, identity.qgram)
		if err != nil {
			return nil, nil, stats, err
		}
		var encoded [32]byte
		copy(encoded[:], target.Bytes())
		if old, ok := tSeen[encoded]; ok && old != identity {
			return nil, nil, stats, fmt.Errorf("target point collision")
		}
		tSeen[encoded] = identity
		join, err := targetcrypto.JoinBucketComponent(kT, identity.joinID, targetBits)
		if err != nil {
			return nil, nil, stats, err
		}
		word, err := targetcrypto.WordBucketComponent(kT, identity.qgram, targetBits)
		if err != nil {
			return nil, nil, stats, err
		}
		group.target = target
		group.bucket = uint16(targetcrypto.CombineBucketComponents(join, word))
		targets = append(targets, *group)
	}
	stats.Anchor.LogicalGroups, stats.Target.LogicalGroups = len(anchors), len(targets)
	return anchors, targets, stats, nil
}

func shareAndPad(anchors []anchorLogicalGroup, targets []targetLogicalGroup, kT targetcrypto.MasterKey, anchorBits, targetBits int, stats *BuildStats) (PublicMetadata, PartyIndex, PartyIndex, error) {
	sort.Slice(anchors, func(i, j int) bool {
		if anchors[i].bucket != anchors[j].bucket {
			return anchors[i].bucket < anchors[j].bucket
		}
		return bytes.Compare(anchors[i].z[:], anchors[j].z[:]) < 0
	})
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].bucket != targets[j].bucket {
			return targets[i].bucket < targets[j].bucket
		}
		return bytes.Compare(targets[i].target.Bytes(), targets[j].target.Bytes()) < 0
	})
	meta := PublicMetadata{Q: Q, AnchorBucketBits: uint8(anchorBits), TargetBucketBits: uint8(targetBits)}
	var cs0, cs1 PartyIndex
	for start := 0; start < len(anchors); {
		end, lpad := start, 0
		for end < len(anchors) && anchors[end].bucket == anchors[start].bucket {
			if len(anchors[end].postings) > lpad {
				lpad = len(anchors[end].postings)
			}
			end++
		}
		b0 := AnchorPartyBucket{BucketID: anchors[start].bucket, LPad: uint32(lpad)}
		b1 := AnchorPartyBucket{BucketID: b0.BucketID, LPad: b0.LPad}
		for i := start; i < end; i++ {
			g0 := AnchorPartyGroup{Z: anchors[i].z}
			g1 := AnchorPartyGroup{Z: anchors[i].z}
			for slot := 0; slot < lpad; slot++ {
				var id uint64
				var pos uint32
				valid := domain.BitZero
				if slot < len(anchors[i].postings) {
					id = anchors[i].postings[slot].recordID
					pos = anchors[i].postings[slot].position
					valid = domain.BitOne
					stats.Anchor.RealSlots++
				}
				s0, s1, err := makeAnchorSlot(id, pos, valid, kT, targetBits)
				if err != nil {
					return PublicMetadata{}, PartyIndex{}, PartyIndex{}, err
				}
				g0.Slots = append(g0.Slots, s0)
				g1.Slots = append(g1.Slots, s1)
			}
			b0.Groups = append(b0.Groups, g0)
			b1.Groups = append(b1.Groups, g1)
		}
		meta.AnchorBuckets = append(meta.AnchorBuckets, BucketMetadata{b0.BucketID, b0.LPad, uint32(len(b0.Groups))})
		cs0.AnchorBuckets = append(cs0.AnchorBuckets, b0)
		cs1.AnchorBuckets = append(cs1.AnchorBuckets, b1)
		start = end
	}
	for start := 0; start < len(targets); {
		end, lpad := start, 0
		for end < len(targets) && targets[end].bucket == targets[start].bucket {
			if len(targets[end].postings) > lpad {
				lpad = len(targets[end].postings)
			}
			end++
		}
		b0 := TargetPartyBucket{BucketID: targets[start].bucket, LPad: uint32(lpad)}
		b1 := TargetPartyBucket{BucketID: b0.BucketID, LPad: b0.LPad}
		for i := start; i < end; i++ {
			p0, p1, err := splitPoint(targets[i].target)
			if err != nil {
				return PublicMetadata{}, PartyIndex{}, PartyIndex{}, err
			}
			g0 := TargetPartyGroup{TargetKeyShare: p0}
			g1 := TargetPartyGroup{TargetKeyShare: p1}
			for slot := 0; slot < lpad; slot++ {
				var id uint64
				var pos uint32
				valid := domain.BitZero
				if slot < len(targets[i].postings) {
					id = targets[i].postings[slot].recordID
					pos = targets[i].postings[slot].position
					valid = domain.BitOne
					stats.Target.RealSlots++
				}
				s0, s1, err := makeTargetSlot(id, pos, valid)
				if err != nil {
					return PublicMetadata{}, PartyIndex{}, PartyIndex{}, err
				}
				g0.Slots = append(g0.Slots, s0)
				g1.Slots = append(g1.Slots, s1)
			}
			b0.Groups = append(b0.Groups, g0)
			b1.Groups = append(b1.Groups, g1)
		}
		meta.TargetBuckets = append(meta.TargetBuckets, BucketMetadata{b0.BucketID, b0.LPad, uint32(len(b0.Groups))})
		cs0.TargetBuckets = append(cs0.TargetBuckets, b0)
		cs1.TargetBuckets = append(cs1.TargetBuckets, b1)
		start = end
	}
	finishStats(&stats.Anchor, meta.AnchorBuckets)
	finishStats(&stats.Target, meta.TargetBuckets)
	return meta, cs0, cs1, nil
}

func makeAnchorSlot(id uint64, pos uint32, valid domain.Bit, kT targetcrypto.MasterKey, targetBits int) (AnchorPartySlot, AnchorPartySlot, error) {
	r0, r1, err := splitRing64(domain.Ring64(id))
	if err != nil {
		return AnchorPartySlot{}, AnchorPartySlot{}, err
	}
	p0, p1, err := splitRing32(domain.Ring32(pos))
	if err != nil {
		return AnchorPartySlot{}, AnchorPartySlot{}, err
	}
	v0, v1, err := splitBit(valid)
	if err != nil {
		return AnchorPartySlot{}, AnchorPartySlot{}, err
	}
	kappa := ristretto255.NewScalar()
	beta := targetcrypto.BucketComponent(0)
	if valid == domain.BitOne {
		kappa, err = targetcrypto.KJoin(kT, id)
		if err != nil {
			return AnchorPartySlot{}, AnchorPartySlot{}, err
		}
		beta, err = targetcrypto.JoinBucketComponent(kT, id, targetBits)
		if err != nil {
			return AnchorPartySlot{}, AnchorPartySlot{}, err
		}
	}
	k0, k1, err := splitScalar(kappa)
	if err != nil {
		return AnchorPartySlot{}, AnchorPartySlot{}, err
	}
	b0, b1, err := splitBucket(beta, targetBits)
	if err != nil {
		return AnchorPartySlot{}, AnchorPartySlot{}, err
	}
	return AnchorPartySlot{r0, p0, v0, k0, b0}, AnchorPartySlot{r1, p1, v1, k1, b1}, nil
}
func makeTargetSlot(id uint64, pos uint32, valid domain.Bit) (TargetPartySlot, TargetPartySlot, error) {
	r0, r1, err := splitRing64(domain.Ring64(id))
	if err != nil {
		return TargetPartySlot{}, TargetPartySlot{}, err
	}
	p0, p1, err := splitRing32(domain.Ring32(pos))
	if err != nil {
		return TargetPartySlot{}, TargetPartySlot{}, err
	}
	v0, v1, err := splitBit(valid)
	if err != nil {
		return TargetPartySlot{}, TargetPartySlot{}, err
	}
	return TargetPartySlot{r0, p0, v0}, TargetPartySlot{r1, p1, v1}, nil
}
func finishStats(stats *SideStats, buckets []BucketMetadata) {
	stats.NonemptyBuckets = len(buckets)
	groups := make([]int, len(buckets))
	lpads := make([]int, len(buckets))
	slots := make([]int, len(buckets))
	for i, b := range buckets {
		groups[i] = int(b.GroupCount)
		lpads[i] = int(b.LPad)
		slots[i] = int(b.GroupCount) * int(b.LPad)
		stats.PaddedSlots += slots[i]
	}
	stats.GroupCount = distribution(groups)
	stats.LPad = distribution(lpads)
	stats.SlotsPerBucket = distribution(slots)
	if stats.RealSlots > 0 {
		stats.PaddingRatio = float64(stats.PaddedSlots) / float64(stats.RealSlots)
	}
}
func distribution(values []int) Distribution {
	if len(values) == 0 {
		return Distribution{}
	}
	sort.Ints(values)
	at := func(p float64) int {
		idx := int(float64(len(values)-1)*p + 0.999999999)
		if idx >= len(values) {
			idx = len(values) - 1
		}
		return values[idx]
	}
	return Distribution{values[0], at(.50), at(.95), at(.99), values[len(values)-1]}
}
