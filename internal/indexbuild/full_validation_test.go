package indexbuild

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sort"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"pmeq/internal/anchorindex"
	"pmeq/internal/domain"
	"pmeq/internal/reconstruct"
	"pmeq/internal/targetcrypto"
)

type repeatedKey struct {
	recordID uint64
	qgram    string
}
type repeatedSummary struct {
	Pairs    int
	Max      int
	Examples []string
}

func TestFullMusicBrainzValidation(t *testing.T) {
	if os.Getenv("PMEQ_FULL_VALIDATION") != "1" {
		t.Skip("set PMEQ_FULL_VALIDATION=1 for the full-dataset experiment")
	}
	parseStarted := time.Now()
	af, err := os.Open(realAreaPath)
	if err != nil {
		t.Fatal(err)
	}
	areas, areaInput, err := LoadAreaWithStats(af, 0)
	closeErr := af.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	areaParse := time.Since(parseStarted)
	aliasStarted := time.Now()
	tf, err := os.Open(realAliasPath)
	if err != nil {
		t.Fatal(err)
	}
	aliases, aliasInput, err := LoadAreaAliasWithStats(tf, 0)
	closeErr = tf.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	aliasParse := time.Since(aliasStarted)
	parseTotal := time.Since(parseStarted)
	t.Logf("INPUT area=%+v area_alias=%+v parse_area=%s parse_alias=%s parse_total=%s", areaInput, aliasInput, areaParse, aliasParse, parseTotal)
	if areaInput.RawRows != 120071 || areaInput.UsableRows != 120071 || areaInput.ShortNames != 644 || areaInput.QGramOccurrences != 906584 {
		t.Fatalf("Anchor raw regression: %+v", areaInput)
	}
	if aliasInput.RawRows != 67896 || aliasInput.UsableRows != 67896 || aliasInput.ShortNames != 4047 || aliasInput.QGramOccurrences != 480945 {
		t.Fatalf("Target raw regression: %+v", aliasInput)
	}

	kB, kT := testKeys(t)
	uniforms, tiers := make(map[int]LayoutAnalysis), make(map[int]LayoutAnalysis)
	for _, bits := range []int{8, 10, 12, 13, 14} {
		started := time.Now()
		uniform, tier, err := AnalyzeLayouts(areas, aliases, kB, kT, bits, bits)
		if err != nil {
			t.Fatal(err)
		}
		uniforms[bits], tiers[bits] = uniform, tier
		t.Logf("LAYOUT k=%d B=%d elapsed=%s anchor_tier={%s max=%+v} anchor_uniform={%s} anchor_reduction=%.6f target_tier={%s max=%+v} target_uniform={%s} target_reduction=%.6f", bits, 1<<bits, time.Since(started), formatSide(tier.Anchor), tier.AnchorMaxGroup, formatSide(uniform.Anchor), float64(uniform.Anchor.PaddedSlots)/float64(tier.Anchor.PaddedSlots), formatSide(tier.Target), tier.TargetMaxGroup, formatSide(uniform.Target), float64(uniform.Target.PaddedSlots)/float64(tier.Target.PaddedSlots))
	}
	base := tiers[8]
	if base.Anchor.LogicalGroups != 110115 || base.Target.LogicalGroups != 310331 {
		t.Fatalf("logical group regression anchor=%d target=%d", base.Anchor.LogicalGroups, base.Target.LogicalGroups)
	}
	if base.TargetMaxGroup.Occurrences > 64 {
		t.Fatalf("Target grouping regression: max group=%d", base.TargetMaxGroup.Occurrences)
	}
	t.Logf("TIER_POPULATION anchor=%+v target=%+v", base.AnchorTiers, base.TargetTiers)
	if os.Getenv("PMEQ_FULL_LAYOUT_ONLY") == "1" {
		t.Log("layout-only run requested; materialization intentionally skipped")
		return
	}

	anchorSlotSize := unsafe.Sizeof(AnchorPartySlot{})
	targetSlotSize := unsafe.Sizeof(TargetPartySlot{})
	anchorGroupSize := unsafe.Sizeof(AnchorPartyGroup{})
	targetGroupSize := unsafe.Sizeof(TargetPartyGroup{})
	anchorBucketSize := unsafe.Sizeof(AnchorPartyBucket{})
	targetBucketSize := unsafe.Sizeof(TargetPartyBucket{})
	lowerBound := uint64(2) * (uint64(base.Anchor.PaddedSlots)*uint64(anchorSlotSize) + uint64(base.Target.PaddedSlots)*uint64(targetSlotSize) + uint64(base.Anchor.LogicalGroups)*uint64(anchorGroupSize) + uint64(base.Target.LogicalGroups)*uint64(targetGroupSize) + uint64(base.Anchor.NonemptyBuckets)*uint64(anchorBucketSize) + uint64(base.Target.NonemptyBuckets)*uint64(targetBucketSize))
	t.Logf("MEMORY_ESTIMATE AnchorPartySlot=%d TargetPartySlot=%d AnchorPartyGroup=%d TargetPartyGroup=%d AnchorPartyBucket=%d TargetPartyBucket=%d CS0+CS1_lower_bound_bytes=%d GiB=%.6f", anchorSlotSize, targetSlotSize, anchorGroupSize, targetGroupSize, anchorBucketSize, targetBucketSize, lowerBound, float64(lowerBound)/(1<<30))
	if lowerBound > 12*(uint64(1)<<30) {
		t.Logf("MATERIALIZATION skipped: estimate exceeds 12 GiB")
		return
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var peak atomic.Uint64
	peak.Store(before.Alloc)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		defer close(done)
		for {
			select {
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				for {
					old := peak.Load()
					if m.Alloc <= old || peak.CompareAndSwap(old, m.Alloc) {
						break
					}
				}
			case <-stop:
				return
			}
		}
	}()
	buildWallStarted := time.Now()
	metadata, cs0, cs1, buildStats, err := Build(areas, aliases, kB, kT, 8, 8)
	buildWall := time.Since(buildWallStarted)
	close(stop)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.Alloc > peak.Load() {
		peak.Store(after.Alloc)
	}
	t.Logf("MATERIALIZED k=8 wall=%s logical_crypto=%s sharing_padding=%s builder_total=%s heap_before=%d heap_peak=%d heap_peak_delta=%d heap_after=%d", buildWall, buildStats.LogicalBuildTime, buildStats.SharingPadTime, buildStats.TotalBuildTime, before.Alloc, peak.Load(), peak.Load()-before.Alloc, after.Alloc)
	if !equalLayoutStats(base, metadata, buildStats) {
		t.Fatal("materialized Build layout differs from AnalyzeLayout")
	}

	auditStarted := time.Now()
	anchors, targets, logicalStats, err := buildLogical(areas, aliases, kB, kT, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if logicalStats.Anchor.QGramOccurrences != base.Anchor.RealSlots || logicalStats.Target.QGramOccurrences != base.Target.RealSlots {
		t.Fatal("audit logical occurrence mismatch")
	}
	reconstruction := auditFullSamples(t, anchors, targets, kT, 8, cs0, cs1)
	padChecks := auditPadWidths(t, anchors, targets, cs0, cs1)
	pairs := auditGroupIdentities(t, anchors, targets, kB, kT)
	aRepeat := repeatArea(areas)
	tRepeat := repeatAliases(aliases)
	auditFreshRepeatedPayload(t, anchors, kT, 8, cs0, cs1)
	t.Logf("AUDIT reconstruction=%s pad_width_checks=%d identity_pairs=%d repeated_anchor=%+v repeated_target=%+v elapsed=%s", reconstruction, padChecks, pairs, aRepeat, tRepeat, time.Since(auditStarted))
}

func equalLayoutStats(layout LayoutAnalysis, metadata PublicMetadata, stats BuildStats) bool {
	return fmt.Sprint(layout.Metadata) == fmt.Sprint(metadata) && reflect.DeepEqual(layout.Anchor, stats.Anchor) && reflect.DeepEqual(layout.Target, stats.Target)
}

func auditFullSamples(t *testing.T, anchors []anchorLogicalGroup, targets []targetLogicalGroup, kT targetcrypto.MasterKey, bits int, cs0, cs1 PartyIndex) string {
	t.Helper()
	am := make(map[[16]byte]anchorLogicalGroup, len(anchors))
	for _, g := range anchors {
		am[g.z] = g
	}
	tm := make(map[[32]byte]targetLogicalGroup, len(targets))
	for _, g := range targets {
		var key [32]byte
		copy(key[:], g.target.Bytes())
		tm[key] = g
	}
	ar, ad, tr, td, tg := 0, 0, 0, 0, 0
	for bi := range cs0.AnchorBuckets {
		for gi := range cs0.AnchorBuckets[bi].Groups {
			g0, g1 := cs0.AnchorBuckets[bi].Groups[gi], cs1.AnchorBuckets[bi].Groups[gi]
			expected, ok := am[g0.Z]
			if !ok {
				t.Fatal("unknown Anchor Z")
			}
			for si := range g0.Slots {
				valid := reconstruct.RecoverBit(g0.Slots[si].ValidityShare, g1.Slots[si].ValidityShare)
				if valid == domain.BitOne && ar < 10000 {
					auditAnchorReal(t, g0.Slots[si], g1.Slots[si], expected.postings[si], kT, bits)
					ar++
				} else if valid == domain.BitZero && ad < 10000 {
					auditAnchorDummy(t, g0.Slots[si], g1.Slots[si])
					ad++
				}
			}
		}
	}
	for bi := range cs0.TargetBuckets {
		for gi := range cs0.TargetBuckets[bi].Groups {
			g0, g1 := cs0.TargetBuckets[bi].Groups[gi], cs1.TargetBuckets[bi].Groups[gi]
			key := combinePoint(t, g0.TargetKeyShare, g1.TargetKeyShare)
			expected, ok := tm[key]
			if !ok {
				t.Fatal("unknown reconstructed Target point")
			}
			if tg < 10000 {
				var want [32]byte
				copy(want[:], expected.target.Bytes())
				if key != want {
					t.Fatal("Target group point mismatch")
				}
				tg++
			}
			for si := range g0.Slots {
				valid := reconstruct.RecoverBit(g0.Slots[si].ValidityShare, g1.Slots[si].ValidityShare)
				if valid == domain.BitOne && tr < 10000 {
					p := expected.postings[si]
					if uint64(reconstruct.RecoverRing64(g0.Slots[si].RecordIDShare, g1.Slots[si].RecordIDShare)) != p.recordID || uint32(reconstruct.RecoverRing32(g0.Slots[si].PositionShare, g1.Slots[si].PositionShare)) != p.position {
						t.Fatal("Target real mismatch")
					}
					tr++
				} else if valid == domain.BitZero && td < 10000 {
					if reconstruct.RecoverRing64(g0.Slots[si].RecordIDShare, g1.Slots[si].RecordIDShare) != 0 || reconstruct.RecoverRing32(g0.Slots[si].PositionShare, g1.Slots[si].PositionShare) != 0 {
						t.Fatal("Target dummy mismatch")
					}
					td++
				}
			}
		}
	}
	wantAD, wantTD := 10000, 10000
	realA, realT := 0, 0
	for _, g := range anchors {
		realA += len(g.postings)
	}
	for _, g := range targets {
		realT += len(g.postings)
	}
	dummyA := anchorSlotCount(cs0.AnchorBuckets) - realA
	dummyT := targetSlotCount(cs0.TargetBuckets) - realT
	if dummyA < wantAD {
		wantAD = dummyA
	}
	if dummyT < wantTD {
		wantTD = dummyT
	}
	if ar != 10000 || tr != 10000 || tg != 10000 || ad != wantAD || td != wantTD {
		t.Fatalf("sample counts A real/dummy=%d/%d T real/dummy/groups=%d/%d/%d wants dummy=%d/%d", ar, ad, tr, td, tg, wantAD, wantTD)
	}
	return fmt.Sprintf("anchor_real=%d anchor_dummy=%d target_real=%d target_dummy=%d target_groups=%d", ar, ad, tr, td, tg)
}

func auditAnchorReal(t *testing.T, a, b AnchorPartySlot, p anchorPosting, kT targetcrypto.MasterKey, bits int) {
	t.Helper()
	if uint64(reconstruct.RecoverRing64(a.RecordIDShare, b.RecordIDShare)) != p.recordID || uint32(reconstruct.RecoverRing32(a.PositionShare, b.PositionShare)) != p.position || reconstruct.RecoverBit(a.ValidityShare, b.ValidityShare) != domain.BitOne {
		t.Fatal("Anchor real mismatch")
	}
	want, err := targetcrypto.KJoin(kT, p.recordID)
	if err != nil {
		t.Fatal(err)
	}
	var wb [32]byte
	copy(wb[:], want.Bytes())
	beta, err := targetcrypto.JoinBucketComponent(kT, p.recordID, bits)
	if err != nil {
		t.Fatal(err)
	}
	if combineScalar(t, a.KappaJoinShare, b.KappaJoinShare) != wb || a.BucketJoinShare.Value()^b.BucketJoinShare.Value() != beta {
		t.Fatal("Anchor real routing payload mismatch")
	}
}
func auditAnchorDummy(t *testing.T, a, b AnchorPartySlot) {
	t.Helper()
	if reconstruct.RecoverRing64(a.RecordIDShare, b.RecordIDShare) != 0 || reconstruct.RecoverRing32(a.PositionShare, b.PositionShare) != 0 || reconstruct.RecoverBit(a.ValidityShare, b.ValidityShare) != domain.BitZero || combineScalar(t, a.KappaJoinShare, b.KappaJoinShare) != ([32]byte{}) || a.BucketJoinShare.Value()^b.BucketJoinShare.Value() != 0 {
		t.Fatal("Anchor dummy mismatch")
	}
}
func anchorSlotCount(b []AnchorPartyBucket) int {
	n := 0
	for _, x := range b {
		for _, g := range x.Groups {
			n += len(g.Slots)
		}
	}
	return n
}
func targetSlotCount(b []TargetPartyBucket) int {
	n := 0
	for _, x := range b {
		for _, g := range x.Groups {
			n += len(g.Slots)
		}
	}
	return n
}

func auditPadWidths(t *testing.T, anchors []anchorLogicalGroup, targets []targetLogicalGroup, cs0, cs1 PartyIndex) int {
	t.Helper()
	am := make(map[[16]byte]int, len(anchors))
	for _, g := range anchors {
		am[g.z] = len(g.postings)
	}
	tm := make(map[[32]byte]int, len(targets))
	for _, g := range targets {
		var key [32]byte
		copy(key[:], g.target.Bytes())
		tm[key] = len(g.postings)
	}
	checks := 0
	for bi := range cs0.AnchorBuckets {
		for gi := range cs0.AnchorBuckets[bi].Groups {
			if checks >= 10000 {
				break
			}
			a, b := cs0.AnchorBuckets[bi].Groups[gi], cs1.AnchorBuckets[bi].Groups[gi]
			want, err := TierWidth(am[a.Z])
			if err != nil {
				t.Fatal(err)
			}
			if a.PadWidth != uint32(want) || b.PadWidth != uint32(want) || len(a.Slots) != want || len(b.Slots) != want {
				t.Fatal("Anchor PadWidth audit failed")
			}
			checks++
		}
	}
	targetChecks := 0
	for bi := range cs0.TargetBuckets {
		for gi := range cs0.TargetBuckets[bi].Groups {
			if targetChecks >= 10000 {
				break
			}
			a, b := cs0.TargetBuckets[bi].Groups[gi], cs1.TargetBuckets[bi].Groups[gi]
			key := combinePoint(t, a.TargetKeyShare, b.TargetKeyShare)
			want, err := TierWidth(tm[key])
			if err != nil {
				t.Fatal(err)
			}
			if a.PadWidth != uint32(want) || b.PadWidth != uint32(want) || len(a.Slots) != want || len(b.Slots) != want {
				t.Fatal("Target PadWidth audit failed")
			}
			targetChecks++
		}
	}
	if checks != 10000 || targetChecks != 10000 {
		t.Fatalf("PadWidth checks Anchor/Target=%d/%d", checks, targetChecks)
	}
	return checks + targetChecks
}

func auditGroupIdentities(t *testing.T, anchors []anchorLogicalGroup, targets []targetLogicalGroup, kB anchorindex.Key, kT targetcrypto.MasterKey) int {
	t.Helper()
	checks := 0
	for i := 0; i < len(anchors) && checks < 10000; i++ {
		z, err := anchorindex.Encode(kB, anchors[i].qgram)
		if err != nil || z != anchors[i].z {
			t.Fatal("Anchor identity regression")
		}
		if i > 0 && anchors[i].qgram != anchors[i-1].qgram && anchors[i].z == anchors[i-1].z {
			t.Fatal("different Anchor qgrams share Z")
		}
		checks++
	}
	sameWordDifferentJoin, sameJoinDifferentWord := false, false
	wordJoin := map[string]uint64{}
	joinWord := map[uint64]string{}
	for i := 0; i < len(targets) && checks < 20000; i++ {
		g := targets[i]
		want, err := targetcrypto.DeriveTargetGroupPoint(kT, g.joinID, g.qgram)
		if err != nil || !bytes.Equal(want.Bytes(), g.target.Bytes()) {
			t.Fatal("Target identity regression")
		}
		if old, ok := wordJoin[g.qgram]; ok && old != g.joinID {
			sameWordDifferentJoin = true
		} else {
			wordJoin[g.qgram] = g.joinID
		}
		if old, ok := joinWord[g.joinID]; ok && old != g.qgram {
			sameJoinDifferentWord = true
		} else {
			joinWord[g.joinID] = g.qgram
		}
		checks++
	}
	if checks < 20000 || !sameWordDifferentJoin || !sameJoinDifferentWord {
		t.Fatalf("identity coverage checks=%d sameWordDifferentJoin=%v sameJoinDifferentWord=%v", checks, sameWordDifferentJoin, sameJoinDifferentWord)
	}
	return checks
}

func repeatArea(records []AreaRecord) repeatedSummary {
	counts := map[repeatedKey]int{}
	for _, r := range records {
		VisitQGrams(r.Name, func(q string, _ uint32) { counts[repeatedKey{r.ID, q}]++ })
	}
	return summarizeRepeats(counts)
}
func repeatAliases(records []AreaAliasRecord) repeatedSummary {
	counts := map[repeatedKey]int{}
	for _, r := range records {
		VisitQGrams(r.Name, func(q string, _ uint32) { counts[repeatedKey{r.ID, q}]++ })
	}
	return summarizeRepeats(counts)
}
func summarizeRepeats(counts map[repeatedKey]int) repeatedSummary {
	var out repeatedSummary
	for key, n := range counts {
		if n < 2 {
			continue
		}
		out.Pairs++
		if n > out.Max {
			out.Max = n
		}
		if len(out.Examples) < 5 {
			out.Examples = append(out.Examples, fmt.Sprintf("record=%d qgram=%q count=%d", key.recordID, key.qgram, n))
		}
	}
	sort.Strings(out.Examples)
	return out
}

func auditFreshRepeatedPayload(t *testing.T, groups []anchorLogicalGroup, kT targetcrypto.MasterKey, bits int, cs0, cs1 PartyIndex) {
	t.Helper()
	var selected anchorLogicalGroup
	var record uint64
	for _, g := range groups {
		seen := map[uint64]int{}
		for _, p := range g.postings {
			seen[p.recordID]++
			if seen[p.recordID] >= 2 {
				selected = g
				record = p.recordID
				break
			}
		}
		if record != 0 {
			break
		}
	}
	if record == 0 {
		t.Fatal("no repeated Anchor occurrence found")
	}
	var semanticK [32]byte
	var semanticB targetcrypto.BucketComponent
	found := 0
	for bi := range cs0.AnchorBuckets {
		for gi := range cs0.AnchorBuckets[bi].Groups {
			if cs0.AnchorBuckets[bi].Groups[gi].Z != selected.z {
				continue
			}
			for si := range cs0.AnchorBuckets[bi].Groups[gi].Slots {
				a, b := cs0.AnchorBuckets[bi].Groups[gi].Slots[si], cs1.AnchorBuckets[bi].Groups[gi].Slots[si]
				if uint64(reconstruct.RecoverRing64(a.RecordIDShare, b.RecordIDShare)) != record {
					continue
				}
				k := combineScalar(t, a.KappaJoinShare, b.KappaJoinShare)
				beta := a.BucketJoinShare.Value() ^ b.BucketJoinShare.Value()
				if found == 0 {
					semanticK, semanticB = k, beta
				} else if k != semanticK || beta != semanticB {
					t.Fatal("repeated occurrence routing semantics differ")
				}
				found++
			}
		}
	}
	wantK, err := targetcrypto.KJoin(kT, record)
	if err != nil {
		t.Fatal(err)
	}
	var wb [32]byte
	copy(wb[:], wantK.Bytes())
	wantB, err := targetcrypto.JoinBucketComponent(kT, record, bits)
	if err != nil {
		t.Fatal(err)
	}
	if found < 2 || semanticK != wb || semanticB != wantB {
		t.Fatal("fresh sharing repeated-occurrence spot check failed")
	}
}
