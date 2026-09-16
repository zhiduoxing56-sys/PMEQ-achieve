package indexbuild

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/gtank/ristretto255"
	"pmeq/internal/anchorindex"
	"pmeq/internal/domain"
	"pmeq/internal/reconstruct"
	"pmeq/internal/targetcrypto"
)

const (
	realAreaPath  = "/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area"
	realAliasPath = "/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area_alias"
)

func TestRealMusicBrainz1000(t *testing.T) {
	areaFile, err := os.Open(realAreaPath)
	if err != nil {
		t.Fatal(err)
	}
	defer areaFile.Close()
	start := time.Now()
	areas, err := LoadArea(areaFile, 1000)
	if err != nil {
		t.Fatal(err)
	}
	areaParse := time.Since(start)
	aliasFile, err := os.Open(realAliasPath)
	if err != nil {
		t.Fatal(err)
	}
	defer aliasFile.Close()
	start = time.Now()
	aliases, err := LoadAreaAlias(aliasFile, 1000)
	if err != nil {
		t.Fatal(err)
	}
	aliasParse := time.Since(start)
	if len(areas) != 1000 || len(aliases) != 1000 {
		t.Fatalf("records area=%d alias=%d", len(areas), len(aliases))
	}
	kB, kT := testKeys(t)
	for _, bits := range []int{8, 14} {
		bits := bits
		t.Run(fmt.Sprintf("k%d", bits), func(t *testing.T) {
			meta, cs0, cs1, stats, err := Build(areas, aliases, kB, kT, bits, bits)
			if err != nil {
				t.Fatal(err)
			}
			auditPartyAlignment(t, meta, cs0, cs1)
			t.Logf("paths area=%s area_alias=%s parse_area=%s parse_alias=%s", realAreaPath, realAliasPath, areaParse, aliasParse)
			t.Logf("k=%d anchor=%s", bits, formatSide(stats.Anchor))
			t.Logf("k=%d target=%s", bits, formatSide(stats.Target))
			t.Logf("k=%d logical_build=%s sharing_padding=%s total=%s", bits, stats.LogicalBuildTime, stats.SharingPadTime, stats.TotalBuildTime)
			if bits == 8 {
				auditReconstructionSamples(t, areas, aliases, kB, kT, bits, cs0, cs1)
			}
		})
	}
}

func formatSide(s SideStats) string {
	return fmt.Sprintf("raw=%d short=%d occurrences=%d groups=%d nonempty_buckets=%d group_count=%+v lpad=%+v real_slots=%d padded_slots=%d padding_ratio=%.6f", s.RawRecords, s.ShortStrings, s.QGramOccurrences, s.LogicalGroups, s.NonemptyBuckets, s.GroupCount, s.LPad, s.RealSlots, s.PaddedSlots, s.PaddingRatio)
}

func auditPartyAlignment(t *testing.T, meta PublicMetadata, a, b PartyIndex) {
	t.Helper()
	if meta.Q != 4 || len(a.AnchorBuckets) != len(b.AnchorBuckets) || len(a.TargetBuckets) != len(b.TargetBuckets) {
		t.Fatal("party/public shapes differ")
	}
	for i := range a.AnchorBuckets {
		if a.AnchorBuckets[i].BucketID != b.AnchorBuckets[i].BucketID || a.AnchorBuckets[i].LPad != b.AnchorBuckets[i].LPad || len(a.AnchorBuckets[i].Groups) != len(b.AnchorBuckets[i].Groups) {
			t.Fatal("anchor buckets differ")
		}
		for j := range a.AnchorBuckets[i].Groups {
			if a.AnchorBuckets[i].Groups[j].Z != b.AnchorBuckets[i].Groups[j].Z || len(a.AnchorBuckets[i].Groups[j].Slots) != len(b.AnchorBuckets[i].Groups[j].Slots) {
				t.Fatal("anchor group order differs")
			}
		}
	}
	for i := range a.TargetBuckets {
		if a.TargetBuckets[i].BucketID != b.TargetBuckets[i].BucketID || a.TargetBuckets[i].LPad != b.TargetBuckets[i].LPad || len(a.TargetBuckets[i].Groups) != len(b.TargetBuckets[i].Groups) {
			t.Fatal("target buckets differ")
		}
	}
}

func auditReconstructionSamples(t *testing.T, areas []AreaRecord, aliases []AreaAliasRecord, kB anchorindex.Key, kT targetcrypto.MasterKey, bits int, cs0, cs1 PartyIndex) {
	t.Helper()
	anchors, targets, _, err := buildLogical(areas, aliases, kB, kT, bits, bits)
	if err != nil {
		t.Fatal(err)
	}
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
	am := map[[16]byte]anchorLogicalGroup{}
	for _, g := range anchors {
		am[g.z] = g
	}
	tm := map[[32]byte]targetLogicalGroup{}
	for _, g := range targets {
		var key [32]byte
		copy(key[:], g.target.Bytes())
		tm[key] = g
	}
	var ar, ad, tr, td, points int
	for bi := range cs0.AnchorBuckets {
		for gi := range cs0.AnchorBuckets[bi].Groups {
			g0, g1 := cs0.AnchorBuckets[bi].Groups[gi], cs1.AnchorBuckets[bi].Groups[gi]
			expected := am[g0.Z]
			for si := range g0.Slots {
				s0, s1 := g0.Slots[si], g1.Slots[si]
				id := uint64(reconstruct.RecoverRing64(s0.RecordIDShare, s1.RecordIDShare))
				pos := uint32(reconstruct.RecoverRing32(s0.PositionShare, s1.PositionShare))
				valid := reconstruct.RecoverBit(s0.ValidityShare, s1.ValidityShare)
				kappa := combineScalar(t, s0.KappaJoinShare, s1.KappaJoinShare)
				beta := s0.BucketJoinShare.Value() ^ s1.BucketJoinShare.Value()
				if si < len(expected.postings) {
					p := expected.postings[si]
					wantK, err := targetcrypto.KJoin(kT, p.recordID)
					if err != nil {
						t.Fatal(err)
					}
					var wantKB [32]byte
					copy(wantKB[:], wantK.Bytes())
					wantB, err := targetcrypto.JoinBucketComponent(kT, p.recordID, bits)
					if err != nil {
						t.Fatal(err)
					}
					if id != p.recordID || pos != p.position || valid != domain.BitOne || kappa != wantKB || beta != wantB {
						t.Fatal("anchor real reconstruction mismatch")
					}
					ar++
				} else {
					if id != 0 || pos != 0 || valid != domain.BitZero || kappa != ([32]byte{}) || beta != 0 {
						t.Fatal("anchor dummy reconstruction mismatch")
					}
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
				t.Fatal("target group point is not derived identity")
			}
			points++
			for si := range g0.Slots {
				s0, s1 := g0.Slots[si], g1.Slots[si]
				id := uint64(reconstruct.RecoverRing64(s0.RecordIDShare, s1.RecordIDShare))
				pos := uint32(reconstruct.RecoverRing32(s0.PositionShare, s1.PositionShare))
				valid := reconstruct.RecoverBit(s0.ValidityShare, s1.ValidityShare)
				if si < len(expected.postings) {
					p := expected.postings[si]
					if id != p.recordID || pos != p.position || valid != domain.BitOne {
						t.Fatal("target real reconstruction mismatch")
					}
					tr++
				} else {
					if id != 0 || pos != 0 || valid != domain.BitZero {
						t.Fatal("target dummy reconstruction mismatch")
					}
					td++
				}
			}
		}
	}
	if ar < 1000 || ad < 1000 || tr < 1000 || td < 1000 {
		t.Fatalf("insufficient reconstruction samples anchor real/dummy=%d/%d target real/dummy=%d/%d", ar, ad, tr, td)
	}
	t.Logf("reconstruction verified anchor real=%d dummy=%d target real=%d dummy=%d target_points=%d", ar, ad, tr, td, points)
}

func combinePoint(t *testing.T, a, b targetcrypto.PointShare) [32]byte {
	t.Helper()
	ab, bb := a.CanonicalBytes(), b.CanonicalBytes()
	x, err := ristretto255.NewElement().SetCanonicalBytes(ab[:])
	if err != nil {
		t.Fatal(err)
	}
	y, err := ristretto255.NewElement().SetCanonicalBytes(bb[:])
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], ristretto255.NewElement().Add(x, y).Bytes())
	return out
}
