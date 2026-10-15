package indexbuild

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gtank/ristretto255"
	"pmeq/internal/anchorindex"
	"pmeq/internal/domain"
	"pmeq/internal/preprocess"
	"pmeq/internal/reconstruct"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
)

func TestBuildRejectsTierOverflow(t *testing.T) {
	kB, kT := testKeys(t)
	_, _, _, _, err := Build([]AreaRecord{{ID: 1, Name: strings.Repeat("a", 32772)}}, nil, kB, kT, 8, 8)
	if !errors.Is(err, ErrTierOverflow) {
		t.Fatalf("Build overflow error=%v, want ErrTierOverflow", err)
	}
}

func testKeys(t *testing.T) (anchorindex.Key, targetcrypto.MasterKey) {
	t.Helper()
	var a, b [32]byte
	for i := range a {
		a[i] = byte(i + 1)
		b[i] = byte(255 - i)
	}
	kB, err := anchorindex.NewKey(a)
	if err != nil {
		t.Fatal(err)
	}
	kT, err := targetcrypto.NewMasterKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return kB, kT
}

func TestQGramCodePointSemantics(t *testing.T) {
	var grams []string
	var positions []uint32
	if !VisitQGrams("甲乙丙丁戊", func(q string, p uint32) { grams = append(grams, q); positions = append(positions, p) }) {
		t.Fatal("reported short")
	}
	if !reflect.DeepEqual(grams, []string{"甲乙丙丁", "乙丙丁戊"}) || !reflect.DeepEqual(positions, []uint32{0, 1}) {
		t.Fatalf("grams=%q positions=%v", grams, positions)
	}
	if VisitQGrams("甲乙丙", func(string, uint32) { t.Fatal("short string emitted") }) {
		t.Fatal("short string accepted")
	}
}

func TestAnchorBucketMSBFirst(t *testing.T) {
	var z anchorindex.Value
	z[0], z[1], z[2] = 0xab, 0xcd, 0x80
	for k, want := range map[int]uint32{8: 0xab, 14: 0x2af3, 1: 1, 16: 0xabcd, 17: 0x1579b} {
		got, err := AnchorBucket(z, k)
		if err != nil || got != want {
			t.Fatalf("k=%d got=%x err=%v want=%x", k, got, err, want)
		}
	}
	for _, k := range []int{0, 18} {
		if _, err := AnchorBucket(z, k); err == nil {
			t.Fatalf("accepted k=%d", k)
		}
	}
}

func TestLogicalGroupIdentityAndRepeatedOccurrences(t *testing.T) {
	kB, kT := testKeys(t)
	areas := []AreaRecord{{1, "aaaaa"}, {2, "zaaaaz"}}
	aliases := []AreaAliasRecord{{10, "aaaaa", 7}, {11, "aaaaa", 7}, {12, "aaaaa", 8}, {13, "baaaab", 7}}
	a, tg, stats, err := buildLogical(areas, aliases, kB, kT, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	anchor := map[string]int{}
	for _, g := range a {
		anchor[g.qgram] = len(g.postings)
	}
	if anchor["aaaa"] != 3 {
		t.Fatalf("repeated anchor occurrences=%d want 3", anchor["aaaa"])
	}
	target := map[targetIdentity]int{}
	for _, g := range tg {
		target[targetIdentity{g.joinID, g.qgram}] = len(g.postings)
		join, err := targetcrypto.JoinBucketComponent(kT, g.joinID, 8)
		if err != nil {
			t.Fatal(err)
		}
		word, err := targetcrypto.WordBucketComponent(kT, g.qgram, 8)
		if err != nil {
			t.Fatal(err)
		}
		if g.bucket != uint32(join^word) {
			t.Fatalf("target bucket=%d want join XOR word=%d", g.bucket, join^word)
		}
	}
	if target[targetIdentity{7, "aaaa"}] != 5 {
		t.Fatalf("same (area,qgram) count=%d", target[targetIdentity{7, "aaaa"}])
	}
	if target[targetIdentity{8, "aaaa"}] != 2 {
		t.Fatal("qgram-only target grouping regression")
	}
	if _, ok := target[targetIdentity{7, "baaa"}]; !ok {
		t.Fatal("same area/different qgram missing")
	}
	if stats.Anchor.QGramOccurrences != 5 || stats.Target.QGramOccurrences != 9 {
		t.Fatalf("occurrences A=%d T=%d", stats.Anchor.QGramOccurrences, stats.Target.QGramOccurrences)
	}
}

func TestRepeatedOccurrenceReconstruction(t *testing.T) {
	kB, kT := testKeys(t)
	_, cs0, cs1, _, err := Build([]AreaRecord{{ID: 77, Name: "aaaaa"}}, nil, kB, kT, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	z, err := anchorindex.Encode(kB, "aaaa")
	if err != nil {
		t.Fatal(err)
	}
	wantKappa, err := targetcrypto.KJoin(kT, 77)
	if err != nil {
		t.Fatal(err)
	}
	var wantKappaBytes [32]byte
	copy(wantKappaBytes[:], wantKappa.Bytes())
	wantBucket, err := targetcrypto.JoinBucketComponent(kT, 77, 8)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for bi := range cs0.AnchorBuckets {
		for gi := range cs0.AnchorBuckets[bi].Groups {
			if cs0.AnchorBuckets[bi].Groups[gi].Z != z {
				continue
			}
			found = true
			g0, g1 := cs0.AnchorBuckets[bi].Groups[gi], cs1.AnchorBuckets[bi].Groups[gi]
			if g0.PadWidth != 4 || g1.PadWidth != 4 || len(g0.Slots) != 4 || len(g1.Slots) != 4 {
				t.Fatalf("repeated qgram PadWidth/slots=%d/%d/%d/%d want 4", g0.PadWidth, g1.PadWidth, len(g0.Slots), len(g1.Slots))
			}
			for i := range g0.Slots {
				a, b := g0.Slots[i], g1.Slots[i]
				if i >= 2 {
					if reconstruct.RecoverRing64(a.RecordIDShare, b.RecordIDShare) != 0 || reconstruct.RecoverRing32(a.PositionShare, b.PositionShare) != 0 || reconstruct.RecoverBit(a.ValidityShare, b.ValidityShare) != domain.BitZero || combineScalar(t, a.KappaJoinShare, b.KappaJoinShare) != ([32]byte{}) || a.BucketJoinShare.Value()^b.BucketJoinShare.Value() != 0 {
						t.Fatalf("dummy %d reconstructed incorrectly", i)
					}
					continue
				}
				if reconstruct.RecoverRing64(a.RecordIDShare, b.RecordIDShare) != 77 || reconstruct.RecoverRing32(a.PositionShare, b.PositionShare) != domain.Ring32(i) || reconstruct.RecoverBit(a.ValidityShare, b.ValidityShare) != domain.BitOne || combineScalar(t, a.KappaJoinShare, b.KappaJoinShare) != wantKappaBytes || a.BucketJoinShare.Value()^b.BucketJoinShare.Value() != wantBucket {
					t.Fatalf("occurrence %d reconstructed incorrectly", i)
				}
			}
		}
	}
	if !found {
		t.Fatal("repeated qgram group missing")
	}
}

func TestFreshSharingIsInvokedPerPaddedOccurrence(t *testing.T) {
	kB, kT := testKeys(t)
	old64, old32, oldBit, oldScalar, oldBucket, oldPoint := splitRing64, splitRing32, splitBit, splitScalar, splitBucket, splitPoint
	defer func() {
		splitRing64, splitRing32, splitBit, splitScalar, splitBucket, splitPoint = old64, old32, oldBit, oldScalar, oldBucket, oldPoint
	}()
	var n64, n32, nBit, nScalar, nBucket, nPoint int
	// Wrappers count calls while retaining the production fresh-random splitters.
	splitRing64 = func(v domain.Ring64) (share.Ring64Share, share.Ring64Share, error) {
		n64++
		return preprocess.SplitRing64(v)
	}
	splitRing32 = func(v domain.Ring32) (share.Ring32Share, share.Ring32Share, error) {
		n32++
		return preprocess.SplitRing32(v)
	}
	splitBit = func(v domain.Bit) (share.BitShare, share.BitShare, error) { nBit++; return preprocess.SplitBit(v) }
	splitScalar = func(v *ristretto255.Scalar) (targetcrypto.ScalarShare, targetcrypto.ScalarShare, error) {
		nScalar++
		return targetcrypto.SplitScalar(v)
	}
	splitBucket = func(v targetcrypto.BucketComponent, k int) (targetcrypto.BucketShare, targetcrypto.BucketShare, error) {
		nBucket++
		return targetcrypto.SplitBucketComponent(v, k)
	}
	splitPoint = func(v *ristretto255.Element) (targetcrypto.PointShare, targetcrypto.PointShare, error) {
		nPoint++
		return targetcrypto.SplitPoint(v)
	}
	_, _, _, stats, err := Build([]AreaRecord{{1, "aaaaa"}, {2, "bcdefgh"}}, []AreaAliasRecord{{10, "aaaaa", 1}, {11, "bcdefgh", 2}}, kB, kT, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	total := stats.Anchor.PaddedSlots + stats.Target.PaddedSlots
	if n64 != total || n32 != total || nBit != total || nScalar != stats.Anchor.PaddedSlots || nBucket != stats.Anchor.PaddedSlots || nPoint != stats.Target.LogicalGroups {
		t.Fatalf("calls 64/32/bit/scalar/bucket/point=%d/%d/%d/%d/%d/%d stats=%+v", n64, n32, nBit, nScalar, nBucket, nPoint, stats)
	}
	if stats.Anchor.QGramOccurrences < 2 || stats.Target.QGramOccurrences < 2 {
		t.Fatal("test did not contain repeated occurrences")
	}
}

func TestPartySchemaHasNoPlaintextFields(t *testing.T) {
	forbidden := map[string]bool{"name": true, "qname": true, "qgram": true, "joinid": true, "area": true, "rawrecord": true, "peershare": true, "bothshares": true}
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if forbidden[strings.ToLower(f.Name)] {
				t.Errorf("forbidden party-state field %s.%s", typ, f.Name)
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeOf(PartyIndex{}))
	assertFields := func(typ reflect.Type, want []string) {
		t.Helper()
		var got []string
		for i := 0; i < typ.NumField(); i++ {
			got = append(got, typ.Field(i).Name)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s fields=%v want=%v", typ, got, want)
		}
	}
	assertFields(reflect.TypeOf(AnchorPartySlot{}), []string{"RecordIDShare", "PositionShare", "ValidityShare", "KappaJoinShare", "BucketJoinShare"})
	assertFields(reflect.TypeOf(TargetPartySlot{}), []string{"RecordIDShare", "PositionShare", "ValidityShare"})
	assertFields(reflect.TypeOf(AnchorPartyGroup{}), []string{"Z", "PadWidth", "Slots"})
	assertFields(reflect.TypeOf(TargetPartyGroup{}), []string{"TargetKeyShare", "PadWidth", "Slots"})
}

func TestPaddingReconstructsSemanticZero(t *testing.T) {
	kB, kT := testKeys(t)
	_, cs0, cs1, stats, err := Build([]AreaRecord{{1, "aaaaa"}, {2, "abcdefghi"}}, []AreaAliasRecord{{10, "aaaaa", 1}, {11, "abcdefghi", 2}}, kB, kT, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Anchor.PaddedSlots == stats.Anchor.RealSlots || stats.Target.PaddedSlots == stats.Target.RealSlots {
		t.Skip("deterministic keys did not place unequal groups together")
	}
	checkA := func(a, b AnchorPartySlot) {
		if reconstruct.RecoverRing64(a.RecordIDShare, b.RecordIDShare) != 0 || reconstruct.RecoverRing32(a.PositionShare, b.PositionShare) != 0 || reconstruct.RecoverBit(a.ValidityShare, b.ValidityShare) != domain.BitZero {
			t.Fatal("anchor dummy is not 0/0/0")
		}
		if combineScalar(t, a.KappaJoinShare, b.KappaJoinShare) != ([32]byte{}) || a.BucketJoinShare.Value()^b.BucketJoinShare.Value() != 0 {
			t.Fatal("anchor dummy routing payload is nonzero")
		}
	}
	for bi := range cs0.AnchorBuckets {
		for gi := range cs0.AnchorBuckets[bi].Groups {
			for si := range cs0.AnchorBuckets[bi].Groups[gi].Slots {
				a, b := cs0.AnchorBuckets[bi].Groups[gi].Slots[si], cs1.AnchorBuckets[bi].Groups[gi].Slots[si]
				if reconstruct.RecoverBit(a.ValidityShare, b.ValidityShare) == domain.BitZero {
					checkA(a, b)
					return
				}
			}
		}
	}
	t.Fatal("no anchor dummy found")
}

func combineScalar(t *testing.T, a, b targetcrypto.ScalarShare) [32]byte {
	t.Helper()
	ab, bb := a.CanonicalBytes(), b.CanonicalBytes()
	x, err := ristretto255.NewScalar().SetCanonicalBytes(ab[:])
	if err != nil {
		t.Fatal(err)
	}
	y, err := ristretto255.NewScalar().SetCanonicalBytes(bb[:])
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], ristretto255.NewScalar().Add(x, y).Bytes())
	return out
}
