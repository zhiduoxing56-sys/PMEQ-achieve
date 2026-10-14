package indexbuild

import (
	"errors"
	"reflect"
	"testing"

	"github.com/gtank/ristretto255"
	"pmeq/internal/domain"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
)

func TestTierWidth(t *testing.T) {
	tests := []struct{ n, w int }{{1, 4}, {4, 4}, {5, 16}, {16, 16}, {17, 64}, {64, 64}, {65, 256}, {256, 256}, {257, 1024}, {1024, 1024}, {1025, 4096}, {4096, 4096}, {4097, 8192}, {8192, 8192}, {8193, 16384}, {16384, 16384}, {16385, 32768}, {32768, 32768}}
	for _, test := range tests {
		got, err := TierWidth(test.n)
		if err != nil || got != test.w {
			t.Fatalf("TierWidth(%d)=%d,%v want %d", test.n, got, err, test.w)
		}
	}
	if _, err := TierWidth(0); err == nil {
		t.Fatal("accepted empty group")
	}
	if _, err := TierWidth(32769); !errors.Is(err, ErrTierOverflow) {
		t.Fatalf("overflow error=%v", err)
	}
}

func TestTierLayoutMatchesBuildAndUniformRemainsBaseline(t *testing.T) {
	kB, kT := testKeys(t)
	areas := []AreaRecord{{1, "aaaaa"}, {2, "abcdefgh"}}
	aliases := []AreaAliasRecord{{10, "aaaaa", 1}, {11, "abcdefgh", 2}, {12, "abcde", 2}}
	tier, err := AnalyzeTierLayout(areas, aliases, kB, kT, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	uniform, err := AnalyzeUniformLayout(areas, aliases, kB, kT, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	metadata, cs0, cs1, stats, err := Build(areas, aliases, kB, kT, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tier.Metadata, metadata) || !reflect.DeepEqual(tier.Anchor, stats.Anchor) || !reflect.DeepEqual(tier.Target, stats.Target) {
		t.Fatalf("tier analysis differs from Build")
	}
	if uniform.Anchor.LPad.Max == 0 || uniform.Target.LPad.Max == 0 || tier.Anchor.PadWidth.Max == 0 || tier.Target.PadWidth.Max == 0 {
		t.Fatal("uniform/tier analyzers did not expose their distinct padding statistics")
	}
	for bi := range cs0.AnchorBuckets {
		for gi := range cs0.AnchorBuckets[bi].Groups {
			a, b := cs0.AnchorBuckets[bi].Groups[gi], cs1.AnchorBuckets[bi].Groups[gi]
			if a.PadWidth != b.PadWidth || len(a.Slots) != int(a.PadWidth) || len(b.Slots) != int(b.PadWidth) {
				t.Fatal("Anchor PadWidth mismatch")
			}
		}
	}
	for bi := range cs0.TargetBuckets {
		for gi := range cs0.TargetBuckets[bi].Groups {
			a, b := cs0.TargetBuckets[bi].Groups[gi], cs1.TargetBuckets[bi].Groups[gi]
			if a.PadWidth != b.PadWidth || len(a.Slots) != int(a.PadWidth) || len(b.Slots) != int(b.PadWidth) {
				t.Fatal("Target PadWidth mismatch")
			}
		}
	}
}

func TestLayoutAnalyzersNeverShare(t *testing.T) {
	kB, kT := testKeys(t)
	areas := []AreaRecord{{1, "aaaaa"}}
	aliases := []AreaAliasRecord{{10, "aaaaa", 1}}
	old64, old32, oldBit, oldScalar, oldBucket, oldPoint := splitRing64, splitRing32, splitBit, splitScalar, splitBucket, splitPoint
	defer func() {
		splitRing64, splitRing32, splitBit, splitScalar, splitBucket, splitPoint = old64, old32, oldBit, oldScalar, oldBucket, oldPoint
	}()
	called := false
	splitRing64 = func(domain.Ring64) (share.Ring64Share, share.Ring64Share, error) {
		called = true
		return share.Ring64Share{}, share.Ring64Share{}, nil
	}
	splitRing32 = func(domain.Ring32) (share.Ring32Share, share.Ring32Share, error) {
		called = true
		return share.Ring32Share{}, share.Ring32Share{}, nil
	}
	splitBit = func(domain.Bit) (share.BitShare, share.BitShare, error) {
		called = true
		return share.BitShare{}, share.BitShare{}, nil
	}
	splitScalar = func(*ristretto255.Scalar) (targetcrypto.ScalarShare, targetcrypto.ScalarShare, error) {
		called = true
		return targetcrypto.ScalarShare{}, targetcrypto.ScalarShare{}, nil
	}
	splitBucket = func(targetcrypto.BucketComponent, int) (targetcrypto.BucketShare, targetcrypto.BucketShare, error) {
		called = true
		return 0, 0, nil
	}
	splitPoint = func(*ristretto255.Element) (targetcrypto.PointShare, targetcrypto.PointShare, error) {
		called = true
		return targetcrypto.PointShare{}, targetcrypto.PointShare{}, nil
	}
	if _, err := AnalyzeUniformLayout(areas, aliases, kB, kT, 8, 8); err != nil {
		t.Fatal(err)
	}
	if _, err := AnalyzeTierLayout(areas, aliases, kB, kT, 8, 8); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("layout analyzer invoked share splitter")
	}
}
