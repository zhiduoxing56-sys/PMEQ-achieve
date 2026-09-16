package indexbuild

import (
	"reflect"
	"testing"

	"github.com/gtank/ristretto255"
	"pmeq/internal/domain"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
)

func TestAnalyzeLayoutMatchesBuildWithoutSharing(t *testing.T) {
	kB, kT := testKeys(t)
	areas := []AreaRecord{{1, "aaaaa"}, {2, "abcdefgh"}}
	aliases := []AreaAliasRecord{{10, "aaaaa", 1}, {11, "abcdefgh", 2}, {12, "abcde", 2}}
	analysis, err := AnalyzeLayout(areas, aliases, kB, kT, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _, _, stats, err := Build(areas, aliases, kB, kT, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(analysis.Metadata, metadata) || !reflect.DeepEqual(analysis.Anchor, stats.Anchor) || !reflect.DeepEqual(analysis.Target, stats.Target) {
		t.Fatalf("analysis differs from materialized build\nanalysis=%+v\nbuild metadata=%+v stats=%+v", analysis, metadata, stats)
	}

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
	if _, err := AnalyzeLayout(areas, aliases, kB, kT, 8, 8); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("AnalyzeLayout invoked a share splitter")
	}
}
