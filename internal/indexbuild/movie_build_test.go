package indexbuild

import (
	"github.com/gtank/ristretto255"
	"pmeq/internal/anchorindex"
	"pmeq/internal/targetcrypto"
	"testing"
)

func TestMovieBuildUsesSameJoinAndVersionedFields(t *testing.T) {
	ak, _ := anchorindex.NewKey([32]byte{1})
	tk, _ := targetcrypto.NewMasterKey([32]byte{2})
	anchors := []AreaRecord{{ID: 1, Name: "abcd"}, {ID: 2, Name: "abcd"}}
	joins := []uint64{9, 9}
	targets := []AreaAliasRecord{{ID: 9, Area: 9, Name: "abcd"}}
	_, a, b, _, err := BuildMovie(anchors, joins, targets, ak, tk)
	if err != nil {
		t.Fatal(err)
	}
	z, err := anchorindex.EncodeMovie(ak, "abcd")
	if err != nil {
		t.Fatal(err)
	}
	ab, err := AnchorBucket(z, 16)
	if err != nil || len(a.AnchorBuckets) != 1 || a.AnchorBuckets[0].BucketID != ab || a.AnchorBuckets[0].Groups[0].Z != z {
		t.Fatal("movie anchor domain")
	}
	if len(a.AnchorBuckets[0].Groups[0].Slots) != 4 {
		t.Fatal("padding tier")
	}
	join, _ := targetcrypto.JoinBucketComponent(tk, 9, 16)
	word, _ := targetcrypto.MovieWordBucketComponent(tk, "abcd", 16)
	bin := uint32(join ^ word)
	if len(a.TargetBuckets) != 1 || a.TargetBuckets[0].BucketID != bin || b.TargetBuckets[0].BucketID != bin {
		t.Fatal("movie target bucket")
	}
	x, err := ristretto255.NewElement().SetCanonicalBytes(a.TargetBuckets[0].Groups[0].TargetKeyShare[:])
	if err != nil {
		t.Fatal(err)
	}
	y, err := ristretto255.NewElement().SetCanonicalBytes(b.TargetBuckets[0].Groups[0].TargetKeyShare[:])
	if err != nil {
		t.Fatal(err)
	}
	want, err := targetcrypto.DeriveMovieGroupPoint(tk, 9, "abcd")
	if err != nil || ristretto255.NewElement().Add(x, y).Equal(want) != 1 {
		t.Fatal("movie point mismatch")
	}
}
