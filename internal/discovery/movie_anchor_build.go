package discovery

import (
	"crypto/rand"
	"encoding/hex"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorindex"
	"pmeq/internal/imdbprod"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/zeroagg"
)

// WriteMovieAnchorBuckets is trusted-DO only. It reuses the production keyed
// index builder, incidence layout, zero labels, and permutation equations, but
// commits and releases one selected bucket before creating the next.
func WriteMovieAnchorBuckets(w *MovieAnchorWriter, areas []indexbuild.AreaRecord, joins []uint64, ak anchorindex.Key, tk targetcrypto.MasterKey, layout *aggregation.DealerLayout, selected func(uint32) bool, witness func(uint32, incidence.DealerLayout, []incidence.Posting) error) (int, error) {
	if w == nil || w.lock == nil || w.catalog.Complete || layout == nil || layout.LayoutID != w.catalog.LayoutID || layout.N != imdbprod.AnchorObjects || len(areas) != layout.N || len(joins) != layout.N || imdbprod.KeyFingerprint([32]byte(ak), [32]byte(tk)) != w.keyFingerprint {
		return 0, ErrBinding
	}
	written := 0
	err := indexbuild.VisitMovieAnchorBuckets(areas, joins, ak, tk, func(bucket uint32) bool {
		return !w.Has(bucket) && (selected == nil || selected(bucket))
	}, func(meta indexbuild.BucketMetadata, b0, b1 indexbuild.AnchorPartyBucket, posts []incidence.Posting) error {
		local, err := incidence.PrepareLayout(posts)
		if err != nil {
			return err
		}
		labels0, labels1, err := zeroagg.ShareCoordinates(local.Coordinates, local.D)
		if err != nil {
			return err
		}
		s0, s1, err := layout.Alignment(meta.BucketID, local, posts)
		if err != nil {
			return err
		}
		defer s1.Discard()
		defer clear(s0.RhoSeed[:])
		var label [16]byte
		if _, err = rand.Read(label[:]); err != nil {
			return err
		}
		labelID := hex.EncodeToString(label[:])
		a0 := AnchorStatic{Bucket: b0, D: local.D, T: len(posts), Labels: labels0, LabelID: labelID, Stage0: s0}
		a1 := AnchorStatic{Bucket: b1, D: local.D, T: len(posts), Labels: labels1, LabelID: labelID, Stage1: s1}
		if err = w.PutPair(meta.BucketID, a0, a1); err != nil {
			return err
		}
		// The optional witness stays in the trusted DO process. It is used by
		// bounded correctness probes and is never serialized into a cloud file.
		if witness != nil {
			if err = witness(meta.BucketID, local, posts); err != nil {
				return err
			}
		}
		written++
		return nil
	})
	return written, err
}
