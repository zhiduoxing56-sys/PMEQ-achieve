// Package anchorquery is the authorized Query User boundary for Anchor tokens.
package anchorquery

import (
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"pmeq/internal/dpf128"
	"pmeq/internal/dpf128/gen"
	"pmeq/internal/indexbuild"
)

// MakeOccurrence derives the HMAC point and DPF keys without exposing the
// q-gram, kB, or alpha in either returned cloud token.
func MakeOccurrence(kB anchorindex.Key, chunk anchorfilter.QueryChunk, tau, uPos uint32, bucketBits int, user *anchorfilter.UserPreprocessing) (anchorfilter.PartyQuery, anchorfilter.PartyQuery, error) {
	return makeOccurrence(kB, chunk, tau, uPos, bucketBits, user, anchorindex.Encode)
}

func MakeMovieOccurrence(kB anchorindex.Key, chunk anchorfilter.QueryChunk, tau, uPos uint32, bucketBits int, user *anchorfilter.UserPreprocessing) (anchorfilter.PartyQuery, anchorfilter.PartyQuery, error) {
	return makeOccurrence(kB, chunk, tau, uPos, bucketBits, user, anchorindex.EncodeMovie)
}

func makeOccurrence(kB anchorindex.Key, chunk anchorfilter.QueryChunk, tau, uPos uint32, bucketBits int, user *anchorfilter.UserPreprocessing, encode func(anchorindex.Key, string) (anchorindex.Value, error)) (anchorfilter.PartyQuery, anchorfilter.PartyQuery, error) {
	z, err := encode(kB, chunk.QGram)
	if err != nil {
		return anchorfilter.PartyQuery{}, anchorfilter.PartyQuery{}, err
	}
	bucket, err := indexbuild.AnchorBucket(z, bucketBits)
	if err != nil {
		return anchorfilter.PartyQuery{}, anchorfilter.PartyQuery{}, err
	}
	k0, k1, err := gen.Gen(dpf128.PointFromAnchorValue(z))
	if err != nil {
		return anchorfilter.PartyQuery{}, anchorfilter.PartyQuery{}, err
	}
	pid, l, r, err := user.ConsumeBounds(chunk.Position, tau, uPos)
	if err != nil {
		return anchorfilter.PartyQuery{}, anchorfilter.PartyQuery{}, err
	}
	a := anchorfilter.PartyQuery{PID: pid, BucketID: bucket, DPFKey: k0, Ltilde: l, RplusTilde: r}
	b := anchorfilter.PartyQuery{PID: pid, BucketID: bucket, DPFKey: k1, Ltilde: l, RplusTilde: r}
	return a, b, nil
}
