// Package candidatequery is the authorized Query User final recovery boundary.
package candidatequery

import (
	"encoding/binary"
	"errors"
	"pmeq/internal/domain"
	"pmeq/internal/share"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetrouting"
)

var ErrResult = errors.New("candidatequery: invalid result binding, masked zero or duplicate pair")

type Pair struct{ AnchorRecordID, TargetRecordID uint64 }
type CandidatePairs struct {
	QueryID [16]byte
	Pairs   []Pair
}
type Binding struct {
	Manifest                        targetrouting.Manifest
	LayoutID, CompactionID, QueryID [16]byte
}

const HeaderBytes = 86

func valid(s targetaggregation.CandidatePairShares) bool {
	return s.Manifest.Validate() == nil && s.Manifest.TargetBucketBits == 16 && s.Manifest.IndexID != [16]byte{} && s.LayoutID != [16]byte{} && s.CompactionID != [16]byte{} && s.QueryID != [16]byte{} && s.K >= 0 && s.K <= 120071 && s.DTarget == 26 && len(s.PairKeepShares) == 26*s.K && len(s.AnchorIDShares) == 26*s.K && len(s.TargetIDShares) == 26*s.K
}

// EncodeShares serializes one party only. It never tests the secret Keep value.
func EncodeShares(party uint8, s targetaggregation.CandidatePairShares) ([]byte, error) {
	if party > 1 || !valid(s) {
		return nil, ErrResult
	}
	b := make([]byte, HeaderBytes+17*26*s.K)
	copy(b, "PMEQPAIR")
	b[8] = party
	copy(b[9:25], s.Manifest.IndexID[:])
	b[25] = 16
	binary.LittleEndian.PutUint32(b[26:], 4)
	copy(b[30:46], s.LayoutID[:])
	copy(b[46:62], s.CompactionID[:])
	copy(b[62:78], s.QueryID[:])
	binary.LittleEndian.PutUint32(b[78:], uint32(s.K))
	binary.LittleEndian.PutUint32(b[82:], 26)
	for i, k := range s.PairKeepShares {
		at := HeaderBytes + 17*i
		if k.Value() {
			b[at] = 1
		}
		binary.LittleEndian.PutUint64(b[at+1:], uint64(s.AnchorIDShares[i].Value()))
		binary.LittleEndian.PutUint64(b[at+9:], uint64(s.TargetIDShares[i].Value()))
	}
	return b, nil
}
func DecodeShares(party uint8, w Binding, b []byte) (targetaggregation.CandidatePairShares, error) {
	var s targetaggregation.CandidatePairShares
	if len(b) < HeaderBytes || string(b[:8]) != "PMEQPAIR" || b[8] != party || party > 1 {
		return s, ErrResult
	}
	copy(s.Manifest.IndexID[:], b[9:25])
	s.Manifest.TargetBucketBits = b[25]
	s.Manifest.Q = binary.LittleEndian.Uint32(b[26:])
	copy(s.LayoutID[:], b[30:46])
	copy(s.CompactionID[:], b[46:62])
	copy(s.QueryID[:], b[62:78])
	s.K = int(binary.LittleEndian.Uint32(b[78:]))
	s.DTarget = int(binary.LittleEndian.Uint32(b[82:]))
	if s.Manifest != w.Manifest || s.LayoutID != w.LayoutID || s.CompactionID != w.CompactionID || s.QueryID != w.QueryID || s.K > 120071 || s.DTarget != 26 || len(b) != HeaderBytes+17*26*s.K {
		return s, ErrResult
	}
	s.PairKeepShares = make([]share.BitShare, 26*s.K)
	s.AnchorIDShares = make([]share.Ring64Share, 26*s.K)
	s.TargetIDShares = make([]share.Ring64Share, 26*s.K)
	for i := range s.PairKeepShares {
		at := HeaderBytes + 17*i
		if b[at] > 1 {
			return s, ErrResult
		}
		s.PairKeepShares[i] = share.NewBitShare(domain.Bit(b[at] == 1))
		s.AnchorIDShares[i] = share.NewRing64Share(domain.Ring64(binary.LittleEndian.Uint64(b[at+1:])))
		s.TargetIDShares[i] = share.NewRing64Share(domain.Ring64(binary.LittleEndian.Uint64(b[at+9:])))
	}
	if !valid(s) {
		return s, ErrResult
	}
	return s, nil
}

// Recover must be called only by the authorized user, over authenticated party
// channels and the expected query/compaction binding. No sorting or deduplication
// can silently change a malformed result: duplicates and nonzero masked zeros fail.
func Recover(w Binding, a, b []byte) (CandidatePairs, error) {
	x, e := DecodeShares(0, w, a)
	if e != nil {
		return CandidatePairs{}, e
	}
	y, e := DecodeShares(1, w, b)
	if e != nil || x.K != y.K {
		return CandidatePairs{}, ErrResult
	}
	out := CandidatePairs{QueryID: w.QueryID, Pairs: make([]Pair, 0)}
	seen := map[Pair]bool{}
	for i := range x.PairKeepShares {
		keep := x.PairKeepShares[i].Value().Add(y.PairKeepShares[i].Value())
		p := Pair{uint64(x.AnchorIDShares[i].Value() + y.AnchorIDShares[i].Value()), uint64(x.TargetIDShares[i].Value() + y.TargetIDShares[i].Value())}
		if !keep {
			if p != (Pair{}) {
				return CandidatePairs{}, ErrResult
			}
			continue
		}
		if seen[p] {
			return CandidatePairs{}, ErrResult
		}
		seen[p] = true
		out.Pairs = append(out.Pairs, p)
	}
	return out, nil
}
