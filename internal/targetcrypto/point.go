package targetcrypto

import (
	"crypto/rand"
	"crypto/sha512"
	"io"

	"github.com/gtank/ristretto255"
)

// targetBasePoint is the fixed KHPRF base point
//
//	P = Element.SetUniformBytes(SHA512("PMEQ-TARGET-KHPRF-POINT-V1")).
//
// The canonical Ristretto255 generator is deliberately not used, so that the
// routing base point occupies its own semantic domain and cannot be reused as a
// future retrieval base point.
var targetBasePoint = deriveTargetBasePoint()

func deriveTargetBasePoint() *ristretto255.Element {
	digest := sha512.Sum512([]byte(targetPointDomain))
	element, err := ristretto255.NewElement().SetUniformBytes(digest[:])
	if err != nil {
		// Unreachable: SetUniformBytes rejects only a wrong input length, and
		// digest is a fixed 64-byte array.
		panic("targetcrypto: fixed KHPRF base point derivation failed: " + err.Error())
	}
	return element
}

// TargetBasePoint returns a fresh copy of the fixed KHPRF base point P. It is
// not the canonical generator and is not the identity.
func TargetBasePoint() *ristretto255.Element {
	return ristretto255.NewElement().Set(targetBasePoint)
}

// PartEval computes one party's partial KHPRF evaluation kappaShare * P. The
// result is that party's additive share of the full point and reveals nothing
// about the peer share.
func PartEval(share ScalarShare) (*ristretto255.Element, error) {
	scalar, err := share.scalar()
	if err != nil {
		return nil, err
	}
	return ristretto255.NewElement().ScalarMult(scalar, targetBasePoint), nil
}

// FullEval computes kappa * P for a complete scalar. It exists for the trusted
// data-owner build path and for tests; no cloud-facing package may call it.
func FullEval(kappa *ristretto255.Scalar) *ristretto255.Element {
	return ristretto255.NewElement().ScalarMult(kappa, targetBasePoint)
}

// DeriveTargetGroupPoint computes the full Target group point
//
//	T = (KJoin(k_T, joinID) + KWord(k_T, qgram)) * P.
//
// It is a trusted data-owner build-time helper: it returns the complete group
// point, so it must never be reachable from a cloud-facing package.
func DeriveTargetGroupPoint(key MasterKey, joinID uint64, qgram string) (*ristretto255.Element, error) {
	joinScalar, err := KJoin(key, joinID)
	if err != nil {
		return nil, err
	}
	wordScalar, err := KWord(key, qgram)
	if err != nil {
		return nil, err
	}
	return FullEval(CombineScalar(joinScalar, wordScalar)), nil
}

func DeriveMovieGroupPoint(key MasterKey, joinID uint64, qgram string) (*ristretto255.Element, error) {
	joinScalar, err := KJoin(key, joinID)
	if err != nil {
		return nil, err
	}
	wordScalar, err := KMovieWord(key, qgram)
	if err != nil {
		return nil, err
	}
	return FullEval(CombineScalar(joinScalar, wordScalar)), nil
}

func DeriveMoviecastGroupPoint(key MasterKey, joinID uint64, qgram string) (*ristretto255.Element, error) {
	joinScalar, err := KJoin(key, joinID)
	if err != nil {
		return nil, err
	}
	wordScalar, err := KMoviecastWord(key, qgram)
	if err != nil {
		return nil, err
	}
	return FullEval(CombineScalar(joinScalar, wordScalar)), nil
}

// PointShare is one party's additive share of a Target group point. It holds a
// single canonical 32-byte Ristretto255 encoding and nothing else: no peer
// share, no full point, no party index, and no derivation metadata. Encoding a
// share and XORing it with the peer encoding has no protocol meaning.
type PointShare [32]byte

// NewPointShare validates and wraps a party-local point share supplied by a
// future party-file reader.
func NewPointShare(canonical [32]byte) (PointShare, error) {
	if _, err := ristretto255.NewElement().SetCanonicalBytes(canonical[:]); err != nil {
		return PointShare{}, ErrShareEncoding
	}
	return PointShare(canonical), nil
}

// CanonicalBytes returns this party's share as the canonical 32-byte
// Ristretto255 encoding.
func (p PointShare) CanonicalBytes() [32]byte { return [32]byte(p) }

func (p PointShare) element() (*ristretto255.Element, error) {
	return ristretto255.NewElement().SetCanonicalBytes(p[:])
}

// SplitPoint additively shares a group point between two parties: it samples a
// uniform scalar r, sets T0 = r * P, and sets T1 = T - T0, so that
// T0 + T1 = T. Neither share alone carries information about T.
func SplitPoint(target *ristretto255.Element) (PointShare, PointShare, error) {
	return splitPointWithReader(rand.Reader, target)
}

func splitPointWithReader(random io.Reader, target *ristretto255.Element) (PointShare, PointShare, error) {
	r, err := uniformScalar(random)
	if err != nil {
		return PointShare{}, PointShare{}, err
	}
	left := ristretto255.NewElement().ScalarMult(r, targetBasePoint)
	right := ristretto255.NewElement().Subtract(target, left)
	var leftBytes, rightBytes [32]byte
	copy(leftBytes[:], left.Bytes())
	copy(rightBytes[:], right.Bytes())
	return PointShare(leftBytes), PointShare(rightBytes), nil
}
