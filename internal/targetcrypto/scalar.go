package targetcrypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"

	"github.com/gtank/ristretto255"
)

// ErrShareEncoding reports a party-local share that is not a valid canonical
// encoding for its domain.
var ErrShareEncoding = errors.New("targetcrypto: share is not a canonical encoding")

// KJoin derives the keyed join scalar
//
//	kappa_J = Scalar.SetUniformBytes(HMAC-SHA512(k_T, Frame(joinScalarDomain, U64BE(joinID))))
//
// from the master key and a MusicBrainz join value. The result is an element of
// Z_l.
func KJoin(key MasterKey, joinID uint64) (*ristretto255.Scalar, error) {
	message, err := CanonicalJoin(joinScalarDomain, joinID)
	if err != nil {
		return nil, err
	}
	return scalarFromHMAC(key, message)
}

// KWord derives the keyed word scalar
//
//	kappa_w = Scalar.SetUniformBytes(HMAC-SHA512(k_T, Frame(wordScalarDomain, "PSMJ", "area_alias", "name", "area", qgram)))
//
// from the master key and a query q-gram.
func KWord(key MasterKey, qgram string) (*ristretto255.Scalar, error) {
	message, err := CanonicalWord(wordScalarDomain, qgram)
	if err != nil {
		return nil, err
	}
	return scalarFromHMAC(key, message)
}

func KMovieWord(key MasterKey, qgram string) (*ristretto255.Scalar, error) {
	message, err := CanonicalMovieWord("PMEQ-TARGET-IMDB-WORD-SCALAR-V1", qgram)
	if err != nil {
		return nil, err
	}
	return scalarFromHMAC(key, message)
}

func KMoviecastWord(key MasterKey, qgram string) (*ristretto255.Scalar, error) {
	message, err := CanonicalMoviecastWord("PMEQ-TARGET-IMDB-REVERSE-WORD-SCALAR-V1", qgram)
	if err != nil {
		return nil, err
	}
	return scalarFromHMAC(key, message)
}

// scalarFromHMAC is the only scalar derivation path. The master key is used
// exclusively as an HMAC key; it is never a message field, the digest is never
// reduced by a hand-written modulus, and the result is never rejected or
// retried: a zero component does not break the routing algebra, and retrying a
// single component could not remove the identity case of the combined scalar
// anyway.
func scalarFromHMAC(key MasterKey, message []byte) (*ristretto255.Scalar, error) {
	mac := hmac.New(sha512.New, key[:])
	_, _ = mac.Write(message)
	digest := mac.Sum(nil)
	return ristretto255.NewScalar().SetUniformBytes(digest)
}

// CombineScalar returns a + b in Z_l.
func CombineScalar(a, b *ristretto255.Scalar) *ristretto255.Scalar {
	return ristretto255.NewScalar().Add(a, b)
}

// ScalarShare is one party's additive share of a scalar in Z_l. It holds a
// single canonical 32-byte little-endian scalar encoding and nothing else: no
// peer share, no full secret, no party index, and no derivation metadata.
type ScalarShare [32]byte

// NewScalarShare validates and wraps a party-local scalar share supplied by a
// future party-file reader.
func NewScalarShare(canonical [32]byte) (ScalarShare, error) {
	if _, err := ristretto255.NewScalar().SetCanonicalBytes(canonical[:]); err != nil {
		return ScalarShare{}, ErrShareEncoding
	}
	return ScalarShare(canonical), nil
}

// CanonicalBytes returns this party's share as the canonical 32-byte
// little-endian scalar encoding.
func (s ScalarShare) CanonicalBytes() [32]byte { return [32]byte(s) }

func (s ScalarShare) scalar() (*ristretto255.Scalar, error) {
	return ristretto255.NewScalar().SetCanonicalBytes(s[:])
}

// CombineScalarShare returns a + b in Z_l for two party-local shares. Applying
// it to a party's own kappa_J and kappa_w shares yields that party's partial
// evaluation input.
func CombineScalarShare(a, b ScalarShare) (ScalarShare, error) {
	left, err := a.scalar()
	if err != nil {
		return ScalarShare{}, err
	}
	right, err := b.scalar()
	if err != nil {
		return ScalarShare{}, err
	}
	var out [32]byte
	copy(out[:], ristretto255.NewScalar().Add(left, right).Bytes())
	return ScalarShare(out), nil
}

// SplitScalar additively shares a scalar in Z_l between two parties using fresh
// uniform randomness.
func SplitScalar(secret *ristretto255.Scalar) (ScalarShare, ScalarShare, error) {
	return splitScalarWithReader(rand.Reader, secret)
}

func splitScalarWithReader(random io.Reader, secret *ristretto255.Scalar) (ScalarShare, ScalarShare, error) {
	left, err := uniformScalar(random)
	if err != nil {
		return ScalarShare{}, ScalarShare{}, err
	}
	right := ristretto255.NewScalar().Subtract(secret, left)
	var leftBytes, rightBytes [32]byte
	copy(leftBytes[:], left.Bytes())
	copy(rightBytes[:], right.Bytes())
	return ScalarShare(leftBytes), ScalarShare(rightBytes), nil
}

// scalarShareFromScalar wraps a scalar as a party-local share encoding.
func scalarShareFromScalar(value *ristretto255.Scalar) ScalarShare {
	var out [32]byte
	copy(out[:], value.Bytes())
	return ScalarShare(out)
}

// uniformScalar samples a uniform element of Z_l from random.
func uniformScalar(random io.Reader) (*ristretto255.Scalar, error) {
	var raw [64]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return nil, err
	}
	return ristretto255.NewScalar().SetUniformBytes(raw[:])
}
