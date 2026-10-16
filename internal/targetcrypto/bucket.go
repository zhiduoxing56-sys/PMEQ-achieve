package targetcrypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

// Bucket width bounds. The current production width is not fixed by PHASE 3B;
// this package only requires a power-of-two bucket space B = 2^k.
const (
	// MinBucketBits is the smallest supported bucket width.
	MinBucketBits = 1
	// MaxBucketBits is the largest supported bucket width.
	MaxBucketBits = 17
)

// ErrBucketBits reports a bucket width outside [MinBucketBits, MaxBucketBits].
var ErrBucketBits = errors.New("targetcrypto: bucket bits must be between 1 and 17")

// BucketComponent is a k-bit routing component in F_2^k. Only the low k bits
// are significant; the width is a public system parameter.
type BucketComponent uint32

// JoinBucketComponent derives the keyed join routing component
//
//	beta_J = HMAC-SHA256(k_T, Frame(joinBucketDomain, U64BE(joinID)))  truncated to k bits
//
// taking the first k bits of the digest in most-significant-bit-first order. It
// returns a full component; the data owner shares it before distribution.
func JoinBucketComponent(key MasterKey, joinID uint64, k int) (BucketComponent, error) {
	if err := checkBucketBits(k); err != nil {
		return 0, err
	}
	message, err := CanonicalJoin(joinBucketDomain, joinID)
	if err != nil {
		return 0, err
	}
	return bucketComponentFromHMAC(key, message, k), nil
}

// WordBucketComponent derives the keyed word routing component from the Target
// logical tuple (PSMJ, area_alias, name, area, qgram).
func WordBucketComponent(key MasterKey, qgram string, k int) (BucketComponent, error) {
	if err := checkBucketBits(k); err != nil {
		return 0, err
	}
	message, err := CanonicalWord(wordBucketDomain, qgram)
	if err != nil {
		return 0, err
	}
	return bucketComponentFromHMAC(key, message, k), nil
}

func MovieWordBucketComponent(key MasterKey, qgram string, k int) (BucketComponent, error) {
	if err := checkBucketBits(k); err != nil {
		return 0, err
	}
	message, err := CanonicalMovieWord("PMEQ-TARGET-IMDB-BUCKET-WORD-V1", qgram)
	if err != nil {
		return 0, err
	}
	return bucketComponentFromHMAC(key, message, k), nil
}

func MoviecastWordBucketComponent(key MasterKey, qgram string, k int) (BucketComponent, error) {
	if err := checkBucketBits(k); err != nil {
		return 0, err
	}
	message, err := CanonicalMoviecastWord("PMEQ-TARGET-IMDB-REVERSE-BUCKET-WORD-V1", qgram)
	if err != nil {
		return 0, err
	}
	return bucketComponentFromHMAC(key, message, k), nil
}

func bucketComponentFromHMAC(key MasterKey, message []byte, k int) BucketComponent {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(message)
	return prefixBits(mac.Sum(nil), k)
}

// prefixBits reads the first k bits of digest in most-significant-bit-first
// order. It never reduces an integer modulo the bucket count.
func prefixBits(digest []byte, k int) BucketComponent {
	bytesNeeded := (k + 7) / 8
	var acc uint32
	for i := 0; i < bytesNeeded; i++ {
		acc = acc<<8 | uint32(digest[i])
	}
	return BucketComponent(acc >> uint(bytesNeeded*8-k))
}

func checkBucketBits(k int) error {
	if k < MinBucketBits || k > MaxBucketBits {
		return ErrBucketBits
	}
	return nil
}

// CombineBucketComponents returns a XOR b in F_2^k. Neither input is revealed
// by the result unless the other input is already known.
func CombineBucketComponents(a, b BucketComponent) BucketComponent {
	return a ^ b
}

// BucketShare is one party's XOR share of a bucket component. It is a single
// local k-bit value and nothing else: no peer share, no full component, and no
// derivation metadata.
type BucketShare uint32

// Value returns this party's share as a bucket component.
func (s BucketShare) Value() BucketComponent {
	return BucketComponent(s)
}

// SplitBucketComponent XOR-shares a bucket component in F_2^k between two
// parties using fresh uniform randomness.
func SplitBucketComponent(beta BucketComponent, k int) (BucketShare, BucketShare, error) {
	return splitBucketComponentWithReader(rand.Reader, beta, k)
}

func splitBucketComponentWithReader(random io.Reader, beta BucketComponent, k int) (BucketShare, BucketShare, error) {
	if err := checkBucketBits(k); err != nil {
		return 0, 0, err
	}
	mask := uint32(1)<<uint(k) - 1
	bytesNeeded := (k + 7) / 8
	var raw [3]byte
	if _, err := io.ReadFull(random, raw[:bytesNeeded]); err != nil {
		return 0, 0, err
	}
	left := uint32(0)
	for i := 0; i < bytesNeeded; i++ {
		left = left<<8 | uint32(raw[i])
	}
	left >>= uint(bytesNeeded*8 - k)
	value := uint32(beta) & mask
	return BucketShare(left), BucketShare((value ^ left) & mask), nil
}

// BucketDomain binds local XOR operations to the manifest's explicit width.
// It does not infer width from Anchor parameters or silently truncate a share.
type BucketDomain uint8

func NewBucketDomain(bits int) (BucketDomain, error) {
	if e := checkBucketBits(bits); e != nil {
		return BucketDomain(0), e
	}
	return BucketDomain(bits), nil
}
func (d BucketDomain) Bits() int { return int(d) }
func (d BucketDomain) Validate(s BucketShare) error {
	if e := checkBucketBits(int(d)); e != nil {
		return e
	}
	if uint32(s) >= uint32(1)<<uint8(d) {
		return ErrShareEncoding
	}
	return nil
}
func (d BucketDomain) XOR(a, b BucketShare) (BucketShare, error) {
	if e := d.Validate(a); e != nil {
		return 0, e
	}
	if e := d.Validate(b); e != nil {
		return 0, e
	}
	return a ^ b, nil
}
func (d BucketDomain) Open(a, b BucketShare) (BucketComponent, error) {
	v, e := d.XOR(a, b)
	return v.Value(), e
}
