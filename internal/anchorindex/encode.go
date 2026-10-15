// Package anchorindex implements the canonical keyed 128-bit representation
// for the frozen PMEQ Anchor logical key.
package anchorindex

import (
	"crypto/hmac"
	"crypto/sha256"
)

const anchorIndexDomain = "PMEQ-BSMJ-INDEX-V1"

// Encode returns the first 16 bytes of HMAC-SHA256 under key over the exact
// ASCII domain literal followed by the canonical Anchor logical-key bytes.
func Encode(key Key, qgram string) (Value, error) {
	return encodeWith(key, qgram, canonicalAnchorLogicalKey, anchorIndexDomain)
}

// EncodeMovie uses the IMDb object/search/join tuple under a versioned domain.
func EncodeMovie(key Key, qgram string) (Value, error) {
	return encodeWith(key, qgram, canonicalMovieLogicalKey, "PMEQ-BSMJ-IMDB-INDEX-V1")
}

func encodeWith(key Key, qgram string, canonical func(string) ([]byte, error), domain string) (Value, error) {
	var value Value
	if !key.valid() {
		return value, errZeroKey
	}
	logicalKey, err := canonical(qgram)
	if err != nil {
		return value, err
	}

	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write(logicalKey)
	digest := mac.Sum(nil)
	copy(value[:], digest[:len(value)])
	return value, nil
}
