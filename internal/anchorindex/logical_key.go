package anchorindex

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

const (
	anchorIndexKind = "BSMJ"
	anchorTable     = "area"
	anchorSearch    = "name"
	anchorJoin      = "id"
	anchorQ         = 4
)

var (
	errInvalidUTF8  = errors.New("anchorindex: qgram is not valid UTF-8")
	errInvalidQ     = errors.New("anchorindex: qgram must contain exactly four Unicode code points")
	errFieldTooLong = errors.New("anchorindex: logical-key field exceeds uint32 byte length")
)

// canonicalAnchorLogicalKey is the only production logical-key encoder. It
// deliberately preserves the caller's UTF-8 bytes: no normalization, case
// folding, whitespace trimming, or other rewriting is performed.
func canonicalAnchorLogicalKey(qgram string) ([]byte, error) {
	if !utf8.ValidString(qgram) {
		return nil, errInvalidUTF8
	}
	if utf8.RuneCountInString(qgram) != anchorQ {
		return nil, errInvalidQ
	}
	return encodeLengthDelimited(anchorIndexKind, anchorTable, anchorSearch, anchorJoin, qgram)
}

func canonicalMovieLogicalKey(qgram string) ([]byte, error) {
	if !utf8.ValidString(qgram) {
		return nil, errInvalidUTF8
	}
	if utf8.RuneCountInString(qgram) != anchorQ {
		return nil, errInvalidQ
	}
	return encodeLengthDelimited("BSMJ-IMDB-V1", "MOVIECAST", "aliasTitle", "tconst", qgram)
}

// canonicalMovieTitleLogicalKey is the separate reverse outsourcing domain.
func canonicalMovieTitleLogicalKey(qgram string) ([]byte, error) {
	if !utf8.ValidString(qgram) {
		return nil, errInvalidUTF8
	}
	if utf8.RuneCountInString(qgram) != anchorQ {
		return nil, errInvalidQ
	}
	return encodeLengthDelimited("BSMJ-IMDB-REVERSE-V1", "MOVIE", "primaryTitle", "tconst", qgram)
}

func encodeLengthDelimited(fields ...string) ([]byte, error) {
	total := 0
	for _, field := range fields {
		if uint64(len(field)) > uint64(^uint32(0)) {
			return nil, errFieldTooLong
		}
		total += 4 + len(field)
	}

	out := make([]byte, 0, total)
	for _, field := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	return out, nil
}
