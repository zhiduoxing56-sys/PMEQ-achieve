package targetcrypto

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

// Domain separation constants. Each maps to exactly one derivation; role
// specific duplicates of these constants are forbidden.
const (
	joinScalarDomain = "PMEQ-TARGET-JOIN-SCALAR-V1"
	wordScalarDomain = "PMEQ-TARGET-WORD-SCALAR-V1"
	joinBucketDomain = "PMEQ-TARGET-BUCKET-JOIN-V1"
	wordBucketDomain = "PMEQ-TARGET-BUCKET-WORD-V1"

	targetPointDomain = "PMEQ-TARGET-KHPRF-POINT-V1"

	// Logical Target tuple components. These are protocol identifiers, not
	// physical MusicBrainz column positions.
	psmjLabel        = "PSMJ"
	targetTable      = "area_alias"
	targetSearchAttr = "name"
	targetJoinAttr   = "area"

	targetQ = 4
)

var (
	// ErrInvalidUTF8 reports a q-gram that is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("targetcrypto: qgram is not valid UTF-8")
	// ErrInvalidQ reports a q-gram that is not exactly targetQ code points.
	ErrInvalidQ = errors.New("targetcrypto: qgram must contain exactly four Unicode code points")
	// ErrFieldTooLong reports a canonical encoding field longer than uint32.
	ErrFieldTooLong = errors.New("targetcrypto: field exceeds uint32 byte length")
)

// Frame is the only canonical target encoder. Every component, including the
// domain label, is prefixed by its 32-bit big-endian byte length, so no two
// distinct field lists can produce the same encoding. It preserves the exact
// input bytes: it performs no normalization, case folding, or trimming.
func Frame(domain string, fields ...[]byte) ([]byte, error) {
	if uint64(len(domain)) > uint64(^uint32(0)) {
		return nil, ErrFieldTooLong
	}
	total := 4 + len(domain)
	for _, field := range fields {
		if uint64(len(field)) > uint64(^uint32(0)) {
			return nil, ErrFieldTooLong
		}
		total += 4 + len(field)
	}

	out := make([]byte, 0, total)
	out = binary.BigEndian.AppendUint32(out, uint32(len(domain)))
	out = append(out, domain...)
	for _, field := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	return out, nil
}

// CanonicalJoin encodes a MusicBrainz join value (area.id on the Anchor side,
// area_alias.area on the Target side) as a single unsigned 64-bit big-endian
// field under the supplied domain.
func CanonicalJoin(domain string, joinID uint64) ([]byte, error) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], joinID)
	return Frame(domain, raw[:])
}

// CanonicalWord encodes the Target logical tuple
// (PSMJ, area_alias, name, area, qgram) under the supplied domain. The q-gram
// must be valid UTF-8 containing exactly targetQ Unicode code points.
func CanonicalWord(domain string, qgram string) ([]byte, error) {
	if !utf8.ValidString(qgram) {
		return nil, ErrInvalidUTF8
	}
	if utf8.RuneCountInString(qgram) != targetQ {
		return nil, ErrInvalidQ
	}
	return Frame(domain,
		[]byte(psmjLabel),
		[]byte(targetTable),
		[]byte(targetSearchAttr),
		[]byte(targetJoinAttr),
		[]byte(qgram),
	)
}
