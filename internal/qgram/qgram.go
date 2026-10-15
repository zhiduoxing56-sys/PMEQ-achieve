// Package qgram provides explicit Unicode-codepoint fragments for parameter experiments.
// It does not construct an index or change any production default or encoding domain.
package qgram

import (
	"errors"
	"unicode/utf8"
)

type Chunk struct {
	Word     string
	Position uint32
}

func Overlapping(text string, q int) ([]Chunk, error) {
	if q < 1 || !utf8.ValidString(text) {
		return nil, errors.New("qgram: invalid q or UTF-8")
	}
	r := []rune(text)
	out := make([]Chunk, 0)
	for p := 0; p+q <= len(r); p++ {
		out = append(out, Chunk{string(r[p : p+q]), uint32(p)})
	}
	return out, nil
}

// Query uses the first count complete disjoint chunks; count=0 means all chunks.
// The original full query remains unchanged for exact edit-distance verification.
func Query(text string, q, count int) ([]Chunk, error) {
	if q < 1 || count < 0 || !utf8.ValidString(text) {
		return nil, errors.New("qgram: invalid query parameters")
	}
	r := []rune(text)
	if count > len(r)/q {
		return nil, errors.New("qgram: insufficient complete query chunks")
	}
	if count == 0 {
		count = len(r) / q
	}
	out := make([]Chunk, count)
	for h := range out {
		p := h * q
		out[h] = Chunk{string(r[p : p+q]), uint32(p)}
	}
	return out, nil
}
