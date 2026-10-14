// Package targetquery is the authorized Query User boundary, never a cloud runtime.
package targetquery

import (
	"crypto/rand"
	"errors"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetrouting"
)

// GenerateTokens is QUERY USER ONLY, before the Anchor query starts. No cloud
// routine calls it. Each occurrence is freshly shared, including repeated words.
func GenerateTokens(m targetrouting.Manifest, key targetcrypto.MasterKey, text string) (targetrouting.QueryToken, targetrouting.QueryToken, error) {
	if e := m.Validate(); e != nil {
		return targetrouting.QueryToken{}, targetrouting.QueryToken{}, e
	}
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return targetrouting.QueryToken{}, targetrouting.QueryToken{}, e
	}
	runes := []rune(text)
	n := len(runes) / 4
	a, b := targetrouting.QueryToken{Manifest: m, QueryID: id, Party: 0, Words: make([]targetrouting.WordToken, n)}, targetrouting.QueryToken{Manifest: m, QueryID: id, Party: 1, Words: make([]targetrouting.WordToken, n)}
	for h := 0; h < n; h++ {
		word := string(runes[4*h : 4*h+4])
		kw, e := targetcrypto.KWord(key, word)
		if e != nil {
			return a, b, e
		}
		p, q, e := targetcrypto.SplitPoint(targetcrypto.FullEval(kw))
		if e != nil {
			return a, b, e
		}
		beta, e := targetcrypto.WordBucketComponent(key, word, int(m.TargetBucketBits))
		if e != nil {
			return a, b, e
		}
		u, v, e := targetcrypto.SplitBucketComponent(beta, int(m.TargetBucketBits))
		if e != nil {
			return a, b, e
		}
		occurrence := targetrouting.Occurrence{OccurrenceID: uint32(h), Position: uint32(4 * h)}
		a.Words[h] = targetrouting.WordToken{Occurrence: occurrence, WordPointShare: p, BucketWordShare: u}
		b.Words[h] = targetrouting.WordToken{Occurrence: occurrence, WordPointShare: q, BucketWordShare: v}
	}
	return a, b, nil
}

var ErrShortTarget = errors.New("targetquery: target shorter than q=4; completeness remains OPEN")

// GeneratePositionTokens runs at the initial Query User boundary only. users
// are preprovisioned one-time PHASE4 packets, one capacity per occurrence.
func GeneratePositionTokens(m targetrouting.Manifest, key targetcrypto.MasterKey, text string, tau uint32, users []anchorfilter.UserPreprocessing) (targetrouting.QueryToken, targetrouting.QueryToken, error) {
	if len([]rune(text)) < 4 {
		return targetrouting.QueryToken{}, targetrouting.QueryToken{}, ErrShortTarget
	}
	if len(users) != len([]rune(text))/4 {
		return targetrouting.QueryToken{}, targetrouting.QueryToken{}, targetrouting.ErrBinding
	}
	a, b, e := GenerateTokens(m, key, text)
	if e != nil {
		return a, b, e
	}
	a.Position = make([]anchorfilter.PositionToken, len(users))
	b.Position = make([]anchorfilter.PositionToken, len(users))
	for i := range users {
		pid, l, r, e := users[i].ConsumeBounds(uint32(4*i), tau, 62)
		if e != nil {
			return a, b, e
		}
		a.Position[i] = anchorfilter.PositionToken{PID: pid, Ltilde: l, RplusTilde: r}
		b.Position[i] = a.Position[i]
	}
	return a, b, nil
}
