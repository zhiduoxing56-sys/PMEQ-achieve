// Package anchorfilter wires the tiered Anchor index to DPF matching,
// externally supplied LLAMA SCMP, and batched F2 filtering.
package anchorfilter

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"pmeq/internal/domain"
	"pmeq/internal/dpf128"
	"pmeq/internal/f2beaver"
	"pmeq/internal/indexbuild"
	"pmeq/internal/material"
	"pmeq/internal/preprocess"
	"pmeq/internal/qgram"
	"pmeq/internal/share"
)

type QueryChunk struct {
	QGram    string
	Position uint32
}

// QueryChunks emits non-overlapping complete q=4 rune chunks and preserves repeats.
func QueryChunks(q string) []QueryChunk {
	out, _ := QueryChunksWithQ(q, indexbuild.Q, 0)
	return out
}

// QueryChunksWithQ explicitly constructs experimental signatures. Production
// index/token domain binding remains the caller's responsibility; no default changes.
func QueryChunksWithQ(text string, q, count int) ([]QueryChunk, error) {
	fragments, err := qgram.Query(text, q, count)
	if err != nil {
		return nil, err
	}
	out := make([]QueryChunk, len(fragments))
	for i, c := range fragments {
		out[i] = QueryChunk{QGram: c.Word, Position: c.Position}
	}
	return out, nil
}

// DeriveBin returns the smallest signed SCMP width satisfying Upos+1 < 2^(Bin-1).
func DeriveBin(uPos uint32) (uint8, error) {
	for b := uint8(2); b <= 32; b++ {
		if uint64(uPos)+1 < uint64(1)<<(b-1) {
			return b, nil
		}
	}
	return 0, errors.New("anchorfilter: position domain requires Bin > 32")
}

func mask(bin uint8) uint32 {
	if bin == 32 {
		return ^uint32(0)
	}
	return uint32(1)<<bin - 1
}
func ReducePosition(s share.Ring32Share, bin uint8) (uint32, error) {
	if bin == 0 || bin > 32 {
		return 0, errors.New("anchorfilter: invalid Bin")
	}
	return uint32(s.Value()) & mask(bin), nil
}

type SCMPKeyShare struct {
	opaque []byte
	rb     share.BitShare
	use    *material.UseGuard
}

func NewSCMPKeyShare(opaque []byte, rb share.BitShare) SCMPKeyShare {
	return SCMPKeyShare{append([]byte(nil), opaque...), rb, material.NewUseGuard()}
}
func (k SCMPKeyShare) Opaque() []byte                  { return append([]byte(nil), k.opaque...) }
func (k SCMPKeyShare) OutputMaskShare() share.BitShare { return k.rb }

// SCMPBackend is the narrow adapter boundary for the external validated LLAMA primitive.
// KeyGen implements Bout=1; Eval returns the raw masked output including key.rb.
type SCMPBackend interface {
	KeyGen(bin uint8, inputMask, boundMask uint32, outputMask domain.Bit) (SCMPKeyShare, SCMPKeyShare, error)
	Eval(party uint8, key SCMPKeyShare, maskedInput, maskedBound uint32) (share.BitShare, error)
}

type UserPreprocessing struct {
	PID        [16]byte
	EtaL, EtaR uint32
	use        *material.UseGuard
	bin        uint8
}
type PartyPreprocessing struct {
	PID          [16]byte
	Bin          uint8
	RhoL, RhoR   []uint32
	Lower, Upper []SCMPKeyShare
}

// Preprocess creates a query-independent, one-use packet for one bucket invocation.
func Preprocess(n int, bin uint8, backend SCMPBackend) (UserPreprocessing, PartyPreprocessing, PartyPreprocessing, error) {
	if n < 0 || bin < 2 || bin > 32 {
		return UserPreprocessing{}, PartyPreprocessing{}, PartyPreprocessing{}, errors.New("anchorfilter: invalid preprocessing size or Bin")
	}
	u := UserPreprocessing{use: material.NewUseGuard(), bin: bin}
	if _, err := io.ReadFull(rand.Reader, u.PID[:]); err != nil {
		return u, PartyPreprocessing{}, PartyPreprocessing{}, err
	}
	var err error
	if u.EtaL, err = randomRing(bin); err != nil {
		return u, PartyPreprocessing{}, PartyPreprocessing{}, err
	}
	if u.EtaR, err = randomRing(bin); err != nil {
		return u, PartyPreprocessing{}, PartyPreprocessing{}, err
	}
	p0 := PartyPreprocessing{PID: u.PID, Bin: bin, RhoL: make([]uint32, n), RhoR: make([]uint32, n), Lower: make([]SCMPKeyShare, n), Upper: make([]SCMPKeyShare, n)}
	p1 := PartyPreprocessing{PID: u.PID, Bin: bin, RhoL: make([]uint32, n), RhoR: make([]uint32, n), Lower: make([]SCMPKeyShare, n), Upper: make([]SCMPKeyShare, n)}
	for i := 0; i < n; i++ {
		rL, e := randomRing(bin)
		if e != nil {
			return u, p0, p1, e
		}
		rR, e := randomRing(bin)
		if e != nil {
			return u, p0, p1, e
		}
		p0.RhoL[i], p1.RhoL[i], e = splitRing(rL, bin)
		if e != nil {
			return u, p0, p1, e
		}
		p0.RhoR[i], p1.RhoR[i], e = splitRing(rR, bin)
		if e != nil {
			return u, p0, p1, e
		}
		omegaL, e := randomBit()
		if e != nil {
			return u, p0, p1, e
		}
		omegaR, e := randomBit()
		if e != nil {
			return u, p0, p1, e
		}
		p0.Lower[i], p1.Lower[i], e = backend.KeyGen(bin, rL, u.EtaL, omegaL)
		if e != nil {
			return u, p0, p1, e
		}
		p0.Upper[i], p1.Upper[i], e = backend.KeyGen(bin, rR, u.EtaR, omegaR)
		if e != nil {
			return u, p0, p1, e
		}
	}
	return u, p0, p1, nil
}

func randomRing(bin uint8) (uint32, error) {
	var b [4]byte
	if _, e := io.ReadFull(rand.Reader, b[:]); e != nil {
		return 0, e
	}
	return binary.LittleEndian.Uint32(b[:]) & mask(bin), nil
}
func randomBit() (domain.Bit, error) {
	var b [1]byte
	_, e := io.ReadFull(rand.Reader, b[:])
	return domain.Bit(b[0]&1 == 1), e
}
func splitRing(v uint32, bin uint8) (uint32, uint32, error) {
	a, e := randomRing(bin)
	return a, (v - a) & mask(bin), e
}

type PartyQuery struct {
	PID                [16]byte
	BucketID           uint32
	DPFKey             dpf128.Key
	Ltilde, RplusTilde uint32
}

// ConsumeBounds runs at the authorized Query User boundary and consumes the
// one-time packet while masking this occurrence's clipped interval.
func (user *UserPreprocessing) ConsumeBounds(pQ, tau, uPos uint32) ([16]byte, uint32, uint32, error) {
	if user == nil || user.use == nil {
		return [16]byte{}, 0, 0, errors.New("anchorfilter: preprocessing pid already consumed")
	}
	if pQ > uPos {
		return [16]byte{}, 0, 0, errors.New("anchorfilter: query position exceeds public position domain")
	}
	bin, e := DeriveBin(uPos)
	if e != nil {
		return [16]byte{}, 0, 0, e
	}
	if bin != user.bin {
		return [16]byte{}, 0, 0, errors.New("anchorfilter: query position width differs from preprocessing")
	}
	l, r := Bounds(pQ, tau, uPos)
	m := mask(bin)
	if !user.use.Claim(0) {
		return [16]byte{}, 0, 0, errors.New("anchorfilter: preprocessing pid already consumed")
	}
	return user.PID, (l + user.EtaL) & m, (r + 1 + user.EtaR) & m, nil
}

func Bounds(pQ, tau, uPos uint32) (uint32, uint32) {
	l := uint32(0)
	if pQ > tau {
		l = pQ - tau
	}
	r := pQ + tau
	if r < pQ || r > uPos {
		r = uPos
	}
	return l, r
}

type PartyPrepared struct {
	Match, Validity []share.BitShare
	PL, PR          []uint32
}
type OpenedPositions struct{ PL, PR []uint32 }

// PreparationMetrics counts only local DPF evaluations; no hidden values are logged.
type PreparationMetrics struct {
	MatchWall      time.Duration
	DPFEvaluations uint64
}

func PrepareParty(bucket indexbuild.AnchorPartyBucket, query PartyQuery, prep PartyPreprocessing) (PartyPrepared, error) {
	return prepareParty(bucket, query, prep, nil)
}

func PreparePartyMeasured(bucket indexbuild.AnchorPartyBucket, query PartyQuery, prep PartyPreprocessing, metrics *PreparationMetrics) (PartyPrepared, error) {
	return prepareParty(bucket, query, prep, metrics)
}

func prepareParty(bucket indexbuild.AnchorPartyBucket, query PartyQuery, prep PartyPreprocessing, metrics *PreparationMetrics) (PartyPrepared, error) {
	if bucket.BucketID != query.BucketID || prep.PID != query.PID {
		return PartyPrepared{}, errors.New("anchorfilter: bucket or pid mismatch")
	}
	n := 0
	for _, g := range bucket.Groups {
		n += len(g.Slots)
	}
	if n != len(prep.RhoL) || n != len(prep.RhoR) || n != len(prep.Lower) || n != len(prep.Upper) {
		return PartyPrepared{}, errors.New("anchorfilter: preprocessing capacity mismatch")
	}
	o := PartyPrepared{Match: make([]share.BitShare, 0, n), Validity: make([]share.BitShare, 0, n), PL: make([]uint32, 0, n), PR: make([]uint32, 0, n)}
	m := mask(prep.Bin)
	j := 0
	for _, g := range bucket.Groups {
		var started time.Time
		if metrics != nil {
			started = time.Now()
		}
		mg := dpf128.Eval(query.DPFKey, dpf128.PointFromAnchorValue(g.Z))
		if metrics != nil {
			metrics.MatchWall += time.Since(started)
			metrics.DPFEvaluations++
		}
		for _, s := range g.Slots {
			p, e := ReducePosition(s.PositionShare, prep.Bin)
			if e != nil {
				return PartyPrepared{}, e
			}
			o.Match = append(o.Match, mg)
			o.Validity = append(o.Validity, s.ValidityShare)
			o.PL = append(o.PL, (p+prep.RhoL[j])&m)
			o.PR = append(o.PR, (p+prep.RhoR[j])&m)
			j++
		}
	}
	return o, nil
}

// OpenMaskedPositions opens only p+rho for every slot in one logical batch.
func OpenMaskedPositions(pL0, pR0, pL1, pR1 []uint32, bin uint8) (OpenedPositions, error) {
	if len(pL0) != len(pL1) || len(pR0) != len(pR1) || len(pL0) != len(pR0) {
		return OpenedPositions{}, errors.New("anchorfilter: position opening length mismatch")
	}
	m := mask(bin)
	o := OpenedPositions{PL: make([]uint32, len(pL0)), PR: make([]uint32, len(pR0))}
	for i := range o.PL {
		o.PL[i] = (pL0[i] + pL1[i]) & m
		o.PR[i] = (pR0[i] + pR1[i]) & m
	}
	return o, nil
}

func EvalPosition(party uint8, query PartyQuery, prep PartyPreprocessing, opened OpenedPositions, backend SCMPBackend) ([]share.BitShare, error) {
	if party > 1 || query.PID != prep.PID || len(opened.PL) != len(prep.Lower) || len(opened.PR) != len(prep.Upper) {
		return nil, errors.New("anchorfilter: invalid SCMP evaluation batch")
	}
	out := make([]share.BitShare, len(opened.PL))
	for i := range out {
		// Key handles copied into a sliced route batch share the same guard.
		// Each comparison instance may be evaluated only once by this wrapper.
		if !prep.Lower[i].use.Claim(0) || !prep.Upper[i].use.Claim(0) {
			return nil, errors.New("anchorfilter: comparison material already consumed")
		}
		eL, e := backend.Eval(party, prep.Lower[i], opened.PL[i], query.Ltilde)
		if e != nil {
			return nil, e
		}
		eR, e := backend.Eval(party, prep.Upper[i], opened.PR[i], query.RplusTilde)
		if e != nil {
			return nil, e
		}
		cL := share.LocalSubBit(eL, prep.Lower[i].rb)
		cR := share.LocalSubBit(eR, prep.Upper[i].rb)
		out[i] = share.LocalAddBit(cL, cR)
	}
	return out, nil
}

// ComposeHits evaluates the two required batched AND layers and leaves hits in F2.
func ComposeHits(a, b PartyPrepared, pos0, pos1 []share.BitShare) ([]share.BitShare, []share.BitShare, error) {
	if len(a.Match) != len(pos0) || len(b.Match) != len(pos1) {
		return nil, nil, fmt.Errorf("anchorfilter: composition length mismatch")
	}
	t0, t1, e := f2beaver.BatchAND(a.Match, b.Match, a.Validity, b.Validity)
	if e != nil {
		return nil, nil, e
	}
	return f2beaver.BatchAND(t0, t1, pos0, pos1)
}

// SplitPosition is used by domain tests and trusted harnesses only.
func SplitPosition(p uint32) (share.Ring32Share, share.Ring32Share, error) {
	return preprocess.SplitRing32(domain.Ring32(p))
}
