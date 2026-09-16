package aggregation

// This is the old candidate compaction masked-permutation protocol, lifted
// fieldwise to F2 x Ring64 x Z_l x F2^16. No plaintext payload codec exists.
import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/gtank/ristretto255"
	"pmeq/internal/domain"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
)

const CandidateCount = 120071

var ErrCompaction = errors.New("compaction: shape, binding, or consumed packet")

type compactTuple struct {
	keep   domain.Bit
	id     uint64
	scalar ristretto255.Scalar
	bucket uint16
}

func tupleAdd(a, b compactTuple) compactTuple {
	var c compactTuple
	c.keep = a.keep.Add(b.keep)
	c.id = a.id + b.id
	c.scalar.Add(&a.scalar, &b.scalar)
	c.bucket = a.bucket ^ b.bucket
	return c
}
func tupleSub(a, b compactTuple) compactTuple {
	var c compactTuple
	c.keep = a.keep.Sub(b.keep)
	c.id = a.id - b.id
	c.scalar.Subtract(&a.scalar, &b.scalar)
	c.bucket = a.bucket ^ b.bucket
	return c
}
func randomTuples(n int) ([]compactTuple, error) {
	out := make([]compactTuple, n)
	var raw [75]byte
	for i := range out {
		if _, e := rand.Read(raw[:]); e != nil {
			return nil, e
		}
		out[i].keep = domain.Bit(raw[0]&1 != 0)
		out[i].id = binary.LittleEndian.Uint64(raw[1:9])
		if _, e := out[i].scalar.SetUniformBytes(raw[9:73]); e != nil {
			return nil, e
		}
		out[i].bucket = binary.LittleEndian.Uint16(raw[73:75])
	}
	return out, nil
}
func inputTuples(x CandidateInput, id [16]byte, n int) ([]compactTuple, error) {
	if x.LayoutID != id || len(x.KeepShare) != n || len(x.Payload) != n {
		return nil, ErrCompaction
	}
	out := make([]compactTuple, n)
	for i, p := range x.Payload {
		out[i].keep = x.KeepShare[i].Value()
		out[i].id = uint64(p.RecordIDShare.Value())
		out[i].bucket = uint16(p.BucketJoinShare)
		if _, e := out[i].scalar.SetCanonicalBytes(p.KappaJoinShare[:]); e != nil {
			return nil, e
		}
	}
	return out, nil
}

// compactState is reachable through pointers only: value copies of a packet
// share its mutex and consumption state. There is no reset/refill online API.
type compactState struct {
	mu            sync.Mutex
	layout, query [16]byte
	n, phase      int
	perm          []uint32
	c, t, r       []compactTuple
	shuffled      []compactTuple
}
type Compaction0 struct{ state *compactState }
type Compaction1 struct{ state *compactState }

// ShuffleMessage contains masked tuples, never a peer's unmasked shares.
type ShuffleMessage struct {
	layout, query [16]byte
	stage         int
	values        []compactTuple
}

// KeepOpening is deliberately limited to the final shuffled Keep shares.
type KeepOpening struct {
	layout, query [16]byte
	party         uint8
	bits          []domain.Bit
}

type CompactedCandidates struct {
	LayoutID        [16]byte
	CompactionID    [16]byte
	K               int
	RecordIDShare   []share.Ring64Share
	KappaJoinShare  []targetcrypto.ScalarShare
	BucketJoinShare []targetcrypto.BucketShare
}

// PreprocessCompaction is OFFLINE DEALER ONLY. Each call samples independent
// fresh permutations and masks. Deliver each returned object only to its party.
// Existing PartyPool tickets can bind the fresh CompactionID to an offline epoch.
func PreprocessCompaction(layout [16]byte, n int) (*Compaction0, *Compaction1, error) {
	if n < 0 || uint64(n) > uint64(^uint32(0)) {
		return nil, nil, ErrCompaction
	}
	var query [16]byte
	if _, e := rand.Read(query[:]); e != nil {
		return nil, nil, e
	}
	p, e := permutation(n)
	if e != nil {
		return nil, nil, e
	}
	q, e := permutation(n)
	if e != nil {
		return nil, nil, e
	}
	t0, e := randomTuples(n)
	if e != nil {
		return nil, nil, e
	}
	r0, e := randomTuples(n)
	if e != nil {
		return nil, nil, e
	}
	t1, e := randomTuples(n)
	if e != nil {
		return nil, nil, e
	}
	r1, e := randomTuples(n)
	if e != nil {
		return nil, nil, e
	}
	c0, c1 := make([]compactTuple, n), make([]compactTuple, n)
	for i, j := range p {
		c0[j] = tupleSub(t0[i], r0[j])
	}
	for i, j := range q {
		c1[j] = tupleSub(t1[i], r1[j])
	}
	return &Compaction0{&compactState{layout: layout, query: query, n: n, perm: p, c: c0, t: t1, r: r1}}, &Compaction1{&compactState{layout: layout, query: query, n: n, perm: q, c: c1, t: t0, r: r0}}, nil
}
func (p *Compaction0) ID() [16]byte { return p.state.query }
func (p *Compaction1) ID() [16]byte { return p.state.query }

// Begin sends CS1 -> CS0: d0=x1-t0. CS1 keeps r0 as its stage-1 share.
func (p *Compaction1) Begin(x CandidateInput) (ShuffleMessage, error) {
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != 0 {
		return ShuffleMessage{}, ErrCompaction
	}
	v, e := inputTuples(x, s.layout, s.n)
	if e != nil {
		return ShuffleMessage{}, e
	}
	for i := range v {
		v[i] = tupleSub(v[i], s.t[i])
	}
	clear(s.t)
	s.t = nil
	s.phase = 1
	return ShuffleMessage{s.layout, s.query, 1, v}, nil
}

// Stage1 applies tau0 to every field. This result stays local to CS0.
func (p *Compaction0) Stage1(x CandidateInput, m ShuffleMessage) error {
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != 0 || m.layout != s.layout || m.query != s.query || m.stage != 1 || len(m.values) != s.n {
		return ErrCompaction
	}
	v, e := inputTuples(x, s.layout, s.n)
	if e != nil {
		return e
	}
	out := make([]compactTuple, s.n)
	for i, j := range s.perm {
		out[j] = tupleAdd(tupleAdd(v[i], m.values[i]), s.c[j])
	}
	clear(v)
	clear(s.c)
	s.c = nil
	clear(s.perm)
	s.perm = nil
	s.shuffled = out
	s.phase = 1
	return nil
}

// BeginStage2 sends CS0 -> CS1: d1=y0-t1. CS0 retains fresh r1.
func (p *Compaction0) BeginStage2() (ShuffleMessage, error) {
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != 1 {
		return ShuffleMessage{}, ErrCompaction
	}
	v := s.shuffled
	for i := range v {
		v[i] = tupleSub(v[i], s.t[i])
	}
	clear(s.t)
	s.t = nil
	s.shuffled = s.r
	s.r = nil
	s.phase = 2
	return ShuffleMessage{s.layout, s.query, 2, v}, nil
}

// Stage2 applies tau1 to every field; no input gamma is exported.
func (p *Compaction1) Stage2(m ShuffleMessage) error {
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != 1 || m.layout != s.layout || m.query != s.query || m.stage != 2 || len(m.values) != s.n {
		return ErrCompaction
	}
	out := make([]compactTuple, s.n)
	for i, j := range s.perm {
		out[j] = tupleAdd(tupleAdd(s.r[i], m.values[i]), s.c[j])
	}
	clear(s.r)
	s.r = nil
	clear(s.c)
	s.c = nil
	clear(s.perm)
	s.perm = nil
	s.shuffled = out
	s.phase = 2
	return nil
}
func opening(s *compactState, party uint8) (KeepOpening, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != 2 {
		return KeepOpening{}, ErrCompaction
	}
	bits := make([]domain.Bit, s.n)
	for i := range bits {
		bits[i] = s.shuffled[i].keep
	}
	s.phase = 3
	return KeepOpening{s.layout, s.query, party, bits}, nil
}
func (p *Compaction0) OpenKeep() (KeepOpening, error) { return opening(p.state, 0) }
func (p *Compaction1) OpenKeep() (KeepOpening, error) { return opening(p.state, 1) }
func extract(s *compactState, peer KeepOpening, party uint8) (CompactedCandidates, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != 3 || peer.party == party || peer.layout != s.layout || peer.query != s.query || len(peer.bits) != s.n {
		return CompactedCandidates{}, ErrCompaction
	}
	k := 0
	for i, v := range s.shuffled {
		if v.keep.Add(peer.bits[i]) {
			k++
		}
	}
	out := CompactedCandidates{LayoutID: s.layout, CompactionID: s.query, K: k, RecordIDShare: make([]share.Ring64Share, k), KappaJoinShare: make([]targetcrypto.ScalarShare, k), BucketJoinShare: make([]targetcrypto.BucketShare, k)}
	j := 0
	for i, v := range s.shuffled {
		if v.keep.Add(peer.bits[i]) {
			out.RecordIDShare[j] = share.NewRing64Share(domain.Ring64(v.id))
			copy(out.KappaJoinShare[j][:], v.scalar.Bytes())
			out.BucketJoinShare[j] = targetcrypto.BucketShare(v.bucket)
			j++
		}
	}
	clear(s.shuffled)
	s.shuffled = nil
	s.phase = 4
	return out, nil
}
func (p *Compaction0) Extract(peer KeepOpening) (CompactedCandidates, error) {
	return extract(p.state, peer, 0)
}
func (p *Compaction1) Extract(peer KeepOpening) (CompactedCandidates, error) {
	return extract(p.state, peer, 1)
}
