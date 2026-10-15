// Package targetposition composes existing PHASE4 SCMP and F2 Beaver primitives.
// It ends at secret posting hits in sealed physical slot order.
package targetposition

import (
	"crypto/sha256"
	"encoding/binary"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/f2beaver"
	"pmeq/internal/share"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetrouting"
	"sync"
	"time"
)

const ChunkSlots = 1024
const HeaderBytes = 57

var ErrBinding = targetpe.ErrBinding

type Group struct{ GroupOrdinal, PadWidth, SlotRelativeOffset int }
type Route struct {
	CandidateIndex, OccurrenceID uint32
	BucketID                     uint32
	SlotOffset, SlotCount        int
	Groups                       []Group
}
type TargetPostingHits struct {
	Manifest                        targetrouting.Manifest
	LayoutID, CompactionID, QueryID [16]byte
	K                               int
	Occurrences                     []targetrouting.Occurrence
	AnchorRecordIDShare             []share.Ring64Share
	Routes                          []Route
	HitShares                       []share.BitShare
}
type material struct {
	prep          anchorfilter.PartyPreprocessing
	first, second f2beaver.PartyBatch
}
type packetState struct {
	sync.Mutex
	used      bool
	materials []material
}
type Packet struct {
	state       *packetState
	lineage     targetpe.AlignmentLineage
	party       uint8
	maxPosition uint32
	bin         uint8
}
type OfflineBytes struct{ SCMP, Beaver uint64 } // one party, serialized field widths

// Preprocess is OFFLINE Q_pool allocation, before initial QueryToken generation.
// Each occurrence capacity can be a public upper bound; all unused keys burn.
func Preprocess(l targetpe.AlignmentLineage, capacities []int, backend anchorfilter.SCMPBackend) ([]anchorfilter.UserPreprocessing, Packet, Packet, OfflineBytes, error) {
	return PreprocessWithDomain(l, capacities, 7, 62, backend)
}

func PreprocessWithDomain(l targetpe.AlignmentLineage, capacities []int, bin uint8, maxPosition uint32, backend anchorfilter.SCMPBackend) ([]anchorfilter.UserPreprocessing, Packet, Packet, OfflineBytes, error) {
	users := make([]anchorfilter.UserPreprocessing, len(capacities))
	a := Packet{state: &packetState{}, lineage: l, party: 0, maxPosition: maxPosition, bin: bin}
	b := Packet{state: &packetState{}, lineage: l, party: 1, maxPosition: maxPosition, bin: bin}
	var bytes OfflineBytes
	derived, e := anchorfilter.DeriveBin(maxPosition)
	if e != nil || derived != bin {
		return nil, a, b, bytes, ErrBinding
	}
	for i, n := range capacities {
		if n < 0 {
			return nil, a, b, bytes, ErrBinding
		}
		u, x, y, e := anchorfilter.Preprocess(n, bin, backend)
		if e != nil {
			return nil, a, b, bytes, e
		}
		users[i] = u
		x0, x1, e := f2beaver.Preprocess(n)
		if e != nil {
			return nil, a, b, bytes, e
		}
		y0, y1, e := f2beaver.Preprocess(n)
		if e != nil {
			return nil, a, b, bytes, e
		}
		a.state.materials = append(a.state.materials, material{x, x0, y0})
		b.state.materials = append(b.state.materials, material{y, x1, y1})
		for j := 0; j < n; j++ {
			bytes.SCMP += uint64(len(x.Lower[j].Opaque()) + len(x.Upper[j].Opaque()) + 2 + 8)
		}
		bytes.Beaver += uint64(6 * n)
	}
	return users, a, b, bytes, nil
}

type Metrics struct {
	Expansion, Comparison, Correction, MatchAND, ValidityAND, Output time.Duration
	SCMPBytes, ANDBytes, FramingBytes                                uint64
}
type Session struct {
	idx                        *targetpe.PartyIndex
	backend                    anchorfilter.SCMPBackend
	token                      targetrouting.QueryToken
	in                         targetpe.TargetGroupMatches
	materials                  []material
	cursors                    []int
	out                        TargetPostingHits
	binding                    [32]byte
	ri, local, stage, n, off   int
	pending, done              bool
	own                        []byte
	pos, valid, match, product []share.BitShare
	metrics                    Metrics
	bin                        uint8
	maxPosition                uint32
}

func Begin(idx *targetpe.PartyIndex, in targetpe.TargetGroupMatches, tok targetrouting.QueryToken, p Packet, backend anchorfilter.SCMPBackend) (*Session, error) {
	if p.state == nil || p.party != idx.Party() || tok.Party != idx.Party() || in.Manifest != idx.Manifest() || tok.Manifest != in.Manifest || tok.QueryID != in.QueryID || in.QueryID == [16]byte{} || in.CompactionID == [16]byte{} || in.LayoutID != idx.Lineage().LayoutID || p.lineage != idx.Lineage() || in.K < 0 || in.K > idx.Lineage().N || len(in.AnchorRecordIDShare) != in.K || len(tok.Position) != len(in.Occurrences) || len(tok.Words) != len(in.Occurrences) || len(in.Routes) != in.K*len(in.Occurrences) {
		return nil, ErrBinding
	}
	p.state.Lock()
	defer p.state.Unlock()
	if p.state.used || len(p.state.materials) != len(in.Occurrences) {
		return nil, ErrBinding
	}
	start := time.Now()
	s := &Session{idx: idx, backend: backend, token: tok, in: in, cursors: make([]int, len(in.Occurrences)), bin: p.bin, maxPosition: p.maxPosition}
	s.out = TargetPostingHits{Manifest: in.Manifest, LayoutID: in.LayoutID, CompactionID: in.CompactionID, QueryID: in.QueryID, K: in.K, Occurrences: append([]targetrouting.Occurrence(nil), in.Occurrences...), AnchorRecordIDShare: append([]share.Ring64Share(nil), in.AnchorRecordIDShare...)}
	capacities := make([]int, len(in.Occurrences))
	gcount, total := 0, 0
	hash := sha256.New()
	hash.Write(in.Manifest.IndexID[:])
	hash.Write(in.LayoutID[:])
	hash.Write(in.QueryID[:])
	hash.Write(in.CompactionID[:])
	d := idx.StructureDigest()
	hash.Write(d[:])
	for h, o := range in.Occurrences {
		if o.OccurrenceID != uint32(h) || o.Position != uint32(4*h) || o.Position > p.maxPosition || tok.Words[h].Occurrence != o || tok.Position[h].PID != p.state.materials[h].prep.PID || p.state.materials[h].prep.Bin != p.bin || tok.Position[h].Ltilde >= uint32(1)<<p.bin || tok.Position[h].RplusTilde >= uint32(1)<<p.bin {
			return nil, ErrBinding
		}
		hash.Write(tok.Position[h].PID[:])
		binary.Write(hash, binary.LittleEndian, tok.Position[h].Ltilde)
		binary.Write(hash, binary.LittleEndian, tok.Position[h].RplusTilde)
	}
	for i, r := range in.Routes {
		if r.CandidateIndex != uint32(i/len(in.Occurrences)) || r.OccurrenceID != uint32(i%len(in.Occurrences)) || r.MatchOffset != gcount {
			return nil, ErrBinding
		}
		gs := idx.PositionGroups(r.BucketID)
		if len(gs) != r.GroupCount {
			return nil, ErrBinding
		}
		route := Route{CandidateIndex: r.CandidateIndex, OccurrenceID: r.OccurrenceID, BucketID: r.BucketID, SlotOffset: total}
		for gi, g := range gs {
			route.Groups = append(route.Groups, Group{gi, int(g.PadWidth), route.SlotCount})
			route.SlotCount += int(g.PadWidth)
		}
		total += route.SlotCount
		capacities[r.OccurrenceID] += route.SlotCount
		gcount += len(gs)
		s.out.Routes = append(s.out.Routes, route)
		binary.Write(hash, binary.LittleEndian, r.CandidateIndex)
		binary.Write(hash, binary.LittleEndian, r.OccurrenceID)
		binary.Write(hash, binary.LittleEndian, r.BucketID)
	}
	if gcount != len(in.MatchShares) {
		return nil, ErrBinding
	}
	for h, n := range capacities {
		if n > len(p.state.materials[h].prep.Lower) {
			return nil, ErrBinding
		}
	}
	p.state.used = true
	s.materials = p.state.materials
	p.state.materials = nil
	copy(s.binding[:], hash.Sum(nil))
	s.out.HitShares = make([]share.BitShare, total)
	s.metrics.Expansion = time.Since(start)
	s.skipEmpty()
	return s, nil
}
func (s *Session) skipEmpty() {
	for s.ri < len(s.out.Routes) && s.local == s.out.Routes[s.ri].SlotCount {
		s.ri++
		s.local = 0
	}
}
func (s *Session) Done() bool { return s.ri == len(s.out.Routes) }
func (s *Session) frame(payload []byte) []byte {
	b := make([]byte, HeaderBytes+len(payload))
	copy(b, "PMEQTP09")
	copy(b[8:40], s.binding[:])
	b[40] = s.idx.Party()
	b[41] = byte(s.stage)
	binary.LittleEndian.PutUint32(b[42:46], uint32(s.ri))
	binary.LittleEndian.PutUint32(b[46:50], uint32(s.local))
	binary.LittleEndian.PutUint32(b[50:54], uint32(s.n))
	b[54] = s.bin
	b[55] = 1
	b[56] = 0
	copy(b[HeaderBytes:], payload)
	s.metrics.FramingBytes += HeaderBytes
	return b
}
func (s *Session) Next() ([]byte, error) {
	if s.done || s.pending || s.Done() {
		return nil, ErrBinding
	}
	r := s.out.Routes[s.ri]
	h := int(r.OccurrenceID)
	m := s.materials[h]
	var payload []byte
	if s.stage == 0 {
		start := time.Now()
		s.n = min(ChunkSlots, r.SlotCount-s.local)
		s.off = s.cursors[h]
		payload = make([]byte, 8*s.n)
		s.valid = make([]share.BitShare, s.n)
		s.match = make([]share.BitShare, s.n)
		for _, g := range r.Groups {
			lo := max(s.local, g.SlotRelativeOffset)
			hi := min(s.local+s.n, g.SlotRelativeOffset+g.PadWidth)
			for x := lo; x < hi; x++ {
				j := x - s.local
				p, v := s.idx.PositionSlot(r.BucketID, g.GroupOrdinal, x-g.SlotRelativeOffset)
				p7, e := anchorfilter.ReducePosition(p, s.bin)
				if e != nil {
					return nil, e
				}
				mask := uint32(1)<<s.bin - 1
				binary.LittleEndian.PutUint32(payload[j*8:], (p7+m.prep.RhoL[s.off+j])&mask)
				binary.LittleEndian.PutUint32(payload[j*8+4:], (p7+m.prep.RhoR[s.off+j])&mask)
				s.valid[j] = v
				s.match[j] = s.in.MatchShares[s.in.Routes[s.ri].MatchOffset+g.GroupOrdinal]
			}
		}
		s.metrics.Expansion += time.Since(start)
		s.metrics.SCMPBytes += uint64(len(payload))
	} else {
		start := time.Now()
		trip := m.first.Slice(s.off, s.off+s.n)
		x, y := s.match, s.pos
		if s.stage == 2 {
			trip = m.second.Slice(s.off, s.off+s.n)
			x, y = s.product, s.valid
		}
		d, e, err := f2beaver.Mask(x, y, trip)
		if err != nil {
			return nil, err
		}
		payload = make([]byte, 2*s.n)
		for i := range d {
			if d[i].Value() {
				payload[2*i] = 1
			}
			if e[i].Value() {
				payload[2*i+1] = 1
			}
		}
		if s.stage == 1 {
			s.metrics.MatchAND += time.Since(start)
		} else {
			s.metrics.ValidityAND += time.Since(start)
		}
		s.metrics.ANDBytes += uint64(len(payload))
	}
	s.own = payload
	s.pending = true
	return s.frame(payload), nil
}
func (s *Session) Accept(b []byte) error {
	if !s.pending || len(b) != HeaderBytes+len(s.own) || string(b[:8]) != "PMEQTP09" || string(b[8:40]) != string(s.binding[:]) || b[40] != 1-s.idx.Party() || b[41] != byte(s.stage) || binary.LittleEndian.Uint32(b[42:46]) != uint32(s.ri) || binary.LittleEndian.Uint32(b[46:50]) != uint32(s.local) || binary.LittleEndian.Uint32(b[50:54]) != uint32(s.n) || b[54] != s.bin || b[55] != 1 || b[56] != 0 {
		return ErrBinding
	}
	r := s.out.Routes[s.ri]
	h := int(r.OccurrenceID)
	m := s.materials[h]
	peer := b[HeaderBytes:]
	if s.stage == 0 {
		start := time.Now()
		opened := anchorfilter.OpenedPositions{PL: make([]uint32, s.n), PR: make([]uint32, s.n)}
		for i := 0; i < s.n; i++ {
			x, y := binary.LittleEndian.Uint32(peer[8*i:]), binary.LittleEndian.Uint32(peer[8*i+4:])
			mask := uint32(1)<<s.bin - 1
			if x > mask || y > mask {
				return ErrBinding
			}
			opened.PL[i] = (x + binary.LittleEndian.Uint32(s.own[8*i:])) & mask
			opened.PR[i] = (y + binary.LittleEndian.Uint32(s.own[8*i+4:])) & mask
		}
		// Same PHASE4 primitive and rb convention; split timing records backend Eval
		// separately from local output conversion without changing its mathematics.
		q := s.token.Position[h]
		s.metrics.Expansion += time.Since(start)
		sub := m.prep
		sub.Lower = sub.Lower[s.off : s.off+s.n]
		sub.Upper = sub.Upper[s.off : s.off+s.n]
		timed := &timedBackend{backend: s.backend}
		start = time.Now()
		var err error
		s.pos, err = anchorfilter.EvalPosition(s.idx.Party(), anchorfilter.PartyQuery{PID: q.PID, Ltilde: q.Ltilde, RplusTilde: q.RplusTilde}, sub, opened, timed)
		elapsed := time.Since(start)
		s.metrics.Comparison += timed.elapsed
		s.metrics.Correction += elapsed - timed.elapsed
		if err != nil {
			return err
		}
	} else {
		start := time.Now()
		opened := f2beaver.Opened{D: make([]domain.Bit, s.n), E: make([]domain.Bit, s.n)}
		for i := 0; i < s.n; i++ {
			if peer[2*i] > 1 || peer[2*i+1] > 1 {
				return ErrBinding
			}
			opened.D[i] = domain.Bit(s.own[2*i]^peer[2*i] != 0)
			opened.E[i] = domain.Bit(s.own[2*i+1]^peer[2*i+1] != 0)
		}
		trip := m.first.Slice(s.off, s.off+s.n)
		if s.stage == 2 {
			trip = m.second.Slice(s.off, s.off+s.n)
		}
		out, e := f2beaver.Finish(s.idx.Party(), trip, opened)
		if e != nil {
			return e
		}
		if s.stage == 1 {
			s.product = out
			s.pos = nil
			s.match = nil
			s.metrics.MatchAND += time.Since(start)
		} else {
			s.metrics.ValidityAND += time.Since(start)
			start = time.Now()
			copy(s.out.HitShares[r.SlotOffset+s.local:], out)
			s.metrics.Output += time.Since(start)
		}
	}
	s.pending = false
	s.own = nil
	s.stage++
	if s.stage == 3 {
		s.stage = 0
		s.local += s.n
		s.cursors[h] += s.n
		s.valid = nil
		s.product = nil
		s.skipEmpty()
	}
	return nil
}
func (s *Session) Output() (TargetPostingHits, error) {
	if s.done || !s.Done() {
		return TargetPostingHits{}, ErrBinding
	}
	s.done = true
	s.materials = nil
	// Retained until PHASE10 consumes the original secret GroupMatch result.
	out := s.out
	s.out = TargetPostingHits{}
	return out, nil
}
func (s *Session) Metrics() Metrics { return s.metrics }

// Instrumentation delegates to the same PHASE4 backend. No comparator or output
// correction is implemented here; EvalPosition owns its original rb semantics.
type timedBackend struct {
	backend anchorfilter.SCMPBackend
	elapsed time.Duration
}

func (b *timedBackend) KeyGen(bin uint8, x, y uint32, o domain.Bit) (anchorfilter.SCMPKeyShare, anchorfilter.SCMPKeyShare, error) {
	return b.backend.KeyGen(bin, x, y, o)
}
func (b *timedBackend) Eval(p uint8, k anchorfilter.SCMPKeyShare, x, y uint32) (share.BitShare, error) {
	start := time.Now()
	v, e := b.backend.Eval(p, k, x, y)
	b.elapsed += time.Since(start)
	return v, e
}
