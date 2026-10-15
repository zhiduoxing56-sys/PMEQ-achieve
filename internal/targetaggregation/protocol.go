package targetaggregation

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/f2beaver"
	"pmeq/internal/incidence"
	"pmeq/internal/ring64beaver"
	"pmeq/internal/share"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
	"pmeq/internal/targetrouting"
)

type CandidatePairShares struct {
	Manifest                        targetrouting.Manifest
	LayoutID, CompactionID, QueryID [16]byte
	K, DTarget                      int
	PairKeepShares                  []share.BitShare
	AnchorIDShares, TargetIDShares  []share.Ring64Share
}

// Exchange transports one party's framed MASKED message and returns the peer's
// framed masked message. It must not grant access to peer protocol objects.
type Exchange func([]byte) ([]byte, error)
type Metrics struct {
	Stages      [15]time.Duration
	OnlineBytes uint64
}
type session struct {
	party    uint8
	binding  [32]byte
	seq      uint32
	exchange Exchange
	waiting  time.Duration
	metrics  Metrics
}

func (s *session) send(body []byte) ([]byte, error) {
	m := make([]byte, 37+len(body))
	copy(m, s.binding[:])
	binary.LittleEndian.PutUint32(m[32:36], s.seq)
	m[36] = s.party
	copy(m[37:], body)
	t := time.Now()
	peer, e := s.exchange(m)
	s.waiting += time.Since(t)
	s.metrics.OnlineBytes += uint64(len(m))
	if e != nil {
		return nil, e
	}
	if len(peer) != len(m) || !bytes.Equal(peer[:32], m[:32]) || binary.LittleEndian.Uint32(peer[32:36]) != s.seq || peer[36] != 1-s.party {
		return nil, ErrBinding
	}
	s.seq++
	return peer[37:], nil
}
func (s *session) timed(stage int, fn func() error) error {
	start, w := time.Now(), s.waiting
	e := fn()
	s.metrics.Stages[stage] += time.Since(start) - (s.waiting - w)
	return e
}
func (s *session) zOpen(m incidence.Masked) (incidence.Opened, error) {
	body := make([]byte, len(m.D)+len(m.E))
	for i, v := range m.D {
		body[i] = byte(v)
	}
	for i, v := range m.E {
		body[len(m.D)+i] = byte(v)
	}
	p, e := s.send(body)
	if e != nil {
		return incidence.Opened{}, e
	}
	peer := incidence.Masked{D: make([]incidence.Z128, len(m.D)), E: make([]incidence.Z128, len(m.E))}
	for i, v := range p {
		if v > 127 {
			return incidence.Opened{}, ErrBinding
		}
		if i < len(m.D) {
			peer.D[i] = incidence.Z128(v)
		} else {
			peer.E[i-len(m.D)] = incidence.Z128(v)
		}
	}
	return incidence.OpenMasked(m, peer)
}
func (s *session) b2a(bits []share.BitShare, p *incidence.PartyTriples) ([]incidence.Share, error) {
	x, m, e := incidence.BeginB2A(bits, p)
	if e != nil {
		return nil, e
	}
	o, e := s.zOpen(m)
	if e != nil {
		return nil, e
	}
	return x.Finish(o)
}
func (s *session) compare(v []incidence.Share, p *aggregation.ComparisonParty, bound uint32, backend anchorfilter.SCMPBackend) ([]share.BitShare, error) {
	a, e := p.Prepare(v)
	if e != nil {
		return nil, e
	}
	body := make([]byte, len(a))
	for i, x := range a {
		body[i] = byte(x)
	}
	peer, e := s.send(body)
	if e != nil {
		return nil, e
	}
	for i, b := range peer {
		if b > 127 {
			return nil, ErrBinding
		}
		a[i] = a[i].Add(incidence.Z128(b))
	}
	return p.Finish(a, bound, backend)
}
func (s *session) ring(p ring64beaver.Packet, x, y []share.Ring64Share, bits []share.BitShare) ([]share.Ring64Share, error) {
	var pending *ring64beaver.Pending
	var m ring64beaver.Message
	var e error
	if bits != nil {
		pending, m, e = ring64beaver.BeginB2A(p, bits)
	} else {
		pending, m, e = ring64beaver.Begin(p, x, y)
	}
	if e != nil {
		return nil, e
	}
	body := make([]byte, 16*len(m.D))
	for i := range m.D {
		binary.LittleEndian.PutUint64(body[16*i:], m.D[i])
		binary.LittleEndian.PutUint64(body[16*i+8:], m.E[i])
	}
	peer, e := s.send(body)
	if e != nil {
		return nil, e
	}
	pm := ring64beaver.Message{D: make([]uint64, len(m.D)), E: make([]uint64, len(m.D))}
	for i := range pm.D {
		pm.D[i] = binary.LittleEndian.Uint64(peer[16*i:])
		pm.E[i] = binary.LittleEndian.Uint64(peer[16*i+8:])
	}
	return pending.Finish(pm)
}
func (s *session) and(x, y []share.BitShare, p f2beaver.PartyBatch) ([]share.BitShare, error) {
	d, e, err := f2beaver.Mask(x, y, p)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 2*len(x))
	for i := range x {
		if d[i].Value() {
			body[2*i] = 1
		}
		if e[i].Value() {
			body[2*i+1] = 1
		}
	}
	peer, err := s.send(body)
	if err != nil {
		return nil, err
	}
	pd, pe := make([]share.BitShare, len(x)), make([]share.BitShare, len(x))
	for i := range x {
		if peer[2*i] > 1 || peer[2*i+1] > 1 {
			return nil, ErrBinding
		}
		pd[i] = share.NewBitShare(domain.Bit(peer[2*i] != 0))
		pe[i] = share.NewBitShare(domain.Bit(peer[2*i+1] != 0))
	}
	o, err := f2beaver.Open(d, e, pd, pe)
	if err != nil {
		return nil, err
	}
	return f2beaver.Finish(s.party, p, o)
}

func validate(side *PartySidecar, h targetposition.TargetPostingHits, g targetpe.TargetGroupMatches, p Packet, t ThresholdToken) ([32]byte, error) {
	var zero [32]byte
	if side == nil || int(side.manifest.DTarget) != p.shape.Capacity() || side.manifest.MaxMultiplicity != MaxMultiplicity || p.state == nil || p.shape.validate(p.lineage.N) != nil || p.party != side.party || p.lineage.IndexID != side.manifest.IndexID || h.Manifest != g.Manifest || h.Manifest != (targetrouting.Manifest{IndexID: side.manifest.IndexID, TargetBucketBits: side.bits, Q: 4}) || h.LayoutID != p.lineage.LayoutID || h.LayoutID != g.LayoutID || h.CompactionID == [16]byte{} || h.CompactionID != g.CompactionID || h.QueryID == [16]byte{} || h.QueryID != g.QueryID || h.QueryID != t.QueryID || t.PacketID != p.id || t.FBound > 127 || t.KeepBound > 127 || h.K != g.K || h.K < 0 || h.K > p.shape.K || len(h.Occurrences) != p.shape.R || t.R != p.shape.R || len(g.Occurrences) != p.shape.R || len(h.AnchorRecordIDShare) != h.K || len(g.AnchorRecordIDShare) != h.K || len(h.HitShares) > p.shape.S || len(g.MatchShares) > p.shape.G || len(h.Routes) != h.K*p.shape.R || len(g.Routes) != len(h.Routes) {
		return zero, ErrBinding
	}
	for i, o := range h.Occurrences {
		if o != g.Occurrences[i] || o.OccurrenceID != uint32(i) || o.Position != uint32(4*i) {
			return zero, ErrBinding
		}
	}
	for i, v := range h.AnchorRecordIDShare {
		if v != g.AnchorRecordIDShare[i] {
			return zero, ErrBinding
		}
	}
	hash := sha256.New()
	hash.Write(side.manifest.StructureDigest[:])
	hash.Write(side.manifest.IndexID[:])
	hash.Write([]byte(side.manifest.ManifestSHA256))
	hash.Write([]byte(side.manifest.PartySHA256[0]))
	hash.Write([]byte(side.manifest.PartySHA256[1]))
	hash.Write(h.LayoutID[:])
	hash.Write(h.CompactionID[:])
	hash.Write(h.QueryID[:])
	hash.Write(p.id[:])
	binary.Write(hash, binary.LittleEndian, t.FBound)
	binary.Write(hash, binary.LittleEndian, t.KeepBound)
	so, goff := 0, 0
	for i, r := range h.Routes {
		pr := g.Routes[i]
		b := side.buckets[r.BucketID]
		if b.matrix == nil {
			return zero, ErrBinding
		}
		if r.CandidateIndex != uint32(i/p.shape.R) || r.OccurrenceID != uint32(i%p.shape.R) || r.CandidateIndex != pr.CandidateIndex || r.OccurrenceID != pr.OccurrenceID || r.BucketID != pr.BucketID || r.SlotOffset != so || pr.MatchOffset != goff || r.SlotCount != b.matrix.T || len(r.Groups) != len(b.widths) || pr.GroupCount != len(b.widths) {
			return zero, ErrBinding
		}
		local := 0
		for j, q := range r.Groups {
			if q.GroupOrdinal != j || q.PadWidth != int(b.widths[j]) || q.SlotRelativeOffset != local {
				return zero, ErrBinding
			}
			local += q.PadWidth
		}
		if local != r.SlotCount {
			return zero, ErrBinding
		}
		so += r.SlotCount
		goff += pr.GroupCount
		binary.Write(hash, binary.LittleEndian, r.BucketID)
		binary.Write(hash, binary.LittleEndian, uint64(r.SlotCount))
	}
	if so != len(h.HitShares) || goff != len(g.MatchShares) {
		return zero, ErrBinding
	}
	copy(zero[:], hash.Sum(nil))
	return zero, nil
}

// Run is one cloud's protocol invocation. Every nonlocal operation exchanges
// only framed masked differences. The online graph has no dealer/raw DB call.
func Run(side *PartySidecar, h targetposition.TargetPostingHits, g targetpe.TargetGroupMatches, p Packet, t ThresholdToken, backend anchorfilter.SCMPBackend, exchange Exchange) (CandidatePairShares, Metrics, error) {
	var out CandidatePairShares
	if side != nil && side.file != nil {
		view := *side
		view.buckets = make([]bucket, len(side.buckets))
		loaded := make(map[uint32]bool)
		for _, route := range h.Routes {
			if loaded[route.BucketID] {
				continue
			}
			b, err := side.loadBucket(route.BucketID)
			if err != nil {
				return out, Metrics{}, err
			}
			view.buckets[route.BucketID] = b
			loaded[route.BucketID] = true
		}
		defer func() {
			for id := range loaded {
				view.buckets[id] = bucket{}
			}
		}()
		side = &view
	}
	binding, e := validate(side, h, g, p, t)
	if e != nil || backend == nil || exchange == nil {
		return out, Metrics{}, ErrBinding
	}
	p.state.Lock()
	if p.state.used {
		p.state.Unlock()
		return out, Metrics{}, ErrBinding
	}
	p.state.used = true
	p.state.Unlock()
	s := &session{party: p.party, binding: binding, exchange: exchange}
	out = CandidatePairShares{Manifest: h.Manifest, LayoutID: h.LayoutID, CompactionID: h.CompactionID, QueryID: h.QueryID, K: h.K, DTarget: p.shape.Capacity()}
	if h.K == 0 {
		out.PairKeepShares = []share.BitShare{}
		out.AnchorIDShares = []share.Ring64Share{}
		out.TargetIDShares = []share.Ring64Share{}
		return out, s.metrics, nil
	}
	d := p.shape.Capacity()
	r, m, zlen := p.shape.R, h.K*d, h.K*p.shape.R*d
	// Burn unused public capacity. All masks were provisioned before online
	// execution; no actual candidate count is needed by the offline dealer.
	if e = p.f.Limit(zlen); e != nil {
		return CandidatePairShares{}, s.metrics, e
	}
	if e = p.keep.Limit(m); e != nil {
		return CandidatePairShares{}, s.metrics, e
	}
	for i, n := range map[int]int{0: len(g.MatchShares), 2: zlen, 4: m, 5: m, 6: m} {
		if e = p.ring[i].Limit(n); e != nil {
			return CandidatePairShares{}, s.metrics, e
		}
	}
	if len(h.HitShares) < p.shape.S {
		stream, err := incidence.ClaimTriples(p.hit)
		if err != nil {
			return CandidatePairShares{}, s.metrics, err
		}
		p.hit, e = stream.Take(len(h.HitShares))
		if e != nil {
			return CandidatePairShares{}, s.metrics, e
		}
	}
	if zlen < p.shape.K*p.shape.R*d {
		stream, err := incidence.ClaimTriples(p.z)
		if err != nil {
			return CandidatePairShares{}, s.metrics, err
		}
		p.z, e = stream.Take(zlen)
		if e != nil {
			return CandidatePairShares{}, s.metrics, e
		}
	}
	var hits, F, C, za []incidence.Share
	var z, keep, rep []share.BitShare
	var match, ids, selected, rep64, keep64, aid, tid []share.Ring64Share
	steps := []func() error{
		func() error { hits, e = s.b2a(h.HitShares, p.hit); return e },
		func() error {
			F = make([]incidence.Share, zlen)
			stream, err := incidence.ClaimTriples(p.inc)
			if err != nil {
				return err
			}
			for ri, route := range h.Routes {
				a, err := incidence.NewAggregator(p.party, side.buckets[route.BucketID].matrix, 64)
				if err != nil {
					return err
				}
				for lo := 0; lo < route.SlotCount; lo += 64 {
					n := min(64, route.SlotCount-lo)
					tr, err := stream.Take(n)
					if err != nil {
						return err
					}
					msg, err := a.BeginChunk(hits[route.SlotOffset+lo:route.SlotOffset+lo+n], tr)
					if err != nil {
						return err
					}
					opened, err := s.zOpen(msg)
					if err != nil {
						return err
					}
					if err = a.FinishChunk(opened); err != nil {
						return err
					}
				}
				v, err := a.Result()
				if err != nil {
					return err
				}
				copy(F[ri*d:], v)
			}
			hits = nil
			return nil
		},
		func() error { z, e = s.compare(F, p.f, t.FBound, backend); F = nil; return e },
		func() error { za, e = s.b2a(z, p.z); return e },
		func() error {
			C = make([]incidence.Share, m)
			for c := 0; c < h.K; c++ {
				for hi := 0; hi < r; hi++ {
					for u := 0; u < d; u++ {
						j := (c*r+hi)*d + u
						C[c*d+u] = incidence.Add(C[c*d+u], za[j])
					}
				}
			}
			za = nil
			return nil
		},
		func() error { keep, e = s.compare(C, p.keep, t.KeepBound, backend); C = nil; return e },
		func() error { match, e = s.ring(p.ring[0], nil, nil, g.MatchShares); return e },
		func() error {
			ids = make([]share.Ring64Share, zlen)
			for ri, route := range g.Routes {
				payload := side.buckets[route.BucketID].ids
				for lo := 0; lo < route.GroupCount; lo += 64 {
					n := min(64, route.GroupCount-lo)
					x := make([]share.Ring64Share, n*d)
					for j := 0; j < n; j++ {
						for u := 0; u < d; u++ {
							x[j*d+u] = match[route.MatchOffset+lo+j]
						}
					}
					tr, err := p.ring[1].Take(n * d)
					if err != nil {
						return err
					}
					v, err := s.ring(tr, x, payload[lo*d:(lo+n)*d], nil)
					if err != nil {
						return err
					}
					for j, a := range v {
						q := ri*d + j%d
						ids[q] = share.LocalAddRing64(ids[q], a)
					}
				}
			}
			match = nil
			return nil
		},
		func() error {
			rep = make([]share.BitShare, zlen)
			seen := make([]share.BitShare, m)
			for hi := 0; hi < r; hi++ {
				x, y := make([]share.BitShare, m), make([]share.BitShare, m)
				for c := 0; c < h.K; c++ {
					for u := 0; u < d; u++ {
						j := c*d + u
						x[j] = z[(c*r+hi)*d+u]
						y[j] = seen[j]
						if p.party == 0 {
							y[j] = share.LocalAddBit(y[j], share.NewBitShare(true))
						}
					}
				}
				v, err := s.and(x, y, p.rep.Slice(hi*m, (hi+1)*m))
				if err != nil {
					return err
				}
				for c := 0; c < h.K; c++ {
					for u := 0; u < d; u++ {
						j := c*d + u
						rep[(c*r+hi)*d+u] = v[j]
						seen[j] = share.LocalAddBit(seen[j], v[j])
					}
				}
			}
			z = nil
			return nil
		},
		func() error { rep64, e = s.ring(p.ring[2], nil, nil, rep); rep = nil; return e },
		func() error {
			selected = make([]share.Ring64Share, m)
			for lo := 0; lo < zlen; lo += 4096 {
				n := min(4096, zlen-lo)
				tr, err := p.ring[3].Take(n)
				if err != nil {
					return err
				}
				v, err := s.ring(tr, rep64[lo:lo+n], ids[lo:lo+n], nil)
				if err != nil {
					return err
				}
				for i, a := range v {
					j := lo + i
					c := j / (r * d)
					u := j % d
					selected[c*d+u] = share.LocalAddRing64(selected[c*d+u], a)
				}
			}
			rep64 = nil
			ids = nil
			return nil
		},
		func() error { keep64, e = s.ring(p.ring[4], nil, nil, keep); return e },
		func() error {
			x := make([]share.Ring64Share, m)
			for j := range x {
				x[j] = h.AnchorRecordIDShare[j/d]
			}
			aid, e = s.ring(p.ring[5], keep64, x, nil)
			return e
		},
		func() error {
			tid, e = s.ring(p.ring[6], keep64, selected, nil)
			keep64 = nil
			selected = nil
			return e
		},
		func() error {
			out.PairKeepShares = keep
			out.AnchorIDShares = aid
			out.TargetIDShares = tid
			return nil
		},
	}
	for i, fn := range steps {
		if e = s.timed(i, fn); e != nil {
			return CandidatePairShares{}, s.metrics, e
		}
		// The default build inlines a no-op. Opt-in trusted test builds check
		// these local shares outside every component timing window.
		switch i {
		case 1:
			auditStage(h.QueryID, p.party, "F", F)
		case 2:
			auditStage(h.QueryID, p.party, "z", z)
		case 4:
			auditStage(h.QueryID, p.party, "C", C)
		case 5:
			auditStage(h.QueryID, p.party, "Keep", keep)
		case 8:
			auditStage(h.QueryID, p.party, "rep", rep)
		case 10:
			auditStage(h.QueryID, p.party, "selected", selected)
		case 12:
			auditStage(h.QueryID, p.party, "Anchor", aid)
		case 13:
			auditStage(h.QueryID, p.party, "Target", tid)
		}
	}
	return out, s.metrics, nil
}
