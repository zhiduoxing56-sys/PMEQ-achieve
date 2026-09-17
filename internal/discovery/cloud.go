package discovery

import (
	"bytes"
	"encoding/binary"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/candidatequery"
	"pmeq/internal/domain"
	"pmeq/internal/f2beaver"
	"pmeq/internal/incidence"
	"pmeq/internal/share"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
	"pmeq/internal/targetrouting"
	"time"
)

type endpoint struct {
	party         uint8
	query, packet [16]byte
	seq           uint32
	wire          func([]byte) ([]byte, error)
	sent          uint64
}

func (s *endpoint) send(body []byte) []byte {
	b := make([]byte, 37+len(body))
	copy(b, s.query[:])
	copy(b[16:], s.packet[:])
	binary.LittleEndian.PutUint32(b[32:], s.seq)
	b[36] = s.party
	copy(b[37:], body)
	s.sent += uint64(len(b))
	peer, e := s.wire(b)
	check(e)
	if len(peer) < 37 || !bytes.Equal(peer[:32], b[:32]) || binary.LittleEndian.Uint32(peer[32:]) != s.seq || peer[36] != 1-s.party {
		check(ErrBinding)
	}
	s.seq++
	return peer[37:]
}
func zbytes(v []incidence.Z128) []byte {
	b := make([]byte, len(v))
	for i, x := range v {
		b[i] = byte(x)
	}
	return b
}
func zvalues(b []byte) []incidence.Z128 {
	v := make([]incidence.Z128, len(b))
	for i, x := range b {
		if x > 127 {
			check(ErrBinding)
		}
		v[i] = incidence.Z128(x)
	}
	return v
}
func (s *endpoint) masked(m incidence.Masked) incidence.Opened {
	b := append(zbytes(m.D), zbytes(m.E)...)
	p := s.send(b)
	if len(p) != len(b) {
		check(ErrBinding)
	}
	o, e := incidence.OpenMasked(m, incidence.Masked{D: zvalues(p[:len(m.D)]), E: zvalues(p[len(m.D):])})
	check(e)
	return o
}
func (s *endpoint) b2a(x []share.BitShare, p *incidence.PartyTriples) []incidence.Share {
	v, m, e := incidence.BeginB2A(x, p)
	check(e)
	out, e := v.Finish(s.masked(m))
	check(e)
	return out
}
func (s *endpoint) compare(x []incidence.Share, p *aggregation.ComparisonParty, bound uint32, backend anchorfilter.SCMPBackend) []share.BitShare {
	m, e := p.Prepare(x)
	check(e)
	o, e := aggregation.OpenComparison(m, zvalues(s.send(zbytes(m))))
	check(e)
	out, e := p.Finish(o, bound, backend)
	check(e)
	return out
}
func (s *endpoint) and(x, y []share.BitShare, p f2beaver.PartyBatch) []share.BitShare {
	d, e, err := f2beaver.Mask(x, y, p)
	check(err)
	b := make([]byte, 2*len(d))
	for i := range d {
		if d[i].Value() {
			b[i] = 1
		}
		if e[i].Value() {
			b[len(d)+i] = 1
		}
	}
	v := s.send(b)
	if len(v) != len(b) {
		check(ErrBinding)
	}
	o := f2beaver.Opened{D: make([]domain.Bit, len(d)), E: make([]domain.Bit, len(d))}
	for i := range d {
		if v[i] > 1 || v[len(d)+i] > 1 {
			check(ErrBinding)
		}
		o.D[i] = domain.Bit((b[i] ^ v[i]) == 1)
		o.E[i] = domain.Bit((b[len(d)+i] ^ v[len(d)+i]) == 1)
	}
	out, err := f2beaver.Finish(s.party, p, o)
	check(err)
	return out
}

type cloudMetrics struct {
	Stages                   [7]time.Duration
	Sent                     uint64
	K, Routes, Groups, Slots int
}

func runParty(st *Static, p *PartyPacket, raw []byte, backend anchorfilter.SCMPBackend, wire func([]byte) ([]byte, error)) (output []byte, metrics cloudMetrics, err error) {
	defer caught(&err)
	started := time.Now()
	if st == nil || p == nil || st.party != p.party {
		check(ErrBinding)
	}
	check(p.g.claim())
	t, e := decodeToken(raw, st.target.Manifest(), st.party)
	check(e)
	if p.id != t.packet || len(t.anchor) != len(p.anchor) {
		check(ErrBinding)
	}
	s := &endpoint{party: st.party, query: t.target.QueryID, packet: p.id, wire: wire}
	count := aggregation.NewCount(st.payload.LayoutID, aggregation.CandidateCount)
	for h, q := range t.anchor {
		ap := &p.anchor[h]
		as, ok := st.anchor[q.BucketID]
		if !ok || ap.bucket != q.BucketID {
			check(ErrBinding)
		}
		pr, e := anchorfilter.PrepareParty(as.Bucket, q, ap.position)
		check(e)
		var b bytes.Buffer
		put(&b, pr.PL)
		put(&b, pr.PR)
		v := bytes.NewReader(s.send(b.Bytes()))
		pl, rr := make([]uint32, len(pr.PL)), make([]uint32, len(pr.PR))
		get(v, &pl)
		get(v, &rr)
		if v.Len() != 0 {
			check(ErrBinding)
		}
		opened, e := anchorfilter.OpenMaskedPositions(pr.PL, pr.PR, pl, rr, 7)
		check(e)
		pos, e := anchorfilter.EvalPosition(st.party, q, ap.position, opened, backend)
		check(e)
		hit := s.and(s.and(pr.Match, pr.Validity, ap.and[0]), pos, ap.and[1])
		ar := s.b2a(hit, ap.hit)
		g, e := incidence.NewAggregator(st.party, as.Incidence, 64)
		check(e)
		for ci, tr := range ap.inc {
			lo := ci * 64
			hi := min(lo+64, len(ar))
			m, e := g.BeginChunk(ar[lo:hi], tr)
			check(e)
			check(g.FinishChunk(s.masked(m)))
		}
		f, e := g.Result()
		check(e)
		z := s.compare(f, ap.f, t.f[h], backend)
		az := s.b2a(z, ap.z)
		var msg []byte
		if st.party == 1 {
			m, e := ap.p1.Message1(az)
			check(e)
			msg = zbytes(m)
		}
		peer := s.send(msg)
		var y []incidence.Share
		msg = nil
		if st.party == 0 {
			m, out, e := as.Stage0.Message2(ap.p0, az, zvalues(peer))
			check(e)
			msg = zbytes(m)
			y = out
		}
		peer = s.send(msg)
		if st.party == 1 {
			y, e = as.Stage1.Finish(ap.p1, zvalues(peer))
			check(e)
		}
		check(count.Add(st.payload.LayoutID, y))
		p.anchor[h] = anchorPacket{}
	}
	keep := s.compare(count.Values(), p.keep, t.keep, backend)
	input, e := aggregation.AlignOutput(st.payload, st.payload.LayoutID, keep)
	check(e)
	metrics.Stages[0] = time.Since(started)
	started = time.Now()
	var msg []byte
	if st.party == 1 {
		m, e := p.c1.Begin(input)
		check(e)
		msg = m.Encode()
	}
	peer := s.send(msg)
	msg = nil
	if st.party == 0 {
		m, e := aggregation.DecodeShuffle(peer)
		check(e)
		check(p.c0.Stage1(input, m))
		m, e = p.c0.BeginStage2()
		check(e)
		msg = m.Encode()
	}
	peer = s.send(msg)
	if st.party == 1 {
		m, e := aggregation.DecodeShuffle(peer)
		check(e)
		check(p.c1.Stage2(m))
	}
	var ko aggregation.KeepOpening
	if st.party == 0 {
		ko, e = p.c0.OpenKeep()
	} else {
		ko, e = p.c1.OpenKeep()
	}
	check(e)
	other, e := aggregation.DecodeKeepOpening(s.send(ko.Encode()))
	check(e)
	var c aggregation.CompactedCandidates
	if st.party == 0 {
		c, e = p.c0.Extract(other)
	} else {
		c, e = p.c1.Extract(other)
	}
	check(e)
	metrics.K = c.K
	metrics.Stages[1] = time.Since(started)
	started = time.Now()
	cv := targetrouting.Candidates{LayoutID: c.LayoutID, CompactionID: c.CompactionID, TargetBucketBits: c.TargetBucketBits, K: c.K, RecordIDShare: c.RecordIDShare, KappaJoinShare: c.KappaJoinShare, BucketJoinShare: c.BucketJoinShare}
	route, m, e := targetrouting.Prepare(st.target.Manifest(), st.party, cv, t.target, 16)
	check(e)
	routes, e := route.Finish(s.send(m))
	check(e)
	metrics.Routes = len(routes.Routes)
	metrics.Stages[2] = time.Since(started)
	started = time.Now()
	pe, e := st.target.Begin(routes, p.pe, targetpe.RecommendedWorkers)
	check(e)
	groups := 0
	for _, r := range routes.Routes {
		groups += len(st.target.PositionGroups(r.BucketID))
	}
	if groups > 0 {
		for i := 0; i < 8; i++ {
			m, e := pe.Next()
			check(e)
			check(pe.Accept(s.send(m)))
		}
	}
	gm, e := pe.Output()
	check(e)
	metrics.Groups = groups
	metrics.Stages[3] = time.Since(started)
	started = time.Now()
	position, e := targetposition.Begin(st.target, gm, t.target, p.position, backend)
	check(e)
	for !position.Done() {
		m, e := position.Next()
		check(e)
		check(position.Accept(s.send(m)))
	}
	hits, e := position.Output()
	check(e)
	gm, e = position.RetainedGroupMatches()
	check(e)
	metrics.Slots = len(hits.HitShares)
	metrics.Stages[4] = time.Since(started)
	started = time.Now()
	pairs, _, e := targetaggregation.Run(st.sidecar, hits, gm, p.agg, t.agg, backend, func(m []byte) ([]byte, error) { return s.send(m), nil })
	check(e)
	metrics.Stages[5] = time.Since(started)
	started = time.Now()
	output, e = candidatequery.EncodeShares(st.party, pairs)
	check(e)
	metrics.Stages[6] = time.Since(started)
	metrics.Sent = s.sent
	return
}
