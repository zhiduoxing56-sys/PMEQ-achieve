package discovery

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
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
	"pmeq/internal/zeroagg"
	"time"
)

type endpoint struct {
	nextKind      string
	trace         []FrameAudit
	party         uint8
	query, packet [16]byte
	seq           uint32
	wire          func([]byte) ([]byte, error)
	sent          uint64
	wait          time.Duration
	operations    AnchorOperations
	phase         int
	phaseBytes    [8]uint64
}

func (s *endpoint) send(body []byte) []byte {
	s.audit(body)
	b := make([]byte, 37+len(body))
	copy(b, s.query[:])
	copy(b[16:], s.packet[:])
	binary.LittleEndian.PutUint32(b[32:], s.seq)
	b[36] = s.party
	copy(b[37:], body)
	s.sent += uint64(len(b))
	s.phaseBytes[s.phase] += uint64(len(b))
	started := time.Now()
	peer, e := s.wire(b)
	s.wait += time.Since(started)
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
	p := s.sendKind("z128-beaver-opening", b)
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
	s.operations.B2AProducts += uint64(len(x))
	return out
}
func (s *endpoint) compare(x []incidence.Share, p *aggregation.ComparisonParty, bound uint32, backend anchorfilter.SCMPBackend) []share.BitShare {
	m, e := p.Prepare(x)
	check(e)
	o, e := aggregation.OpenComparison(m, zvalues(s.sendKind("masked-comparison", zbytes(m))))
	check(e)
	out, e := p.Finish(o, bound, backend)
	check(e)
	s.operations.SCMP += uint64(len(x))
	return out
}
func (s *endpoint) and(x, y []share.BitShare, p f2beaver.PartyBatch) []share.BitShare {
	d, e, err := f2beaver.Mask(x, y, p)
	check(err)
	b := make([]byte, 2*len(d))
	for i := range d {
		b[i] = byte(zeroagg.CanonicalBit(d[i].Value()))
		b[len(d)+i] = byte(zeroagg.CanonicalBit(e[i].Value()))
	}
	v := s.sendKind("boolean-beaver-opening", b)
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
	s.operations.BooleanProducts += uint64(len(x))
	return out
}

type cloudMetrics struct {
	ZeroFFT, ZeroMul            time.Duration
	ZeroGates                   uint64
	ZeroRounds                  int
	Trace                       []FrameAudit
	Rounds                      uint32
	Anchor                      AnchorBreakdown
	Diagnostics                 AnchorDiagnostics
	PhaseBytes                  [8]uint64
	Stages                      [8]time.Duration
	Sent                        uint64
	K, M, Routes, Groups, Slots int
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
	defer func() {
		metrics.Sent = s.sent
		metrics.PhaseBytes = s.phaseBytes
		metrics.Rounds = s.seq
		metrics.Trace = s.trace
	}()
	n := len(st.payload.Slots)
	count := aggregation.NewCount(st.payload.LayoutID, n)
	for h, q := range t.anchor {
		ap := &p.anchor[h]
		as, ok := st.anchor[q.BucketID]
		if !ok || ap.bucket != q.BucketID {
			check(ErrBinding)
		}
		block := AnchorBlock{Block: h, Bucket: q.BucketID, Groups: len(as.Bucket.Groups), PaddedSlots: as.T, ObjectCoordinates: as.D, GlobalCoordinates: n, ReservedPositionSlots: len(ap.position.Lower), ReservedBooleanProducts: 2 * len(ap.position.Lower), ReservedGFProducts: uint64(ap.zero.TotalGates()), ReservedObjectB2A: ap.z.N}
		for _, group := range as.Bucket.Groups {
			block.GroupPadWidths = append(block.GroupPadWidths, group.PadWidth)
		}
		if ap.zeroRef == nil || ap.zero == nil {
			check(ErrBinding)
		}
		bindingMark := s.mark()
		{
			tag, e := json.Marshal(ap.zeroRef.Binding)
			check(e)
			if !bytes.Equal(s.sendKind("zero-material-binding", tag), tag) {
				check(ErrBinding)
			}
		}
		block.MaterialBinding = s.since(bindingMark)
		mark := s.mark()
		var prepMetrics anchorfilter.PreparationMetrics
		partStarted := time.Now()
		pr, e := anchorfilter.PreparePartyMeasured(as.Bucket, q, ap.position, &prepMetrics)
		check(e)
		var b bytes.Buffer
		put(&b, pr.PL)
		put(&b, pr.PR)
		v := bytes.NewReader(s.sendKind("anchor-masked-position", b.Bytes()))
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
		s.operations.DPFEvaluations += prepMetrics.DPFEvaluations
		s.operations.SCMP += uint64(2 * len(pos))
		block.Position = s.since(mark)
		block.IndexMatch = AnchorStage{Wall: prepMetrics.MatchWall, Operations: AnchorOperations{DPFEvaluations: prepMetrics.DPFEvaluations}}
		block.Position.Wall -= prepMetrics.MatchWall
		block.Position.Operations.DPFEvaluations = 0
		mark = s.mark()
		hit := s.and(s.and(pr.Match, pr.Validity, ap.and[0]), pos, ap.and[1])
		block.ValidityAND = s.since(mark)
		metrics.Anchor.Filter += time.Since(partStarted)
		var z []share.BitShare
		{
			partStarted = time.Now()
			mark = s.mark()
			x := make([]zeroagg.F, len(hit))
			for i, v := range hit {
				x[i] = zeroagg.CanonicalBit(v.Value())
			}
			ap.zero.Bind(func(body []byte) []byte {
				peer := s.sendKind("gf-beaver-opening", body)
				if p.interruptZero {
					check(fmt.Errorf("validation: interrupted after first GF opening"))
				}
				return peer
			})
			out := ap.zero.Aggregate(x, as.Labels)
			z = make([]share.BitShare, as.D)
			for j := range z {
				z[j] = share.NewBitShare(domain.Bit(out[j/8]&(1<<uint(j%8)) != 0))
			}
			metrics.ZeroFFT += ap.zero.FFTTime
			metrics.ZeroMul += ap.zero.MulTime
			s.operations.GFProducts += uint64(ap.zero.GatesUsed())
			metrics.ZeroGates += uint64(ap.zero.GatesUsed())
			metrics.ZeroRounds += ap.zero.Rounds
			block.ZeroPolynomial = s.since(mark)
			metrics.Anchor.ZeroPolynomial += time.Since(partStarted)

		}
		partStarted = time.Now()
		mark = s.mark()
		az := s.b2a(z, ap.z)
		block.ObjectB2A = s.since(mark)
		metrics.Anchor.ZB2A += time.Since(partStarted)
		partStarted = time.Now()
		mark = s.mark()
		var msg []byte
		if st.party == 1 {
			m, e := ap.p1.Message1(az)
			check(e)
			msg = zbytes(m)
		}
		peer := s.sendKind("masked-coordinate-alignment", msg)
		var y []incidence.Share
		msg = nil
		if st.party == 0 {
			m, out, e := as.Stage0.Message2(ap.p0, az, zvalues(peer))
			check(e)
			msg = zbytes(m)
			y = out
		}
		peer = s.sendKind("masked-coordinate-alignment", msg)
		if st.party == 1 {
			y, e = as.Stage1.Finish(ap.p1, zvalues(peer))
			check(e)
		}
		s.operations.Permutations++
		s.operations.PermutationCoordinates += uint64(n)
		block.Alignment = s.since(mark)
		metrics.Anchor.Alignment += time.Since(partStarted)
		partStarted = time.Now()
		mark = s.mark()
		check(count.Add(st.payload.LayoutID, y))
		block.Accumulation = s.since(mark)
		metrics.Diagnostics.Blocks = append(metrics.Diagnostics.Blocks, block)
		metrics.Anchor.Count += time.Since(partStarted)
		p.anchor[h] = anchorPacket{}
	}
	partStarted := time.Now()
	mark := s.mark()
	keep := s.compare(count.Values(), p.keep, t.keep, backend)
	input, e := aggregation.AlignOutput(st.payload, st.payload.LayoutID, keep)
	check(e)
	metrics.Diagnostics.FinalThreshold = s.since(mark)
	metrics.Diagnostics.ReservedFinalComparisons = n
	metrics.Diagnostics.Operations = s.operations
	metrics.Diagnostics.SentBytes = s.sent
	metrics.Anchor.Keep = time.Since(partStarted)
	metrics.Stages[0] = time.Since(started)
	metrics.Anchor.Other = metrics.Stages[0] - metrics.Anchor.Total()
	s.phase = 1
	started = time.Now()
	var msg []byte
	if st.party == 1 {
		m, e := p.c1.Begin(input)
		check(e)
		msg = m.Encode()
	}
	peer := s.sendKind("compaction-masked-shuffle", msg)
	msg = nil
	if st.party == 0 {
		m, e := aggregation.DecodeShuffleForDomain(peer, n)
		check(e)
		check(p.c0.Stage1(input, m))
		m, e = p.c0.BeginStage2()
		check(e)
		msg = m.Encode()
	}
	peer = s.sendKind("compaction-masked-shuffle", msg)
	if st.party == 1 {
		m, e := aggregation.DecodeShuffleForDomain(peer, n)
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
	other, e := aggregation.DecodeKeepOpeningForDomain(s.sendKind("compaction-permitted-keep-opening", ko.Encode()), n)
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
	if c.K > p.capacity {
		check(ErrCandidateCapacity)
	}
	metrics.Stages[1] = time.Since(started)
	s.phase = 2
	started = time.Now()
	cv := targetrouting.Candidates{LayoutID: c.LayoutID, CompactionID: c.CompactionID, TargetBucketBits: c.TargetBucketBits, K: c.K, RecordIDShare: c.RecordIDShare, KappaJoinShare: c.KappaJoinShare, BucketJoinShare: c.BucketJoinShare}
	route, m, e := targetrouting.Prepare(st.target.Manifest(), st.party, cv, t.target, 16)
	check(e)
	routes, e := route.Finish(s.sendKind("khprf-blinded-routing", m))
	check(e)
	metrics.Routes = len(routes.Routes)
	metrics.Stages[2] = time.Since(started)
	s.phase = 3
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
			check(pe.Accept(s.sendKind("private-equality-opening", m)))
		}
	}
	gm, e := pe.Output()
	check(e)
	metrics.Groups = groups
	metrics.Stages[3] = time.Since(started)
	s.phase = 4
	started = time.Now()
	position, e := targetposition.Begin(st.target, gm, t.target, p.position, backend)
	check(e)
	for !position.Done() {
		m, e := position.Next()
		check(e)
		check(position.Accept(s.sendKind("target-position-masked-opening", m)))
	}
	hits, e := position.Output()
	check(e)
	gm, e = position.RetainedGroupMatches()
	check(e)
	metrics.Slots = len(hits.HitShares)
	metrics.Stages[4] = time.Since(started)
	s.phase = 5
	started = time.Now()
	pairs, _, e := targetaggregation.Run(st.sidecar, hits, gm, p.agg, t.agg, backend, func(m []byte) ([]byte, error) { return s.sendKind("existing-target-aggregation", m), nil })
	check(e)
	metrics.Stages[5] = time.Since(started)
	s.phase = 6
	started = time.Now()
	if p.output != nil {
		selected, err := p.output.Select(t.target.QueryID, pairs.PairKeepShares, pairs.AnchorIDShares, pairs.TargetIDShares, func(m []byte) ([]byte, error) { return s.sendKind("existing-selected-output", m), nil })
		check(err)
		metrics.M = len(selected.Anchor)
		metrics.Stages[6] = time.Since(started)
		s.phase = 7
		started = time.Now()
		output, e = candidatequery.EncodeSelected(st.party, candidatequery.Binding{Manifest: pairs.Manifest, LayoutID: pairs.LayoutID, CompactionID: pairs.CompactionID, QueryID: pairs.QueryID}, selected)
	} else {
		output, e = candidatequery.EncodeSharesForDomain(st.party, pairs, n)
	}
	check(e)
	metrics.Stages[7] = time.Since(started)
	metrics.Sent = s.sent
	return
}
