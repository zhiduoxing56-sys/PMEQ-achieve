package discovery

import (
	"context"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/candidatequery"
	"runtime"
	"sync"
	"time"
)

// AnchorBreakdown partitions one party's Anchor wall time. Each category sums
// all occurrences, including message waits. Other includes entry/loop overhead.
// Its sum equals that party's Anchor timer; it is not a sum of party maxima.
type AnchorBreakdown struct {
	Filter, ZeroPolynomial, ZB2A, Alignment, Count, Keep, Other time.Duration
}

func (a AnchorBreakdown) Total() time.Duration {
	return a.Filter + a.ZeroPolynomial + a.ZB2A + a.Alignment + a.Count + a.Keep + a.Other
}

type Metrics struct {
	ZeroFFT, ZeroMul [2]time.Duration
	PersistentLoad   PersistentLoad
	Trace            [2][]FrameAudit
	ZeroGates        [2]uint64
	ZeroRounds       [2]int
	ExchangeRounds   [2]uint32
	// AnchorParts uses the party with the larger complete Anchor duration.
	AnchorParts       AnchorBreakdown
	AnchorPartyParts  [2]AnchorBreakdown
	AnchorDiagnostics [2]AnchorDiagnostics
	ServerPhaseBytes  [2][8]uint64

	Token, Anchor, Compaction, Routing, TargetPE, TargetPosition, TargetAggregation, GlobalPermutation, OutputEncoding, Recovery, Cloud, LocalE2E time.Duration
	UserToCloud, CloudToUser                                                                                                                      [2]uint64
	ServerBytes                                                                                                                                   uint64
	K, M, Routes, Groups, Slots                                                                                                                   int
	PeakHeap                                                                                                                                      uint64
}

// RunLocal is the integrated LOCAL transport coordinator. Each goroutine gets
// only its own static/packet/token, an Eval backend, and a byte-message endpoint.
// User token generation ends before clouds start; the next user operation is
// recovery. This is not socket/network latency. Provision must already be done.
func RunCloudLocal(ctx context.Context, q Query, keys UserKeys, u *UserPacket, statics [2]*Static, packets [2]*PartyPacket, backend anchorfilter.SCMPBackend) (wires [2][]byte, binding candidatequery.Binding, m Metrics, err error) {
	if err = Validate(q); err != nil {
		return
	}
	if u == nil || statics[0] == nil || statics[1] == nil || packets[0] == nil || packets[1] == nil || backend == nil {
		return wires, binding, m, ErrBinding
	}
	for party := 0; party < 2; party++ {
		s, p := statics[party], packets[party]
		if s.target == nil || s.sidecar == nil || len(s.payload.Slots) != s.target.Lineage().N || s.party != uint8(party) || p.party != uint8(party) || p.g == nil || u.g == nil || p.id != u.id || u.layout != s.payload.LayoutID {
			return wires, binding, m, ErrBinding
		}
	}
	if statics[0].target.Lineage() != statics[1].target.Lineage() || statics[0].target.ManifestDigest() != statics[1].target.ManifestDigest() {
		return wires, binding, m, ErrBinding
	}
	m.PersistentLoad, err = loadPersistentQuery(u, packets, statics)
	if err != nil {
		return wires, binding, m, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var peak uint64
	sample := func() {
		var x runtime.MemStats
		runtime.ReadMemStats(&x)
		mu.Lock()
		peak = max(peak, x.HeapAlloc)
		mu.Unlock()
	}
	sample()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(10 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				sample()
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
		sample()
		mu.Lock()
		m.PeakHeap = peak
		mu.Unlock()
	}()
	start := time.Now()
	tokens, e := generate(q, keys, u, statics[0].target.Manifest())
	if e != nil {
		return wires, binding, m, e
	}
	m.Token = time.Since(start)
	for i := range tokens {
		m.UserToCloud[i] = uint64(len(tokens[i]))
	}
	channels := [2]chan []byte{make(chan []byte, 1), make(chan []byte, 1)}
	type result struct {
		party   int
		wire    []byte
		metrics cloudMetrics
		err     error
	}
	results := make(chan result, 2)
	cloudStart := time.Now()
	for party := 0; party < 2; party++ {
		go func(party int, ownStatic *Static, ownPacket *PartyPacket, ownToken []byte, outgoing chan<- []byte, incoming <-chan []byte, sink chan<- result) {
			wire := func(b []byte) ([]byte, error) {
				select {
				case outgoing <- b:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				select {
				case b := <-incoming:
					return b, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			b, n, e := runParty(ownStatic, ownPacket, ownToken, backend, wire)
			if e != nil {
				cancel()
			}
			sink <- result{party, b, n, e}
		}(party, statics[party], packets[party], tokens[party], channels[party], channels[1-party], results)
	}
	var stages [8]time.Duration
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err != nil && err == nil {
			err = r.err
		}
		wires[r.party] = r.wire
		m.CloudToUser[r.party] = uint64(len(r.wire))
		m.ServerBytes += r.metrics.Sent
		m.Trace[r.party] = r.metrics.Trace
		m.ZeroFFT[r.party] = r.metrics.ZeroFFT
		m.ZeroMul[r.party] = r.metrics.ZeroMul
		m.ZeroGates[r.party] = r.metrics.ZeroGates
		m.ZeroRounds[r.party] = r.metrics.ZeroRounds
		m.ExchangeRounds[r.party] = r.metrics.Rounds
		m.AnchorPartyParts[r.party] = r.metrics.Anchor
		m.AnchorDiagnostics[r.party] = r.metrics.Diagnostics
		m.ServerPhaseBytes[r.party] = r.metrics.PhaseBytes
		if r.metrics.Stages[0] > m.AnchorParts.Total() {
			m.AnchorParts = r.metrics.Anchor
		}
		for j, d := range r.metrics.Stages {
			stages[j] = max(stages[j], d)
		}
		if i == 0 {
			m.M = r.metrics.M
			m.K = r.metrics.K
			m.Routes = r.metrics.Routes
			m.Groups = r.metrics.Groups
			m.Slots = r.metrics.Slots
		} else if err == nil && (m.M != r.metrics.M || m.K != r.metrics.K || m.Routes != r.metrics.Routes || m.Groups != r.metrics.Groups || m.Slots != r.metrics.Slots) {
			err = ErrBinding
		}
	}
	m.Cloud = time.Since(cloudStart)
	m.Anchor, m.Compaction, m.Routing, m.TargetPE, m.TargetPosition, m.TargetAggregation, m.GlobalPermutation, m.OutputEncoding = stages[0], stages[1], stages[2], stages[3], stages[4], stages[5], stages[6], stages[7]
	if err != nil {
		return
	}
	t, e := decodeToken(tokens[0], statics[0].target.Manifest(), 0)
	if e != nil {
		return wires, binding, m, e
	}
	binding = candidatequery.Binding{Manifest: statics[0].target.Manifest(), LayoutID: u.layout, CompactionID: u.compaction, QueryID: t.target.QueryID}
	m.LocalE2E = time.Since(start)
	return
}

// RunLocal preserves the historical 26-slot test harness recovery. Production
// callers use RunCloudLocal and receive only the two result wires.
func RunLocal(ctx context.Context, q Query, keys UserKeys, u *UserPacket, statics [2]*Static, packets [2]*PartyPacket, backend anchorfilter.SCMPBackend) (out candidatequery.CandidatePairs, m Metrics, err error) {
	wires, binding, m, e := RunCloudLocal(ctx, q, keys, u, statics, packets, backend)
	if e != nil {
		return out, m, e
	}
	start := time.Now()
	out, err = candidatequery.RecoverForDomain(binding, wires[0], wires[1], statics[0].target.Lineage().N)
	m.Recovery = time.Since(start)
	m.LocalE2E += m.Recovery
	return
}
