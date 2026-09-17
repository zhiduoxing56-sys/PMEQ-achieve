package discovery

import (
	"context"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/candidatequery"
	"runtime"
	"sync"
	"time"
)

type Metrics struct {
	Token, Anchor, Compaction, Routing, TargetPE, TargetPosition, TargetAggregation, OutputEncoding, Recovery, Cloud, LocalE2E time.Duration
	UserToCloud, CloudToUser                                                                                                   [2]uint64
	ServerBytes                                                                                                                uint64
	K, Routes, Groups, Slots                                                                                                   int
	PeakHeap                                                                                                                   uint64
}

// RunLocal is the integrated LOCAL transport coordinator. Each goroutine gets
// only its own static/packet/token, an Eval backend, and a byte-message endpoint.
// User token generation ends before clouds start; the next user operation is
// recovery. This is not socket/network latency. Provision must already be done.
func RunLocal(ctx context.Context, q Query, keys UserKeys, u *UserPacket, statics [2]*Static, packets [2]*PartyPacket, backend anchorfilter.SCMPBackend) (out candidatequery.CandidatePairs, m Metrics, err error) {
	if err = Validate(q); err != nil {
		return
	}
	if u == nil || statics[0] == nil || statics[1] == nil || packets[0] == nil || packets[1] == nil || backend == nil {
		return out, m, ErrBinding
	}
	for party := 0; party < 2; party++ {
		s, p := statics[party], packets[party]
		if s.target == nil || s.sidecar == nil || s.party != uint8(party) || p.party != uint8(party) || p.g == nil || u.g == nil || p.id != u.id || u.layout != s.payload.LayoutID {
			return out, m, ErrBinding
		}
	}
	if statics[0].target.Lineage() != statics[1].target.Lineage() || statics[0].target.ManifestDigest() != statics[1].target.ManifestDigest() {
		return out, m, ErrBinding
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
		return out, m, e
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
	var wires [2][]byte
	var stages [7]time.Duration
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err != nil && err == nil {
			err = r.err
		}
		wires[r.party] = r.wire
		m.CloudToUser[r.party] = uint64(len(r.wire))
		m.ServerBytes += r.metrics.Sent
		for j, d := range r.metrics.Stages {
			stages[j] = max(stages[j], d)
		}
		if i == 0 {
			m.K = r.metrics.K
			m.Routes = r.metrics.Routes
			m.Groups = r.metrics.Groups
			m.Slots = r.metrics.Slots
		} else if err == nil && (m.K != r.metrics.K || m.Routes != r.metrics.Routes || m.Groups != r.metrics.Groups || m.Slots != r.metrics.Slots) {
			err = ErrBinding
		}
	}
	m.Cloud = time.Since(cloudStart)
	m.Anchor, m.Compaction, m.Routing, m.TargetPE, m.TargetPosition, m.TargetAggregation, m.OutputEncoding = stages[0], stages[1], stages[2], stages[3], stages[4], stages[5], stages[6]
	if err != nil {
		return
	}
	recoveryStart := time.Now()
	t, e := decodeToken(tokens[0], statics[0].target.Manifest(), 0)
	if e != nil {
		return out, m, e
	}
	out, err = candidatequery.Recover(candidatequery.Binding{Manifest: statics[0].target.Manifest(), LayoutID: u.layout, CompactionID: u.compaction, QueryID: t.target.QueryID}, wires[0], wires[1])
	m.Recovery = time.Since(recoveryStart)
	m.LocalE2E = time.Since(start)
	return
}
