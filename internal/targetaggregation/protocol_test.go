package targetaggregation

import (
	"context"
	"encoding/binary"
	"math/rand"
	"testing"
	"time"

	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/incidence"
	"pmeq/internal/share"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
	"pmeq/internal/targetrouting"
)

// Insecure TEST ONLY SCMP oracle. Native benchmarks never use this backend.
type oracleBackend struct{}

func (oracleBackend) KeyGen(bin uint8, x, y uint32, o domain.Bit) (anchorfilter.SCMPKeyShare, anchorfilter.SCMPKeyShare, error) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, x)
	binary.LittleEndian.PutUint32(b[4:], y)
	return anchorfilter.NewSCMPKeyShare(b, share.NewBitShare(o)), anchorfilter.NewSCMPKeyShare(b, share.NewBitShare(false)), nil
}
func (oracleBackend) Eval(p uint8, k anchorfilter.SCMPKeyShare, x, y uint32) (share.BitShare, error) {
	v := false
	if p == 0 {
		b := k.Opaque()
		v = ((x-binary.LittleEndian.Uint32(b))-(y-binary.LittleEndian.Uint32(b[4:])))&127 < 64
	}
	return share.LocalAddBit(share.NewBitShare(domain.Bit(v)), k.OutputMaskShare()), nil
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}

type fixture struct {
	side    [2]*PartySidecar
	hits    [2]targetposition.TargetPostingHits
	groups  [2]targetpe.TargetGroupMatches
	shape   Shape
	lineage targetpe.AlignmentLineage
	counts  []int
	ids     []uint64
}

func makeFixture(t *testing.T, k, r, aliases int) fixture {
	f := fixture{shape: Shape{K: k, R: r, S: k * r * 128, G: k * r * 2}, lineage: targetpe.AlignmentLineage{IndexID: [16]byte{1}, LayoutID: [16]byte{2}, N: 120071}, counts: make([]int, k*26), ids: make([]uint64, 26)}
	rng := rand.New(rand.NewSource(10101))
	splitBit := func(v bool) (share.BitShare, share.BitShare) {
		a := rng.Intn(2) != 0
		return share.NewBitShare(domain.Bit(a)), share.NewBitShare(domain.Bit(a != v))
	}
	for u := 0; u < aliases; u++ {
		f.ids[u] = uint64(1<<40) + uint64(u) + 7
	}
	var coeff [2][]byte
	var payload [2][]share.Ring64Share
	for u := 0; u < 2; u++ {
		coeff[u] = make([]byte, 26*128)
		payload[u] = make([]share.Ring64Share, 52)
	}
	for s := 0; s < 128; s++ {
		ord := s % 64
		if ord == 26 || ord == 27 {
			ord = 0
		}
		for u := 0; u < 26; u++ {
			v := byte(0)
			if ord < aliases && ord == u {
				v = 1
			}
			a := byte(rng.Intn(128))
			coeff[0][s*26+u] = a
			coeff[1][s*26+u] = (v - a) & 127
		}
	}
	for gi := 0; gi < 2; gi++ {
		for u := 0; u < 26; u++ {
			a := rng.Uint64()
			payload[0][gi*26+u] = share.NewRing64Share(domain.Ring64(a))
			payload[1][gi*26+u] = share.NewRing64Share(domain.Ring64(f.ids[u] - a))
		}
	}
	for u := 0; u < 2; u++ {
		f.side[u] = &PartySidecar{party: uint8(u), bits: 16, buckets: make([]bucket, 1<<16), manifest: SidecarManifest{IndexID: f.lineage.IndexID, DTarget: 26, MaxMultiplicity: MaxMultiplicity}}
		matrix, e := incidence.FromLocalCoefficients(26, 128, coeff[u])
		must(t, e)
		f.side[u].buckets[0] = bucket{[]uint32{64, 64}, matrix, payload[u]}
		m := targetrouting.Manifest{IndexID: f.lineage.IndexID, TargetBucketBits: 16, Q: 4}
		f.hits[u] = targetposition.TargetPostingHits{Manifest: m, LayoutID: f.lineage.LayoutID, CompactionID: [16]byte{3}, QueryID: [16]byte{4}, K: k, AnchorRecordIDShare: make([]share.Ring64Share, k), HitShares: make([]share.BitShare, f.shape.S)}
		f.groups[u] = targetpe.TargetGroupMatches{Manifest: m, LayoutID: f.lineage.LayoutID, CompactionID: [16]byte{3}, QueryID: [16]byte{4}, K: k, AnchorRecordIDShare: make([]share.Ring64Share, k), MatchShares: make([]share.BitShare, f.shape.G)}
		for hi := 0; hi < r; hi++ {
			o := targetrouting.Occurrence{OccurrenceID: uint32(hi), Position: uint32(hi * 4)}
			f.hits[u].Occurrences = append(f.hits[u].Occurrences, o)
			f.groups[u].Occurrences = append(f.groups[u].Occurrences, o)
		}
	}
	for c := 0; c < k; c++ {
		a := rng.Uint64()
		f.hits[0].AnchorRecordIDShare[c] = share.NewRing64Share(domain.Ring64(a))
		f.hits[1].AnchorRecordIDShare[c] = share.NewRing64Share(domain.Ring64(uint64(100+c) - a))
		for u := 0; u < 2; u++ {
			f.groups[u].AnchorRecordIDShare[c] = f.hits[u].AnchorRecordIDShare[c]
		}
		for hi := 0; hi < r; hi++ {
			ri := c*r + hi
			for u := 0; u < 2; u++ {
				f.hits[u].Routes = append(f.hits[u].Routes, targetposition.Route{CandidateIndex: uint32(c), OccurrenceID: uint32(hi), SlotOffset: ri * 128, SlotCount: 128, Groups: []targetposition.Group{{GroupOrdinal: 0, PadWidth: 64, SlotRelativeOffset: 0}, {GroupOrdinal: 1, PadWidth: 64, SlotRelativeOffset: 64}}})
				f.groups[u].Routes = append(f.groups[u].Routes, targetpe.Route{CandidateIndex: uint32(c), OccurrenceID: uint32(hi), MatchOffset: ri * 2, GroupCount: 2})
			}
			for gi := 0; gi < 2; gi++ {
				a, b := splitBit(c == 0 && gi == hi%2)
				f.groups[0].MatchShares[ri*2+gi], f.groups[1].MatchShares[ri*2+gi] = a, b
			}
			for s := 0; s < 128; s++ {
				ord := s % 64
				if ord == 26 || ord == 27 {
					ord = 0
				}
				hit := c == 0 && s/64 == hi%2 && ord < aliases && (ord+hi)%3 != 2
				a, b := splitBit(hit)
				f.hits[0].HitShares[ri*128+s], f.hits[1].HitShares[ri*128+s] = a, b
			}
			for u := 0; u < aliases; u++ {
				if c == 0 && (u+hi)%3 != 2 {
					f.counts[c*26+u]++
				}
			}
		}
	}
	return f
}

func runFixture(t *testing.T, f fixture, tau int, b anchorfilter.SCMPBackend) ([2]CandidatePairShares, [2]Metrics) {
	return runFixtureCapacity(t, f, tau, b, f.shape)
}
func runFixtureCapacity(t *testing.T, f fixture, tau int, b anchorfilter.SCMPBackend, capacity Shape) ([2]CandidatePairShares, [2]Metrics) {
	t.Helper()
	users, a, bp, _, e := Preprocess(f.lineage, capacity, b)
	must(t, e)
	token, e := users.Token(f.hits[0].QueryID, tau)
	must(t, e)
	packets := [2]Packet{a, bp}
	var out [2]CandidatePairShares
	var metrics [2]Metrics
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ch := [2]chan []byte{make(chan []byte, 1), make(chan []byte, 1)}
	errc := make(chan error, 2)
	for u := 0; u < 2; u++ {
		go func(u int) {
			exchange := func(m []byte) ([]byte, error) {
				select {
				case ch[u] <- m:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				select {
				case p := <-ch[1-u]:
					return p, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			var err error
			out[u], metrics[u], err = Run(f.side[u], f.hits[u], f.groups[u], packets[u], token, b, exchange)
			if err != nil {
				cancel()
			}
			errc <- err
		}(u)
	}
	for u := 0; u < 2; u++ {
		must(t, <-errc)
	}
	if f.shape.K == 0 {
		if metrics[0].OnlineBytes+metrics[1].OnlineBytes != 0 {
			t.Fatal("empty traffic")
		}
	} else {
		z, m := f.shape.K*f.shape.R*26, f.shape.K*26
		body := 58*f.shape.S + 864*f.shape.G + 74*z + 98*m
		batches := 2 * f.shape.K * f.shape.R // fixture routes have128 slots,64 per chunk
		groupBatches := f.shape.K * f.shape.R
		frames := 9 + batches + groupBatches + f.shape.R + (z+4095)/4096
		if got := metrics[0].OnlineBytes + metrics[1].OnlineBytes; got != uint64(body+74*frames) {
			t.Fatal("wire accounting", got, body+74*frames)
		}
	}
	if _, _, e = Run(f.side[0], f.hits[0], f.groups[0], a, token, b, func([]byte) ([]byte, error) { t.Error("reused packet exchanged"); return nil, nil }); e == nil {
		t.Fatal("copied packet reused")
	}
	for j := 0; j < f.shape.K*26; j++ {
		keep := bool(out[0].PairKeepShares[j].Value().Add(out[1].PairKeepShares[j].Value()))
		want := f.counts[j] >= f.shape.R-tau
		if keep != want {
			t.Fatal("Keep", j, keep, want)
		}
		aid := uint64(out[0].AnchorIDShares[j].Value() + out[1].AnchorIDShares[j].Value())
		tid := uint64(out[0].TargetIDShares[j].Value() + out[1].TargetIDShares[j].Value())
		if want {
			if aid != uint64(100+j/26) || tid != f.ids[j%26] {
				t.Fatal("IDs", j, aid, tid)
			}
		} else if aid != 0 || tid != 0 {
			t.Fatal("inactive ID", j)
		}
	}
	return out, metrics
}
func TestFixedPairs(t *testing.T) {
	for _, k := range []int{0, 1, 2} {
		for _, r := range []int{1, 3, 16} {
			for _, aliases := range []int{0, 1, 26} {
				for _, tau := range []int{0, r - 1} {
					runFixture(t, makeFixture(t, k, r, aliases), tau, oracleBackend{})
				}
			}
		}
	}
}
func TestThreshold(t *testing.T) {
	for r := -1; r <= 17; r++ {
		for tau := -1; tau <= 17; tau++ {
			v, e := Threshold(r, tau)
			valid := r >= 1 && r <= 16 && tau >= 0 && tau < r
			if (e == nil) != valid || valid && v != r-tau {
				t.Fatal(r, tau, v, e)
			}
		}
	}
}
func TestBindings(t *testing.T) {
	f := makeFixture(t, 1, 1, 1)
	u, a, _, _, e := Preprocess(f.lineage, f.shape, oracleBackend{})
	must(t, e)
	tok, e := u.Token(f.hits[0].QueryID, 0)
	must(t, e)
	for _, mutate := range []func(*targetposition.TargetPostingHits){func(h *targetposition.TargetPostingHits) { h.QueryID[0]++ }, func(h *targetposition.TargetPostingHits) {
		h.Routes = append([]targetposition.Route(nil), h.Routes...)
		h.Routes[0].SlotOffset++
	}, func(h *targetposition.TargetPostingHits) { h.K++ }} {
		h := f.hits[0]
		mutate(&h)
		if _, e = validate(f.side[0], h, f.groups[0], a, tok); e == nil {
			t.Fatal("bad input accepted")
		}
	}
}

func TestCapacityPrefixes(t *testing.T) {
	for _, k := range []int{0, 1, 2} {
		for _, r := range []int{1, 16} {
			f := makeFixture(t, k, r, 26)
			capacity := Shape{K: k + 1, R: r, S: f.shape.S + 128*r, G: f.shape.G + 2*r}
			runFixtureCapacity(t, f, r-1, oracleBackend{}, capacity)
		}
	}
}
