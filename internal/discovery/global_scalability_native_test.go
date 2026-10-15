//go:build phase6native

package discovery

// Operator-only benchmark. No RunLocal, index construction, routing, or E2E.
import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	mr "math/rand"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpnative"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
)

type scaleProfile struct {
	Query, R, Lambda, K int
	Histogram           []int
}
type scaleSample struct {
	Operator, Distribution, Status    string
	N, K, Query, R, Lambda, Iteration int
	Warmup                            bool
	Milliseconds, OfflineMilliseconds float64
	Sent, Received                    [2]uint64
	Rounds                            [2]uint32
	PeakHeapBytes                     uint64
	PeakRSSBytes                      uint64
}

func scaleMust(e error) {
	if e != nil {
		panic(e)
	}
}
func scaleWrite(path string, x any) {
	b, e := json.MarshalIndent(x, "", " ")
	scaleMust(e)
	scaleMust(os.WriteFile(path, b, 0600))
}

func TestGlobalScaleProfiles(t *testing.T) {
	if os.Getenv("PMEQ_SCALE_PROFILE") != "1" {
		t.Skip("opt-in")
	}
	b, e := os.ReadFile("../../results/anchor-breakdown-queries.json")
	scaleMust(e)
	var rows []struct {
		Query    int
		Rejected bool
		Metrics  struct{ K int }
	}
	scaleMust(json.Unmarshal(b, &rows))
	f, e := os.Open("../../results/phase7b-workload.jsonl.gz")
	scaleMust(e)
	defer f.Close()
	gz, e := gzip.NewReader(f)
	scaleMust(e)
	defer gz.Close()
	var queries []struct {
		Query          int
		Anchor, Target string
		Tau            int
	}
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 65536), 4<<20)
	for sc.Scan() {
		var q struct {
			Query          int
			Anchor, Target string
			Tau            int
		}
		scaleMust(json.Unmarshal(sc.Bytes(), &q))
		queries = append(queries, q)
	}
	scaleMust(sc.Err())
	raw, e := os.Open("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area")
	scaleMust(e)
	defer raw.Close()
	areas, e := indexbuild.LoadArea(raw, 0)
	scaleMust(e)
	if len(areas) != 120071 || len(rows) != 1003 || len(queries) != 1003 {
		t.Fatal("unexpected source shape")
	}
	names := make([][]rune, len(areas))
	for i, a := range areas {
		names[i] = []rune(a.Name)
	}
	profiles := []scaleProfile{}
	for _, row := range rows {
		if row.Rejected {
			continue
		}
		q := queries[row.Query]
		chunks := anchorfilter.QueryChunks(q.Anchor)
		p := scaleProfile{Query: row.Query, R: len(chunks), Lambda: len(chunks) - q.Tau, Histogram: make([]int, len(chunks)+1)}
		for _, name := range names {
			c := 0
			for _, chunk := range chunks {
				for pos := max(0, int(chunk.Position)-q.Tau); pos <= int(chunk.Position)+q.Tau && pos+4 <= len(name); pos++ {
					if string(name[pos:pos+4]) == chunk.QGram {
						c++
						break
					}
				}
			}
			p.Histogram[c]++
			if c >= p.Lambda {
				p.K++
			}
		}
		if p.K != row.Metrics.K {
			t.Fatalf("query %d plaintext histogram K=%d production K=%d", p.Query, p.K, row.Metrics.K)
		}
		profiles = append(profiles, p)
	}
	if len(profiles) != 854 {
		t.Fatal(len(profiles))
	}
	scaleWrite("../../results/global-scale-profiles.json", profiles)
	t.Logf("validated all %d empirical c histograms against saved production K", len(profiles))
}

// Fresh dealer material per invocation; only the actual online production calls
// and their real encoded local transport are inside the latency boundary.
func scaleRun(n int, operator, distribution string, p scaleProfile, k, iteration int) scaleSample {
	rng := mr.New(mr.NewSource(20260920 + int64(iteration)))
	sample := scaleSample{Operator: operator, Distribution: distribution, Status: "ok", N: n, K: k, Query: p.Query, R: p.R, Lambda: p.Lambda, Iteration: iteration, Warmup: iteration < 10}
	layout := [16]byte{71}
	query := [16]byte{72}
	packet := [16]byte{73}
	var counts [2][]incidence.Share
	var comp [2]*aggregation.ComparisonParty
	var bound uint32
	var cp0 *aggregation.Compaction0
	var cp1 *aggregation.Compaction1
	var input [2]aggregation.CandidateInput
	expected := make([]bool, n)
	var payload [2]aggregation.PartyPayload
	offline := time.Now()
	if operator == "keep" {
		counts[0] = make([]incidence.Share, n)
		counts[1] = make([]incidence.Share, n)
		masks := make([]byte, n)
		_, e := rand.Read(masks)
		scaleMust(e)
		cdf := make([]int, len(p.Histogram))
		for i, h := range p.Histogram {
			cdf[i] = h
			if i > 0 {
				cdf[i] += cdf[i-1]
			}
		}
		gotK := 0
		for j := 0; j < n; j++ {
			c := 0
			if distribution == "empirical" {
				draw := rng.Intn(120071)
				c = sort.SearchInts(cdf, draw+1)
			} else {
				c = rng.Intn(p.R + 1)
			}
			expected[j] = c >= p.Lambda
			if expected[j] {
				gotK++
			}
			counts[0][j] = incidence.NewShare(incidence.Z128(masks[j] & 127))
			counts[1][j] = incidence.NewShare(incidence.Z128(byte(c) - (masks[j] & 127)))
		}
		sample.K = gotK
		u, a, b, e := aggregation.PreprocessComparison(n, scmpnative.Backend{})
		scaleMust(e)
		comp = [2]*aggregation.ComparisonParty{a, b}
		bound, e = u.Mask(p.Lambda)
		scaleMust(e)
		for party := range payload {
			payload[party] = aggregation.PartyPayload{LayoutID: layout, Slots: make([]aggregation.PayloadShare, n)}
		}
	} else {
		ids := make([]uint64, n)
		for j := range ids {
			ids[j] = uint64(j + 1)
		}
		var key [32]byte
		key[0] = 9
		master, e := targetcrypto.NewMasterKey(key)
		scaleMust(e)
		_, a, b, e := aggregation.GeneratePayload(ids, master, 16)
		scaleMust(e)
		payload = [2]aggregation.PartyPayload{a, b}
		layout = a.LayoutID
		masks := make([]byte, n)
		_, e = rand.Read(masks)
		scaleMust(e)
		perm := rng.Perm(n)
		for j := 0; j < k; j++ {
			expected[perm[j]] = true
		}
		for party := 0; party < 2; party++ {
			input[party] = aggregation.CandidateInput{LayoutID: layout, Payload: payload[party].Slots, KeepShare: make([]share.BitShare, n)}
		}
		for j, v := range expected {
			x := masks[j]&1 != 0
			input[0].KeepShare[j] = share.NewBitShare(domain.Bit(x))
			input[1].KeepShare[j] = share.NewBitShare(domain.Bit(x != v))
		}
		cp0, cp1, e = aggregation.PreprocessCompaction(layout, n)
		scaleMust(e)
		packet = cp0.ID()
	}
	sample.OfflineMilliseconds = float64(time.Since(offline)) / 1e6
	runtime.GC()
	var mu sync.Mutex
	var peak, peakRSS uint64
	mem := func() {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		stat, e := os.ReadFile("/proc/self/statm")
		scaleMust(e)
		pages, e := strconv.ParseUint(strings.Fields(string(stat))[1], 10, 64)
		scaleMust(e)
		mu.Lock()
		peak = max(peak, m.HeapAlloc)
		peakRSS = max(peakRSS, pages*uint64(os.Getpagesize()))
		mu.Unlock()
	}
	mem()
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				mem()
			}
		}
	}()
	channels := [2]chan []byte{make(chan []byte, 1), make(chan []byte, 1)}
	var out [2][]share.BitShare
	var candidates [2]aggregation.CompactedCandidates
	var endpoints [2]*endpoint
	var wg sync.WaitGroup
	wg.Add(2)
	start := time.Now()
	for party := 0; party < 2; party++ {
		go func(party int) {
			defer wg.Done()
			s := &endpoint{party: uint8(party), query: query, packet: packet, wire: func(b []byte) ([]byte, error) { channels[party] <- b; return <-channels[1-party], nil }}
			endpoints[party] = s
			if operator == "keep" {
				// Same Values copy, endpoint.compare and AlignOutput as runParty Keep.
				values := append([]incidence.Share(nil), counts[party]...)
				out[party] = s.compare(values, comp[party], bound, scmpnative.Backend{})
				_, e := aggregation.AlignOutput(payload[party], layout, out[party])
				scaleMust(e)
			} else {
				var msg []byte
				if party == 1 {
					m, e := cp1.Begin(input[1])
					scaleMust(e)
					msg = m.Encode()
				}
				peer := s.send(msg)
				msg = nil
				if party == 0 {
					m, e := aggregation.DecodeShuffleForDomain(peer, n)
					scaleMust(e)
					scaleMust(cp0.Stage1(input[0], m))
					m, e = cp0.BeginStage2()
					scaleMust(e)
					msg = m.Encode()
				}
				peer = s.send(msg)
				if party == 1 {
					m, e := aggregation.DecodeShuffleForDomain(peer, n)
					scaleMust(e)
					scaleMust(cp1.Stage2(m))
				}
				var opening aggregation.KeepOpening
				var e error
				if party == 0 {
					opening, e = cp0.OpenKeep()
				} else {
					opening, e = cp1.OpenKeep()
				}
				scaleMust(e)
				other, e := aggregation.DecodeKeepOpeningForDomain(s.send(opening.Encode()), n)
				scaleMust(e)
				if party == 0 {
					candidates[party], e = cp0.Extract(other)
				} else {
					candidates[party], e = cp1.Extract(other)
				}
				scaleMust(e)
			}
		}(party)
	}
	wg.Wait()
	sample.Milliseconds = float64(time.Since(start)) / 1e6
	close(stop)
	<-stopped
	mem()
	sample.PeakHeapBytes = peak
	sample.PeakRSSBytes = peakRSS
	for party, s := range endpoints {
		sample.Sent[party] = s.sent
		sample.Received[1-party] = s.sent
		sample.Rounds[party] = s.seq
	}
	if operator == "keep" {
		for j, v := range expected {
			if bool(out[0][j].Value().Add(out[1][j].Value())) != v {
				panic("Keep mismatch")
			}
		}
	} else {
		if candidates[0].K != k || candidates[1].K != k {
			panic("K mismatch")
		}
		// Verify every selected ID and its scalar/bucket, not just output length.
		want := map[uint64]aggregation.PayloadShare{}
		for j, v := range expected {
			if v {
				id := uint64(payload[0].Slots[j].RecordIDShare.Value() + payload[1].Slots[j].RecordIDShare.Value())
				sc, e := targetcrypto.CombineScalarShare(payload[0].Slots[j].KappaJoinShare, payload[1].Slots[j].KappaJoinShare)
				scaleMust(e)
				want[id] = aggregation.PayloadShare{KappaJoinShare: sc, BucketJoinShare: payload[0].Slots[j].BucketJoinShare ^ payload[1].Slots[j].BucketJoinShare}
			}
		}
		for j := 0; j < k; j++ {
			id := uint64(candidates[0].RecordIDShare[j].Value() + candidates[1].RecordIDShare[j].Value())
			w, ok := want[id]
			sc, e := targetcrypto.CombineScalarShare(candidates[0].KappaJoinShare[j], candidates[1].KappaJoinShare[j])
			scaleMust(e)
			if !ok || sc != w.KappaJoinShare || candidates[0].BucketJoinShare[j]^candidates[1].BucketJoinShare[j] != w.BucketJoinShare {
				panic("payload mismatch")
			}
			delete(want, id)
		}
	}
	return sample
}

func TestGlobalScaleOperator(t *testing.T) {
	operator := os.Getenv("PMEQ_SCALE_OPERATOR")
	if operator == "" {
		t.Skip("opt-in")
	}
	n, e := strconv.Atoi(os.Getenv("PMEQ_SCALE_N"))
	scaleMust(e)
	distribution := os.Getenv("PMEQ_SCALE_DISTRIBUTION")
	b, e := os.ReadFile("../../results/global-scale-profiles.json")
	scaleMust(e)
	var profiles []scaleProfile
	scaleMust(json.Unmarshal(b, &profiles))
	sorted := append([]scaleProfile(nil), profiles...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].K < sorted[j].K })
	ratioIndex := map[string]int{"median": (len(sorted) - 1) / 2, "p95": int(math.Ceil(.95*float64(len(sorted)))) - 1, "max": len(sorted) - 1}
	k := 0
	if operator == "exact_k" {
		k = int(math.Round(float64(n) * float64(sorted[ratioIndex[distribution]].K) / 120071))
	}
	path := fmt.Sprintf("../../results/global-scale-%s-%d-%s.jsonl", operator, n, distribution)
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	scaleMust(e)
	defer f.Close()
	enc := json.NewEncoder(f)
	count := 60
	if os.Getenv("PMEQ_SCALE_SMOKE") == "1" {
		count = 1
	}
	for i := 0; i < count; i++ {
		// The same deterministic query schedule pairs the two c-distribution cases.
		p := profiles[(i*137+19)%len(profiles)]
		s := scaleRun(n, operator, distribution, p, k, i)
		scaleMust(enc.Encode(s))
		scaleMust(f.Sync())
		if i%10 == 0 || i == count-1 {
			t.Logf("%s N=%d %s iteration=%d online=%.3fms offline=%.3fms", operator, n, distribution, i, s.Milliseconds, s.OfflineMilliseconds)
		}
	}
}
