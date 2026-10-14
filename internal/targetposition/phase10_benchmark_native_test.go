//go:build phase6native

package targetposition_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"pmeq/internal/scmpnative"
	ta "pmeq/internal/targetaggregation"
	"pmeq/internal/targetposition"
)

func TestPhase10NativeBenchmarks(t *testing.T) {
	if os.Getenv("PMEQ_TARGET_AGG_BENCH") != "1" {
		t.Skip("opt-in actual native Target aggregation component benchmarks")
	}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	type sample struct {
		Stages                  [15]time.Duration
		Online, HeapDelta, Heap uint64
	}
	type result struct {
		S, K, R, Tau, Warmups int
		Offline               ta.OfflineBody
		Samples               []sample
		Status                string
	}
	var results []result
	mr, e := os.ReadFile("../../artifacts/phase7b/manifest.json")
	must(e)
	raw, e := os.ReadFile("../../artifacts/phase10b/manifest.json")
	must(e)
	var manifest ta.SidecarManifest
	must(json.Unmarshal(raw, &manifest))
	var side [2]*ta.PartySidecar
	fixtures := targetposition.BuildPhase10BenchmarkFixtures(t)
	for u, name := range []string{"cs0.aggregation.bin", "cs1.aggregation.bin"} {
		f, e := os.Open(filepath.Join("../../artifacts/phase10b", name))
		must(e)
		side[u], e = ta.LoadSidecar(manifest, mr, fixtures[0].Index[u], f)
		f.Close()
		must(e)
	}
	for fi, f := range fixtures {
		if os.Getenv("PMEQ_TARGET_AGG_BENCH_SCOPE") != "small_mean" && fi == len(fixtures)-1 {
			continue
		}
		if os.Getenv("PMEQ_TARGET_AGG_BENCH_SCOPE") == "small_mean" && fi != 0 && fi != len(fixtures)-1 {
			continue
		}
		k, r := f.Hits[0].K, len(f.Hits[0].Occurrences)
		warm, n := 10, 50
		if f.S > 500000 {
			warm, n = 5, 20
		}
		res := result{S: f.S, K: k, R: r, Tau: f.Tau, Warmups: warm, Status: "SUM OF MEASURED COMPONENTS"}
		var expected [][3]uint64
		for trial := 0; trial < warm+n; trial++ {
			u, p0, p1, cost, e := ta.Preprocess(f.Index[0].Lineage(), ta.Shape{K: k, R: r, S: f.S, G: len(f.Matches[0].MatchShares)}, scmpnative.Backend{})
			must(e)
			token, e := u.Token(f.Hits[0].QueryID, f.Tau)
			must(e)
			res.Offline = cost
			runtime.GC()
			var base runtime.MemStats
			runtime.ReadMemStats(&base)
			packets := [2]ta.Packet{p0, p1}
			var out [2]ta.CandidatePairShares
			var metrics [2]ta.Metrics
			peaks := [2]uint64{base.HeapAlloc, base.HeapAlloc}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			ch := [2]chan []byte{make(chan []byte, 1), make(chan []byte, 1)}
			errs := make(chan error, 2)
			for party := 0; party < 2; party++ {
				go func(party int) {
					ex := func(m []byte) ([]byte, error) {
						if len(m) > 4096 {
							var ms runtime.MemStats
							runtime.ReadMemStats(&ms)
							peaks[party] = max(peaks[party], ms.HeapAlloc)
						}
						select {
						case ch[party] <- m:
						case <-ctx.Done():
							return nil, ctx.Err()
						}
						select {
						case p := <-ch[1-party]:
							return p, nil
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					}
					var err error
					out[party], metrics[party], err = ta.Run(side[party], f.Hits[party], f.Matches[party], packets[party], token, scmpnative.Backend{}, ex)
					if err != nil {
						cancel()
					}
					errs <- err
				}(party)
			}
			for party := 0; party < 2; party++ {
				must(<-errs)
			}
			cancel()
			var end runtime.MemStats
			runtime.ReadMemStats(&end)
			peaks[0] = max(peaks[0], end.HeapAlloc)
			if trial == 0 {
				expected = make([][3]uint64, k*26)
			}
			for j := 0; j < k*26; j++ {
				keep := uint64(0)
				if out[0].PairKeepShares[j].Value().Add(out[1].PairKeepShares[j].Value()) {
					keep = 1
				}
				v := [3]uint64{keep, uint64(out[0].AnchorIDShares[j].Value() + out[1].AnchorIDShares[j].Value()), uint64(out[0].TargetIDShares[j].Value() + out[1].TargetIDShares[j].Value())}
				if trial == 0 {
					expected[j] = v
				} else if v != expected[j] {
					t.Fatal("fresh trial changed pair")
				}
				if keep == 0 && (v[1] != 0 || v[2] != 0) {
					t.Fatal("inactive ID")
				}
			}
			if trial >= warm {
				s := sample{Online: metrics[0].OnlineBytes + metrics[1].OnlineBytes, Heap: max(peaks[0], peaks[1])}
				if s.Heap > base.HeapAlloc {
					s.HeapDelta = s.Heap - base.HeapAlloc
				}
				for i := range s.Stages {
					s.Stages[i] = metrics[0].Stages[i] + metrics[1].Stages[i]
				}
				res.Samples = append(res.Samples, s)
			}
		}
		results = append(results, res)
		t.Logf("PHASE10 benchmark S=%d K=%d r=%d warm=%d measured=%d errors=0", f.S, k, r, warm, n)
		raw, e = json.Marshal(results)
		must(e)
		path := "../../results/phase10b-benchmarks.json"
		if os.Getenv("PMEQ_TARGET_AGG_BENCH_SCOPE") == "small_mean" {
			path = "../../results/phase10b-memory-benchmarks.json"
		}
		must(os.WriteFile(path, append(raw, '\n'), 0600))
	}
}
