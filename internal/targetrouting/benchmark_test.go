package targetrouting_test

import (
	"os"
	"pmeq/internal/targetquery"
	r "pmeq/internal/targetrouting"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func quantiles(v []float64) (float64, float64) {
	sort.Float64s(v)
	return v[(len(v)+1)/2-1], v[(95*len(v)+99)/100-1]
}
func TestRoutingBenchmarks(t *testing.T) {
	mode := os.Getenv("PMEQ_ROUTING_BENCH")
	if mode == "" {
		t.Skip("set PMEQ_ROUTING_BENCH=sweep or grid")
	}
	m := manifest(t, 8)
	workers := []int{1, 4, 8, 16}
	ks := []int{431, 2843}
	rs := []int{5}
	if mode == "grid" {
		workers = []int{16}
		if s := os.Getenv("PMEQ_ROUTING_WORKERS"); s != "" {
			v, e := strconv.Atoi(s)
			must(t, e)
			workers = []int{v}
		}
		ks = []int{1, 5, 64, 431, 512, 2843, 4780}
		rs = []int{1, 2, 5, 7, 16}
	}
	t.Logf("MEMORY route_struct=%d state_header=%d max_pairs=%d state_both_bytes=%d below_12GiB=true", unsafe.Sizeof(r.Route{}), unsafe.Sizeof(r.RoutedCandidates{}), 4780*16, 2*(uint64(unsafe.Sizeof(r.RoutedCandidates{}))+8*4780+8*16+uint64(unsafe.Sizeof(r.Route{}))*4780*16))
	for _, k := range ks {
		a, b := fixtures(t, k, k, 8)
		c, d := compact(t, a, b, 8)
		for _, nr := range rs {
			for _, w := range workers {
				if mode == "grid" && w == 16 && nr == 5 && (k == 431 || k == 2843) {
					continue
				} // reuse selected-worker sweep rows
				samples := make([][]float64, 4)
				var peak uint64
				for iteration := 0; iteration < 12; iteration++ {
					runtime.GC()
					var before runtime.MemStats
					runtime.ReadMemStats(&before)
					start := time.Now()
					u, v, e := targetquery.GenerateTokens(m, key(t), strings.Repeat("abcd", nr))
					must(t, e)
					uw, e := r.EncodeToken(u)
					must(t, e)
					vw, e := r.EncodeToken(v)
					must(t, e)
					user := time.Since(start)
					start = time.Now()
					u, e = r.DecodeToken(m, 0, uw)
					must(t, e)
					p, pm, e := r.Prepare(m, 0, c, u, w)
					must(t, e)
					left := time.Since(start)
					start = time.Now()
					v, e = r.DecodeToken(m, 1, vw)
					must(t, e)
					q, qm, e := r.Prepare(m, 1, d, v, w)
					must(t, e)
					right := time.Since(start)
					start = time.Now()
					x, e := p.Finish(qm)
					must(t, e)
					y, e := q.Finish(pm)
					must(t, e)
					opening := time.Since(start)
					var after runtime.MemStats
					runtime.ReadMemStats(&after)
					if len(x.Routes) != k*nr || len(y.Routes) != k*nr || len(pm) != r.OpeningHeaderBytes+2*k*nr {
						t.Fatal("bench shape")
					}
					for i := range x.Routes {
						if x.Routes[i].BucketID != y.Routes[i].BucketID {
							t.Fatal("bench bucket")
						}
					}
					if iteration >= 2 {
						for i, duration := range []time.Duration{user, left, right, opening} {
							samples[i] = append(samples[i], float64(duration)/1e6)
						}
						if after.HeapAlloc > before.HeapAlloc && after.HeapAlloc-before.HeapAlloc > peak {
							peak = after.HeapAlloc - before.HeapAlloc
						}
					}
					runtime.KeepAlive(x)
					runtime.KeepAlive(y)
				}
				u50, u95 := quantiles(samples[0])
				a50, a95 := quantiles(samples[1])
				b50, b95 := quantiles(samples[2])
				o50, o95 := quantiles(samples[3])
				t.Logf("ROUTING_BENCH mode=%s K=%d r=%d workers=%d warmup=2 measured=10 user=%.6f/%.6f cs0=%.6f/%.6f cs1=%.6f/%.6f opening=%.6f/%.6f p50/p95_ms user_each=%d server_total=%d state_both=%d heap_increment=%d", mode, k, nr, w, u50, u95, a50, a95, b50, b95, o50, o95, r.TokenBytes(nr), 2*(r.OpeningHeaderBytes+2*k*nr), 2*(uint64(unsafe.Sizeof(r.RoutedCandidates{}))+uint64(8*k+8*nr)+uint64(unsafe.Sizeof(r.Route{}))*uint64(k*nr)), peak)
			}
		}
	}
}
