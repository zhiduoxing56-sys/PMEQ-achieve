package targetpe

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"pmeq/internal/targetartifact"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetquery"
	"pmeq/internal/targetrouting"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type benchmarkTrace struct {
	Target       string
	Joins        []uint64
	CompactionID [16]byte
}
type benchmarkFixture struct {
	G   int
	idx [2]*PartyIndex
	r   [2]targetrouting.RoutedCandidates
}

func benchmarkFixtures(t *testing.T) map[int]benchmarkFixture {
	t.Helper()
	dir := "../../artifacts/phase7b"
	mr, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	must(t, e)
	pr, e := os.ReadFile(filepath.Join(dir, "payload-manifest.json"))
	must(t, e)
	var pm PayloadManifest
	must(t, json.Unmarshal(pr, &pm))
	lineage := AlignmentLineage{pm.IndexID, pm.LayoutID, pm.N}
	var idx [2]*PartyIndex
	for u := 0; u < 2; u++ {
		name := "cs0"
		if u == 1 {
			name = "cs1"
		}
		f, e := os.Open(filepath.Join(dir, name+".psmj.bin"))
		must(t, e)
		p, e := os.Open(filepath.Join(dir, name+".payload.bin"))
		must(t, e)
		idx[u], e = Load(bytes.NewReader(mr), bytes.NewReader(pr), f, p, uint8(u), lineage)
		must(t, e)
		f.Close()
		p.Close()
	}
	m := idx[0].manifest
	f, e := os.Open(filepath.Join(dir, "cs0.payload.bin"))
	must(t, e)
	p0, e := targetartifact.ReadPayload(f, m, 0, pm.LayoutID, uint32(pm.N))
	must(t, e)
	f.Close()
	f, e = os.Open(filepath.Join(dir, "cs1.payload.bin"))
	must(t, e)
	p1, e := targetartifact.ReadPayload(f, m, 1, pm.LayoutID, uint32(pm.N))
	must(t, e)
	f.Close()
	byID := map[uint64]int{}
	for i, a := range p0.Slots {
		byID[uint64(a.RecordIDShare.Value()+p1.Slots[i].RecordIDShare.Value())] = i
	}
	f, e = os.Open("../../results/phase7b-workload.jsonl.gz")
	must(t, e)
	z, e := gzip.NewReader(f)
	must(t, e)
	scan := bufio.NewScanner(z)
	scan.Buffer(make([]byte, 65536), 4<<20)
	var qs []benchmarkTrace
	for scan.Scan() {
		var q benchmarkTrace
		must(t, json.Unmarshal(scan.Bytes(), &q))
		qs = append(qs, q)
	}
	must(t, scan.Err())
	f.Close()
	f, e = os.Open("../../results/phase7b-loads.json.gz")
	must(t, e)
	z, e = gzip.NewReader(f)
	must(t, e)
	var loads []struct {
		Bits    int
		Queries []struct{ GroupComparisons int }
	}
	must(t, json.NewDecoder(z).Decode(&loads))
	f.Close()
	var gs []int
	for _, l := range loads {
		if l.Bits == 16 {
			for _, q := range l.Queries {
				gs = append(gs, q.GroupComparisons)
			}
		}
	}
	var key [32]byte
	for i := range key {
		key[i] = byte(255 - i)
	}
	kt, e := targetcrypto.NewMasterKey(key)
	must(t, e)
	out := map[int]benchmarkFixture{}
	for _, g := range []int{1, 49, 1908, 5745, 50754, 180227} {
		qi := -1
		for i, v := range gs {
			if v == g {
				qi = i
				break
			}
		}
		if qi < 0 {
			t.Fatal("representative query absent", g)
		}
		q := qs[qi]
		var c [2]targetrouting.Candidates
		for u := 0; u < 2; u++ {
			c[u] = targetrouting.Candidates{LayoutID: pm.LayoutID, CompactionID: q.CompactionID, TargetBucketBits: 16, K: len(q.Joins)}
			for _, id := range q.Joins {
				at, ok := byID[id]
				if !ok {
					t.Fatal("candidate")
				}
				v := p0.Slots[at]
				if u == 1 {
					v = p1.Slots[at]
				}
				c[u].RecordIDShare = append(c[u].RecordIDShare, v.RecordIDShare)
				c[u].KappaJoinShare = append(c[u].KappaJoinShare, v.KappaJoinShare)
				c[u].BucketJoinShare = append(c[u].BucketJoinShare, v.BucketJoinShare)
			}
		}
		a, b, e := targetquery.GenerateTokens(idx[0].Manifest(), kt, q.Target)
		must(t, e)
		u, ma, e := targetrouting.Prepare(idx[0].Manifest(), 0, c[0], a, 16)
		must(t, e)
		v, mb, e := targetrouting.Prepare(idx[1].Manifest(), 1, c[1], b, 16)
		must(t, e)
		r0, e := u.Finish(mb)
		must(t, e)
		r1, e := v.Finish(ma)
		must(t, e)
		out[g] = benchmarkFixture{g, idx, [2]targetrouting.RoutedCandidates{r0, r1}}
	}
	return out
}
func TestPEBenchmarks(t *testing.T) {
	mode := os.Getenv("PMEQ_PE_BENCH")
	if mode == "" {
		t.Skip("explicit performance experiment")
	}
	fixtures := benchmarkFixtures(t)
	gs := []int{1, 49, 1908, 5745, 50754, 180227}
	workers := []int{RecommendedWorkers}
	if mode == "workers" {
		gs = []int{50754, 180227}
		workers = []int{1, 4, 8, 16}
	}
	for _, g := range gs {
		for _, worker := range workers {
			if mode == "small" && g >= 50754 {
				continue
			}
			if mode == "large" && g < 50754 {
				continue
			}
			fixture := fixtures[g]
			warm, measured := 10, 50
			if g == 180227 {
				warm, measured = 5, 20
			}
			type sample struct{ A, B, C, D, E float64 }
			var samples []sample
			var peak uint64
			var wire, frame uint64
			for trial := -warm; trial < measured; trial++ {
				p, q, e := Preprocess(fixture.idx[0].lineage, g)
				must(t, e)
				runtime.GC()
				var before runtime.MemStats
				runtime.ReadMemStats(&before)
				observe := func() {
					var m runtime.MemStats
					runtime.ReadMemStats(&m)
					if m.HeapAlloc > before.HeapAlloc && m.HeapAlloc-before.HeapAlloc > peak {
						peak = m.HeapAlloc - before.HeapAlloc
					}
				}
				a, e := fixture.idx[0].Begin(fixture.r[0], p, worker)
				must(t, e)
				b, e := fixture.idx[1].Begin(fixture.r[1], q, worker)
				must(t, e)
				observe()
				for round := 0; round < 8; round++ {
					m0, e := a.Next()
					must(t, e)
					m1, e := b.Next()
					must(t, e)
					observe()
					must(t, a.Accept(m1))
					must(t, b.Accept(m0))
					observe()
				}
				x, e := a.Output()
				must(t, e)
				y, e := b.Output()
				must(t, e)
				if len(x.MatchShares) != g || len(y.MatchShares) != g {
					t.Fatal("output")
				}
				observe()
				am, bm := a.Metrics(), b.Metrics()
				wire = am.PayloadBytes + bm.PayloadBytes
				frame = am.FramingBytes + bm.FramingBytes
				if wire != uint64(8160*Words(g)) || frame != 16*HeaderBytes {
					t.Fatal("wire")
				}
				if trial >= 0 {
					s := sample{A: float64(am.DifferenceEncoding+bm.DifferenceEncoding) / float64(time.Millisecond), B: float64(am.Compute+bm.Compute) / float64(time.Millisecond), C: float64(am.Messages+bm.Messages) / float64(time.Millisecond), D: float64(am.Output+bm.Output) / float64(time.Millisecond)}
					s.E = s.A + s.B + s.C + s.D
					samples = append(samples, s)
				}
			}
			vals := func(field func(sample) float64) []float64 {
				a := make([]float64, len(samples))
				for i, s := range samples {
					a[i] = field(s)
				}
				sort.Float64s(a)
				return []float64{a[(len(a)*50+99)/100-1], a[(len(a)*95+99)/100-1]}
			}
			status, e := os.ReadFile("/proc/self/status")
			must(t, e)
			rss, hwm := 0, 0
			for _, line := range strings.Split(string(status), "\n") {
				f := strings.Fields(line)
				if len(f) > 1 {
					if f[0] == "VmRSS:" {
						rss, _ = strconv.Atoi(f[1])
					}
					if f[0] == "VmHWM:" {
						hwm, _ = strconv.Atoi(f[1])
					}
				}
			}
			t.Logf("PE_MEMORY G=%d workers=%d rss_kib=%d hwm_kib=%d", g, worker, rss, hwm)
			t.Logf("PE_BENCH mode=%s G=%d W=%d workers=%d warmup=%d measured=%d A_ms=%v B_ms=%v C_ms=%v D_ms=%v E_ms=%v offline_each=%d online=%d framing=%d encoding_both=%d matches_both=%d heap_delta=%d", mode, g, Words(g), worker, warm, measured, vals(func(s sample) float64 { return s.A }), vals(func(s sample) float64 { return s.B }), vals(func(s sample) float64 { return s.C }), vals(func(s sample) float64 { return s.D }), vals(func(s sample) float64 { return s.E }), 6120*Words(g), wire, frame, 64*g, 2*g, peak)
		}
	}
}
