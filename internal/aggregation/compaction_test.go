package aggregation

import (
	"fmt"
	"os"
	"pmeq/internal/domain"
	"pmeq/internal/preprocess"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/gtank/ristretto255"
)

type compactMeasurement struct {
	Stage1, Stage2, Opening, Extraction time.Duration
	Heap                                uint64
}

func compactRun(t *testing.T, a, b CandidateInput) (CompactedCandidates, CompactedCandidates, []domain.Bit, compactMeasurement) {
	t.Helper()
	p, q, e := PreprocessCompaction(a.LayoutID, len(a.Payload))
	must(t, e)
	return compactPrepared(t, p, q, a, b)
}
func compactPrepared(t *testing.T, p *Compaction0, q *Compaction1, a, b CandidateInput) (CompactedCandidates, CompactedCandidates, []domain.Bit, compactMeasurement) {
	t.Helper()
	var m compactMeasurement
	sampleHeap := func() {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		if mem.HeapAlloc > m.Heap {
			m.Heap = mem.HeapAlloc
		}
	}
	st := time.Now()
	d, e := q.Begin(b)
	must(t, e)
	must(t, p.Stage1(a, d))
	m.Stage1 = time.Since(st)
	sampleHeap()
	st = time.Now()
	v, e := p.BeginStage2()
	must(t, e)
	must(t, q.Stage2(v))
	m.Stage2 = time.Since(st)
	sampleHeap()
	st = time.Now()
	o, e := p.OpenKeep()
	must(t, e)
	w, e := q.OpenKeep()
	must(t, e)
	pattern := make([]domain.Bit, len(o.bits))
	for i := range pattern {
		pattern[i] = o.bits[i].Add(w.bits[i])
	}
	m.Opening = time.Since(st)
	sampleHeap()
	st = time.Now()
	x, e := p.Extract(w)
	must(t, e)
	y, e := q.Extract(o)
	must(t, e)
	m.Extraction = time.Since(st)
	sampleHeap()
	if p.state.shuffled != nil || q.state.shuffled != nil {
		t.Fatal("retained N-sized output")
	}
	if _, e = p.Extract(w); e == nil {
		t.Fatal("reused extraction")
	}
	return x, y, pattern, m
}
func testCompactInput(t *testing.T, n, k int) (CandidateInput, CandidateInput) {
	a, b := CandidateInput{LayoutID: [16]byte{6}, KeepShare: make([]share.BitShare, n), Payload: make([]PayloadShare, n)}, CandidateInput{LayoutID: [16]byte{6}, KeepShare: make([]share.BitShare, n), Payload: make([]PayloadShare, n)}
	for i := range a.Payload {
		var e error
		a.KeepShare[i], b.KeepShare[i], e = preprocess.SplitBit(domain.Bit(i < k))
		must(t, e)
		// Include Ring64 wraparound and independent scalar/bucket values.
		a.Payload[i].RecordIDShare, b.Payload[i].RecordIDShare, e = preprocess.SplitRing64(domain.Ring64(^uint64(0) - uint64(i)))
		must(t, e)
		var raw [64]byte
		for j := range raw {
			raw[j] = byte(i >> (8 * (j % 8)))
		}
		sc, e := ristretto255.NewScalar().SetUniformBytes(raw[:])
		must(t, e)
		a.Payload[i].KappaJoinShare, b.Payload[i].KappaJoinShare, e = targetcrypto.SplitScalar(sc)
		must(t, e)
		a.Payload[i].BucketJoinShare, b.Payload[i].BucketJoinShare, e = targetcrypto.SplitBucketComponent(targetcrypto.BucketComponent(i*79), 16)
		must(t, e)
	}
	return a, b
}

type clearPayload struct {
	id     uint64
	scalar targetcrypto.ScalarShare
	bucket targetcrypto.BucketShare
}

func verifyCompaction(t *testing.T, a, b CandidateInput, x, y CompactedCandidates) {
	t.Helper()
	want := map[clearPayload]int{}
	for i, p := range a.Payload {
		if a.KeepShare[i].Value().Add(b.KeepShare[i].Value()) {
			q := b.Payload[i]
			s, e := targetcrypto.CombineScalarShare(p.KappaJoinShare, q.KappaJoinShare)
			must(t, e)
			want[clearPayload{uint64(p.RecordIDShare.Value() + q.RecordIDShare.Value()), s, p.BucketJoinShare ^ q.BucketJoinShare}]++
		}
	}
	if x.K != y.K || x.K != len(x.RecordIDShare) || x.K != len(x.KappaJoinShare) || x.K != len(x.BucketJoinShare) || x.K != len(y.RecordIDShare) || x.K != len(y.KappaJoinShare) || x.K != len(y.BucketJoinShare) || x.LayoutID != a.LayoutID || y.LayoutID != a.LayoutID || x.CompactionID != y.CompactionID {
		t.Fatal("output schema")
	}
	for i := 0; i < x.K; i++ {
		s, e := targetcrypto.CombineScalarShare(x.KappaJoinShare[i], y.KappaJoinShare[i])
		must(t, e)
		v := clearPayload{uint64(x.RecordIDShare[i].Value() + y.RecordIDShare[i].Value()), s, x.BucketJoinShare[i] ^ y.BucketJoinShare[i]}
		if want[v] == 0 {
			t.Fatal("extra/duplicate/wrong payload", v.id)
		}
		want[v]--
	}
	for _, v := range want {
		if v != 0 {
			t.Fatal("missing candidate")
		}
	}
}
func TestExactKCompaction(t *testing.T) {
	for _, n := range []int{0, 1, 127, CandidateCount} {
		ks := []int{0, n}
		if n > 1 {
			ks = append(ks, 1, 8, n/2, n-1)
		}
		for _, k := range ks {
			if k > n {
				continue
			}
			t.Run(fmt.Sprintf("N%dK%d", n, k), func(t *testing.T) {
				a, b := testCompactInput(t, n, k)
				x, y, pat, _ := compactRun(t, a, b)
				verifyCompaction(t, a, b, x, y)
				u, v, pat2, _ := compactRun(t, a, b)
				verifyCompaction(t, a, b, u, v)
				if x.K != k || u.K != k || x.CompactionID == u.CompactionID {
					t.Fatal("count/fresh ID")
				}
				if n == CandidateCount && k > 0 && k < n && reflect.DeepEqual(pat, pat2) {
					t.Fatal("same fresh support")
				}
				if n > 1 && k == n && reflect.DeepEqual(x.RecordIDShare, u.RecordIDShare) {
					t.Fatal("not refreshed")
				}
			})
		}
	}
}
func TestCompactionBindings(t *testing.T) {
	a, b := testCompactInput(t, 32, 8)
	p, q, e := PreprocessCompaction(a.LayoutID, 32)
	must(t, e)
	if _, e = p.OpenKeep(); e == nil {
		t.Fatal("early open")
	}
	bad := b
	bad.LayoutID[0]++
	if _, e = q.Begin(bad); e == nil {
		t.Fatal("layout")
	}
	bad = b
	bad.Payload = bad.Payload[:31]
	if _, e = q.Begin(bad); e == nil {
		t.Fatal("length")
	}
	d, e := q.Begin(b)
	must(t, e)
	copyQ := *q
	if _, e = copyQ.Begin(b); e == nil {
		t.Fatal("copy reuses packet")
	}
	other, _, e := PreprocessCompaction(a.LayoutID, 32)
	must(t, e)
	if e = other.Stage1(a, d); e == nil {
		t.Fatal("wrong query")
	}
	must(t, p.Stage1(a, d))
	if e = p.Stage1(a, d); e == nil {
		t.Fatal("reused stage1")
	}
	v, e := p.BeginStage2()
	must(t, e)
	must(t, q.Stage2(v))
	if e = q.Stage2(v); e == nil {
		t.Fatal("reused stage2")
	}
	o, e := p.OpenKeep()
	must(t, e)
	w, e := q.OpenKeep()
	must(t, e)
	if _, e = p.Extract(o); e == nil {
		t.Fatal("own opening")
	}
	x, e := p.Extract(w)
	must(t, e)
	y, e := q.Extract(o)
	must(t, e)
	verifyCompaction(t, a, b, x, y)
}
func TestCompactionBenchmark(t *testing.T) {
	if os.Getenv("PMEQ_COMPACTION_BENCH") != "1" {
		t.Skip("set PMEQ_COMPACTION_BENCH=1")
	}
	ks := []int{0, 1, 8, 64, 512}
	if s := os.Getenv("PMEQ_COMPACTION_KS"); s != "" {
		ks = splitInts(s)
	}
	seen := map[int]bool{}
	for _, k := range ks {
		if seen[k] {
			continue
		}
		seen[k] = true
		a, b := testCompactInput(t, CandidateCount, k)
		samples := make([][]float64, 4)
		var peak uint64
		for run := 0; run < 60; run++ {
			p, q, e := PreprocessCompaction(a.LayoutID, CandidateCount)
			must(t, e)
			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			x, y, _, m := compactPrepared(t, p, q, a, b)
			verifyCompaction(t, a, b, x, y)
			if run >= 10 {
				for j, d := range []time.Duration{m.Stage1, m.Stage2, m.Opening, m.Extraction} {
					samples[j] = append(samples[j], float64(d)/1e6)
				}
				if m.Heap > before.HeapAlloc && m.Heap-before.HeapAlloc > peak {
					peak = m.Heap - before.HeapAlloc
				}
			}
		}
		for _, s := range samples {
			sort.Float64s(s)
		}
		t.Logf("BENCH N=%d K=%d warmup=10 measured=50 stage1=%.6f/%.6f stage2=%.6f/%.6f open=%.6f/%.6f extract=%.6f/%.6f p50/p95_ms sampled_heap_increment=%d", CandidateCount, k, samples[0][24], samples[0][47], samples[1][24], samples[1][47], samples[2][24], samples[2][47], samples[3][24], samples[3][47], peak)
	}
}
func splitInts(s string) []int {
	var out []int
	for _, v := range strings.Split(s, ",") {
		k, e := strconv.Atoi(v)
		if e == nil {
			out = append(out, k)
		}
	}
	return out
}

func TestCompactionAccounting(t *testing.T) {
	n := uint64(CandidateCount)
	t.Logf("N=%d tuple_size=%d offline_logical=%d permutation_bytes=%d stage1=%d stage2=%d keep_open=%d output_both=84*K prep_backing=%d conservative_temporary_backing=%d", n, unsafe.Sizeof(compactTuple{}), 266*n, 8*n, 43*n, 43*n, 2*n, (6*uint64(unsafe.Sizeof(compactTuple{}))+8)*n, (10*uint64(unsafe.Sizeof(compactTuple{}))+11)*n)
	a, b := testCompactInput(t, 32, 8)
	p, q, e := PreprocessCompaction(a.LayoutID, 32)
	must(t, e)
	pool0, pool1 := NewPartyPool(a.LayoutID, PoolConfig{1}), NewPartyPool(a.LayoutID, PoolConfig{1})
	must(t, pool0.Provision(PacketID(p.ID())))
	must(t, pool1.Provision(PacketID(q.ID())))
	pool0.Seal()
	pool1.Seal()
	must(t, pool0.Consume(PacketID(p.ID())))
	must(t, pool1.Consume(PacketID(q.ID())))
	x, y, _, _ := compactPrepared(t, p, q, a, b)
	verifyCompaction(t, a, b, x, y)
	if e = pool0.Consume(PacketID(p.ID())); e == nil {
		t.Fatal("pool replay")
	}
}
