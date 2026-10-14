//go:build phase6native

// Independent timing harness: all cryptographic generation uses production APIs.
package offlinegeneration_test

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"pmeq/internal/discovery"
	"pmeq/internal/domain"
	"pmeq/internal/dpf128"
	"pmeq/internal/dpf128/codec"
	"pmeq/internal/dpf128/gen"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpnative"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
)

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func root() string { return os.Getenv("PMEQ_OFFLINE_ROOT") }
func out() string  { return os.Getenv("PMEQ_OFFLINE_OUTPUT") }
func readJSON(t *testing.T, path string, x any) {
	b, e := os.ReadFile(filepath.Join(root(), path))
	must(t, e)
	must(t, json.Unmarshal(b, x))
}
func exclusive(t *testing.T, path string) *os.File {
	f, e := os.OpenFile(filepath.Join(out(), path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(t, e)
	return f
}
func save(t *testing.T, path string, x any) {
	f := exclusive(t, path)
	defer f.Close()
	must(t, json.NewEncoder(f).Encode(x))
}

type traceRow struct {
	Query          int
	Anchor, Target string
	Tau            int
	Joins          []uint64
}
type queryRow struct {
	Query    int
	Rejected bool
	Pairs    int
	Metrics  discovery.Metrics
	Offline  discovery.OfflineBytes
}
type shape struct {
	Query                            int
	N, K, R                          int
	AnchorT, AnchorD, TargetCapacity []int
	Count                            int
	Level                            string
}

// Read-only workload census. No Build, index shares, auxiliary state, or query execution.
func TestOfflineGenerationShapes(t *testing.T) {
	if out() == "" {
		t.Skip("opt-in")
	}
	var rows []queryRow
	readJSON(t, "results/timing-calibration-20260920/run-1/work/results/phase11-queries.json", &rows)
	f, e := os.Open(filepath.Join(root(), "results/phase7b-workload.jsonl.gz"))
	must(t, e)
	defer f.Close()
	z, e := gzip.NewReader(f)
	must(t, e)
	defer z.Close()
	dec := json.NewDecoder(z)
	traces := map[int]traceRow{}
	for dec.More() {
		var q traceRow
		must(t, dec.Decode(&q))
		traces[q.Query] = q
	}
	var kb, kt [32]byte
	for i := range kb {
		kb[i] = byte(i + 1)
		kt[i] = byte(255 - i)
	}
	key, e := anchorindex.NewKey(kb)
	must(t, e)
	targetkey, e := targetcrypto.NewMasterKey(kt)
	must(t, e)
	needed := map[uint32]bool{}
	qb := map[int][]uint32{}
	for _, r := range rows {
		if r.Rejected {
			continue
		}
		for _, c := range anchorfilter.QueryChunks(traces[r.Query].Anchor) {
			v, e := anchorindex.Encode(key, c.QGram)
			must(t, e)
			b, e := indexbuild.AnchorBucket(v, 16)
			must(t, e)
			needed[b] = true
			qb[r.Query] = append(qb[r.Query], b)
		}
	}
	a, e := os.Open(os.Getenv("PMEQ_OFFLINE_AREA"))
	must(t, e)
	defer a.Close()
	areas, e := indexbuild.LoadArea(a, 0)
	must(t, e)
	if len(areas) != 120071 {
		t.Fatal("N")
	}
	groups := map[anchorindex.Value]int{}
	ids := map[uint32]map[uint64]bool{}
	for _, r := range areas {
		indexbuild.VisitQGrams(r.Name, func(q string, _ uint32) {
			v, e := anchorindex.Encode(key, q)
			must(t, e)
			b, e := indexbuild.AnchorBucket(v, 16)
			must(t, e)
			if !needed[b] {
				return
			}
			groups[v]++
			if ids[b] == nil {
				ids[b] = map[uint64]bool{}
			}
			ids[b][r.ID] = true
		})
	}
	ts := map[uint32]int{}
	ds := map[uint32]int{}
	for v, n := range groups {
		b, e := indexbuild.AnchorBucket(v, 16)
		must(t, e)
		w, e := indexbuild.TierWidth(n)
		must(t, e)
		ts[b] += w
	}
	for b, m := range ids {
		d, e := incidence.RecordCapacity(len(m))
		must(t, e)
		ds[b] = d
	}
	// Final bits16 public bucket metadata only. All other historical layouts ignored.
	lf, e := os.Open(filepath.Join(root(), "results/phase7b-layouts.json.gz"))
	must(t, e)
	defer lf.Close()
	lg, e := gzip.NewReader(lf)
	must(t, e)
	defer lg.Close()
	var layouts []struct {
		Bits    int
		Buckets []struct {
			ID            uint32
			Groups, Slots int
		}
	}
	must(t, json.NewDecoder(lg).Decode(&layouts))
	slots := map[uint32]int{}
	ng := map[uint32]int{}
	for _, l := range layouts {
		if l.Bits != 16 {
			continue
		}
		for _, b := range l.Buckets {
			slots[b.ID] = b.Slots
			ng[b.ID] = b.Groups
		}
	}
	if len(slots) != 65536 {
		t.Fatal("final metadata shape")
	}
	all := []shape{}
	for _, r := range rows {
		if r.Rejected {
			continue
		}
		q := traces[r.Query]
		words := anchorfilter.QueryChunks(q.Target)
		s := shape{Query: q.Query, N: 120071, K: r.Metrics.K, R: len(words)}
		ta, sd, pdt := 0, 0, 0
		for _, b := range qb[q.Query] {
			s.AnchorT = append(s.AnchorT, ts[b])
			s.AnchorD = append(s.AnchorD, ds[b])
			ta += ts[b]
			sd += ds[b]
			pdt += ts[b] * ds[b]
		}
		if uint64(1168*ta) != r.Offline.AnchorPosition {
			t.Fatal("Anchor T does not reproduce recorded volume", q.Query)
		}
		// Current Provision: Hit B2A6T + vector triples(2T+4DT) + F comparison572D + z B2A6D + alignment6Nr + Keep572N.
		expected := uint64(8*ta + 4*pdt + 578*sd + 6*s.N*len(s.AnchorT) + 572*s.N)
		if expected != r.Offline.AnchorAggregation {
			t.Fatal("Anchor D does not reproduce recorded volume", q.Query, expected, r.Offline.AnchorAggregation)
		}
		s.TargetCapacity = make([]int, len(words))
		total, gcount := 0, 0
		for _, join := range q.Joins {
			j, e := targetcrypto.JoinBucketComponent(targetkey, join, 16)
			must(t, e)
			for h, w := range words {
				v, e := targetcrypto.WordBucketComponent(targetkey, w.QGram, 16)
				must(t, e)
				b := uint32(j) ^ uint32(v)
				s.TargetCapacity[h] += slots[b]
				total += slots[b]
				gcount += ng[b]
			}
		}
		if len(q.Joins) != s.K || total != r.Metrics.Slots || gcount != r.Metrics.Groups || uint64(1168*total) != r.Offline.TargetPosition {
			t.Fatal("Target capacity census mismatch", q.Query)
		}
		s.Count = 2*ta + sd + s.N + 2*total + 26*s.K*(s.R+1)
		all = append(all, s)
	}
	if len(all) != 854 {
		t.Fatal("query count")
	}
	save(t, "scmp-query-shapes.json", all)
	sort.Slice(all, func(i, j int) bool {
		if all[i].Count == all[j].Count {
			return all[i].Query < all[j].Query
		}
		return all[i].Count < all[j].Count
	})
	selected := []shape{}
	for j, p := range []float64{.5, .95, 1} {
		pos := float64(len(all)-1) * p
		i := int(pos)
		fraction := pos - float64(i)
		if fraction > .5 {
			i++
		}
		s := all[i]
		s.Level = []string{"median", "p95", "max"}[j]
		selected = append(selected, s)
	}
	save(t, "scmp-representatives.json", selected)
	t.Logf("SCMP census verified all854; selected=%+v", selected)
}

// Boundaries-only memory readings, outside timing. No sampling goroutine.
func mem() (heap, rss uint64) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	b, _ := os.ReadFile("/proc/self/statm")
	x := strings.Fields(string(b))
	if len(x) > 1 {
		p, _ := strconv.ParseUint(x[1], 10, 64)
		rss = p * uint64(os.Getpagesize())
	}
	return m.HeapAlloc, rss
}
func resourceGuard(t *testing.T, d time.Duration) {
	b, e := os.ReadFile("/proc/meminfo")
	must(t, e)
	for _, l := range strings.Split(string(b), "\n") {
		x := strings.Fields(l)
		if len(x) > 1 && x[0] == "MemAvailable:" {
			n, _ := strconv.ParseUint(x[1], 10, 64)
			if n < 2*1024*1024 {
				t.Fatal("resource stop: less than2GiB MemAvailable")
			}
		}
	}
	if d > 60*time.Second {
		t.Fatal("resource stop: single generation exceeds60s")
	}
}

type sample struct {
	Kind, Level, Phase                                                                         string
	Iteration, N, Count                                                                        int
	Nanoseconds                                                                                int64
	CS0Bytes, CS1Bytes, UserBytes, MaterialBytes, MetadataBytes, HeapAfterBytes, RSSAfterBytes uint64
	SpotCheck                                                                                  bool
}

func runFile(t *testing.T, kind, level string) *os.File {
	return exclusive(t, kind+"-"+level+"-raw.jsonl")
}
func emit(t *testing.T, f *os.File, s sample) {
	must(t, json.NewEncoder(f).Encode(s))
	must(t, f.Sync())
	if s.Iteration%5 == 0 || s.Phase == "pilot" {
		t.Logf("%s/%s %s iteration=%d time=%s bytes=%d heap_after=%d rss_after=%d", s.Kind, s.Level, s.Phase, s.Iteration, time.Duration(s.Nanoseconds), s.MaterialBytes, s.HeapAfterBytes, s.RSSAfterBytes)
	}
}
func choose(t *testing.T, n int) int {
	var b [2]byte
	_, e := rand.Read(b[:])
	must(t, e)
	return (int(b[0])*256 + int(b[1])) % n
}

func TestOfflineDPFGeneration(t *testing.T) {
	if out() == "" {
		t.Skip("opt-in")
	}
	f := runFile(t, "dpf", "single")
	defer f.Close()
	pick := choose(t, 1000)
	for i := 0; i < 1100; i++ {
		var alpha dpf128.Point
		_, e := rand.Read(alpha[:])
		must(t, e)
		start := time.Now()
		a, b, e := gen.Gen(alpha)
		elapsed := time.Since(start)
		must(t, e)
		ab, bb := codec.EncodeKey(a), codec.EncodeKey(b)
		phase := "measured"
		if i < 100 {
			phase = "warmup"
		}
		check := i == 0 || i == 100 || i == 100+pick || i == 1099
		if check {
			aa, e := codec.DecodeKey(ab)
			must(t, e)
			bbb, e := codec.DecodeKey(bb)
			must(t, e)
			wrong := alpha
			wrong[15] ^= 1
			if !bool(dpf128.Eval(aa, alpha).Value().Add(dpf128.Eval(bbb, alpha).Value())) || bool(dpf128.Eval(aa, wrong).Value().Add(dpf128.Eval(bbb, wrong).Value())) {
				t.Fatal("DPF correctness")
			}
		}
		emit(t, f, sample{Kind: "dpf", Level: "single", Phase: phase, Iteration: i, N: 128, Count: 1, Nanoseconds: elapsed.Nanoseconds(), CS0Bytes: uint64(len(ab)), CS1Bytes: uint64(len(bb)), MaterialBytes: uint64(len(ab) + len(bb)), SpotCheck: check})
	}
}

type comparison struct {
	u    *aggregation.BoundMask
	a, b *aggregation.ComparisonParty
	n    int
}
type position struct {
	u    anchorfilter.UserPreprocessing
	a, b anchorfilter.PartyPreprocessing
	n    int
}
type material struct {
	comp []comparison
	pos  []position
}

func makeComp(n int) (comparison, error) {
	u, a, b, e := aggregation.PreprocessComparison(n, scmpnative.Backend{})
	return comparison{u, a, b, n}, e
}
func generateMaterial(s shape, single bool) (material, error) {
	m := material{}
	if single {
		c, e := makeComp(1)
		m.comp = append(m.comp, c)
		return m, e
	}
	for i, n := range s.AnchorT {
		u, a, b, e := anchorfilter.Preprocess(n, 7, scmpnative.Backend{})
		if e != nil {
			return m, e
		}
		m.pos = append(m.pos, position{u, a, b, n})
		c, e := makeComp(s.AnchorD[i])
		if e != nil {
			return m, e
		}
		m.comp = append(m.comp, c)
	}
	c, e := makeComp(s.N)
	if e != nil {
		return m, e
	}
	m.comp = append(m.comp, c)
	for _, n := range s.TargetCapacity {
		u, a, b, e := anchorfilter.Preprocess(n, 7, scmpnative.Backend{})
		if e != nil {
			return m, e
		}
		m.pos = append(m.pos, position{u, a, b, n})
	}
	for _, n := range []int{26 * s.K * s.R, 26 * s.K} {
		c, e := makeComp(n)
		if e != nil {
			return m, e
		}
		m.comp = append(m.comp, c)
	}
	return m, nil
}
func compBody(p *aggregation.ComparisonParty) uint64 {
	v := reflect.ValueOf(p).Elem()
	keys := v.FieldByName("keys")
	n := uint64(v.FieldByName("masks").Len())
	for i := 0; i < keys.Len(); i++ {
		n += uint64(keys.Index(i).FieldByName("opaque").Len() + 1)
	}
	return n
}
func volumes(m material) (a, b, u, metadata uint64, count int) {
	for _, c := range m.comp {
		a += compBody(c.a)
		b += compBody(c.b)
		u++
		count += c.n
	}
	for _, p := range m.pos {
		for j, x := range []anchorfilter.PartyPreprocessing{p.a, p.b} {
			v := uint64(4 * (len(x.RhoL) + len(x.RhoR)))
			for i := range x.Lower {
				v += uint64(len(x.Lower[i].Opaque()) + len(x.Upper[i].Opaque()) + 2)
			}
			if j == 0 {
				a += v
			} else {
				b += v
			}
		}
		u += 8
		metadata += 48
		count += 2 * p.n
	}
	return
}
func checkMaterial(t *testing.T, m material) {
	backend := scmpnative.Backend{}
	// Production ComparisonParty APIs, at most one full group per generated material.
	for _, c := range m.comp {
		if c.n == 0 {
			continue
		}
		a, b := make([]incidence.Share, c.n), make([]incidence.Share, c.n)
		for i := range a {
			a[i] = incidence.NewShare(17)
			b[i] = incidence.NewShare(incidence.Z128(i%32 - 17))
		}
		bound, e := c.u.Mask(12)
		must(t, e)
		x, e := c.a.Prepare(a)
		must(t, e)
		y, e := c.b.Prepare(b)
		must(t, e)
		v, e := aggregation.OpenComparison(x, y)
		must(t, e)
		p, e := c.a.Finish(v, bound, backend)
		must(t, e)
		q, e := c.b.Finish(v, bound, backend)
		must(t, e)
		for i := range p {
			if bool(p[i].Value().Add(q[i].Value())) != (i%32 >= 12) {
				t.Fatal("SCMP aggregate correctness", i)
			}
		}
		break
	}
	// Few native evaluations per positional group, rb correction identical to EvalPosition.
	for _, p := range m.pos {
		if p.n == 0 {
			continue
		}
		for _, i := range []int{0, p.n / 2, p.n - 1} {
			for _, pair := range []struct {
				k0, k1      anchorfilter.SCMPKeyShare
				r0, r1, eta uint32
			}{{p.a.Lower[i], p.b.Lower[i], p.a.RhoL[i], p.b.RhoL[i], p.u.EtaL}, {p.a.Upper[i], p.b.Upper[i], p.a.RhoR[i], p.b.RhoR[i], p.u.EtaR}} {
				for _, v := range []uint32{0, 12, 31} {
					x := (v + pair.r0 + pair.r1) & 127
					y := (12 + pair.eta) & 127
					a, e := backend.Eval(0, pair.k0, x, y)
					must(t, e)
					b, e := backend.Eval(1, pair.k1, x, y)
					must(t, e)
					a = share.LocalSubBit(a, pair.k0.OutputMaskShare())
					b = share.LocalSubBit(b, pair.k1.OutputMaskShare())
					if bool(a.Value().Add(b.Value())) != (v >= 12) {
						t.Fatal("SCMP position correctness")
					}
				}
			}
		}
	}
}
func TestOfflineSCMPGeneration(t *testing.T) {
	if out() == "" {
		t.Skip("opt-in")
	}
	level := os.Getenv("PMEQ_OFFLINE_LEVEL")
	single := level == "single"
	s := shape{Count: 1, Level: level}
	warm, measured := 100, 1000
	if !single {
		var shapes []shape
		readJSON(t, strings.TrimPrefix(out(), root()+"/")+"/scmp-representatives.json", &shapes)
		found := false
		for _, v := range shapes {
			if v.Level == level {
				s = v
				found = true
			}
		}
		if !found {
			t.Fatal("unknown level")
		}
		warm, measured = 5, 30
	}
	f := runFile(t, "scmp", level)
	defer f.Close()
	pick := choose(t, measured)
	// Prime native once initialization before declared warmups; not a recorded trial.
	_, e := makeComp(0)
	must(t, e)
	for i := 0; i < warm+measured; i++ {
		if !single {
			runtime.GC()
		}
		start := time.Now()
		m, e := generateMaterial(s, single)
		elapsed := time.Since(start)
		must(t, e)
		heap, rss := mem()
		a, b, u, meta, count := volumes(m)
		if count != s.Count {
			t.Fatal("count")
		}
		check := i == 0 || i == warm || i == warm+pick || i == warm+measured-1
		if check {
			checkMaterial(t, m)
		}
		phase := "measured"
		if i < warm {
			phase = "warmup"
		}
		emit(t, f, sample{Kind: "scmp", Level: level, Phase: phase, Iteration: i, N: s.N, Count: count, Nanoseconds: elapsed.Nanoseconds(), CS0Bytes: a, CS1Bytes: b, UserBytes: u, MaterialBytes: a + b + u, MetadataBytes: meta, HeapAfterBytes: heap, RSSAfterBytes: rss, SpotCheck: check})
		runtime.KeepAlive(m)
		resourceGuard(t, elapsed)
	}
}

func compactBytes(p any) uint64 {
	v := reflect.ValueOf(p).Elem().FieldByName("state").Elem()
	total := uint64(v.FieldByName("perm").Len()) * uint64(v.FieldByName("perm").Type().Elem().Size())
	for _, name := range []string{"c", "t", "r"} {
		x := v.FieldByName(name)
		typ := x.Type().Elem()
		width := uintptr(0)
		for i := 0; i < typ.NumField(); i++ {
			width += typ.Field(i).Type.Size()
		}
		total += uint64(x.Len()) * uint64(width)
	}
	return total
}
func compactCheck(t *testing.T, p *aggregation.Compaction0, q *aggregation.Compaction1, n int, layout [16]byte) {
	a, b := aggregation.CandidateInput{LayoutID: layout, Payload: make([]aggregation.PayloadShare, n), KeepShare: make([]share.BitShare, n)}, aggregation.CandidateInput{LayoutID: layout, Payload: make([]aggregation.PayloadShare, n), KeepShare: make([]share.BitShare, n)}
	indices := map[int]bool{}
	for len(indices) < 7 {
		indices[chooseLarge(t, n)] = true
	}
	want := map[uint64]bool{}
	for i := 0; i < n; i++ {
		a.Payload[i].RecordIDShare = share.NewRing64Share(domain.Ring64(i + 1))
		a.Payload[i].BucketJoinShare = targetcrypto.BucketShare(i % 65536)
		a.KeepShare[i] = share.NewBitShare(domain.Bit(indices[i]))
		if indices[i] {
			want[uint64(i+1)] = true
		}
	}
	m, e := q.Begin(b)
	must(t, e)
	decoded, e := aggregation.DecodeShuffleForDomain(m.Encode(), n)
	must(t, e)
	must(t, p.Stage1(a, decoded))
	m, e = p.BeginStage2()
	must(t, e)
	decoded, e = aggregation.DecodeShuffleForDomain(m.Encode(), n)
	must(t, e)
	must(t, q.Stage2(decoded))
	o, e := p.OpenKeep()
	must(t, e)
	v, e := q.OpenKeep()
	must(t, e)
	oo, e := aggregation.DecodeKeepOpeningForDomain(o.Encode(), n)
	must(t, e)
	vv, e := aggregation.DecodeKeepOpeningForDomain(v.Encode(), n)
	must(t, e)
	x, e := p.Extract(vv)
	must(t, e)
	y, e := q.Extract(oo)
	must(t, e)
	if x.K != 7 || y.K != 7 {
		t.Fatal("compaction K")
	}
	for i := 0; i < 7; i++ {
		id := uint64(x.RecordIDShare[i].Value() + y.RecordIDShare[i].Value())
		sc, e := targetcrypto.CombineScalarShare(x.KappaJoinShare[i], y.KappaJoinShare[i])
		must(t, e)
		if !want[id] || sc != (targetcrypto.ScalarShare{}) || uint32(x.BucketJoinShare[i]^y.BucketJoinShare[i]) != uint32((id-1)%65536) {
			t.Fatal("compaction payload")
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatal("compaction missing")
	}
}
func chooseLarge(t *testing.T, n int) int {
	var b [4]byte
	_, e := rand.Read(b[:])
	must(t, e)
	return int((uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])) % uint64(n))
}
func TestOfflineExactPreprocessing(t *testing.T) {
	if out() == "" {
		t.Skip("opt-in")
	}
	n, e := strconv.Atoi(os.Getenv("PMEQ_OFFLINE_N"))
	must(t, e)
	warm, measured := 5, 30
	if n >= 500000 {
		warm, measured = 3, 20
	}
	phaseonly := os.Getenv("PMEQ_OFFLINE_PILOT") == "1"
	level := strconv.Itoa(n)
	if phaseonly {
		level += "-pilot"
		warm, measured = 0, 1
	}
	f := runFile(t, "exact", level)
	defer f.Close()
	layout := [16]byte{83}
	ids := map[[16]byte]bool{}
	pick := choose(t, measured)
	for i := 0; i < warm+measured; i++ {
		runtime.GC()
		start := time.Now()
		p, q, e := aggregation.PreprocessCompactionWithBucketBits(layout, n, 16)
		elapsed := time.Since(start)
		must(t, e)
		heap, rss := mem()
		a, b := compactBytes(p), compactBytes(q)
		if a+b != uint64(266*n) || p.ID() != q.ID() || ids[p.ID()] {
			t.Fatal("compaction fresh/volume")
		}
		ids[p.ID()] = true
		check := phaseonly || i == warm+pick
		phase := "measured"
		if i < warm {
			phase = "warmup"
		}
		if phaseonly {
			phase = "pilot"
		}
		// Record before spot check so resource/failure evidence survives. Correctness logged separately.
		emit(t, f, sample{Kind: "exact", Level: strconv.Itoa(n), Phase: phase, Iteration: i, N: n, Count: n, Nanoseconds: elapsed.Nanoseconds(), CS0Bytes: a, CS1Bytes: b, MaterialBytes: a + b, HeapAfterBytes: heap, RSSAfterBytes: rss, SpotCheck: check})
		resourceGuard(t, elapsed)
		if check {
			compactCheck(t, p, q, n, layout)
			t.Logf("correctness exact N=%d iteration=%d PASS (untimed)", n, i)
		}
		runtime.KeepAlive(p)
		runtime.KeepAlive(q)
	}
}

// Keep encoding/csv import for an explicit compile-time interface sanity check.
var _ = csv.NewWriter
var _ = fmt.Sprintf
