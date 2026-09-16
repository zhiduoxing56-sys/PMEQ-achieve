package indexbuild

// Trusted experiment coordinator. Plaintext provenance and reconstruction stay
// here; all online arithmetic uses the party-local incidence package.
import (
	"bytes"
	"math/rand"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	"pmeq/internal/anchorindex"
	"pmeq/internal/domain"
	"pmeq/internal/incidence"
	"pmeq/internal/share"
)

type incidenceBucket struct {
	id      uint16
	slots   []incidence.Posting
	m, d, g int
}
type incidenceMeasurement struct {
	b2a, ax time.Duration
	offline int
	wire    int
	peak    uint64
}

func incidenceBuckets(t *testing.T, areas []AreaRecord) []incidenceBucket {
	kb, kt := testKeys(t)
	groups, _, _, err := buildLogical(areas, nil, kb, kt, 14, 14)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].bucket != groups[j].bucket {
			return groups[i].bucket < groups[j].bucket
		}
		return bytes.Compare(groups[i].z[:], groups[j].z[:]) < 0
	})
	out := []incidenceBucket{}
	for _, g := range groups {
		if len(out) == 0 || out[len(out)-1].id != g.bucket {
			out = append(out, incidenceBucket{id: g.bucket})
		}
		b := &out[len(out)-1]
		b.g++
		w, e := TierWidth(len(g.postings))
		if e != nil {
			t.Fatal(e)
		}
		for _, p := range g.postings {
			b.slots = append(b.slots, incidence.Posting{RecordID: p.recordID, Real: true})
		}
		for i := len(g.postings); i < w; i++ {
			b.slots = append(b.slots, incidence.Posting{})
		}
	}
	for i := range out {
		ids := map[uint64]bool{}
		for _, s := range out[i].slots {
			if s.Real {
				ids[s.RecordID] = true
			}
		}
		out[i].m = len(ids)
		out[i].d, _ = incidence.RecordCapacity(len(ids))
	}
	return out
}

func runIncidence(t *testing.T, l incidence.DealerLayout, p, q *incidence.PartyMatrix, x []bool, chunk int, rng *rand.Rand, sampleHeap bool) incidenceMeasurement {
	t.Helper()
	must := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	n := len(x)
	bits := [2][]share.BitShare{make([]share.BitShare, n), make([]share.BitShare, n)}
	for i, v := range x {
		a := rng.Intn(2) == 1
		bits[0][i] = share.NewBitShare(domain.Bit(a))
		bits[1][i] = share.NewBitShare(domain.Bit(a != v))
	}
	u, v, e := incidence.Preprocess(n, 1)
	must(e)
	m := incidenceMeasurement{offline: 2 * u.StorageBytes(), wire: 4 * n}
	start := time.Now()
	s0, msg0, e := incidence.BeginB2A(bits[0], u)
	must(e)
	s1, msg1, e := incidence.BeginB2A(bits[1], v)
	must(e)
	opened, e := incidence.OpenMasked(msg0, msg1)
	must(e)
	a0, e := s0.Finish(opened)
	must(e)
	a1, e := s1.Finish(opened)
	must(e)
	m.b2a = time.Since(start)
	start = time.Now()
	g0, e := incidence.NewAggregator(0, p, chunk)
	must(e)
	g1, e := incidence.NewAggregator(1, q, chunk)
	must(e)
	m.ax += time.Since(start)
	for off := 0; off < n; off += chunk {
		end := min(n, off+chunk)
		tr0, tr1, e := incidence.Preprocess(end-off, l.D)
		must(e)
		m.offline += 2 * tr0.StorageBytes()
		m.wire += 2 * (end - off) * (1 + l.D)
		start = time.Now()
		msg0, e = g0.BeginChunk(a0[off:end], tr0)
		must(e)
		msg1, e = g1.BeginChunk(a1[off:end], tr1)
		must(e)
		opened, e = incidence.OpenMasked(msg0, msg1)
		must(e)
		must(g0.FinishChunk(opened))
		must(g1.FinishChunk(opened))
		m.ax += time.Since(start)
		if sampleHeap {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > m.peak {
				m.peak = ms.HeapAlloc
			}
		}
	}
	start = time.Now()
	f0, e := g0.Result()
	must(e)
	f1, e := g1.Result()
	must(e)
	m.ax += time.Since(start)
	want := make([]incidence.Z128, l.D)
	for s, j := range l.Coordinates {
		if j >= 0 && x[s] {
			want[j] = want[j].Add(1)
		}
	}
	for j, w := range want {
		if f0[j].Value().Add(f1[j].Value()) != w {
			t.Fatalf("F mismatch j=%d got=%d want=%d", j, f0[j].Value().Add(f1[j].Value()), w)
		}
	}
	return m
}

func TestFullIncidenceExperiment(t *testing.T) {
	if os.Getenv("PMEQ_INCIDENCE_EXPERIMENT") != "1" {
		t.Skip("set PMEQ_INCIDENCE_EXPERIMENT=1 for full workload/correctness/benchmark")
	}
	f, e := os.Open(realAreaPath)
	if e != nil {
		t.Fatal(e)
	}
	areas, stats, e := LoadAreaWithStats(f, 0)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	if stats.RawRows != 120071 || stats.QGramOccurrences != 906584 {
		t.Fatal("raw regression", stats)
	}
	bs := incidenceBuckets(t, areas)
	by := map[uint16]incidenceBucket{}
	total := 0
	for _, b := range bs {
		by[b.id] = b
		total += len(b.slots)
	}
	if total != 1961824 {
		t.Fatal("tier regression", total)
	}
	hot := append([]incidenceBucket{}, bs...)
	sort.Slice(hot, func(i, j int) bool {
		a, b := hot[i].d*len(hot[i].slots), hot[j].d*len(hot[j].slots)
		if a != b {
			return a > b
		}
		return hot[i].id < hot[j].id
	})
	top := map[uint16]bool{}
	for _, b := range hot[:10] {
		top[b.id] = true
	}
	kb, _ := testKeys(t)
	rs, ps, ws := []int{}, []int{}, []int{}
	freq := map[uint16]int{}
	anyTop := 0
	for _, a := range areas {
		runes := []rune(a.Name)
		chunks := len(runes) / Q
		if chunks == 0 {
			continue
		}
		p, w := 0, 0
		seen := map[uint16]bool{}
		for h := 0; h < chunks; h++ {
			z, e := anchorindex.Encode(kb, string(runes[h*Q:(h+1)*Q]))
			if e != nil {
				t.Fatal(e)
			}
			id, e := AnchorBucket(z, 14)
			if e != nil {
				t.Fatal(e)
			}
			b, ok := by[id]
			if !ok {
				t.Fatal("query bucket absent")
			}
			nt := len(b.slots)
			p += b.d * nt
			w += 2 * (nt + b.d*nt)
			seen[id] = true
		}
		found := false
		for id := range seen {
			freq[id]++
			if top[id] {
				found = true
			}
		}
		if found {
			anyTop++
		}
		rs = append(rs, chunks)
		ps = append(ps, p)
		ws = append(ws, w)
	}
	t.Logf("WORKLOAD queries=%d short_excluded=%d r=%+v products=%+v vector_wire=%+v bucket9963=%d top10_union=%d percent=%.6f", len(rs), stats.ShortNames, distribution(rs), distribution(ps), distribution(ws), freq[9963], anyTop, 100*float64(anyTop)/float64(len(rs)))
	for _, b := range hot[:10] {
		t.Logf("HOT id=%d T=%d M=%d D=%d P=%d queries=%d percent=%.6f", b.id, len(b.slots), b.m, b.d, b.d*len(b.slots), freq[b.id], 100*float64(freq[b.id])/float64(len(rs)))
	}
	// Select percentile buckets by physical-slot workload, breaking ties by ID.
	sort.Slice(bs, func(i, j int) bool {
		if len(bs[i].slots) != len(bs[j].slots) {
			return len(bs[i].slots) < len(bs[j].slots)
		}
		return bs[i].id < bs[j].id
	})
	selected := []incidenceBucket{}
	for _, pct := range []float64{.5, .95, .99} {
		selected = append(selected, bs[int(float64(len(bs)-1)*pct+0.999999999)])
	}
	for _, b := range bs {
		seen := map[uint64]bool{}
		dup := false
		for _, s := range b.slots {
			if s.Real {
				if seen[s.RecordID] {
					dup = true
				}
				seen[s.RecordID] = true
			}
		}
		if dup {
			selected = append(selected, b)
			break
		}
	}
	rng := rand.New(rand.NewSource(51015101))
	for i, b := range selected {
		l, e := incidence.PrepareLayout(b.slots)
		if e != nil {
			t.Fatal(e)
		}
		p, q, e := incidence.ShareIncidence(l)
		if e != nil {
			t.Fatal(e)
		}
		counts := map[uint64]int{}
		for _, s := range b.slots {
			if s.Real {
				counts[s.RecordID]++
			}
		}
		var repeated uint64
		for _, s := range b.slots {
			if s.Real && counts[s.RecordID] > 1 {
				repeated = s.RecordID
				break
			}
		}
		for trial := 0; trial < 1000; trial++ {
			x := make([]bool, len(b.slots))
			for s, slot := range b.slots {
				switch trial {
				case 0:
					x[s] = false
				case 1:
					x[s] = slot.Real
				case 2:
					x[s] = !slot.Real
				case 3:
					x[s] = true
				case 4:
					x[s] = slot.Real && slot.RecordID == repeated
				default:
					x[s] = rng.Intn(2) == 1
				}
			}
			runIncidence(t, l, p, q, x, 64, rng, false)
		}
		t.Logf("CORRECTNESS kind=%d id=%d T=%d M=%d D=%d trials=1000 errors=0", i, b.id, len(b.slots), b.m, b.d)
		if i == 3 {
			continue
		}
		for _, chunk := range []int{32, 64, 128, 256} {
			runtime.GC()
			var base runtime.MemStats
			runtime.ReadMemStats(&base)
			bt, at, tot := []int{}, []int{}, []int{}
			var peak uint64
			var last incidenceMeasurement
			for trial := 0; trial < 60; trial++ {
				x := make([]bool, len(b.slots))
				for s := range x {
					x[s] = rng.Intn(2) == 1
				}
				last = runIncidence(t, l, p, q, x, chunk, rng, true)
				if last.peak > peak {
					peak = last.peak
				}
				if trial >= 10 {
					bt = append(bt, int(last.b2a))
					at = append(at, int(last.ax))
					tot = append(tot, int(last.b2a+last.ax))
				}
			}
			t.Logf("BENCH kind=%d id=%d chunk=%d n=50 warmup=10 b2a_ns=%+v ax_ns=%+v total_ns=%+v static_bytes=%d offline_bytes=%d online_payload_bytes=%d openings=%d heap_base=%d heap_peak=%d heap_delta=%d", i, b.id, chunk, distribution(bt), distribution(at), distribution(tot), p.StorageBytes()+q.StorageBytes(), last.offline, last.wire, 1+(len(b.slots)+chunk-1)/chunk, base.HeapAlloc, peak, int64(peak)-int64(base.HeapAlloc))
		}
	}
	b := hot[0]
	nt, d := len(b.slots), b.d
	// Static shares plus O(chunk*D) work, no all-bucket query preprocessing.
	estimate := uint64(2*nt*d + 16*64*d + 32*nt + 32*d)
	t.Logf("HOT_ESTIMATE id=%d static=%d offline=%d online=%d working_bound=%d", b.id, 2*nt*d, 4*nt*d+8*nt, 2*nt*d+6*nt, estimate)
	if estimate > 12*(uint64(1)<<30) {
		t.Log("HOT skipped: >12 GiB")
		return
	}
	l, e := incidence.PrepareLayout(b.slots)
	if e != nil {
		t.Fatal(e)
	}
	p, q, e := incidence.ShareIncidence(l)
	if e != nil {
		t.Fatal(e)
	}
	runtime.GC()
	x := make([]bool, nt)
	for i := range x {
		x[i] = true
	}
	start := time.Now()
	m := runIncidence(t, l, p, q, x, 64, rng, true)
	t.Logf("HOT_MEASURED id=%d chunk=64 b2a=%s ax=%s online_sum=%s wall_including_preprocessing=%s heap_peak=%d errors=0", b.id, m.b2a, m.ax, m.b2a+m.ax, time.Since(start), m.peak)
}
