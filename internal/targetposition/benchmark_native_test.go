//go:build phase6native

package targetposition

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpnative"
	"pmeq/internal/targetartifact"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetquery"
	"pmeq/internal/targetrouting"
	"runtime"
	"sort"
	"testing"
	"time"
)

type positionFixture struct {
	S          int
	idx        [2]*targetpe.PartyIndex
	matches    [2]targetpe.TargetGroupMatches
	tokens     [2]targetrouting.QueryToken
	capacities []int
	tau        uint32
}

func positionFixtures(t *testing.T) []positionFixture { return positionFixturesAt(t, false) }
func positionFixturesAt(t *testing.T, targetOnly bool) []positionFixture {
	idx := loadIndexes(t)
	dir := "../../artifacts/phase7b"
	f, e := os.Open(filepath.Join(dir, "manifest.json"))
	must(t, e)
	manifest, e := indexbuild.ReadTargetManifest(f)
	must(t, e)
	f.Close()
	var payload [2]aggregation.PartyPayload
	for u := 0; u < 2; u++ {
		name := "cs0"
		if u == 1 {
			name = "cs1"
		}
		f, e = os.Open(filepath.Join(dir, name+".payload.bin"))
		must(t, e)
		payload[u], e = targetartifact.ReadPayload(f, manifest, uint8(u), idx[u].Lineage().LayoutID, uint32(idx[u].Lineage().N))
		must(t, e)
		f.Close()
	}
	byID := map[uint64]int{}
	for i, s := range payload[0].Slots {
		byID[uint64(s.RecordIDShare.Value()+payload[1].Slots[i].RecordIDShare.Value())] = i
	}
	f, e = os.Open("../../results/phase7b-workload.jsonl.gz")
	must(t, e)
	z, e := gzip.NewReader(f)
	must(t, e)
	scanner := bufio.NewScanner(z)
	scanner.Buffer(make([]byte, 65536), 4<<20)
	type query struct {
		Target       string
		Joins        []uint64
		CompactionID [16]byte
		Tau          uint32
	}
	var qs []query
	for scanner.Scan() {
		var q query
		must(t, json.Unmarshal(scanner.Bytes(), &q))
		qs = append(qs, q)
	}
	must(t, scanner.Err())
	z.Close()
	f.Close()
	f, e = os.Open("../../results/phase7b-loads.json.gz")
	must(t, e)
	z, e = gzip.NewReader(f)
	must(t, e)
	var loads []struct {
		Bits    int
		Queries []struct{ TouchedSlots int }
	}
	must(t, json.NewDecoder(z).Decode(&loads))
	f.Close()
	var counts []int
	for _, l := range loads {
		if l.Bits == 16 {
			for _, q := range l.Queries {
				counts = append(counts, q.TouchedSlots)
			}
		}
	}
	sorted := []int{}
	for i, n := range counts {
		if !targetOnly || int(qs[i].Tau) < len([]rune(qs[i].Target))/4 {
			sorted = append(sorted, n)
		}
	}
	sort.Ints(sorted)
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(255 - i)
	}
	key, e := targetcrypto.NewMasterKey(raw)
	must(t, e)
	var out []positionFixture
	percentiles := []int{50, 95, 99, 100}
	if targetOnly {
		percentiles = append(percentiles, -1)
	}
	for _, percent := range percentiles {
		want := 0
		if percent < 0 {
			sum := 0
			for _, v := range sorted {
				sum += v
			}
			want = sorted[0]
			distance := func(v int) int64 {
				d := int64(v)*int64(len(sorted)) - int64(sum)
				if d < 0 {
					return -d
				}
				return d
			}
			for _, v := range sorted {
				if distance(v) < distance(want) {
					want = v
				}
			}
		} else {
			want = sorted[(len(sorted)*percent+99)/100-1]
		}
		qi := 0
		for counts[qi] != want || (targetOnly && int(qs[qi].Tau) >= len([]rune(qs[qi].Target))/4) {
			qi++
		}
		q := qs[qi]
		var c [2]targetrouting.Candidates
		for u := 0; u < 2; u++ {
			c[u] = targetrouting.Candidates{LayoutID: idx[u].Lineage().LayoutID, CompactionID: q.CompactionID, TargetBucketBits: 16, K: len(q.Joins)}
			for _, id := range q.Joins {
				s := payload[u].Slots[byID[id]]
				c[u].RecordIDShare = append(c[u].RecordIDShare, s.RecordIDShare)
				c[u].KappaJoinShare = append(c[u].KappaJoinShare, s.KappaJoinShare)
				c[u].BucketJoinShare = append(c[u].BucketJoinShare, s.BucketJoinShare)
			}
		}
		a, b, e := targetquery.GenerateTokens(idx[0].Manifest(), key, q.Target)
		must(t, e)
		u, ma, e := targetrouting.Prepare(idx[0].Manifest(), 0, c[0], a, 1)
		must(t, e)
		v, mb, e := targetrouting.Prepare(idx[1].Manifest(), 1, c[1], b, 1)
		must(t, e)
		r0, e := u.Finish(mb)
		must(t, e)
		r1, e := v.Finish(ma)
		must(t, e)
		g, s := 0, 0
		cap := make([]int, len(a.Words))
		for _, r := range r0.Routes {
			gs := idx[0].PositionGroups(r.BucketID)
			g += len(gs)
			for _, group := range gs {
				s += int(group.PadWidth)
				cap[r.OccurrenceID] += int(group.PadWidth)
			}
		}
		if s != want {
			t.Fatal("representative S")
		}
		p0, p1, e := targetpe.Preprocess(idx[0].Lineage(), g)
		must(t, e)
		x, e := idx[0].Begin(r0, p0, 1)
		must(t, e)
		y, e := idx[1].Begin(r1, p1, 1)
		must(t, e)
		if g > 0 {
			for i := 0; i < 8; i++ {
				m, e := x.Next()
				must(t, e)
				n, e := y.Next()
				must(t, e)
				must(t, x.Accept(n))
				must(t, y.Accept(m))
			}
		}
		o, e := x.Output()
		must(t, e)
		p, e := y.Output()
		must(t, e)
		out = append(out, positionFixture{s, idx, [2]targetpe.TargetGroupMatches{o, p}, [2]targetrouting.QueryToken{a, b}, cap, q.Tau})
	}
	return out
}
func TestPositionNativeBenchmarks(t *testing.T) {
	if os.Getenv("PMEQ_POSITION_BENCH") != "1" {
		t.Skip("set PMEQ_POSITION_BENCH=1; real LLAMA only")
	}
	for _, f := range positionFixtures(t) {
		warm, measured := 10, 50
		if f.S > 500000 {
			warm, measured = 5, 20
		}
		var samples [7][]float64
		var peak uint64
		var offline OfflineBytes
		var framing uint64
		for trial := 0; trial < warm+measured; trial++ {
			users, p0, p1, n, e := Preprocess(f.idx[0].Lineage(), f.capacities, scmpnative.Backend{})
			must(t, e)
			offline = n
			a, b := f.tokens[0], f.tokens[1]
			a.Position = make([]anchorfilter.PositionToken, len(users))
			b.Position = make([]anchorfilter.PositionToken, len(users))
			for h := range users {
				pid, l, r, e := users[h].ConsumeBounds(uint32(4*h), f.tau, 62)
				must(t, e)
				a.Position[h] = anchorfilter.PositionToken{PID: pid, Ltilde: l, RplusTilde: r}
				b.Position[h] = a.Position[h]
			}
			runtime.GC()
			var base, now runtime.MemStats
			runtime.ReadMemStats(&base)
			sampleHeap := func() {
				runtime.ReadMemStats(&now)
				if now.HeapAlloc > base.HeapAlloc {
					peak = max(peak, now.HeapAlloc-base.HeapAlloc)
				}
			}
			x, e := Begin(f.idx[0], f.matches[0], a, p0, scmpnative.Backend{})
			must(t, e)
			y, e := Begin(f.idx[1], f.matches[1], b, p1, scmpnative.Backend{})
			must(t, e)
			sampleHeap()
			rounds := 0
			for !x.Done() {
				m, e := x.Next()
				must(t, e)
				n, e := y.Next()
				must(t, e)
				must(t, x.Accept(n))
				must(t, y.Accept(m))
				rounds++
				if rounds%1024 == 0 {
					sampleHeap()
				}
			}
			o, e := x.Output()
			must(t, e)
			p, e := y.Output()
			must(t, e)
			if len(o.HitShares) != f.S || len(p.HitShares) != f.S {
				t.Fatal("benchmark output")
			}
			sampleHeap()
			m, nm := x.Metrics(), y.Metrics()
			framing = m.FramingBytes + nm.FramingBytes
			if m.SCMPBytes+nm.SCMPBytes != uint64(16*f.S) || m.ANDBytes+nm.ANDBytes != uint64(8*f.S) {
				t.Fatal("benchmark codec")
			}
			values := []time.Duration{m.Expansion + nm.Expansion, m.Comparison + nm.Comparison, m.Correction + nm.Correction, m.MatchAND + nm.MatchAND, m.ValidityAND + nm.ValidityAND, m.Output + nm.Output}
			var total time.Duration
			for i, d := range values {
				total += d
				if trial >= warm {
					samples[i] = append(samples[i], float64(d)/1e6)
				}
			}
			if trial >= warm {
				samples[6] = append(samples[6], float64(total)/1e6)
			}
		}
		var med, hi [7]float64
		for i := range samples {
			sort.Float64s(samples[i])
			med[i] = samples[i][(len(samples[i])*50+99)/100-1]
			hi[i] = samples[i][(len(samples[i])*95+99)/100-1]
		}
		status, e := os.ReadFile("/proc/self/status")
		must(t, e)
		t.Logf("POSITION_BENCH S=%d warmup=%d measured=%d p50_ms=%v p95_ms=%v scmp_offline_party=%d beaver_offline_party=%d online_scmp=%d online_and=%d framing=%d heap_delta=%d", f.S, warm, measured, med, hi, offline.SCMP, offline.Beaver, 16*f.S, 8*f.S, framing, peak)
		for _, line := range bytesLines(status) {
			if len(line) > 6 && (string(line[:6]) == "VmRSS:" || string(line[:6]) == "VmHWM:") {
				t.Logf("POSITION_MEMORY S=%d %s", f.S, line)
			}
		}
	}
}
func bytesLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, v := range b {
		if v == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	return out
}
