//go:build phase6native

package discovery_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"pmeq/internal/candidatequery"
	"pmeq/internal/discovery"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpnative"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetartifact"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetpe"
	"sort"
	"testing"
	"time"
)

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}

type workload struct {
	Query          int
	Anchor, Target string
	Tau            int
	Joins          []uint64
}
type reference struct {
	K, R, S, G, Pairs int
	Rejected          bool
}
type fixture struct {
	indexBuild time.Duration
	keys       discovery.UserKeys
	areas      []indexbuild.AreaRecord
	aliases    map[uint64][]indexbuild.AreaAliasRecord
	idx        [2]*targetpe.PartyIndex
	side       [2]*targetaggregation.PartySidecar
	payload    [2]aggregation.PartyPayload
	layout     *aggregation.DealerLayout
	anchor     [2]map[uint16]indexbuild.AnchorPartyBucket
	posts      map[uint16][]incidence.Posting
	trace      []workload
	ref        []reference
	static     map[string][2]uint64
}

const rawDir = "/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump"

func loadFixture(t *testing.T) *fixture {
	f := &fixture{aliases: map[uint64][]indexbuild.AreaAliasRecord{}, posts: map[uint16][]incidence.Posting{}, static: map[string][2]uint64{}}
	var kb, kt [32]byte
	for i := range kb {
		kb[i] = byte(i + 1)
		kt[i] = byte(255 - i)
	}
	var e error
	f.keys.Anchor, e = anchorindex.NewKey(kb)
	must(t, e)
	f.keys.Target, e = targetcrypto.NewMasterKey(kt)
	must(t, e)
	read := func(name string) []byte { b, e := os.ReadFile(name); must(t, e); return b }
	mr := read("../../artifacts/phase7b/manifest.json")
	pr := read("../../artifacts/phase7b/payload-manifest.json")
	var pm targetpe.PayloadManifest
	must(t, json.Unmarshal(pr, &pm))
	manifest, e := indexbuild.ReadTargetManifest(bytes.NewReader(mr))
	must(t, e)
	lineage := targetpe.AlignmentLineage{IndexID: pm.IndexID, LayoutID: pm.LayoutID, N: pm.N}
	var sm targetaggregation.SidecarManifest
	must(t, json.Unmarshal(read("../../artifacts/phase10b/manifest.json"), &sm))
	for u := 0; u < 2; u++ {
		name := []string{"cs0", "cs1"}[u]
		psmj, e := os.Open("../../artifacts/phase7b/" + name + ".psmj.bin")
		must(t, e)
		payload, e := os.Open("../../artifacts/phase7b/" + name + ".payload.bin")
		must(t, e)
		f.idx[u], e = targetpe.Load(bytes.NewReader(mr), bytes.NewReader(pr), psmj, payload, uint8(u), lineage)
		must(t, e)
		psmj.Close()
		payload.Close()
		payload, e = os.Open("../../artifacts/phase7b/" + name + ".payload.bin")
		must(t, e)
		f.payload[u], e = targetartifact.ReadPayload(payload, manifest, uint8(u), pm.LayoutID, uint32(pm.N))
		must(t, e)
		payload.Close()
		sc, e := os.Open("../../artifacts/phase10b/" + name + ".aggregation.bin")
		must(t, e)
		f.side[u], e = targetaggregation.LoadSidecar(sm, mr, f.idx[u], sc)
		must(t, e)
		sc.Close()
	}
	ids := make([]uint64, pm.N)
	for i := range ids {
		ids[i] = uint64(f.payload[0].Slots[i].RecordIDShare.Value() + f.payload[1].Slots[i].RecordIDShare.Value())
	}
	f.layout, e = aggregation.RestoreDealerLayout(pm.LayoutID, ids)
	must(t, e)
	a, e := os.Open(filepath.Join(rawDir, "area"))
	must(t, e)
	f.areas, e = indexbuild.LoadArea(a, 0)
	must(t, e)
	a.Close()
	a, e = os.Open(filepath.Join(rawDir, "area_alias"))
	must(t, e)
	aliases, e := indexbuild.LoadAreaAlias(a, 0)
	must(t, e)
	a.Close()
	for _, a := range aliases {
		f.aliases[a.Area] = append(f.aliases[a.Area], a)
	}
	// Trusted IndexOutsource setup, outside every online timer. Existing BSMJ
	// builder/math is reused unchanged; no Target index is rebuilt.
	indexStart := time.Now()
	_, a0, a1, stats, e := indexbuild.Build(f.areas, nil, f.keys.Anchor, f.keys.Target, 16, 16)
	must(t, e)
	f.indexBuild = time.Since(indexStart)
	f.anchor = [2]map[uint16]indexbuild.AnchorPartyBucket{{}, {}}
	byZ := map[anchorindex.Value][]incidence.Posting{}
	for _, a := range f.areas {
		indexbuild.VisitQGrams(a.Name, func(q string, _ uint32) {
			z, e := anchorindex.Encode(f.keys.Anchor, q)
			must(t, e)
			byZ[z] = append(byZ[z], incidence.Posting{RecordID: a.ID, Real: true})
		})
	}
	var incidenceBytes uint64
	for i, b := range a0.AnchorBuckets {
		f.anchor[0][b.BucketID] = b
		f.anchor[1][b.BucketID] = a1.AnchorBuckets[i]
		ids := map[uint64]bool{}
		for _, g := range b.Groups {
			p := byZ[g.Z]
			f.posts[b.BucketID] = append(f.posts[b.BucketID], p...)
			for _, p := range p {
				ids[p.RecordID] = true
			}
			for n := len(p); n < len(g.Slots); n++ {
				f.posts[b.BucketID] = append(f.posts[b.BucketID], incidence.Posting{})
			}
		}
		d, e := incidence.RecordCapacity(len(ids))
		must(t, e)
		incidenceBytes += uint64(d * len(f.posts[b.BucketID]))
	}
	bsmj := uint64(stats.Anchor.PaddedSlots*47 + stats.Anchor.LogicalGroups*20 + stats.Anchor.NonemptyBuckets*6)
	f.static["BSMJ semantic fields"] = [2]uint64{bsmj, bsmj}
	f.static["PSMJ sealed files"] = manifest.PartyBytes
	f.static["Anchor incidence full-domain fields"] = [2]uint64{incidenceBytes, incidenceBytes}
	f.static["Anchor alignment full-domain factors"] = [2]uint64{uint64(32 * stats.Anchor.NonemptyBuckets), uint64(4 * pm.N * stats.Anchor.NonemptyBuckets)}
	f.static["Target aggregation sealed files"] = sm.PartyBytes
	f.static["Global sealed payload files"] = [2]uint64{5043028, 5043028}
	in, e := os.Open("../../results/phase7b-workload.jsonl.gz")
	must(t, e)
	gz, e := gzip.NewReader(in)
	must(t, e)
	scanner := bufio.NewScanner(gz)
	scanner.Buffer(make([]byte, 65536), 4<<20)
	for scanner.Scan() {
		var q workload
		must(t, json.Unmarshal(scanner.Bytes(), &q))
		f.trace = append(f.trace, q)
	}
	must(t, scanner.Err())
	gz.Close()
	in.Close()
	must(t, json.Unmarshal(read("../../results/phase10b-queries.json"), &f.ref))
	if len(f.trace) != 1003 || len(f.ref) != 1003 {
		t.Fatal("trace sizes")
	}
	return f
}
func (f *fixture) prepareStatic(t *testing.T, q workload) ([2]*discovery.Static, []uint16) {
	buckets := []uint16{}
	as := [2]map[uint16]discovery.AnchorStatic{{}, {}}
	for _, c := range anchorfilter.QueryChunks(q.Anchor) {
		z, e := anchorindex.Encode(f.keys.Anchor, c.QGram)
		must(t, e)
		id, e := indexbuild.AnchorBucket(z, 16)
		must(t, e)
		buckets = append(buckets, id)
		if _, ok := as[0][id]; ok {
			continue
		}
		posts := f.posts[id]
		local, e := incidence.PrepareLayout(posts)
		must(t, e)
		m0, m1, e := incidence.ShareIncidence(local)
		must(t, e)
		s0, s1, e := f.layout.Alignment(id, local, posts)
		must(t, e)
		b0, b1 := f.anchor[0][id], f.anchor[1][id]
		b0.BucketID = id
		b1.BucketID = id
		as[0][id] = discovery.AnchorStatic{Bucket: b0, Incidence: m0, Stage0: s0}
		as[1][id] = discovery.AnchorStatic{Bucket: b1, Incidence: m1, Stage1: s1}
	}
	var out [2]*discovery.Static
	for u := range out {
		var e error
		out[u], e = discovery.NewStatic(uint8(u), as[u], f.payload[u], f.idx[u], f.side[u])
		must(t, e)
	}
	return out, buckets
}
func (f *fixture) provision(t *testing.T, q workload, statics [2]*discovery.Static, buckets []uint16) (*discovery.UserPacket, [2]*discovery.PartyPacket, discovery.OfflineBytes) {
	// Saved PHASE10 public workload capacities are used only by this offline
	// reservation. They are not inputs to online Anchor Keep, routing or hits.
	words := anchorfilter.QueryChunks(q.Target)
	cap := make([]int, len(words))
	groups, slots := 0, 0
	for _, id := range q.Joins {
		j, e := targetcrypto.JoinBucketComponent(f.keys.Target, id, 16)
		must(t, e)
		for h, w := range words {
			b, e := targetcrypto.WordBucketComponent(f.keys.Target, w.QGram, 16)
			must(t, e)
			gs := f.idx[0].PositionGroups(uint16(j) ^ uint16(b))
			groups += len(gs)
			for _, g := range gs {
				cap[h] += int(g.PadWidth)
				slots += int(g.PadWidth)
			}
		}
	}
	r := f.ref[q.Query]
	if r.G != groups || r.S != slots {
		t.Fatal("offline public workload mismatch")
	}
	u, p0, p1, cost, e := discovery.Provision(statics[0], statics[1], buckets, cap, targetaggregation.Shape{K: r.K, R: len(words), S: slots, G: groups}, scmpnative.Backend{})
	must(t, e)
	return u, [2]*discovery.PartyPacket{p0, p1}, cost
}

// Independent plaintext oracle: raw strings only, no cloud intermediates.
func matches(name, q string, tau int) bool {
	cs := anchorfilter.QueryChunks(q)
	r := []rune(name)
	count := 0
	for _, c := range cs {
		for i := 0; i+4 <= len(r); i++ {
			delta := i - int(c.Position)
			if delta < 0 {
				delta = -delta
			}
			if delta <= tau && string(r[i:i+4]) == c.QGram {
				count++
				break
			}
		}
	}
	return count >= len(cs)-tau
}
func (f *fixture) oracle(q workload) map[candidatequery.Pair]bool {
	out := map[candidatequery.Pair]bool{}
	for _, a := range f.areas {
		if !matches(a.Name, q.Anchor, q.Tau) {
			continue
		}
		for _, alias := range f.aliases[a.ID] {
			if matches(alias.Name, q.Target, q.Tau) {
				out[candidatequery.Pair{AnchorRecordID: a.ID, TargetRecordID: alias.ID}] = true
			}
		}
	}
	return out
}

type row struct {
	Query    int
	Rejected bool
	Pairs    int
	Metrics  discovery.Metrics
	Offline  discovery.OfflineBytes
}

func save(t *testing.T, path string, v any) {
	b, e := json.MarshalIndent(v, "", " ")
	must(t, e)
	must(t, os.WriteFile(path, b, 0600))
}
func TestIntegratedReal(t *testing.T) {
	if os.Getenv("PMEQ_PHASE11") != "1" {
		t.Skip("set PMEQ_PHASE11=1")
	}
	f := loadFixture(t)
	save(t, "../../results/phase11-static.json", f.static)
	var rows []row
	rejected, total := 0, 0
	smoke := os.Getenv("PMEQ_PHASE11_SMOKE") == "1"
	for i, q := range f.trace {
		query := discovery.Query{Anchor: q.Anchor, Target: q.Target, TauAnchor: q.Tau, TauTarget: q.Tau}
		if e := discovery.Validate(query); e != nil {
			if !f.ref[i].Rejected {
				t.Fatal("unexpected rejection", i)
			}
			_, _, e = discovery.RunLocal(context.Background(), query, f.keys, nil, [2]*discovery.Static{}, [2]*discovery.PartyPacket{}, scmpnative.Backend{})
			if e != discovery.ErrDomain {
				t.Fatal("invalid not rejected at entry")
			}
			rows = append(rows, row{Query: i, Rejected: true})
			rejected++
			continue
		}
		if f.ref[i].Rejected {
			t.Fatal("accepted invalid")
		}
		statics, buckets := f.prepareStatic(t, q)
		u, p, cost := f.provision(t, q, statics, buckets)
		out, m, e := discovery.RunLocal(context.Background(), query, f.keys, u, statics, p, scmpnative.Backend{})
		must(t, e)
		want := f.oracle(q)
		seen := map[candidatequery.Pair]bool{}
		for _, pair := range out.Pairs {
			if seen[pair] || !want[pair] {
				t.Fatal("duplicate/false positive/wrong ID", i, pair)
			}
			seen[pair] = true
		}
		if len(seen) != len(want) || len(seen) != f.ref[i].Pairs || m.K != f.ref[i].K || m.Groups != f.ref[i].G || m.Slots != f.ref[i].S {
			t.Fatal("false negative/workload mismatch", i, len(seen), len(want), m)
		}
		rows = append(rows, row{i, false, len(out.Pairs), m, cost})
		total += len(out.Pairs)
		if i%25 == 0 {
			t.Logf("integrated %d/1003 mean-primary samples recorded; last wall=%s", i, m.LocalE2E)
		}
		if smoke && len(rows) >= 4 {
			break
		}
	}
	if !smoke && (rejected != 149 || len(rows) != 1003 || total != 1510) {
		t.Fatal("totals", rejected, len(rows), total)
	}
	name := "../../results/phase11-queries.json"
	if smoke {
		name = "../../results/phase11-smoke.json"
	}
	save(t, name, rows)
	t.Logf("INTEGRATED total=%d rejected=%d valid=%d pairs=%d FP=0 FN=0 duplicate=0 wrongAnchor=0 wrongTarget=0", len(rows), rejected, len(rows)-rejected, total)
}

type bench struct {
	Query, K, Slots, Warmup, Measured int
	Samples                           []discovery.Metrics
}

func TestIntegratedRepeated(t *testing.T) {
	if os.Getenv("PMEQ_PHASE11_BENCH") != "1" {
		t.Skip("set PMEQ_PHASE11_BENCH=1")
	}
	f := loadFixture(t)
	valid := []int{}
	mean := 0.0
	for i, r := range f.ref {
		if !r.Rejected {
			valid = append(valid, i)
			mean += float64(r.S)
		}
	}
	mean /= float64(len(valid))
	sort.SliceStable(valid, func(i, j int) bool { return f.ref[valid[i]].S < f.ref[valid[j]].S })
	nearest := valid[0]
	abs := func(x float64) float64 {
		if x < 0 {
			return -x
		}
		return x
	}
	for _, i := range valid {
		if abs(float64(f.ref[i].S)-mean) < abs(float64(f.ref[nearest].S)-mean) {
			nearest = i
		}
	}
	chosen := []int{nearest, valid[(len(valid)*50+99)/100-1], valid[(len(valid)*95+99)/100-1], valid[(len(valid)*99+99)/100-1]}
	var all []bench
	for rank, i := range chosen {
		q := f.trace[i]
		st, buckets := f.prepareStatic(t, q)
		warm, n := 10, 30
		b := bench{Query: i, K: f.ref[i].K, Slots: f.ref[i].S, Warmup: warm, Measured: n}
		want := f.oracle(q)
		for trial := -warm; trial < n; trial++ {
			u, p, _ := f.provision(t, q, st, buckets)
			out, m, e := discovery.RunLocal(context.Background(), discovery.Query{Anchor: q.Anchor, Target: q.Target, TauAnchor: q.Tau, TauTarget: q.Tau}, f.keys, u, st, p, scmpnative.Backend{})
			must(t, e)
			if len(out.Pairs) != len(want) {
				t.Fatal("benchmark oracle")
			}
			for _, pair := range out.Pairs {
				if !want[pair] {
					t.Fatal("benchmark ID")
				}
			}
			if trial >= 0 {
				b.Samples = append(b.Samples, m)
			}
			if trial%10 == 0 {
				t.Logf("repeated rank=%d trial=%d wall=%s", rank, trial, m.LocalE2E)
			}
		}
		all = append(all, b)
		save(t, "../../results/phase11-benchmarks.json", all)
	}
}

func TestIntegratedNativeEdges(t *testing.T) {
	if os.Getenv("PMEQ_PHASE11_EDGES") != "1" {
		t.Skip("set PMEQ_PHASE11_EDGES=1")
	}
	f := loadFixture(t)
	// Independent thresholds: same Anchor query/capacity, a different legal Target tau.
	q := f.trace[0]
	st, buckets := f.prepareStatic(t, q)
	u, p, _ := f.provision(t, q, st, buckets)
	tq := len(anchorfilter.QueryChunks(q.Target)) - 1
	query := discovery.Query{Anchor: q.Anchor, Target: q.Target, TauAnchor: q.Tau, TauTarget: tq}
	out, _, e := discovery.RunLocal(context.Background(), query, f.keys, u, st, p, scmpnative.Backend{})
	must(t, e)
	want := map[candidatequery.Pair]bool{}
	for _, a := range f.areas {
		if !matches(a.Name, q.Anchor, q.Tau) {
			continue
		}
		for _, a1 := range f.aliases[a.ID] {
			if matches(a1.Name, q.Target, tq) {
				want[candidatequery.Pair{AnchorRecordID: a.ID, TargetRecordID: a1.ID}] = true
			}
		}
	}
	if len(out.Pairs) != len(want) {
		t.Fatal("independent tau cardinality")
	}
	for _, pair := range out.Pairs {
		if !want[pair] {
			t.Fatal("independent tau ID")
		}
	}
	if _, _, e = discovery.RunLocal(context.Background(), query, f.keys, u, st, p, scmpnative.Backend{}); e == nil {
		t.Fatal("reused whole packet")
	}
	// Actual Anchor filtering and compaction must yield K0; no zero intermediate
	// is injected. A valid Unicode query absent from the raw corpus is used.
	q = workload{Anchor: "\U0010ffff\U0010ffff\U0010ffff\U0010ffff", Target: "abcd", Tau: 0}
	st, buckets = f.prepareStatic(t, q)
	u, p0, p1, _, e := discovery.Provision(st[0], st[1], buckets, []int{0}, targetaggregation.Shape{K: 0, R: 1, S: 0, G: 0}, scmpnative.Backend{})
	must(t, e)
	out, m, e := discovery.RunLocal(context.Background(), discovery.Query{Anchor: q.Anchor, Target: q.Target}, f.keys, u, st, [2]*discovery.PartyPacket{p0, p1}, scmpnative.Backend{})
	must(t, e)
	if len(out.Pairs) != 0 || m.K != 0 || m.Routes != 0 || m.CloudToUser != [2]uint64{86, 86} {
		t.Fatal("K0 boundary", out, m)
	}
}

func TestOfflineTiming(t *testing.T) {
	if os.Getenv("PMEQ_PHASE11_OFFLINE") != "1" {
		t.Skip("set PMEQ_PHASE11_OFFLINE=1")
	}
	start := time.Now()
	f := loadFixture(t)
	setup := time.Since(start)
	b, e := os.ReadFile("../../results/phase11-benchmarks.json")
	must(t, e)
	var chosen []bench
	must(t, json.Unmarshal(b, &chosen))
	if len(chosen) != 4 {
		t.Fatal("complete repeated-query evidence required")
	}
	type timing struct {
		Query                             int
		StaticExtension, OneTimeProvision time.Duration
		Offline                           discovery.OfflineBytes
	}
	result := struct {
		BSMJMaterialization, SetupIncludingOracle time.Duration
		Samples                                   []timing
	}{BSMJMaterialization: f.indexBuild, SetupIncludingOracle: setup}
	for _, b := range chosen {
		q := f.trace[b.Query]
		start = time.Now()
		st, buckets := f.prepareStatic(t, q)
		staticTime := time.Since(start)
		start = time.Now()
		_, _, cost := f.provision(t, q, st, buckets)
		result.Samples = append(result.Samples, timing{q.Query, staticTime, time.Since(start), cost})
	}
	save(t, "../../results/phase11-offline-timing.json", result)
}
