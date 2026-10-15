//go:build phase6native

package discovery_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
	"time"

	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"pmeq/internal/candidatequery"
	"pmeq/internal/discovery"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpnative"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetaggregation/gen"
	"pmeq/internal/targetartifact"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetpe"
)

const subsetSeed uint64 = 20260920
const subsetDomain = "PMEQ-DB-SCALE-ANCHOR-ID-V1\x00"

type dbErrors struct{ FP, FN, Duplicates, WrongAnchorID, WrongTargetID int }
type dbQuery struct {
	Phase                                             string
	Scale, Query, Tau, N                              int
	AnchorQuery, TargetQuery                          string
	Metrics                                           discovery.Metrics
	UserToCloud, CloudToUser, ServerBytes, TotalBytes uint64
	FinalPairs, OraclePairs                           int
	Errors                                            dbErrors
	Recovered, Expected                               []candidatequery.Pair
	DomainEvidence                                    map[string]any
	Offline                                           discovery.OfflineBytes
	StaticPreparationNS, ProvisionNS                  int64
}
type dbScale struct {
	Phase                                                                      string
	Scale, N                                                                   int
	AnchorInput, TargetInput                                                   indexbuild.InputStats
	AnchorIndex, TargetIndex                                                   indexbuild.SideStats
	AnchorBuildNS, TargetBuildNS, IndexBuildNS, PayloadBuildNS, SidecarBuildNS int64
	Static                                                                     map[string][2]uint64
	StaticAccounting                                                           string
	QueryCount, FinalPairs                                                     int
	Errors                                                                     dbErrors
}

func dbHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func dbJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.MarshalIndent(v, "", "  ")
	must(t, e)
	return append(b, '\n')
}
func dbWrite(t *testing.T, dir, name string, v any) {
	t.Helper()
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, e)
	_, e = f.Write(dbJSON(t, v))
	must(t, e)
	must(t, f.Close())
}
func dbEqual(t *testing.T, dir, phase string, q int, field string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		dbWrite(t, dir, "first-difference.json", map[string]any{"phase": phase, "query": q, "field": field, "actual": got, "expected": want})
		t.Fatalf("FIRST DIFFERENCE phase=%s query=%d field=%s got=%v want=%v", phase, q, field, got, want)
	}
}
func dbReadInputs(t *testing.T) ([]indexbuild.AreaRecord, []indexbuild.AreaAliasRecord, indexbuild.InputStats, indexbuild.InputStats) {
	f, e := os.Open(filepath.Join(rawDir, "area"))
	must(t, e)
	a, as, e := indexbuild.LoadAreaWithStats(f, 0)
	must(t, e)
	must(t, f.Close())
	f, e = os.Open(filepath.Join(rawDir, "area_alias"))
	must(t, e)
	b, bs, e := indexbuild.LoadAreaAliasWithStats(f, 0)
	must(t, e)
	must(t, f.Close())
	return a, b, as, bs
}
func dbInputStats(areas []indexbuild.AreaRecord, aliases []indexbuild.AreaAliasRecord) (a, b indexbuild.InputStats) {
	add := func(s *indexbuild.InputStats, name string) {
		s.RawRows++
		s.UsableRows++
		n := len([]rune(name))
		if n == 0 {
			s.EmptyNames++
		}
		if n < 4 {
			s.ShortNames++
		} else {
			s.IndexedRecords++
			s.QGramOccurrences += n - 3
		}
	}
	for _, r := range areas {
		add(&a, r.Name)
	}
	for _, r := range aliases {
		add(&b, r.Name)
	}
	return
}
func dbSortedPairs(m map[candidatequery.Pair]bool) []candidatequery.Pair {
	x := make([]candidatequery.Pair, 0, len(m))
	for p := range m {
		x = append(x, p)
	}
	sort.Slice(x, func(i, j int) bool {
		if x[i].AnchorRecordID != x[j].AnchorRecordID {
			return x[i].AnchorRecordID < x[j].AnchorRecordID
		}
		return x[i].TargetRecordID < x[j].TargetRecordID
	})
	return x
}

// Reflection reads lengths and public dimensions only, never secret contents,
// and never mutates or truncates a packet. It runs before the online timer.
func dbDomainEvidence(t *testing.T, st [2]*discovery.Static, packets [2]*discovery.PartyPacket, n int) map[string]any {
	t.Helper()
	e := map[string]any{"N": n, "count_length_proof": "successful RunLocal: NewCount(payload length), strict CountParty.Add and Keep.Prepare lengths", "allocation_proof": "fresh Provision called on these statics; reflected lengths checked before any online consumption"}
	check := func(name string, got int) {
		if got != n {
			t.Fatalf("domain evidence %s=%d != %d", name, got, n)
		}
		e[name] = got
	}
	for u := 0; u < 2; u++ {
		s := reflect.ValueOf(st[u]).Elem()
		p := reflect.ValueOf(packets[u]).Elem()
		prefix := fmt.Sprintf("cs%d_", u)
		check(prefix+"payload", s.FieldByName("payload").FieldByName("Slots").Len())
		check(prefix+"lineage", int(s.FieldByName("target").Elem().FieldByName("lineage").FieldByName("N").Int()))
		for _, name := range []string{"keys", "masks"} {
			check(prefix+"keep_"+name, p.FieldByName("keep").Elem().FieldByName(name).Len())
		}
		state := p.FieldByName(fmt.Sprintf("c%d", u)).Elem().FieldByName("state").Elem()
		check(prefix+"compaction_n", int(state.FieldByName("n").Int()))
		for _, name := range []string{"perm", "c", "t", "r"} {
			check(prefix+"compaction_"+name, state.FieldByName(name).Len())
		}
		aps := p.FieldByName("anchor")
		lens := make([]int, 0, aps.Len()*3)
		for i := 0; i < aps.Len(); i++ {
			prep := aps.Index(i).FieldByName(fmt.Sprintf("p%d", u)).Elem()
			names := []string{"c1", "a2", "b2"}
			if u == 1 {
				names = []string{"a1", "b1", "c2"}
			}
			for _, name := range names {
				got := prep.FieldByName(name).Len()
				if got != n {
					t.Fatalf("alignment material=%d != %d", got, n)
				}
				lens = append(lens, got)
			}
		}
		e[prefix+"alignment_material_lengths"] = lens
		if u == 1 {
			it := s.FieldByName("anchor").MapRange()
			lens = []int{}
			for it.Next() {
				got := it.Value().FieldByName("Stage1").Elem().FieldByName("sigma").Len()
				if got != n {
					t.Fatal("sigma domain", got, n)
				}
				lens = append(lens, got)
			}
			e["alignment_sigma_lengths"] = lens
		}
	}
	return e
}

func dbProvision(t *testing.T, f *fixture, q workload, st [2]*discovery.Static, buckets []uint32) (*discovery.UserPacket, [2]*discovery.PartyPacket, discovery.OfflineBytes) {
	t.Helper()
	words := anchorfilter.QueryChunks(q.Target)
	caps := make([]int, len(words))
	shape := targetaggregation.Shape{R: len(words)}
	// Same trusted offline capacity selection as the original fixture, with
	// Anchor candidate IDs recomputed from THIS dataset using unchanged matches.
	for _, a := range f.areas {
		if !matches(a.Name, q.Anchor, q.Tau) {
			continue
		}
		shape.K++
		j, e := targetcrypto.JoinBucketComponent(f.keys.Target, a.ID, f.bucketBits)
		must(t, e)
		for i, w := range words {
			b, e := targetcrypto.WordBucketComponent(f.keys.Target, w.QGram, f.bucketBits)
			must(t, e)
			for _, g := range f.idx[0].PositionGroups(uint32(j) ^ uint32(b)) {
				shape.G++
				shape.S += int(g.PadWidth)
				caps[i] += int(g.PadWidth)
			}
		}
	}
	u, p0, p1, cost, e := discovery.Provision(st[0], st[1], buckets, caps, shape, scmpnative.Backend{})
	must(t, e)
	return u, [2]*discovery.PartyPacket{p0, p1}, cost
}
func dbReplay(t *testing.T, dir, phase string, scale int, f *fixture, baseline []row, limit int) (dbScale, []dbQuery) {
	t.Helper()
	summary := dbScale{Phase: phase, Scale: scale, N: len(f.areas)}
	records := []dbQuery{}
	file, e := os.OpenFile(filepath.Join(dir, phase+"-queries.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, e)
	defer file.Close()
	enc := json.NewEncoder(file)
	for i, q := range f.trace {
		query := discovery.Query{Anchor: q.Anchor, Target: q.Target, TauAnchor: q.Tau, TauTarget: q.Tau}
		dbEqual(t, dir, phase, i, "query ID", q.Query, i)
		legal := discovery.Validate(query) == nil
		dbEqual(t, dir, phase, i, "query validity", legal, !baseline[i].Rejected)
		if !legal {
			continue
		}
		want := f.oracle(q) // Existing oracle, unmodified, recomputed per invocation.
		r := dbQuery{Phase: phase, Scale: scale, Query: q.Query, Tau: q.Tau, N: len(f.areas), AnchorQuery: q.Anchor, TargetQuery: q.Target, OraclePairs: len(want), Expected: dbSortedPairs(want)}
		started := time.Now()
		st, buckets := f.prepareStatic(t, q)
		r.StaticPreparationNS = int64(time.Since(started))
		started = time.Now()
		u, p, cost := dbProvision(t, f, q, st, buckets)
		r.ProvisionNS = int64(time.Since(started))
		r.Offline = cost
		r.DomainEvidence = dbDomainEvidence(t, st, p, len(f.areas))
		dbEqual(t, dir, phase, q.Query, "offline compaction bytes", cost.Compaction, uint64(266*len(f.areas)))
		out, m, err := discovery.RunLocal(context.Background(), query, f.keys, u, st, p, scmpnative.Backend{})
		if err != nil {
			dbWrite(t, dir, "first-difference.json", map[string]any{"phase": phase, "query": q.Query, "field": "RunLocal error", "actual": err.Error()})
			t.Fatal(err)
		}
		r.Metrics = m
		r.FinalPairs = len(out.Pairs)
		r.UserToCloud = m.UserToCloud[0] + m.UserToCloud[1]
		r.CloudToUser = m.CloudToUser[0] + m.CloudToUser[1]
		r.ServerBytes = m.ServerBytes
		r.TotalBytes = r.UserToCloud + r.CloudToUser + r.ServerBytes
		seen := map[candidatequery.Pair]bool{}
		wa, wt := map[uint64]bool{}, map[uint64]bool{}
		for p := range want {
			wa[p.AnchorRecordID] = true
			wt[p.TargetRecordID] = true
		}
		for _, pair := range out.Pairs {
			if seen[pair] {
				r.Errors.Duplicates++
			}
			seen[pair] = true
			if !want[pair] {
				r.Errors.FP++
			}
			if !wa[pair.AnchorRecordID] {
				r.Errors.WrongAnchorID++
			}
			if !wt[pair.TargetRecordID] {
				r.Errors.WrongTargetID++
			}
		}
		for pair := range want {
			if !seen[pair] {
				r.Errors.FN++
			}
		}
		r.Recovered = dbSortedPairs(seen)
		must(t, enc.Encode(r))
		must(t, file.Sync())
		dbEqual(t, dir, phase, q.Query, "correctness", r.Errors, dbErrors{})
		if scale == 100 {
			b := baseline[i]
			bm := b.Metrics
			checks := []struct {
				name      string
				got, want any
			}{{"K", m.K, bm.K}, {"routes", m.Routes, bm.Routes}, {"groups", m.Groups, bm.Groups}, {"Target slots", m.Slots, bm.Slots}, {"final pairs", r.FinalPairs, b.Pairs}, {"oracle pairs", r.OraclePairs, b.Pairs}, {"UserToCloud", m.UserToCloud, bm.UserToCloud}, {"CloudToUser", m.CloudToUser, bm.CloudToUser}, {"ServerBytes", m.ServerBytes, bm.ServerBytes}, {"TotalBytes", r.TotalBytes, bm.UserToCloud[0] + bm.UserToCloud[1] + bm.CloudToUser[0] + bm.CloudToUser[1] + bm.ServerBytes}}
			for _, c := range checks {
				dbEqual(t, dir, phase, q.Query, c.name, c.got, c.want)
			}
		}
		summary.QueryCount++
		summary.FinalPairs += r.FinalPairs
		records = append(records, r)
		if summary.QueryCount%20 == 0 {
			t.Logf("%s progress %d query=%d pairs=%d N=%d E2E=%s", phase, summary.QueryCount, q.Query, summary.FinalPairs, len(f.areas), m.LocalE2E)
		}
		if limit > 0 && summary.QueryCount == limit {
			break
		}
	}
	wantCount := 854
	if limit > 0 {
		wantCount = limit
	}
	dbEqual(t, dir, phase, -1, "executed queries", summary.QueryCount, wantCount)
	if limit == 0 {
		dbEqual(t, dir, phase, -1, "total pairs", summary.FinalPairs, 1510)
	}
	return summary, records
}

func dbBuild(t *testing.T, dir string, scale int, areas []indexbuild.AreaRecord, aliases []indexbuild.AreaAliasRecord, trace []workload, ref []reference) (*fixture, dbScale) {
	return dbBuildBits(t, dir, scale, 16, areas, aliases, trace, ref)
}

func dbBuildBits(t *testing.T, dir string, scale, bits int, areas []indexbuild.AreaRecord, aliases []indexbuild.AreaAliasRecord, trace []workload, ref []reference) (*fixture, dbScale) {
	t.Helper()
	f := &fixture{bucketBits: bits, areas: areas, aliases: map[uint64][]indexbuild.AreaAliasRecord{}, posts: map[uint32][]incidence.Posting{}, static: map[string][2]uint64{}, trace: trace, ref: ref}
	for _, a := range aliases {
		f.aliases[a.Area] = append(f.aliases[a.Area], a)
	}
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
	s := dbScale{Phase: fmt.Sprintf("pilot-%d", scale), Scale: scale, N: len(areas), StaticAccounting: "BSMJ/incidence/alignment: full-domain semantic fields, not resident memory; PSMJ/payload/sidecar: actual sealed bytes; manifests separate"}
	s.AnchorInput, s.TargetInput = dbInputStats(areas, aliases)
	start := time.Now()
	_, a0, a1, ast, e := indexbuild.Build(areas, nil, f.keys.Anchor, f.keys.Target, bits, bits)
	must(t, e)
	s.AnchorBuildNS = int64(time.Since(start))
	s.AnchorIndex = ast.Anchor
	f.anchor = [2]map[uint32]indexbuild.AnchorPartyBucket{{}, {}}
	byZ := map[anchorindex.Value][]incidence.Posting{}
	for _, a := range areas {
		indexbuild.VisitQGrams(a.Name, func(w string, _ uint32) {
			z, e := anchorindex.Encode(f.keys.Anchor, w)
			must(t, e)
			byZ[z] = append(byZ[z], incidence.Posting{RecordID: a.ID, Real: true})
		})
	}
	var incBytes uint64
	for i, b := range a0.AnchorBuckets {
		f.anchor[0][b.BucketID] = b
		f.anchor[1][b.BucketID] = a1.AnchorBuckets[i]
		ids := map[uint64]bool{}
		for _, g := range b.Groups {
			p := byZ[g.Z]
			f.posts[b.BucketID] = append(f.posts[b.BucketID], p...)
			for _, v := range p {
				ids[v.RecordID] = true
			}
			for j := len(p); j < len(g.Slots); j++ {
				f.posts[b.BucketID] = append(f.posts[b.BucketID], incidence.Posting{})
			}
		}
		d, e := incidence.RecordCapacity(len(ids))
		must(t, e)
		if d > len(areas) {
			t.Fatal("local domain exceeds actual global domain", d, len(areas))
		}
		incBytes += uint64(d * len(f.posts[b.BucketID]))
	}
	start = time.Now()
	meta, t0, t1, tst, e := indexbuild.BuildFinalTargetWithBits(aliases, f.keys.Target, bits)
	must(t, e)
	s.TargetBuildNS = int64(time.Since(start))
	s.TargetIndex = tst.Target
	s.IndexBuildNS = s.AnchorBuildNS + s.TargetBuildNS
	var indexID [16]byte
	_, e = rand.Read(indexID[:])
	must(t, e)
	m, e := indexbuild.NewTargetManifest(indexID, meta, tst.Target)
	must(t, e)
	var files [2][]byte
	for u, p := range []indexbuild.PartyIndex{t0, t1} {
		var b bytes.Buffer
		must(t, indexbuild.WriteTargetParty(&b, m, uint8(u), p))
		files[u] = b.Bytes()
		m.PartyBytes[u] = uint64(b.Len())
		m.PartySHA256[u] = dbHash(b.Bytes())
	}
	mr := dbJSON(t, m)
	ids := make([]uint64, len(areas))
	for i, a := range areas {
		ids[i] = a.ID
	}
	start = time.Now()
	f.layout, f.payload[0], f.payload[1], e = aggregation.GeneratePayload(ids, f.keys.Target, bits)
	must(t, e)
	s.PayloadBuildNS = int64(time.Since(start))
	pm := targetpe.PayloadManifest{IndexID: indexID, LayoutID: f.layout.LayoutID, TargetBucketBits: uint8(bits), N: len(areas)}
	var pb [2][]byte
	for u, p := range f.payload {
		var b bytes.Buffer
		must(t, targetartifact.WritePayload(&b, m, uint8(u), p))
		pb[u] = b.Bytes()
		pm.Bytes[u] = int64(b.Len())
		pm.SHA256[u] = dbHash(b.Bytes())
	}
	pr := dbJSON(t, pm)
	var sb [2]bytes.Buffer
	start = time.Now()
	sm, audit, e := gen.Build(mr, files, aliases, [2]io.Writer{&sb[0], &sb[1]})
	must(t, e)
	s.SidecarBuildNS = int64(time.Since(start))
	for u := 0; u < 2; u++ {
		f.idx[u], e = targetpe.Load(bytes.NewReader(mr), bytes.NewReader(pr), bytes.NewReader(files[u]), bytes.NewReader(pb[u]), uint8(u), targetpe.AlignmentLineage{IndexID: indexID, LayoutID: f.layout.LayoutID, N: len(areas)})
		must(t, e)
		f.payload[u], e = targetartifact.ReadPayload(bytes.NewReader(pb[u]), m, uint8(u), f.layout.LayoutID, uint32(len(areas)))
		must(t, e)
		f.side[u], e = targetaggregation.LoadSidecar(sm, mr, f.idx[u], bytes.NewReader(sb[u].Bytes()))
		must(t, e)
	}
	bucketHeaderBytes := 6
	slotBytes := 47
	if bits > 16 {
		bucketHeaderBytes = 8
		slotBytes = 49
	}
	bsmj := uint64(ast.Anchor.PaddedSlots*slotBytes + ast.Anchor.LogicalGroups*20 + ast.Anchor.NonemptyBuckets*bucketHeaderBytes)
	f.static["BSMJ semantic fields"] = [2]uint64{bsmj, bsmj}
	f.static["PSMJ sealed bytes"] = m.PartyBytes
	f.static["Anchor incidence full-domain fields"] = [2]uint64{incBytes, incBytes}
	f.static["Anchor alignment full-domain factors"] = [2]uint64{uint64(32 * ast.Anchor.NonemptyBuckets), uint64(4 * len(areas) * ast.Anchor.NonemptyBuckets)}
	f.static["Target aggregation sealed bytes"] = sm.PartyBytes
	f.static["Global payload sealed bytes"] = [2]uint64{uint64(pm.Bytes[0]), uint64(pm.Bytes[1])}
	manifestBytes := uint64(len(mr) + len(pr) + len(dbJSON(t, sm)))
	f.static["Public manifests"] = [2]uint64{manifestBytes, manifestBytes}
	s.Static = f.static
	// Persist public manifests and hashes. Secret shares are used in memory;
	// sizes above are from the actual encoders, not extrapolated estimates.
	dbWrite(t, dir, s.Phase+"-target-manifest.json", m)
	dbWrite(t, dir, s.Phase+"-payload-manifest.json", pm)
	dbWrite(t, dir, s.Phase+"-sidecar-manifest.json", sm)
	dbWrite(t, dir, s.Phase+"-sidecar-audit.json", audit)
	return f, s
}

func TestDatabaseRegressionThenPilot(t *testing.T) {
	if os.Getenv("PMEQ_DATABASE_REGRESSION_PILOT") != "1" {
		t.Skip("explicit regression then two-scale pilot only")
	}
	dir := os.Getenv("PMEQ_DATABASE_OUTPUT")
	root, e := filepath.Abs("../..")
	must(t, e)
	if root != "/home/tenggn/projects/clean_pmeq" || !filepath.IsAbs(dir) || !filepath.IsLocal(relPath(t, root, dir)) {
		t.Fatal("repository/output boundary")
	}
	var baseline []row
	raw, e := os.ReadFile("../../results/phase11-queries.json")
	must(t, e)
	must(t, json.Unmarshal(raw, &baseline))
	dbEqual(t, dir, "regression", -1, "baseline rows", len(baseline), 1003)
	areas, aliases, as, bs := dbReadInputs(t)
	dbEqual(t, dir, "regression", -1, "Anchor records", len(areas), 120071)
	dbEqual(t, dir, "regression", -1, "Target records", len(aliases), 67896)
	dbEqual(t, dir, "regression", -1, "normal indexed Target", bs.IndexedRecords, 63849)
	dbEqual(t, dir, "regression", -1, "Target short", bs.ShortNames, 4047)
	dbEqual(t, dir, "regression", -1, "Target real postings", bs.QGramOccurrences, 480945)
	anchorIDs := map[uint64]bool{}
	aliasIDs := map[uint64]bool{}
	for _, a := range areas {
		if anchorIDs[a.ID] {
			t.Fatal("duplicate raw Anchor ID")
		}
		anchorIDs[a.ID] = true
	}
	for _, a := range aliases {
		if aliasIDs[a.ID] || !anchorIDs[a.Area] {
			t.Fatal("raw duplicate/orphan Target", a.ID)
		}
		aliasIDs[a.ID] = true
	}
	var trace []workload
	var ref []reference
	func() {
		f := loadFixture(t)
		trace = f.trace
		ref = f.ref
		dbEqual(t, dir, "regression", -1, "raw Anchor fixture", f.areas, areas)
		dbEqual(t, dir, "regression", -1, "payload N", len(f.payload[0].Slots), 120071)
		dbEqual(t, dir, "regression", -1, "lineage N", f.idx[0].Lineage().N, 120071)
		var manifest indexbuild.TargetManifest
		b, e := os.ReadFile("../../artifacts/phase7b/manifest.json")
		must(t, e)
		must(t, json.Unmarshal(b, &manifest))
		dbEqual(t, dir, "regression", -1, "sealed Target real postings", manifest.RealPostings, uint64(bs.QGramOccurrences))
		dbEqual(t, dir, "regression", -1, "sealed padded slots", manifest.PaddedSlots, uint64(1317260))
		dbEqual(t, dir, "regression", -1, "sealed groups", manifest.LogicalGroups, uint64(310331))
		s, _ := dbReplay(t, dir, "regression-100", 100, f, baseline, 0)
		s.AnchorInput = as
		s.TargetInput = bs
		s.Static = f.static
		s.AnchorBuildNS = int64(f.indexBuild)
		dbWrite(t, dir, "regression-100-summary.json", s)
	}()
	t.Log("GATE PASSED: 854 queries,1510 pairs,all workload/communication fields identical; beginning pilot")
	runtime.GC()
	// No subset ordering or selection is performed before the full gate passes.
	type ranked struct {
		ID   uint64
		Hash [32]byte
	}
	order := make([]ranked, len(areas))
	for i, a := range areas {
		var raw [16]byte
		binary.BigEndian.PutUint64(raw[:8], subsetSeed)
		binary.BigEndian.PutUint64(raw[8:], a.ID)
		order[i] = ranked{a.ID, sha256.Sum256(append([]byte(subsetDomain), raw[:]...))}
	}
	sort.Slice(order, func(i, j int) bool {
		c := bytes.Compare(order[i].Hash[:], order[j].Hash[:])
		if c != 0 {
			return c < 0
		}
		return order[i].ID < order[j].ID
	})
	orderedIDs := make([]uint64, len(order))
	selected := map[uint64]bool{}
	for i, v := range order {
		orderedIDs[i] = v.ID
		if i < len(areas)/5 {
			selected[v.ID] = true
		}
	}
	dbWrite(t, dir, "anchor-order.json", map[string]any{"seed": subsetSeed, "domain_label": subsetDomain, "encoding": "label bytes || uint64-BE(seed) || uint64-BE(area.id); SHA256 ascending then ID ascending", "IDs": orderedIDs})
	var a20 []indexbuild.AreaRecord
	var b20 []indexbuild.AreaAliasRecord
	for _, a := range areas {
		if selected[a.ID] {
			a20 = append(a20, a)
		}
	}
	for _, b := range aliases {
		if selected[b.Area] {
			b20 = append(b20, b)
		}
	}
	dbEqual(t, dir, "pilot-20", -1, "selected Anchor records", len(a20), 24014)
	dbWrite(t, dir, "subset-20.json", map[string]any{"AnchorIDs": orderedIDs[:24014], "AnchorRecords": len(a20), "TargetRecords": len(b20), "AnchorInputSHA256": dbHash(dbJSON(t, a20)), "TargetInputSHA256": dbHash(dbJSON(t, b20)), "join_consistent": true, "proper_subset_of_full": true, "preserves_source_row_order": true})
	for _, scale := range []int{20, 100} {
		a, b := areas, aliases
		if scale == 20 {
			a, b = a20, b20
		}
		func() {
			f, s := dbBuild(t, dir, scale, a, b, trace, ref)
			t.Logf("%s built Anchor=%d Target=%d N=%d", s.Phase, len(a), len(b), s.N)
			if scale == 100 {
				dbEqual(t, dir, s.Phase, -1, "Target real postings", s.TargetIndex.RealSlots, 480945)
				dbEqual(t, dir, s.Phase, -1, "Target padded slots", s.TargetIndex.PaddedSlots, 1317260)
			}
			r, _ := dbReplay(t, dir, s.Phase, scale, f, baseline, 20)
			s.QueryCount = r.QueryCount
			s.FinalPairs = r.FinalPairs
			s.Errors = r.Errors
			dbWrite(t, dir, s.Phase+"-summary.json", s)
		}()
		runtime.GC()
	}
	dbWrite(t, dir, "completed.json", map[string]any{"regression_queries": 854, "regression_pairs": 1510, "pilot_scales": []int{20, 100}, "pilot_queries_per_scale": 20, "status": "passed", "paper_results": false})
}
func relPath(t *testing.T, root, path string) string {
	t.Helper()
	r, e := filepath.Rel(root, path)
	must(t, e)
	return r
}
