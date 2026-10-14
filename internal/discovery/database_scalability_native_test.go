//go:build phase6native

package discovery_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"

	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"pmeq/internal/candidatequery"
	"pmeq/internal/discovery"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpnative"
)

// This file contains experiment orchestration only. The frozen pilot helpers
// supply input loading, builders, provisioning, domain evidence and oracle.
type formalQuery struct {
	dbQuery
	Round, Order, TauAnchor, TauTarget int
	StaticSHA256, PacketIDHash         string
}

func formalOrder(t *testing.T, areas []indexbuild.AreaRecord) []uint64 {
	t.Helper()
	var saved struct {
		Seed        uint64
		DomainLabel string `json:"domain_label"`
		IDs         []uint64
	}
	b, e := os.ReadFile("../../results/n-domain-regression-pilot-20260920/anchor-order.json")
	must(t, e)
	must(t, json.Unmarshal(b, &saved))
	if saved.Seed != subsetSeed || saved.DomainLabel != subsetDomain || len(saved.IDs) != len(areas) {
		t.Fatal("frozen subset order metadata")
	}
	ids := map[uint64]bool{}
	for _, a := range areas {
		if ids[a.ID] {
			t.Fatal("duplicate Anchor ID")
		}
		ids[a.ID] = true
	}
	var previous [32]byte
	var previousID uint64
	for i, id := range saved.IDs {
		if !ids[id] {
			t.Fatal("missing or duplicate ordered ID", id)
		}
		delete(ids, id)
		var raw [16]byte
		binary.BigEndian.PutUint64(raw[:8], subsetSeed)
		binary.BigEndian.PutUint64(raw[8:], id)
		h := sha256.Sum256(append([]byte(subsetDomain), raw[:]...))
		c := bytes.Compare(previous[:], h[:])
		if i > 0 && (c > 0 || (c == 0 && previousID >= id)) {
			t.Fatal("frozen SHA256 order mismatch", i)
		}
		previous, previousID = h, id
	}
	return saved.IDs
}

func formalTrace(t *testing.T) ([]workload, []reference, []row, []int) {
	f, e := os.Open("../../results/phase7b-workload.jsonl.gz")
	must(t, e)
	defer f.Close()
	g, e := gzip.NewReader(f)
	must(t, e)
	defer g.Close()
	s := bufio.NewScanner(g)
	s.Buffer(make([]byte, 65536), 4<<20)
	var trace []workload
	for s.Scan() {
		var q workload
		must(t, json.Unmarshal(s.Bytes(), &q))
		trace = append(trace, q)
	}
	must(t, s.Err())
	var ref []reference
	var base []row
	b, e := os.ReadFile("../../results/phase10b-queries.json")
	must(t, e)
	must(t, json.Unmarshal(b, &ref))
	b, e = os.ReadFile("../../results/phase11-queries.json")
	must(t, e)
	must(t, json.Unmarshal(b, &base))
	if len(trace) != 1003 || len(ref) != 1003 || len(base) != 1003 {
		t.Fatal("trace shape")
	}
	var valid []int
	for i, q := range trace {
		legal := discovery.Validate(discovery.Query{Anchor: q.Anchor, Target: q.Target, TauAnchor: q.Tau, TauTarget: q.Tau}) == nil
		if q.Query != i || base[i].Query != i || legal == base[i].Rejected || legal == ref[i].Rejected {
			t.Fatal("frozen query validity/order", i)
		}
		if legal {
			valid = append(valid, i)
		}
	}
	if len(valid) != 854 {
		t.Fatal("legal query count")
	}
	return trace, ref, base, valid
}

func formalBuckets(t *testing.T, f *fixture, q workload) []uint32 {
	var out []uint32
	for _, c := range anchorfilter.QueryChunks(q.Anchor) {
		z, e := anchorindex.Encode(f.keys.Anchor, c.QGram)
		must(t, e)
		id, e := indexbuild.AnchorBucket(z, 16)
		must(t, e)
		out = append(out, id)
	}
	return out
}

// Construct every indexed Anchor bucket (and any queried empty bucket) once.
// These are the SAME constructors used by fixture.prepareStatic; no protocol
// equations, field representations or alignment algorithms are implemented here.
func formalStatic(t *testing.T, f *fixture, trace []workload, valid []int) ([2]*discovery.Static, map[int][]uint32, int) {
	all := map[uint32]bool{}
	qb := map[int][]uint32{}
	for id := range f.anchor[0] {
		all[id] = true
	}
	for _, i := range valid {
		qb[i] = formalBuckets(t, f, trace[i])
		for _, id := range qb[i] {
			all[id] = true
		}
	}
	ids := make([]int, 0, len(all))
	for id := range all {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	as := [2]map[uint32]discovery.AnchorStatic{{}, {}}
	for j, v := range ids {
		id := uint32(v)
		posts := f.posts[id]
		local, e := incidence.PrepareLayout(posts)
		must(t, e)
		m0, m1, e := incidence.ShareIncidence(local)
		must(t, e)
		s0, s1, e := f.layout.Alignment(id, local, posts)
		must(t, e)
		if s1.GlobalRecords() != len(f.areas) {
			t.Fatal("static alignment N", id)
		}
		b0, b1 := f.anchor[0][id], f.anchor[1][id]
		b0.BucketID = id
		b1.BucketID = id
		as[0][id] = discovery.AnchorStatic{Bucket: b0, Incidence: m0, Stage0: s0}
		as[1][id] = discovery.AnchorStatic{Bucket: b1, Incidence: m1, Stage1: s1}
		if j%1000 == 0 {
			t.Logf("STATIC N=%d buckets=%d/%d", len(f.areas), j, len(ids))
		}
	}
	var st [2]*discovery.Static
	for u := range st {
		var e error
		st[u], e = discovery.NewStatic(uint8(u), as[u], f.payload[u], f.idx[u], f.side[u])
		must(t, e)
	}
	return st, qb, len(ids)
}

// Read-only content fingerprint, including private static shares and sigma.
// Only the digest is exported. No unsafe access, mutation, or static copies.
// Checks occur outside every online timer and cover all static state each round.
func formalHashValue(h hash.Hash, v reflect.Value) {
	var b [8]byte
	put := func(x uint64) { binary.LittleEndian.PutUint64(b[:], x); h.Write(b[:]) }
	put(uint64(v.Kind()))
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			put(0)
			return
		}
		put(1)
		formalHashValue(h, v.Elem())
	case reflect.Struct:
		put(uint64(v.NumField()))
		for i := 0; i < v.NumField(); i++ {
			formalHashValue(h, v.Field(i))
		}
	case reflect.Slice, reflect.Array:
		put(uint64(v.Len()))
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			h.Write(v.Bytes())
			return
		}
		if v.Type().Elem().Kind() == reflect.Uint32 {
			var buf [4096]byte
			used := 0
			for i := 0; i < v.Len(); i++ {
				binary.LittleEndian.PutUint32(buf[used:], uint32(v.Index(i).Uint()))
				used += 4
				if used == len(buf) {
					h.Write(buf[:])
					used = 0
				}
			}
			h.Write(buf[:used])
			return
		}
		for i := 0; i < v.Len(); i++ {
			formalHashValue(h, v.Index(i))
		}
	case reflect.Map:
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
		put(uint64(len(keys)))
		for _, k := range keys {
			formalHashValue(h, k)
			formalHashValue(h, v.MapIndex(k))
		}
	case reflect.String:
		put(uint64(v.Len()))
		h.Write([]byte(v.String()))
	case reflect.Bool:
		if v.Bool() {
			put(1)
		} else {
			put(0)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		put(uint64(v.Int()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		put(v.Uint())
	default:
		panic(fmt.Sprintf("unsupported static fingerprint type %s", v.Type()))
	}
}
func formalStaticHash(st [2]*discovery.Static) string {
	h := sha256.New()
	formalHashValue(h, reflect.ValueOf(st))
	return hex.EncodeToString(h.Sum(nil))
}
func formalPacketID(u *discovery.UserPacket) string {
	v := reflect.ValueOf(u).Elem().FieldByName("id")
	var b [16]byte
	for i := range b {
		b[i] = byte(v.Index(i).Uint())
	}
	return dbHash(b[:])
}

func formalErrors(want map[candidatequery.Pair]bool, got []candidatequery.Pair) (dbErrors, []candidatequery.Pair) {
	var e dbErrors
	seen := map[candidatequery.Pair]bool{}
	wa, wt := map[uint64]bool{}, map[uint64]bool{}
	for p := range want {
		wa[p.AnchorRecordID] = true
		wt[p.TargetRecordID] = true
	}
	for _, p := range got {
		if seen[p] {
			e.Duplicates++
		}
		seen[p] = true
		if !want[p] {
			e.FP++
		}
		if !wa[p.AnchorRecordID] {
			e.WrongAnchorID++
		}
		if !wt[p.TargetRecordID] {
			e.WrongTargetID++
		}
	}
	for p := range want {
		if !seen[p] {
			e.FN++
		}
	}
	return e, dbSortedPairs(seen)
}

func formalCrosscheck(t *testing.T, dir string, r formalQuery, b row) {
	m, bm := r.Metrics, b.Metrics
	for _, c := range []struct {
		name      string
		got, want any
	}{
		{"K", m.K, bm.K}, {"routes", m.Routes, bm.Routes}, {"groups", m.Groups, bm.Groups}, {"slots", m.Slots, bm.Slots}, {"pairs", r.FinalPairs, b.Pairs}, {"oracle", r.OraclePairs, b.Pairs}, {"UserToCloud", m.UserToCloud, bm.UserToCloud}, {"CloudToUser", m.CloudToUser, bm.CloudToUser}, {"ServerBytes", m.ServerBytes, bm.ServerBytes},
	} {
		dbEqual(t, dir, r.Phase, r.Query, c.name, c.got, c.want)
	}
}

func formalCSVHeader() []string {
	return []string{"scale", "round", "query", "order", "tau_anchor", "tau_target", "N", "anchor_query", "target_query", "local_e2e_ns", "Token_ns", "Anchor_ns", "Compaction_ns", "Routing_ns", "TargetPE_ns", "TargetPosition_ns", "TargetAggregation_ns", "OutputEncoding_ns", "Recovery_ns", "Cloud_ns", "AnchorParts", "AnchorPartyParts", "K", "routes", "groups", "target_slots", "final_pairs", "oracle_pairs", "user_cs0_bytes", "user_cs1_bytes", "cs0_user_bytes", "cs1_user_bytes", "intercloud_bytes", "total_online_bytes", "FP", "FN", "duplicates", "wrong_AnchorID", "wrong_TargetID", "static_sha256", "packet_id_hash", "provision_ns"}
}
func formalCSVRow(r formalQuery) []string {
	m := r.Metrics
	out := []string{}
	add := func(x any) { out = append(out, fmt.Sprint(x)) }
	for _, x := range []any{r.Scale, r.Round, r.Query, r.Order, r.TauAnchor, r.TauTarget, r.N, r.AnchorQuery, r.TargetQuery, m.LocalE2E.Nanoseconds(), m.Token.Nanoseconds(), m.Anchor.Nanoseconds(), m.Compaction.Nanoseconds(), m.Routing.Nanoseconds(), m.TargetPE.Nanoseconds(), m.TargetPosition.Nanoseconds(), m.TargetAggregation.Nanoseconds(), m.OutputEncoding.Nanoseconds(), m.Recovery.Nanoseconds(), m.Cloud.Nanoseconds()} {
		add(x)
	}
	b, _ := json.Marshal(m.AnchorParts)
	add(string(b))
	b, _ = json.Marshal(m.AnchorPartyParts)
	add(string(b))
	for _, x := range []any{m.K, m.Routes, m.Groups, m.Slots, r.FinalPairs, r.OraclePairs, m.UserToCloud[0], m.UserToCloud[1], m.CloudToUser[0], m.CloudToUser[1], m.ServerBytes, r.TotalBytes, r.Errors.FP, r.Errors.FN, r.Errors.Duplicates, r.Errors.WrongAnchorID, r.Errors.WrongTargetID, r.StaticSHA256, r.PacketIDHash, r.ProvisionNS} {
		add(x)
	}
	return out
}

func formalScale(t *testing.T, dir string, scale, rounds int, areas []indexbuild.AreaRecord, aliases []indexbuild.AreaAliasRecord, trace []workload, ref []reference, base []row, valid []int, calibration float64) {
	phase := fmt.Sprintf("formal-%d", scale)
	buildDir := filepath.Join(dir, "build")
	must(t, os.Mkdir(buildDir, 0700))
	f, s := dbBuild(t, buildDir, scale, areas, aliases, trace, ref)
	s.Phase = phase
	dbEqual(t, dir, phase, -1, "actual N", f.idx[0].Lineage().N, len(areas))
	start := time.Now()
	st, qb, bucketCount := formalStatic(t, f, trace, valid)
	staticNS := time.Since(start).Nanoseconds()
	stateHash := formalStaticHash(st)
	dbWrite(t, dir, "static.json", map[string]any{"scale": s, "static_construction_ns": staticNS, "static_build_count": 1, "static_bucket_count": bucketCount, "static_sha256": stateHash, "all_indexed_anchor_buckets_materialized": true})
	oracles := map[int]map[candidatequery.Pair]bool{}
	expected := map[int][]candidatequery.Pair{}
	start = time.Now()
	for _, i := range valid {
		oracles[i] = f.oracle(trace[i])
		expected[i] = dbSortedPairs(oracles[i])
	}
	dbWrite(t, dir, "oracle.json", map[string]any{"queries": expected, "oracle_ns": time.Since(start).Nanoseconds(), "N": len(areas)})
	// Probe material is never used online; all measured invocations get new IDs.
	u, p, cost := dbProvision(t, f, trace[valid[0]], st, qb[valid[0]])
	seenIDs := map[string]bool{formalPacketID(u): true}
	dbWrite(t, dir, "domain-preflight.json", dbDomainEvidence(t, st, p, len(areas)))
	dbEqual(t, dir, phase, -1, "probe compaction bytes", cost.Compaction, uint64(266*len(areas)))
	u = nil
	p = [2]*discovery.PartyPacket{}
	means := []float64{}
	provisions := 1
	for round := 1; round <= rounds; round++ {
		rd := filepath.Join(dir, fmt.Sprintf("round-%d", round))
		must(t, os.Mkdir(rd, 0700))
		jf, e := os.OpenFile(filepath.Join(rd, "queries.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		must(t, e)
		cf, e := os.OpenFile(filepath.Join(rd, "queries.csv"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		must(t, e)
		enc := json.NewEncoder(jf)
		cw := csv.NewWriter(cf)
		must(t, cw.Write(formalCSVHeader()))
		cw.Flush()
		must(t, cw.Error())
		totalNS := int64(0)
		pairs := 0
		for order, i := range valid {
			q := trace[i]
			dbWrite(t, rd, fmt.Sprintf("query-%04d-start.json", order), map[string]any{"scale": scale, "round": round, "query": i, "order": order, "N": len(areas)})
			r := formalQuery{dbQuery: dbQuery{Phase: phase, Scale: scale, Query: i, Tau: q.Tau, N: len(areas), AnchorQuery: q.Anchor, TargetQuery: q.Target, OraclePairs: len(oracles[i]), Expected: expected[i]}, Round: round, Order: order, TauAnchor: q.Tau, TauTarget: q.Tau, StaticSHA256: stateHash}
			start = time.Now()
			u, p, cost := dbProvision(t, f, q, st, qb[i])
			r.ProvisionNS = time.Since(start).Nanoseconds()
			provisions++
			r.PacketIDHash = formalPacketID(u)
			dbEqual(t, dir, phase, i, "fresh packet ID", seenIDs[r.PacketIDHash], false)
			seenIDs[r.PacketIDHash] = true
			r.Offline = cost
			r.DomainEvidence = dbDomainEvidence(t, st, p, len(areas))
			dbEqual(t, dir, phase, i, "compaction material bytes", cost.Compaction, uint64(266*len(areas)))
			out, m, e := discovery.RunLocal(context.Background(), discovery.Query{Anchor: q.Anchor, Target: q.Target, TauAnchor: q.Tau, TauTarget: q.Tau}, f.keys, u, st, p, scmpnative.Backend{})
			if e != nil {
				dbWrite(t, dir, "first-difference.json", map[string]any{"scale": scale, "round": round, "query": i, "error": e.Error()})
				t.Fatal(e)
			}
			r.Metrics = m
			r.FinalPairs = len(out.Pairs)
			r.Errors, r.Recovered = formalErrors(oracles[i], out.Pairs)
			r.UserToCloud = m.UserToCloud[0] + m.UserToCloud[1]
			r.CloudToUser = m.CloudToUser[0] + m.CloudToUser[1]
			r.ServerBytes = m.ServerBytes
			r.TotalBytes = r.UserToCloud + r.CloudToUser + r.ServerBytes
			must(t, enc.Encode(r))
			must(t, jf.Sync())
			must(t, cw.Write(formalCSVRow(r)))
			cw.Flush()
			must(t, cw.Error())
			must(t, cf.Sync())
			dbEqual(t, dir, phase, i, "correctness", r.Errors, dbErrors{})
			dbEqual(t, dir, phase, i, "Anchor partition", m.AnchorParts.Total(), m.Anchor)
			if scale == 100 {
				formalCrosscheck(t, dir, r, base[i])
			}
			totalNS += m.LocalE2E.Nanoseconds()
			pairs += r.FinalPairs
			if order%20 == 0 {
				t.Logf("MEASURE scale=%d round=%d progress=%d/%d query=%d pairs=%d E2E=%s", scale, round, order+1, len(valid), i, pairs, m.LocalE2E)
			}
		}
		must(t, jf.Close())
		must(t, cf.Close())
		dbEqual(t, dir, phase, -1, "static content unchanged", formalStaticHash(st), stateHash)
		if scale == 100 {
			dbEqual(t, dir, phase, -1, "full pairs", pairs, 1510)
		}
		mean := float64(totalNS) / float64(len(valid)) / 1e6
		means = append(means, mean)
		dbWrite(t, rd, "completion.json", map[string]any{"scale": scale, "round": round, "queries": len(valid), "pairs": pairs, "mean_ms": mean, "errors": dbErrors{}, "static_sha256": stateHash, "fresh_provisions": len(valid)})
		t.Logf("ROUND COMPLETE scale=%d round=%d mean_ms=%.6f pairs=%d", scale, round, mean, pairs)
		if scale == 100 && math.Abs(mean/calibration-1) > .10 {
			dbWrite(t, dir, "first-difference.json", map[string]any{"field": "calibration drift", "round": round, "mean_ms": mean, "calibration_ms": calibration})
			t.Fatal("calibration drift >10%")
		}
		lo, hi := means[0], means[0]
		for _, v := range means {
			lo = math.Min(lo, v)
			hi = math.Max(hi, v)
		}
		if (hi-lo)/lo > .10 {
			dbWrite(t, dir, "first-difference.json", map[string]any{"field": "round stability", "means_ms": means, "relative_spread": (hi - lo) / lo})
			t.Fatal("round stability >10%")
		}
	}
	dbWrite(t, dir, "completion.json", map[string]any{"scale": scale, "N": len(areas), "rounds": rounds, "queries_per_round": len(valid), "means_ms": means, "static_build_count": 1, "provisions": provisions, "unique_packet_ids": len(seenIDs), "static_sha256": stateHash, "status": "passed"})
}

func TestDatabaseScalabilityFormal(t *testing.T) {
	mode := os.Getenv("PMEQ_DATABASE_SCALABILITY")
	if mode != "formal" && mode != "smoke" && mode != "formal-100" {
		t.Skip("explicit formal or smoke opt-in")
	}
	root, e := filepath.Abs("../..")
	must(t, e)
	dir := os.Getenv("PMEQ_DATABASE_SCALABILITY_OUTPUT")
	if root != "/home/tenggn/projects/clean_pmeq" || !filepath.IsAbs(dir) || !filepath.IsLocal(relPath(t, root, dir)) {
		t.Fatal("repository/output boundary")
	}
	for k, want := range map[string]string{"GOMAXPROCS": "32", "GOGC": "100", "GOMEMLIMIT": "off", "GODEBUG": ""} {
		if os.Getenv(k) != want {
			t.Fatal("frozen environment", k)
		}
	}
	if runtime.Version() != "go1.27.1" || runtime.GOMAXPROCS(0) != 32 {
		t.Fatal("Go/parallelism mismatch")
	}
	areas, aliases, _, _ := dbReadInputs(t)
	dbEqual(t, dir, "input", -1, "Anchor count", len(areas), 120071)
	dbEqual(t, dir, "input", -1, "Target count", len(aliases), 67896)
	order := formalOrder(t, areas)
	trace, ref, base, valid := formalTrace(t)
	ranks := map[uint64]int{}
	for i, id := range order {
		ranks[id] = i
	}
	aliasIDs := map[uint64]bool{}
	for _, a := range aliases {
		if _, ok := ranks[a.Area]; !ok || aliasIDs[a.ID] {
			t.Fatal("orphan/duplicate Target")
		}
		aliasIDs[a.ID] = true
	}
	var cal struct {
		Runs []struct {
			Mean float64 `json:"mean_ms"`
		}
	}
	b, e := os.ReadFile("../../results/timing-calibration-20260920/summary.json")
	must(t, e)
	must(t, json.Unmarshal(b, &cal))
	if len(cal.Runs) != 3 {
		t.Fatal("calibration shape")
	}
	calMean := 0.0
	for _, r := range cal.Runs {
		calMean += r.Mean / 3
	}
	scales := []int{20, 40, 60, 80, 100}
	counts := []int{24014, 48028, 72042, 96056, 120071}
	rounds := 3
	if mode == "formal-100" {
		scales = scales[4:]
		counts = counts[4:]
	}
	if mode == "smoke" {
		scales = scales[:1]
		counts = counts[:1]
		rounds = 1
		valid = valid[:2]
	}
	dbWrite(t, dir, "plan.json", map[string]any{"mode": mode, "scales": scales, "counts": counts, "rounds": rounds, "query_ids": valid, "calibration_mean_ms": calMean, "seed": subsetSeed, "domain_label": subsetDomain, "ordered_ids": order})
	previousA, previousB := map[uint64]bool{}, map[uint64]bool{}
	for j, scale := range scales {
		sd := filepath.Join(dir, "scale-"+strconv.Itoa(scale))
		must(t, os.Mkdir(sd, 0700))
		var a []indexbuild.AreaRecord
		var b []indexbuild.AreaAliasRecord
		selected := map[uint64]bool{}
		for _, id := range order[:counts[j]] {
			selected[id] = true
		}
		for _, v := range areas {
			if selected[v.ID] {
				a = append(a, v)
			}
		}
		bid := map[uint64]bool{}
		for _, v := range aliases {
			if selected[v.Area] {
				b = append(b, v)
				bid[v.ID] = true
			}
		}
		dbEqual(t, sd, "subset", -1, "N", len(a), counts[j])
		for id := range previousA {
			if !selected[id] {
				t.Fatal("Anchor nesting")
			}
		}
		for id := range previousB {
			if !bid[id] {
				t.Fatal("Target nesting")
			}
		}
		if len(selected) <= len(previousA) || len(bid) <= len(previousB) {
			t.Fatal("strict nesting")
		}
		if scale == 100 {
			dbEqual(t, sd, "subset", -1, "full Anchor input", a, areas)
			dbEqual(t, sd, "subset", -1, "full Target input", b, aliases)
		}
		dbWrite(t, sd, "subset.json", map[string]any{"scale": scale, "N": len(a), "TargetRecords": len(b), "AnchorIDs": order[:counts[j]], "AnchorInputSHA256": dbHash(dbJSON(t, a)), "TargetInputSHA256": dbHash(dbJSON(t, b)), "strict_nested": true, "join_consistent": true})
		formalScale(t, sd, scale, rounds, a, b, trace, ref, base, valid, calMean)
		previousA, previousB = selected, bid
		runtime.GC() // Release the finished scale only; never per query or round.
	}
	dbWrite(t, dir, "completed.json", map[string]any{"status": "passed", "mode": mode, "scales": scales, "rounds": rounds, "queries_per_round": len(valid)})
}

func TestDatabaseScalabilityHelpers(t *testing.T) {
	p := candidatequery.Pair{AnchorRecordID: 1, TargetRecordID: 2}
	want := map[candidatequery.Pair]bool{p: true}
	e, _ := formalErrors(want, []candidatequery.Pair{p, p, {AnchorRecordID: 3, TargetRecordID: 4}})
	if e != (dbErrors{FP: 1, Duplicates: 1, WrongAnchorID: 1, WrongTargetID: 1}) {
		t.Fatal(e)
	}
	e, _ = formalErrors(want, nil)
	if e.FN != 1 {
		t.Fatal(e)
	}
	if len(formalCSVHeader()) != len(formalCSVRow(formalQuery{})) {
		t.Fatal("CSV schema")
	}
	a := map[int][]uint32{2: {4, 5}, 1: {9}}
	b := map[int][]uint32{1: {9}, 2: {4, 5}}
	digest := func(x any) string {
		h := sha256.New()
		formalHashValue(h, reflect.ValueOf(x))
		return hex.EncodeToString(h.Sum(nil))
	}
	if digest(a) != digest(b) {
		t.Fatal("map order")
	}
	b[2][0]++
	if digest(a) == digest(b) {
		t.Fatal("mutation not detected")
	}
}
