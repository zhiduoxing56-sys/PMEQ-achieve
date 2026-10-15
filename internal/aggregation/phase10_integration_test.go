//go:build phase10integration && phase9integration && phase6native && phase10audit

package aggregation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"pmeq/internal/incidence"
	"pmeq/internal/share"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	agg "pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpnative"
	ta "pmeq/internal/targetaggregation"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
)

var sidecars [2]*ta.PartySidecar
var indices [2]*targetpe.PartyIndex
var aliasJoins map[uint64][]indexbuild.AreaAliasRecord
var query agg.Phase10Query
var packets [2]ta.Packet
var threshold ta.ThresholdToken
var offline ta.OfflineBody

type row struct {
	Query, Tau, K, R, S, G, Pairs     int
	Rejected                          bool
	Offline                           ta.OfflineBody
	Online, Retained, Heap, HeapDelta uint64
	Stages                            [15]time.Duration
}

var rows []row
var auditMu sync.Mutex
var snapshots map[string][2]any

func fail(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func init() {
	agg.Phase10Setup = setup
	agg.Phase10Prepare = prepare
	agg.Phase10After = after
	agg.Phase10Finish = finish
}
func setup(t *testing.T, idx [2]*targetpe.PartyIndex, aliases []indexbuild.AreaAliasRecord) {
	indices = idx
	ta.SetAuditSinkForTesting(func(id [16]byte, party uint8, name string, v any) {
		auditMu.Lock()
		defer auditMu.Unlock()
		if id != query.QueryID {
			panic("audit query binding")
		}
		var copyValue any
		switch a := v.(type) {
		case []incidence.Share:
			copyValue = append([]incidence.Share(nil), a...)
		case []share.BitShare:
			copyValue = append([]share.BitShare(nil), a...)
		case []share.Ring64Share:
			copyValue = append([]share.Ring64Share(nil), a...)
		}
		pair := snapshots[name]
		pair[party] = copyValue
		snapshots[name] = pair
	})
	aliasJoins = map[uint64][]indexbuild.AreaAliasRecord{}
	for _, a := range aliases {
		aliasJoins[a.Area] = append(aliasJoins[a.Area], a)
	}
	for _, a := range aliasJoins {
		sort.Slice(a, func(i, j int) bool { return a[i].ID < a[j].ID })
		if len(a) > 26 {
			t.Fatal("D bound")
		}
	}
	mr, e := os.ReadFile("../../artifacts/phase7b/manifest.json")
	fail(t, e)
	raw, e := os.ReadFile("../../artifacts/phase10b/manifest.json")
	fail(t, e)
	var m ta.SidecarManifest
	fail(t, json.Unmarshal(raw, &m))
	for u, name := range []string{"cs0.aggregation.bin", "cs1.aggregation.bin"} {
		f, e := os.Open(filepath.Join("../../artifacts/phase10b", name))
		fail(t, e)
		sidecars[u], e = ta.LoadSidecar(m, mr, idx[u], f)
		f.Close()
		fail(t, e)
	}
	// Manifest mismatch must fail before accepting any sidecar body.
	bad := m
	bad.ManifestSHA256 = "bad"
	if _, e = ta.LoadSidecar(bad, mr, idx[0], bytes.NewReader(nil)); e == nil {
		t.Fatal("sidecar binding")
	}
	t.Log("PHASE10 sidecars loaded: all 65536 buckets/310331 groups/1317260 slots match sealed Position order")
}
func prepare(t *testing.T, q agg.Phase10Query) {
	query = q
	snapshots = map[string][2]any{}
	packets = [2]ta.Packet{}
	offline = ta.OfflineBody{}
	if _, e := ta.Threshold(q.R, q.Tau); e != nil {
		return
	}
	u, a, b, n, e := ta.Preprocess(indices[0].Lineage(), ta.Shape{K: q.K, R: q.R, S: q.S, G: q.G}, scmpnative.Backend{})
	fail(t, e)
	threshold, e = u.Token(q.QueryID, q.Tau)
	fail(t, e)
	packets = [2]ta.Packet{a, b}
	offline = n
}
func after(t *testing.T, h [2]targetposition.TargetPostingHits, g [2]targetpe.TargetGroupMatches, anchors []uint64) {
	q := query
	record := row{Query: q.Query, Tau: q.Tau, K: q.K, R: q.R, S: q.S, G: q.G, Offline: offline}
	if len(h[0].HitShares) != q.S || len(g[0].MatchShares) != q.G || len(anchors) != q.K {
		t.Fatal("physical workload")
	}
	if _, e := ta.Threshold(q.R, q.Tau); e != nil {
		record.Rejected = true
		rows = append(rows, record)
		return
	}
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	var out [2]ta.CandidatePairShares
	var metrics [2]ta.Metrics
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	ch := [2]chan []byte{make(chan []byte, 1), make(chan []byte, 1)}
	errs := make(chan error, 2)
	var peaks [2]uint64
	for u := 0; u < 2; u++ {
		go func(u int) {
			ex := func(m []byte) ([]byte, error) {
				if len(m) > 4096 {
					var ms runtime.MemStats
					runtime.ReadMemStats(&ms)
					peaks[u] = max(peaks[u], ms.HeapAlloc)
				}
				select {
				case ch[u] <- m:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				select {
				case p := <-ch[1-u]:
					return p, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			var e error
			out[u], metrics[u], e = ta.Run(sidecars[u], h[u], g[u], packets[u], threshold, scmpnative.Backend{}, ex)
			if e != nil {
				cancel()
			}
			errs <- e
		}(u)
	}
	for u := 0; u < 2; u++ {
		fail(t, <-errs)
	}
	for i := range record.Stages {
		record.Stages[i] = metrics[0].Stages[i] + metrics[1].Stages[i]
	}
	record.Online = metrics[0].OnlineBytes + metrics[1].OnlineBytes
	record.Retained = uint64(34 * q.K * 26)
	record.Heap = max(peaks[0], peaks[1])
	if record.Heap > baseline.HeapAlloc {
		record.HeapDelta = record.Heap - baseline.HeapAlloc
	}
	words := anchorfilter.QueryChunks(q.Target)
	seen := map[[2]uint64]bool{}
	for c, anchor := range anchors {
		aliases := aliasJoins[anchor]
		for u := 0; u < 26; u++ {
			count := 0
			first := -1
			var expectedID uint64
			if u < len(aliases) {
				a := aliases[u]
				for hi, w := range words {
					fcount := 0
					hit := false
					indexbuild.VisitQGrams(a.Name, func(gram string, p uint32) {
						d := int(p) - int(w.Position)
						if d < 0 {
							d = -d
						}
						if gram == w.QGram && d <= q.Tau {
							hit = true
							fcount++
						}
					})
					checkAudit(t, "F", (c*q.R+hi)*26+u, uint64(fcount))
					checkAudit(t, "z", (c*q.R+hi)*26+u, bit(hit))
					checkAudit(t, "rep", (c*q.R+hi)*26+u, bit(hit && first < 0))
					if hit {
						if first < 0 {
							first = hi
						}
						count++
					}
				}
				expectedID = a.ID
			} else {
				for hi := 0; hi < q.R; hi++ {
					for _, stage := range []string{"F", "z", "rep"} {
						checkAudit(t, stage, (c*q.R+hi)*26+u, 0)
					}
				}
			}
			checkAudit(t, "C", c*26+u, uint64(count))
			selected := uint64(0)
			if count > 0 {
				selected = expectedID
			}
			checkAudit(t, "selected", c*26+u, selected)
			want := count >= q.R-q.Tau
			checkAudit(t, "Keep", c*26+u, bit(want))
			j := c*26 + u
			keep := bool(out[0].PairKeepShares[j].Value().Add(out[1].PairKeepShares[j].Value()))
			aid := uint64(out[0].AnchorIDShares[j].Value() + out[1].AnchorIDShares[j].Value())
			tid := uint64(out[0].TargetIDShares[j].Value() + out[1].TargetIDShares[j].Value())
			checkAudit(t, "Anchor", j, aid)
			checkAudit(t, "Target", j, tid)
			if keep != want {
				t.Fatalf("pair predicate query=%d c=%d u=%d got=%v want=%v", q.Query, c, u, keep, want)
			}
			if want {
				if aid != anchor || tid != expectedID {
					t.Fatal("wrong pair ID", q.Query, c, u, aid, tid)
				}
				key := [2]uint64{aid, tid}
				if seen[key] {
					t.Fatal("duplicate pair")
				}
				seen[key] = true
				record.Pairs++
			} else if aid != 0 || tid != 0 {
				t.Fatal("inactive IDs not zero")
			}
		}
	}
	packets = [2]ta.Packet{}
	rows = append(rows, record)
	if len(rows)%50 == 0 {
		t.Logf("PHASE10 query=%d K=%d r=%d S=%d pairs=%d errors=0", q.Query, q.K, q.R, q.S, record.Pairs)
	}
}
func finish(t *testing.T) {
	rejected, routes, slots, groups, pairs := 0, 0, 0, 0, 0
	for _, r := range rows {
		if r.Rejected {
			rejected++
		}
		routes += r.K * r.R
		slots += r.S
		groups += r.G
		pairs += r.Pairs
	}
	if len(rows) != 1003 || rejected != 149 || routes != 466105 || slots != 9380900 || groups != 2209949 {
		t.Fatal("replay totals", len(rows), rejected, routes, slots, groups)
	}
	raw, e := json.Marshal(rows)
	fail(t, e)
	fail(t, os.WriteFile("../../results/phase10b-queries.json", append(raw, '\n'), 0600))
	t.Logf("PHASE10 queries=%d rejected=%d pair_verified=%d routes=%d groups=%d slots=%d pairs=%d false_positive=0 false_negative=0 duplicates=0 wrong_anchor=0 wrong_target=0", len(rows), rejected, len(rows)-rejected, routes, groups, slots, pairs)
}

func bit(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}
func checkAudit(t *testing.T, name string, i int, want uint64) {
	t.Helper()
	a := snapshots[name]
	var got uint64
	switch x := a[0].(type) {
	case []incidence.Share:
		y := a[1].([]incidence.Share)
		got = uint64(x[i].Value().Add(y[i].Value()))
	case []share.BitShare:
		y := a[1].([]share.BitShare)
		got = bit(bool(x[i].Value().Add(y[i].Value())))
	case []share.Ring64Share:
		y := a[1].([]share.Ring64Share)
		got = uint64(x[i].Value() + y[i].Value())
	default:
		t.Fatal("missing audit", name)
	}
	if got != want {
		t.Fatalf("stage %s query=%d i=%d got=%d want=%d", name, query.Query, i, got, want)
	}
}
