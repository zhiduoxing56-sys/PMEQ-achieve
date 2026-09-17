//go:build phase7integration && !phase8integration

package aggregation

import (
	"crypto/rand"
	"encoding/json"
	"github.com/gtank/ristretto255"
	mathrand "math/rand"
	"os"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/indexbuild"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetquery"
	"pmeq/internal/targetrouting"
	"sort"
	"testing"
)

type joinWord struct {
	j uint64
	w string
}
type indexedPoint struct {
	point  [32]byte
	bucket uint16
}
type targetExperiment struct {
	manifest                                             targetrouting.Manifest
	aliases                                              []indexbuild.AreaAliasRecord
	byArea                                               map[uint64][]indexbuild.AreaAliasRecord
	repeated                                             []indexbuild.AreaAliasRecord
	points                                               map[[32]byte]uint16
	logical                                              map[joinWord]indexedPoint
	queries, positive, negative, repeats, pairs, present int
}

var routeExperiment *targetExperiment

func init() {
	harnessTargetBits = 8
	realHarnessSetup = setupTargetRouting
	beforeRoutingQuery = beforeTargetRouting
	afterRoutingQuery = afterTargetRouting
	finishRoutingQueries = finishTargetRouting
}
func asRoutes(c CompactedCandidates) targetrouting.Candidates {
	return targetrouting.Candidates{LayoutID: c.LayoutID, CompactionID: c.CompactionID, TargetBucketBits: c.TargetBucketBits, K: c.K, RecordIDShare: c.RecordIDShare, KappaJoinShare: c.KappaJoinShare, BucketJoinShare: c.BucketJoinShare}
}
func combinedPoint(t *testing.T, a, b targetcrypto.PointShare) [32]byte {
	t.Helper()
	u, e := ristretto255.NewElement().SetCanonicalBytes(a[:])
	must(t, e)
	v, e := ristretto255.NewElement().SetCanonicalBytes(b[:])
	must(t, e)
	var out [32]byte
	copy(out[:], ristretto255.NewElement().Add(u, v).Bytes())
	return out
}
func setupTargetRouting(t *testing.T, h *harness) {
	f, e := os.Open("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area_alias")
	must(t, e)
	aliases, e := indexbuild.LoadAreaAlias(f, 0)
	f.Close()
	must(t, e)
	x := &targetExperiment{byArea: map[uint64][]indexbuild.AreaAliasRecord{}, points: map[[32]byte]uint16{}, logical: map[joinWord]indexedPoint{}}
	counts := []int{}
	short := 0
	for _, a := range aliases {
		chunks := anchorfilter.QueryChunks(a.Name)
		if len(chunks) == 0 {
			short++
			continue
		}
		counts = append(counts, len(chunks))
		x.aliases = append(x.aliases, a)
		x.byArea[a.Area] = append(x.byArea[a.Area], a)
		seen := map[string]bool{}
		repeat := false
		for _, c := range chunks {
			if seen[c.QGram] {
				repeat = true
			}
			seen[c.QGram] = true
		}
		if repeat {
			x.repeated = append(x.repeated, a)
		}
	}
	aliasRNG := mathrand.New(mathrand.NewSource(707))
	aliasRNG.Shuffle(len(x.aliases), func(i, j int) { x.aliases[i], x.aliases[j] = x.aliases[j], x.aliases[i] })
	sort.Ints(counts)
	pct := func(p int) int { return counts[(len(counts)*p+99)/100-1] }
	t.Logf("TARGET_WORKLOAD raw=%d short=%d normal=%d repeated=%d r min=%d p50=%d p90=%d p95=%d p99=%d max=%d", len(aliases), short, len(counts), len(x.repeated), counts[0], pct(50), pct(90), pct(95), pct(99), counts[len(counts)-1])
	// Current PSMJ setting: fully materialize all aliases at explicit target bits=8.
	meta, a, b, stats, e := indexbuild.Build(nil, aliases, h.kb, h.kt, 16, 8)
	must(t, e)
	var indexID [16]byte
	_, e = rand.Read(indexID[:])
	must(t, e)
	x.manifest, e = targetrouting.FromMetadata(indexID, meta)
	must(t, e)
	for bi, bucket := range a.TargetBuckets {
		for gi, g := range bucket.Groups {
			p := combinedPoint(t, g.TargetKeyShare, b.TargetBuckets[bi].Groups[gi].TargetKeyShare)
			if _, ok := x.points[p]; ok {
				t.Fatal("duplicate group point")
			}
			x.points[p] = bucket.BucketID
		}
	}
	// Build an independent logical-key oracle and match EVERY materialized point.
	for _, alias := range aliases {
		indexbuild.VisitQGrams(alias.Name, func(w string, _ uint32) {
			key := joinWord{alias.Area, w}
			if _, ok := x.logical[key]; ok {
				return
			}
			p, e := targetcrypto.DeriveTargetGroupPoint(h.kt, key.j, w)
			must(t, e)
			var encoded [32]byte
			copy(encoded[:], p.Bytes())
			jb, e := targetcrypto.JoinBucketComponent(h.kt, key.j, 8)
			must(t, e)
			wb, e := targetcrypto.WordBucketComponent(h.kt, w, 8)
			must(t, e)
			bucket := uint16(targetcrypto.CombineBucketComponents(jb, wb))
			if x.points[encoded] != bucket {
				t.Fatal("index bucket mismatch")
			}
			if _, ok := x.points[encoded]; !ok {
				t.Fatal("index missing group")
			}
			x.logical[key] = indexedPoint{encoded, bucket}
		})
	}
	if len(x.logical) != 310331 || len(x.points) != 310331 {
		t.Fatal("PSMJ count", len(x.logical), len(x.points))
	}
	t.Logf("PSMJ materialized target_bits=8 anchor_bits=16 groups=%d padded=%d all_group_checks=0 errors", len(x.logical), stats.Target.PaddedSlots)
	routeExperiment = x
	if os.Getenv("PMEQ_ROUTING_SKIP_GROUPS") != "1" {
		checkRouting100k(t, h, x)
	}
}
func routePair(t *testing.T, x *targetExperiment, a, b CompactedCandidates, u, v targetrouting.QueryToken) (targetrouting.RoutedCandidates, targetrouting.RoutedCandidates) {
	t.Helper()
	wa, e := targetrouting.EncodeToken(u)
	must(t, e)
	wb, e := targetrouting.EncodeToken(v)
	must(t, e)
	u, e = targetrouting.DecodeToken(x.manifest, 0, wa)
	must(t, e)
	v, e = targetrouting.DecodeToken(x.manifest, 1, wb)
	must(t, e)
	p, m, e := targetrouting.Prepare(x.manifest, 0, asRoutes(a), u, 4)
	must(t, e)
	q, n, e := targetrouting.Prepare(x.manifest, 1, asRoutes(b), v, 4)
	must(t, e)
	left, e := p.Finish(n)
	must(t, e)
	right, e := q.Finish(m)
	must(t, e)
	return left, right
}
func checkRouting100k(t *testing.T, h *harness, x *targetExperiment) {
	keys := make([]joinWord, 0, len(x.logical))
	byJ := map[uint64][]joinWord{}
	byW := map[string][]joinWord{}
	for k := range x.logical {
		keys = append(keys, k)
		byJ[k.j] = append(byJ[k.j], k)
		byW[k.w] = append(byW[k.w], k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].j != keys[j].j {
			return keys[i].j < keys[j].j
		}
		return keys[i].w < keys[j].w
	})
	unequal := 0
	categories := [3]int{}
	for i := 0; i < 100000; i++ {
		key := keys[i]
		g, ok := h.global.gamma[key.j]
		if !ok {
			t.Fatal("alias join absent")
		}
		a, b := CompactedCandidates{LayoutID: h.global.LayoutID, CompactionID: [16]byte{7}, TargetBucketBits: 8, K: 1}, CompactedCandidates{LayoutID: h.global.LayoutID, CompactionID: [16]byte{7}, TargetBucketBits: 8, K: 1}
		ap, bp := h.payload0.Slots[g], h.payload1.Slots[g]
		a.RecordIDShare = []share.Ring64Share{ap.RecordIDShare}
		b.RecordIDShare = []share.Ring64Share{bp.RecordIDShare}
		a.KappaJoinShare = []targetcrypto.ScalarShare{ap.KappaJoinShare}
		b.KappaJoinShare = []targetcrypto.ScalarShare{bp.KappaJoinShare}
		a.BucketJoinShare = []targetcrypto.BucketShare{ap.BucketJoinShare}
		b.BucketJoinShare = []targetcrypto.BucketShare{bp.BucketJoinShare}
		u, v, e := targetquery.GenerateTokens(x.manifest, h.kt, key.w)
		must(t, e)
		left, right := routePair(t, x, a, b, u, v)
		point := combinedPoint(t, left.Routes[0].Y, right.Routes[0].Y)
		if point != x.logical[key].point || left.Routes[0].BucketID != x.logical[key].bucket || right.Routes[0].BucketID != left.Routes[0].BucketID {
			t.Fatal("equal", i)
		}
		// Pick unequal existing groups, covering all three requested categories.
		category := i % 3
		var other joinWord
		if category == 0 {
			for _, v := range byJ[key.j] {
				if v.w != key.w {
					other = v
					break
				}
			}
		} else if category == 1 {
			for _, v := range byW[key.w] {
				if v.j != key.j {
					other = v
					break
				}
			}
		}
		if other == (joinWord{}) {
			category = 2
			for z := 1; ; z++ {
				v := keys[(i+z*7919)%len(keys)]
				if v.j != key.j && v.w != key.w {
					other = v
					break
				}
			}
		}
		if point == x.logical[other].point {
			t.Fatal("unequal collision")
		}
		categories[category]++
		unequal++
	}
	if categories[0] == 0 || categories[1] == 0 || categories[2] == 0 {
		t.Fatal("unequal coverage")
	}
	t.Logf("GROUP_ROUTING equal=100000 unequal=%d categories=%v errors=0", unequal, categories)
}

type routingQueryContext struct {
	u, v     targetrouting.QueryToken
	text     string
	positive bool
	anchor   string
	tau      int
}

func beforeTargetRouting(t *testing.T, h *harness, Q string, tau int) any {
	x := routeExperiment
	if x == nil {
		return nil
	}
	counts := map[uint64]int{}
	chunks := anchorfilter.QueryChunks(Q)
	for _, c := range chunks {
		seen := map[uint64]bool{}
		lo, hi := anchorfilter.Bounds(c.Position, uint32(tau), 62)
		for _, p := range h.words[c.QGram] {
			if p.pos >= lo && p.pos <= hi {
				seen[p.id] = true
			}
		}
		for id := range seen {
			counts[id]++
		}
	}
	candidates := map[uint64]bool{}
	for id, n := range counts {
		if n >= len(chunks)-tau {
			candidates[id] = true
		}
	}
	var selected indexbuild.AreaAliasRecord
	positive := false
	if x.queries%2 == 0 {
		ids := make([]uint64, 0, len(candidates))
		for id := range candidates {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			if len(x.byArea[id]) > 0 {
				selected = x.byArea[id][0]
				positive = true
				break
			}
		}
	}
	if selected.Name == "" {
		for z := 0; ; z++ {
			selected = x.aliases[(x.queries*7919+z)%len(x.aliases)]
			if !candidates[selected.Area] {
				break
			}
		}
	}
	if x.queries%17 == 0 && len(x.repeated) > 0 {
		selected = x.repeated[x.queries%len(x.repeated)]
		positive = candidates[selected.Area]
	}
	u, v, e := targetquery.GenerateTokens(x.manifest, h.kt, selected.Name)
	must(t, e)
	x.queries++
	if positive {
		x.positive++
	} else {
		x.negative++
	}
	seen := map[string]bool{}
	for _, c := range anchorfilter.QueryChunks(selected.Name) {
		if seen[c.QGram] {
			x.repeats++
			break
		}
		seen[c.QGram] = true
	}
	return routingQueryContext{u, v, selected.Name, positive, Q, tau}
}
func afterTargetRouting(t *testing.T, h *harness, a, b CompactedCandidates, ctx any) {
	if ctx == nil {
		return
	}
	x := routeExperiment
	c := ctx.(routingQueryContext)
	left, right := routePair(t, x, a, b, c.u, c.v)
	words := anchorfilter.QueryChunks(c.text)
	if path := os.Getenv("PMEQ_ROUTING_WORKLOAD"); path != "" {
		joins := make([]uint64, a.K)
		for i := range joins {
			joins[i] = uint64(a.RecordIDShare[i].Value() + b.RecordIDShare[i].Value())
		}
		record := map[string]any{"Query": x.queries - 1, "Anchor": c.anchor, "Tau": c.tau, "Target": c.text, "Positive": c.positive, "CompactionID": a.CompactionID, "Joins": joins, "Words": words}
		f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		must(t, e)
		must(t, json.NewEncoder(f).Encode(record))
		must(t, f.Close())
	}
	if left.CompactionID != a.CompactionID || right.CompactionID != a.CompactionID || len(left.Routes) != a.K*len(words) {
		t.Fatal("routing association")
	}
	for ci := 0; ci < a.K; ci++ {
		j := uint64(a.RecordIDShare[ci].Value() + b.RecordIDShare[ci].Value())
		if left.AnchorRecordIDShare[ci] != a.RecordIDShare[ci] || right.AnchorRecordIDShare[ci] != b.RecordIDShare[ci] {
			t.Fatal("ID association")
		}
		for h, w := range words {
			at := ci*len(words) + h
			u, v := left.Routes[at], right.Routes[at]
			point := combinedPoint(t, u.Y, v.Y)
			expected, e := targetcrypto.DeriveTargetGroupPoint(harnessKey(t), j, w.QGram)
			must(t, e)
			var exp [32]byte
			copy(exp[:], expected.Bytes())
			jb, e := targetcrypto.JoinBucketComponent(harnessKey(t), j, 8)
			must(t, e)
			wb, e := targetcrypto.WordBucketComponent(harnessKey(t), w.QGram, 8)
			must(t, e)
			bucket := uint16(targetcrypto.CombineBucketComponents(jb, wb))
			if point != exp || u.BucketID != bucket || v.BucketID != bucket || u.CandidateIndex != uint32(ci) || u.OccurrenceID != uint32(h) {
				t.Fatal("routing oracle")
			}
			_, exists := x.logical[joinWord{j, w.QGram}]
			actual, found := x.points[point]
			if found != exists || found && actual != bucket {
				t.Fatal("PSMJ identity")
			}
			if found {
				x.present++
			}
			x.pairs++
		}
	}
}
func harnessKey(t *testing.T) targetcrypto.MasterKey {
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(255 - i)
	}
	k, e := targetcrypto.NewMasterKey(raw)
	must(t, e)
	return k
}
func finishTargetRouting(t *testing.T) {
	x := routeExperiment
	if x.positive == 0 || x.negative == 0 || x.repeats == 0 {
		t.Fatal("real coverage")
	}
	t.Logf("PRIVATE_ROUTING queries=%d positive=%d negative=%d repeated=%d pairs=%d present_groups=%d errors=0", x.queries, x.positive, x.negative, x.repeats, x.pairs, x.present)
}
