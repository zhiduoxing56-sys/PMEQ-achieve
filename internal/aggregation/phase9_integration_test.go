//go:build phase9integration && phase6native

package aggregation

import (
	"encoding/json"
	"os"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpnative"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
	"pmeq/internal/targetquery"
	"pmeq/internal/targetrouting"
	"sort"
	"testing"
)

type postingOracleSlot struct {
	p     uint32
	valid bool
}

var postingOracle map[uint32][][]postingOracleSlot
var postingPackets [2]targetposition.Packet
var postingCounts []int
var postingTotal, postingHits, postingZero int
var postingOffline uint64

// PHASE10 hooks belong only to this opt-in trusted test harness. External
// test packages can extend the real chain without a production import cycle.
type Phase10Query struct {
	Query, Tau, K, R, S, G int
	Target                 string
	QueryID                [16]byte
}

var Phase10Setup func(*testing.T, [2]*targetpe.PartyIndex, []indexbuild.AreaAliasRecord)
var Phase10Prepare func(*testing.T, Phase10Query)
var Phase10After func(*testing.T, [2]targetposition.TargetPostingHits, [2]targetpe.TargetGroupMatches, []uint64)
var Phase10Finish func(*testing.T)

func init() {
	setupPostingOracle = setupPostings
	preparePostingToken = preparePostings
	afterGroupPE = checkPostings
	finishPosting = finishPostings
}
func setupPostings(t *testing.T, h *harness, ps [2]indexbuild.PartyIndex) {
	postingOracle = map[uint32][][]postingOracleSlot{}
	for bi, b := range ps[0].TargetBuckets {
		for gi, g := range b.Groups {
			var slots []postingOracleSlot
			for si, s := range g.Slots {
				peer := ps[1].TargetBuckets[bi].Groups[gi].Slots[si]
				p := uint32(s.PositionShare.Value() + peer.PositionShare.Value())
				v := bool(s.ValidityShare.Value().Add(peer.ValidityShare.Value()))
				if p > 62 {
					t.Fatal("signed SCMP domain", p)
				}
				slots = append(slots, postingOracleSlot{p, v})
			}
			postingOracle[b.BucketID] = append(postingOracle[b.BucketID], slots)
		}
	}
	f, e := os.Open("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area_alias")
	must(t, e)
	rows, stats, e := indexbuild.LoadAreaAliasWithStats(f, 0)
	must(t, e)
	f.Close()
	maxP, maxL, maxQ := 0, 0, 0
	for _, r := range rows {
		n := len([]rune(r.Name))
		if n >= 4 {
			maxL = max(maxL, n)
			maxP = max(maxP, n-4)
			maxQ = max(maxQ, 4*(n/4-1))
		}
	}
	t.Logf("TARGET_DOMAIN records=%d indexed=%d short=%d max_posting=%d max_runes=%d max_query_position=%d Bin=7 Bout=1", len(rows), stats.IndexedRecords, stats.ShortNames, maxP, maxL, maxQ)
	if maxP > 62 || maxQ > 62 {
		t.Fatal("Target domain exceeds frozen Bin7")
	}
	if Phase10Setup != nil {
		Phase10Setup(t, peExp.idx, rows)
	}
}
func preparePostings(t *testing.T, h *harness, q peWorkload) (targetrouting.QueryToken, targetrouting.QueryToken) {
	// Trusted offline replay provisioning from the previously published workload.
	// Production uses a reserved upper bound. This happens before initial token,
	// before Anchor, never from secret Match or a cloud query-time dealer call.
	capacities := make([]int, len(q.Words))
	groupCapacity := 0
	for _, j := range q.Joins {
		a, e := targetcrypto.JoinBucketComponent(h.kt, j, 16)
		must(t, e)
		for hi, w := range q.Words {
			b, e := targetcrypto.WordBucketComponent(h.kt, w.QGram, 16)
			must(t, e)
			groupCapacity += len(postingOracle[uint32(a)^uint32(b)])
			for _, gs := range postingOracle[uint32(a)^uint32(b)] {
				capacities[hi] += len(gs)
			}
		}
	}
	users, a, b, n, e := targetposition.Preprocess(peExp.idx[0].Lineage(), capacities, scmpnative.Backend{})
	must(t, e)
	postingPackets = [2]targetposition.Packet{a, b}
	postingOffline += 2 * (n.SCMP + n.Beaver)
	// Same supported threshold family as Anchor, selected at initial QueryToken.
	u, v, e := targetquery.GeneratePositionTokens(peExp.idx[0].Manifest(), h.kt, q.Target, uint32(q.Tau), users)
	must(t, e)
	if Phase10Prepare != nil {
		slots := 0
		for _, n := range capacities {
			slots += n
		}
		Phase10Prepare(t, Phase10Query{q.Query, q.Tau, len(q.Joins), len(q.Words), slots, groupCapacity, q.Target, u.QueryID})
	}
	return u, v
}
func checkPostings(t *testing.T, a, b targetpe.TargetGroupMatches, c peContext, ids []uint64) {
	x, e := targetposition.Begin(peExp.idx[0], a, c.a, postingPackets[0], scmpnative.Backend{})
	must(t, e)
	y, e := targetposition.Begin(peExp.idx[1], b, c.b, postingPackets[1], scmpnative.Backend{})
	must(t, e)
	for !x.Done() {
		u, e := x.Next()
		must(t, e)
		v, e := y.Next()
		must(t, e)
		must(t, x.Accept(v))
		must(t, y.Accept(u))
	}
	o, e := x.Output()
	must(t, e)
	p, e := y.Output()
	must(t, e)
	if Phase10After != nil {
		gm0, err := x.RetainedGroupMatches()
		must(t, err)
		gm1, err := y.RetainedGroupMatches()
		must(t, err)
		Phase10After(t, [2]targetposition.TargetPostingHits{o, p}, [2]targetpe.TargetGroupMatches{gm0, gm1}, ids)
	}
	hits := 0
	for ri, r := range o.Routes {
		off := r.SlotOffset
		for gi, g := range postingOracle[r.BucketID] {
			key := peExp.keys[r.BucketID][gi]
			for si, slot := range g {
				delta := int(slot.p) - int(c.q.Words[r.OccurrenceID].Position)
				if delta < 0 {
					delta = -delta
				}
				expected := key.j == ids[r.CandidateIndex] && key.w == c.q.Words[r.OccurrenceID].QGram && delta <= c.q.Tau && slot.valid
				got := bool(o.HitShares[off].Value().Add(p.HitShares[off].Value()))
				if got != expected {
					t.Fatal("Target posting oracle", peExp.queries, ri, gi, si)
				}
				if got {
					hits++
				}
				off++
			}
		}
		if off != r.SlotOffset+r.SlotCount {
			t.Fatal("slot order")
		}
	}
	n := len(o.HitShares)
	m0, m1 := x.Metrics(), y.Metrics()
	if m0.SCMPBytes+m1.SCMPBytes != uint64(16*n) || m0.ANDBytes+m1.ANDBytes != uint64(8*n) {
		t.Fatal("codec bytes")
	}
	postingTotal += n
	postingHits += hits
	if hits == 0 {
		postingZero++
	}
	postingCounts = append(postingCounts, n)
	postingPackets = [2]targetposition.Packet{}
}
func finishPostings(t *testing.T) {
	if Phase10Finish != nil {
		Phase10Finish(t)
	}
	raw, e := json.Marshal(postingCounts)
	must(t, e)
	if path := os.Getenv("PMEQ_POSITION_COUNTS"); path != "" {
		must(t, os.WriteFile(path, raw, 0600))
	}
	sort.Ints(postingCounts)
	pct := func(p int) int { return postingCounts[(len(postingCounts)*p+99)/100-1] }
	t.Logf("TARGET_POSITION queries=%d routes=%d groups=%d physical_slots=%d hits=%d zero_hit_queries=%d errors=0 S min=%d p50=%d p90=%d p95=%d p99=%d max=%d offline_bytes=%d", len(postingCounts), peExp.routes, peExp.groups, postingTotal, postingHits, postingZero, postingCounts[0], pct(50), pct(90), pct(95), pct(99), postingCounts[len(postingCounts)-1], postingOffline)
}
