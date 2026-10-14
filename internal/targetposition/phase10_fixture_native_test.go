//go:build phase6native

package targetposition

import (
	"pmeq/internal/anchorfilter"
	"pmeq/internal/scmpnative"
	"pmeq/internal/targetpe"
	"testing"
)

type Phase10BenchmarkFixture struct {
	S       int
	Index   [2]*targetpe.PartyIndex
	Hits    [2]TargetPostingHits
	Matches [2]targetpe.TargetGroupMatches
	Tau     int
}

// BuildPhase10BenchmarkFixtures is available only to this package's tests.
// It reuses the PHASE9 saved-real-workload routing/PE fixture builder and runs
// real native Position once, without constructing any Hit from an oracle.
func BuildPhase10BenchmarkFixtures(t *testing.T) []Phase10BenchmarkFixture {
	var out []Phase10BenchmarkFixture
	for _, f := range positionFixturesAt(t, true) {
		users, a, b, _, e := Preprocess(f.idx[0].Lineage(), f.capacities, scmpnative.Backend{})
		must(t, e)
		tok := f.tokens
		for u := range tok {
			tok[u].Position = make([]anchorfilter.PositionToken, len(users))
		}
		for hi := range users {
			pid, l, r, e := users[hi].ConsumeBounds(uint32(4*hi), f.tau, 62)
			must(t, e)
			p := anchorfilter.PositionToken{PID: pid, Ltilde: l, RplusTilde: r}
			tok[0].Position[hi] = p
			tok[1].Position[hi] = p
		}
		x, e := Begin(f.idx[0], f.matches[0], tok[0], a, scmpnative.Backend{})
		must(t, e)
		y, e := Begin(f.idx[1], f.matches[1], tok[1], b, scmpnative.Backend{})
		must(t, e)
		for !x.Done() {
			m, e := x.Next()
			must(t, e)
			n, e := y.Next()
			must(t, e)
			must(t, x.Accept(n))
			must(t, y.Accept(m))
		}
		h0, e := x.Output()
		must(t, e)
		h1, e := y.Output()
		must(t, e)
		g0, e := x.RetainedGroupMatches()
		must(t, e)
		g1, e := y.RetainedGroupMatches()
		must(t, e)
		out = append(out, Phase10BenchmarkFixture{f.S, f.idx, [2]TargetPostingHits{h0, h1}, [2]targetpe.TargetGroupMatches{g0, g1}, int(f.tau)})
	}
	return out
}
