package targetposition

import (
	"pmeq/internal/share"
	"pmeq/internal/targetpe"
	"testing"
)

func TestRetainedGroupMatchesSingleConsume(t *testing.T) {
	s := &Session{in: targetpe.TargetGroupMatches{QueryID: [16]byte{1}, MatchShares: []share.BitShare{share.NewBitShare(true)}}}
	if _, e := s.RetainedGroupMatches(); e == nil {
		t.Fatal("unfinished Position exposed handoff")
	}
	s.done = true
	g, e := s.RetainedGroupMatches()
	if e != nil || len(g.MatchShares) != 1 || !g.MatchShares[0].Value() {
		t.Fatal("lost original Match", e)
	}
	if _, e = s.RetainedGroupMatches(); e == nil {
		t.Fatal("handoff consumed twice")
	}
}
