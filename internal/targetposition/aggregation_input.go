package targetposition

import (
	"pmeq/internal/share"
	"pmeq/internal/targetpe"
)

// RetainedGroupMatches returns the original party-local PE result after
// Position completes. It does not rerun PE, reconstruct Match, or export any
// peer input. PHASE10 checks it against the same posting-output lineage.
func (s *Session) RetainedGroupMatches() (targetpe.TargetGroupMatches, error) {
	if !s.done || s.in.QueryID == [16]byte{} {
		return targetpe.TargetGroupMatches{}, ErrBinding
	}
	o := s.in
	o.MatchShares = append([]share.BitShare(nil), s.in.MatchShares...)
	o.AnchorRecordIDShare = append([]share.Ring64Share(nil), s.in.AnchorRecordIDShare...)
	o.Routes = append([]targetpe.Route(nil), s.in.Routes...)
	s.in = targetpe.TargetGroupMatches{}
	return o, nil
}
