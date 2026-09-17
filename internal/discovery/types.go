// Package discovery runs the supported PMEQ protocol using party-local state.
// The local coordinator is a transport/user harness, never a cloud principal.
package discovery

import (
	"errors"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"pmeq/internal/f2beaver"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
	"pmeq/internal/targetrouting"
	"sync"
)

var ErrDomain = errors.New("discovery: query outside q=4, tau_i<r_i, Anchor r<=14, Target r<=16 domain")
var ErrBinding = errors.New("discovery: invalid binding, capacity, transcript or consumed packet")

type Query struct {
	Anchor, Target       string
	TauAnchor, TauTarget int
}

func Validate(q Query) error {
	if _, e := aggregation.Threshold(len(anchorfilter.QueryChunks(q.Anchor)), q.TauAnchor); e != nil {
		return ErrDomain
	}
	if _, e := targetaggregation.Threshold(len(anchorfilter.QueryChunks(q.Target)), q.TauTarget); e != nil {
		return ErrDomain
	}
	return nil
}

type UserKeys struct {
	Anchor anchorindex.Key
	Target targetcrypto.MasterKey
}

// AnchorStatic is a single party's offline authenticated bucket extension.
// Exactly one of Stage0/Stage1 is nonnil, according to party identity.
type AnchorStatic struct {
	Bucket    indexbuild.AnchorPartyBucket
	Incidence *incidence.PartyMatrix
	Stage0    *aggregation.Stage0
	Stage1    *aggregation.Stage1
}
type Static struct {
	party   uint8
	anchor  map[uint16]AnchorStatic
	payload aggregation.PartyPayload
	target  *targetpe.PartyIndex
	sidecar *targetaggregation.PartySidecar
}

func NewStatic(party uint8, anchor map[uint16]AnchorStatic, payload aggregation.PartyPayload, target *targetpe.PartyIndex, sidecar *targetaggregation.PartySidecar) (*Static, error) {
	if party > 1 || target == nil || sidecar == nil || target.Party() != party || payload.LayoutID != target.Lineage().LayoutID || len(payload.Slots) != aggregation.CandidateCount {
		return nil, ErrBinding
	}
	for id, a := range anchor {
		if a.Bucket.BucketID != id || a.Incidence == nil || (party == 0 && (a.Stage0 == nil || a.Stage1 != nil || a.Stage0.LayoutID != payload.LayoutID || a.Stage0.BucketID != id)) || (party == 1 && (a.Stage1 == nil || a.Stage0 != nil || a.Stage1.LayoutID != payload.LayoutID || a.Stage1.BucketID != id)) {
			return nil, ErrBinding
		}
		n := 0
		for _, g := range a.Bucket.Groups {
			n += len(g.Slots)
			if int(g.PadWidth) != len(g.Slots) {
				return nil, ErrBinding
			}
		}
		if n != a.Incidence.T {
			return nil, ErrBinding
		}
	}
	return &Static{party, anchor, payload, target, sidecar}, nil
}

type guard struct {
	mu   sync.Mutex
	used bool
}

func (g *guard) claim() error {
	if g == nil {
		return ErrBinding
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.used {
		return ErrBinding
	}
	g.used = true
	return nil
}

type anchorPacket struct {
	bucket   uint16
	position anchorfilter.PartyPreprocessing
	and      [2]f2beaver.PartyBatch
	hit, z   *incidence.PartyTriples
	inc      []*incidence.PartyTriples
	f        *aggregation.ComparisonParty
	p0       *aggregation.PermPrep0
	p1       *aggregation.PermPrep1
}
type PartyPacket struct {
	g        *guard
	id       [16]byte
	party    uint8
	anchor   []anchorPacket
	keep     *aggregation.ComparisonParty
	c0       *aggregation.Compaction0
	c1       *aggregation.Compaction1
	pe       targetpe.Packet
	position targetposition.Packet
	agg      targetaggregation.Packet
}
type UserPacket struct {
	g                      *guard
	id, compaction, layout [16]byte
	anchor                 []anchorfilter.UserPreprocessing
	buckets                []uint16
	f                      []*aggregation.BoundMask
	keep                   *aggregation.BoundMask
	target                 []anchorfilter.UserPreprocessing
	agg                    *targetaggregation.UserMaterial
}
type cloudToken struct {
	packet [16]byte
	anchor []anchorfilter.PartyQuery
	f      []uint32
	keep   uint32
	target targetrouting.QueryToken
	agg    targetaggregation.ThresholdToken
}
type OfflineBytes struct{ AnchorPosition, AnchorAggregation, Compaction, TargetPE, TargetPosition, TargetAggregation uint64 }
type fail struct{ err error }

func check(e error) {
	if e != nil {
		panic(fail{e})
	}
}
func caught(e *error) {
	if p := recover(); p != nil {
		if f, ok := p.(fail); ok {
			*e = f.err
		} else {
			panic(p)
		}
	}
}
