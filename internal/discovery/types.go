// Package discovery runs the supported PMEQ protocol using party-local state.
// The local coordinator is a transport/user harness, never a cloud principal.
package discovery

import (
	"encoding/hex"
	"errors"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"pmeq/internal/f2beaver"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/material"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
	"pmeq/internal/targetrouting"
	"pmeq/internal/zeroagg"
	"sync"
)

var ErrDomain = errors.New("discovery: query outside q=4, tau_i<r_i, Anchor r<=14, Target r<=16 domain")
var ErrCandidateCapacity = errors.New("discovery: actual K exceeds public candidate capacity C; no truncation")

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
	Bucket  indexbuild.AnchorPartyBucket
	D, T    int
	Labels  []zeroagg.F
	LabelID string
	Stage0  *aggregation.Stage0
	Stage1  *aggregation.Stage1
}

// Every anchor state is complete GF-label state. Missing labels cannot be deferred.
func validAnchorLabels(a AnchorStatic) bool {
	id, e := hex.DecodeString(a.LabelID)
	return e == nil && len(id) == 16 && hex.EncodeToString(id) == a.LabelID && a.LabelID != "00000000000000000000000000000000" && len(a.Labels) == a.T && a.T >= 0 && a.T <= 65536 && a.D >= 0 && a.D <= 32768 && (a.D == 0 || a.D&(a.D-1) == 0) && ((a.T == 0) == (a.D == 0))
}

type Static struct {
	party   uint8
	anchor  map[uint32]AnchorStatic
	payload aggregation.PartyPayload
	target  *targetpe.PartyIndex
	sidecar *targetaggregation.PartySidecar
}

func NewStatic(party uint8, anchor map[uint32]AnchorStatic, payload aggregation.PartyPayload, target *targetpe.PartyIndex, sidecar *targetaggregation.PartySidecar) (*Static, error) {
	if party > 1 || target == nil || sidecar == nil || target.Party() != party || payload.LayoutID != target.Lineage().LayoutID || target.Lineage().N < 0 || uint64(target.Lineage().N) > uint64(^uint32(0)) || len(payload.Slots) != target.Lineage().N {
		return nil, ErrBinding
	}
	for id, a := range anchor {
		if a.Bucket.BucketID != id || a.D < 0 || a.D > len(payload.Slots) || (party == 0 && (a.Stage0 == nil || a.Stage1 != nil || a.Stage0.LayoutID != payload.LayoutID || a.Stage0.BucketID != id)) || (party == 1 && (a.Stage1 == nil || a.Stage0 != nil || a.Stage1.LayoutID != payload.LayoutID || a.Stage1.BucketID != id || a.Stage1.GlobalRecords() != len(payload.Slots))) {
			return nil, ErrBinding
		}
		n := 0
		for _, g := range a.Bucket.Groups {
			n += len(g.Slots)
			if int(g.PadWidth) != len(g.Slots) {
				return nil, ErrBinding
			}
		}
		if n != a.T || a.D > 32768 || a.T > 65536 || !validAnchorLabels(a) {
			return nil, ErrBinding
		}
	}
	return &Static{party: party, anchor: anchor, payload: payload, target: target, sidecar: sidecar}, nil
}

type guard struct {
	mu       sync.Mutex
	used     bool
	reserved bool
	ledger   string
	id       [16]byte
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
	if g.ledger != "" && !g.reserved {
		if e := material.ClaimPersistent(g.ledger, g.id); e != nil {
			return e
		}
	}
	g.used = true
	return nil
}

type anchorPacket struct {
	zero     *zeroagg.Party
	zeroRef  *zeroReference
	bucket   uint32
	position anchorfilter.PartyPreprocessing
	and      [2]f2beaver.PartyBatch
	z        *incidence.PartyTriples
	p0       *aggregation.PermPrep0
	p1       *aggregation.PermPrep1
}
type PartyPacket struct {
	g              *guard
	id             [16]byte
	party          uint8
	anchor         []anchorPacket
	keep           *aggregation.ComparisonParty
	c0             *aggregation.Compaction0
	c1             *aggregation.Compaction1
	pe             targetpe.Packet
	position       targetposition.Packet
	agg            targetaggregation.Packet
	output         *aggregation.PairPermutation
	capacity       int
	interruptZero  bool
	persistentRefs []zeroReference
}
type UserPacket struct {
	g                      *guard
	id, compaction, layout [16]byte
	anchor                 []anchorfilter.UserPreprocessing
	buckets                []uint32
	keep                   *aggregation.BoundMask
	target                 []anchorfilter.UserPreprocessing
	agg                    *targetaggregation.UserMaterial
}
type cloudToken struct {
	packet [16]byte
	anchor []anchorfilter.PartyQuery
	keep   uint32
	target targetrouting.QueryToken
	agg    targetaggregation.ThresholdToken
}
type OfflineBytes struct{ AnchorPosition, AnchorAggregation, Compaction, TargetPE, TargetPosition, TargetAggregation, OutputPermutation uint64 }
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
