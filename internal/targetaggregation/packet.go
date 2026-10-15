package targetaggregation

import (
	"crypto/rand"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/f2beaver"
	"pmeq/internal/incidence"
	"pmeq/internal/ring64beaver"
	"pmeq/internal/share"
	"pmeq/internal/targetpe"
	"pmeq/internal/zeroagg"
	"sync"
)

type Shape struct {
	K, R, S, G int
	D          int
}

// Capacity keeps historical 26-slot packets usable. Queries may also select 16 slots.
func (s Shape) Capacity() int {
	if s.D == 0 {
		return 26
	}
	return s.D
}

func (s Shape) validate(n int) error {
	d := s.Capacity()
	if (d != 16 && d != 26) || n < 0 || uint64(n) > uint64(^uint32(0)) || s.K < 0 || s.K > n || s.R < 1 || s.R > 16 || s.K > int(^uint(0)>>1)/d/s.R/48 || s.S < 0 || s.G < 0 || s.G > s.S || s.S > int(^uint(0)>>1)/128 || s.G > int(^uint(0)>>1)/(d*24) || (s.K == 0 && (s.S != 0 || s.G != 0)) {
		return ErrBinding
	}
	return nil
}

type UserMaterial struct {
	f, k  *aggregation.BoundMask
	shape Shape
	id    [16]byte
}
type ThresholdToken struct {
	PacketID, QueryID [16]byte
	R                 int
	FBound, KeepBound uint32
}

func (u *UserMaterial) Token(queryID [16]byte, tau int) (ThresholdToken, error) {
	l, e := Threshold(u.shape.R, tau)
	if e != nil || queryID == [16]byte{} {
		return ThresholdToken{}, ErrBinding
	}
	f, e := u.f.Mask(1)
	if e != nil {
		return ThresholdToken{}, e
	}
	k, e := u.k.Mask(l)
	if e != nil {
		return ThresholdToken{}, e
	}
	return ThresholdToken{u.id, queryID, u.shape.R, f, k}, nil
}

type packetState struct {
	sync.Mutex
	used bool
}
type Packet struct {
	state       *packetState
	id          [16]byte
	party       uint8
	lineage     targetpe.AlignmentLineage
	shape       Shape
	hit, inc, z *incidence.PartyTriples
	f, keep     *aggregation.ComparisonParty
	ring        [7]ring64beaver.Packet
	rep         f2beaver.PartyBatch
	zero        []*zeroagg.Party
	zeroT       int
	labelID     string
}

// OfflineBody accounts correlated field bytes, not Go objects or a wire codec.
type OfflineBody struct{ Z128, SCMP, Ring64, F2, GF16 uint64 }

// Count actual opaque native key encodings at trusted preprocessing time.
type countedBackend struct {
	backend anchorfilter.SCMPBackend
	bytes   uint64
}

func (c *countedBackend) KeyGen(bin uint8, x, y uint32, o domain.Bit) (anchorfilter.SCMPKeyShare, anchorfilter.SCMPKeyShare, error) {
	a, b, e := c.backend.KeyGen(bin, x, y, o)
	if e == nil {
		c.bytes += uint64(len(a.Opaque()) + len(b.Opaque()) + 4)
	}
	return a, b, e
}
func (c *countedBackend) Eval(p uint8, k anchorfilter.SCMPKeyShare, x, y uint32) (share.BitShare, error) {
	return c.backend.Eval(p, k, x, y)
}

// Preprocess provisions public K/S/G capacity bounds and an occurrence count
// in a trusted offline epoch. Unused capacity burns on the single query claim.
// It must finish before the user's initial token. A cloud cannot refill it.
// Packet copies share a single claim guard. No value, route bucket, ID, Hit or
// GroupMatch is an input to preprocessing.
func Preprocess(l targetpe.AlignmentLineage, s Shape, b anchorfilter.SCMPBackend) (*UserMaterial, Packet, Packet, OfflineBody, error) {
	return preprocess(l, s, b, 0, "")
}

func PreprocessZero(l targetpe.AlignmentLineage, s Shape, b anchorfilter.SCMPBackend, maxT int, labelID string) (*UserMaterial, Packet, Packet, OfflineBody, error) {
	if maxT < 1 || maxT > 65536 || labelID == "" {
		return nil, Packet{}, Packet{}, OfflineBody{}, ErrBinding
	}
	return preprocess(l, s, b, maxT, labelID)
}

func preprocess(l targetpe.AlignmentLineage, s Shape, b anchorfilter.SCMPBackend, maxT int, labelID string) (*UserMaterial, Packet, Packet, OfflineBody, error) {
	d := s.Capacity()
	var cost OfflineBody
	if s.validate(l.N) != nil || l.IndexID == [16]byte{} || l.LayoutID == [16]byte{} || b == nil {
		return nil, Packet{}, Packet{}, cost, ErrBinding
	}
	var id [16]byte
	if _, e := rand.Read(id[:]); e != nil {
		return nil, Packet{}, Packet{}, cost, e
	}
	p := [2]Packet{{state: &packetState{}, id: id, party: 0, lineage: l, shape: s}, {state: &packetState{}, id: id, party: 1, lineage: l, shape: s}}
	var e error
	inputS, compareN := s.S, s.K*s.R*d
	if maxT > 0 {
		inputS, compareN = 0, 0
		for j := range p {
			p[j].zeroT = maxT
			p[j].labelID = labelID
			p[j].zero = make([]*zeroagg.Party, s.K*s.R)
		}
		capacity := 1
		for capacity < d {
			capacity *= 2
		}
		for i := 0; i < s.K*s.R; i++ {
			a, b, n := zeroagg.Prepare(maxT, capacity)
			p[0].zero[i], p[1].zero[i] = a, b
			cost.GF16 += uint64(n)
		}
	}
	p[0].hit, p[1].hit, e = incidence.Preprocess(inputS, 1)
	if e != nil {
		return nil, Packet{}, Packet{}, cost, e
	}
	p[0].inc, p[1].inc, e = incidence.Preprocess(inputS, d)
	if e != nil {
		return nil, Packet{}, Packet{}, cost, e
	}
	z, m := s.K*s.R*d, s.K*d
	p[0].z, p[1].z, e = incidence.Preprocess(z, 1)
	if e != nil {
		return nil, Packet{}, Packet{}, cost, e
	}
	u := &UserMaterial{shape: s, id: id}
	counted := &countedBackend{backend: b}
	u.f, p[0].f, p[1].f, e = aggregation.PreprocessComparison(compareN, counted)
	if e != nil {
		return nil, Packet{}, Packet{}, cost, e
	}
	u.k, p[0].keep, p[1].keep, e = aggregation.PreprocessComparison(m, counted)
	if e != nil {
		return nil, Packet{}, Packet{}, cost, e
	}
	// Ring stages: Match B2A, group payload, rep B2A, rep payload,
	// Keep B2A, Anchor mask, Target mask.
	sizes := [7]int{s.G, d * s.G, z, z, m, m, m}
	for i, n := range sizes {
		p[0].ring[i], p[1].ring[i], e = ring64beaver.Preprocess(n)
		if e != nil {
			return nil, Packet{}, Packet{}, cost, e
		}
		cost.Ring64 += uint64(48 * n)
	}
	p[0].rep, p[1].rep, e = f2beaver.Preprocess(z)
	if e != nil {
		return nil, Packet{}, Packet{}, cost, e
	}
	cost.Z128 = uint64(6*inputS + (2+4*d)*inputS + 6*z)
	// Bin7/Bout1 native LLAMA codec: 284 key + 1 cached rb + 1 Z128 mask,
	// per party per comparison. BoundMask metadata is accounted separately.
	cost.SCMP = counted.bytes
	cost.F2 = uint64(6 * z)
	return u, p[0], p[1], cost, nil
}
