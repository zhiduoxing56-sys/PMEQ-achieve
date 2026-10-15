package aggregation

import (
	"crypto/rand"
	"math/bits"
)

// PoolConfig is an explicit experiment/system parameter, with no default or
// frozen numerical value. A packet covers one complete query, including each
// qchunk invocation and the final Keep comparison. Static material is excluded.
type PoolConfig struct{ PreprocessingPoolSize uint64 }

func checkedProduct(a, b uint64) (uint64, error) {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return 0, ErrShape
	}
	return lo, nil
}
func checkedSum(values ...uint64) (uint64, error) {
	var sum uint64
	for _, v := range values {
		next, carry := bits.Add64(sum, v, 0)
		if carry != 0 {
			return 0, ErrShape
		}
		sum = next
	}
	return sum, nil
}

// PoolStorage is Q_pool * perQueryOfflineBytes for equal-capacity packets.
// A heterogeneous pool uses sum_i OfflineBytes(shape_i), not a percentile
// multiplied by Q_pool. Public capacity may upper-bound every packet instead.
func (c PoolConfig) PoolStorage(perQueryOfflineBytes uint64) (uint64, error) {
	return checkedProduct(c.PreprocessingPoolSize, perQueryOfflineBytes)
}

type OfflineShape struct{ Products, PostingSlots, LocalCoordinates, Chunks, GlobalRecords uint64 }

// OfflineBytes counts BOTH clouds' correlated material plus user bound masks.
// keyBytes is the external SCMP codec size per party key (284 in PHASE5B2).
// Current Keep is SCMP only: there is no additional Keep Beaver triple.
func (s OfflineShape) OfflineBytes(keyBytes uint64) (uint64, error) {
	coordinates, e := checkedSum(s.LocalCoordinates, s.GlobalRecords)
	if e != nil {
		return 0, e
	}
	keyPair, e := checkedProduct(2, keyBytes)
	if e != nil {
		return 0, e
	}
	keyPair, e = checkedSum(keyPair, 2)
	if e != nil {
		return 0, e
	}
	nr, e := checkedProduct(s.GlobalRecords, s.Chunks)
	if e != nil {
		return 0, e
	}
	terms := [][2]uint64{{4, s.Products}, {8, s.PostingSlots}, {6, s.LocalCoordinates}, {6, nr}, {keyPair, coordinates}}
	values := []uint64{s.Chunks, 1}
	for _, term := range terms {
		v, e := checkedProduct(term[0], term[1])
		if e != nil {
			return 0, e
		}
		values = append(values, v)
	}
	return checkedSum(values...)
}

type PacketID [16]byte

func NewPacketID() (PacketID, error) { var id PacketID; _, e := rand.Read(id[:]); return id, e }

// PartyPool is the party-local lifecycle registry, NOT a material serializer.
// Typed SCMP/triple/permutation packets are owned by that party and indexed by
// PacketID externally; their existing one-time guards still apply. The registry
// contains no raw data, coordinate mapping, masks, or peer state.
type PartyPool struct {
	LayoutID    [16]byte
	config      PoolConfig
	provisioned uint64
	sealed      bool
	available   map[PacketID]struct{}
}

func NewPartyPool(layout [16]byte, c PoolConfig) *PartyPool {
	return &PartyPool{LayoutID: layout, config: c, available: map[PacketID]struct{}{}}
}

// Provision is offline-only; Seal ends provisioning for this pool epoch.
func (p *PartyPool) Provision(id PacketID) error {
	if p.sealed || p.provisioned >= p.config.PreprocessingPoolSize {
		return ErrShape
	}
	if _, ok := p.available[id]; ok {
		return ErrShape
	}
	p.available[id] = struct{}{}
	p.provisioned++
	return nil
}
func (p *PartyPool) Seal() { p.sealed = true }

// Consume removes the ticket before online use; unknown/repeated IDs fail.
// Exhaustion requires a NEW offline pool, never query-time DO/raw-DB access.
func (p *PartyPool) Consume(id PacketID) error {
	if !p.sealed {
		return ErrShape
	}
	if _, ok := p.available[id]; !ok {
		return ErrShape
	}
	delete(p.available, id)
	return nil
}
func (p *PartyPool) Remaining() int { return len(p.available) }
