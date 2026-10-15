package aggregation

import (
	"crypto/rand"
	"pmeq/internal/domain"
	"pmeq/internal/incidence"
	"pmeq/internal/preprocess"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
)

type PayloadShare struct {
	RecordIDShare   share.Ring64Share
	KappaJoinShare  targetcrypto.ScalarShare
	BucketJoinShare targetcrypto.BucketShare
}
type PartyPayload struct {
	LayoutID [16]byte
	Slots    []PayloadShare
}

// DealerLayout alone owns plaintext IDs and gamma. Never embed in cloud state.
type DealerLayout struct {
	LayoutID [16]byte
	gamma    map[uint64]uint32
	N        int
}

func GeneratePayload(ids []uint64, kt targetcrypto.MasterKey, targetBits int) (*DealerLayout, PartyPayload, PartyPayload, error) {
	return GeneratePayloadWithJoins(ids, ids, kt, targetBits)
}

// GeneratePayloadWithJoins keeps object identity independent of the selected
// join value. Sharing, hidden coordinates and routing derivations are unchanged.
func GeneratePayloadWithJoins(ids, joins []uint64, kt targetcrypto.MasterKey, targetBits int) (*DealerLayout, PartyPayload, PartyPayload, error) {
	if len(ids) != len(joins) {
		return nil, PartyPayload{}, PartyPayload{}, ErrShape
	}
	n := len(ids)
	pi, e := permutation(n)
	if e != nil {
		return nil, PartyPayload{}, PartyPayload{}, e
	}
	d := &DealerLayout{gamma: map[uint64]uint32{}, N: n}
	if _, e = rand.Read(d.LayoutID[:]); e != nil {
		return nil, PartyPayload{}, PartyPayload{}, e
	}
	a, b := PartyPayload{d.LayoutID, make([]PayloadShare, n)}, PartyPayload{d.LayoutID, make([]PayloadShare, n)}
	for i, id := range ids {
		if _, ok := d.gamma[id]; ok {
			return nil, a, b, ErrShape
		}
		j := pi[i]
		d.gamma[id] = j
		a.Slots[j].RecordIDShare, b.Slots[j].RecordIDShare, e = preprocess.SplitRing64(domain.Ring64(id))
		if e != nil {
			return nil, a, b, e
		}
		k, e := targetcrypto.KJoin(kt, joins[i])
		if e != nil {
			return nil, a, b, e
		}
		a.Slots[j].KappaJoinShare, b.Slots[j].KappaJoinShare, e = targetcrypto.SplitScalar(k)
		if e != nil {
			return nil, a, b, e
		}
		v, e := targetcrypto.JoinBucketComponent(kt, joins[i], targetBits)
		if e != nil {
			return nil, a, b, e
		}
		a.Slots[j].BucketJoinShare, b.Slots[j].BucketJoinShare, e = targetcrypto.SplitBucketComponent(v, targetBits)
		if e != nil {
			return nil, a, b, e
		}
	}
	return d, a, b, nil
}

// RestoreDealerLayoutFromPayload is trusted-owner recovery from two sealed PL01
// files. The reconstructed full identities remain inside the DO; neither cloud
// is given this map. It lets an interrupted bucket build resume with exactly
// the original global permutation and layout ID.
func RestoreDealerLayoutFromPayload(ids []uint64, a, b PartyPayload) (*DealerLayout, error) {
	if a.LayoutID == [16]byte{} || a.LayoutID != b.LayoutID || len(a.Slots) != len(ids) || len(b.Slots) != len(ids) {
		return nil, ErrShape
	}
	want := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		if want[id] {
			return nil, ErrShape
		}
		want[id] = true
	}
	ordered := make([]uint64, len(ids))
	seen := make(map[uint64]bool, len(ids))
	for j := range a.Slots {
		id := uint64(a.Slots[j].RecordIDShare.Value() + b.Slots[j].RecordIDShare.Value())
		if !want[id] {
			return nil, ErrShape
		}
		if seen[id] {
			return nil, ErrShape
		}
		seen[id] = true
		ordered[j] = id
	}
	return RestoreDealerLayout(a.LayoutID, ordered)
}

// Alignment embeds the existing DO incidence coordinates, then completes pi
// randomly, including unused rows and the appended public-zero coordinates.
func (d *DealerLayout) Alignment(bucket uint32, local incidence.DealerLayout, slots []incidence.Posting) (*Stage0, *Stage1, error) {
	if local.D > d.N || len(local.Coordinates) != len(slots) {
		return nil, nil, ErrShape
	}
	pi := make([]uint32, d.N)
	assigned := make([]bool, d.N)
	used := make([]bool, d.N)
	for s, p := range slots {
		if !p.Real {
			continue
		}
		j := local.Coordinates[s]
		g, ok := d.gamma[p.RecordID]
		if !ok || j < 0 || j >= local.D {
			return nil, nil, ErrShape
		}
		if assigned[j] && pi[j] != g {
			return nil, nil, ErrShape
		}
		pi[j] = g
		assigned[j] = true
		used[g] = true
	}
	tail, e := permutation(d.N)
	if e != nil {
		return nil, nil, e
	}
	free := []uint32{}
	for _, g := range tail {
		if !used[g] {
			free = append(free, g)
		}
	}
	off := 0
	for j := range pi {
		if !assigned[j] {
			if off >= len(free) {
				return nil, nil, ErrShape
			}
			pi[j] = free[off]
			off++
		}
	}
	s0, s1, err := SplitPermutation(d.LayoutID, bucket, pi)
	clear(pi)
	clear(tail)
	clear(free)
	return s0, s1, err
}

type CandidateInput struct {
	LayoutID  [16]byte
	KeepShare []share.BitShare
	Payload   []PayloadShare
}

func AlignOutput(p PartyPayload, id [16]byte, keep []share.BitShare) (CandidateInput, error) {
	if p.LayoutID != id || len(keep) != len(p.Slots) {
		return CandidateInput{}, ErrShape
	}
	return CandidateInput{LayoutID: id, KeepShare: keep, Payload: p.Slots}, nil
}
