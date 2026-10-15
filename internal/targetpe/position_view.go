package targetpe

import "pmeq/internal/share"

// PositionGroup exposes only the calling party's required slot fields. The
// sealed physical order is preserved; record IDs and T shares are not exported.
type PositionGroup struct{ PadWidth uint32 }

func (p *PartyIndex) PositionGroups(bucket uint32) []PositionGroup {
	out := make([]PositionGroup, len(p.buckets[bucket]))
	for i, g := range p.buckets[bucket] {
		out[i] = PositionGroup{g.PadWidth}
	}
	return out
}
func (p *PartyIndex) PositionSlot(bucket uint32, group, slot int) (share.Ring32Share, share.BitShare) {
	s := p.buckets[bucket][group].Slots[slot]
	return s.PositionShare, s.ValidityShare
}
func (p *PartyIndex) Party() uint8 { return p.party }
