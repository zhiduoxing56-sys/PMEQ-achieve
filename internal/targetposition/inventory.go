package targetposition

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/scmpstock"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetrouting"
	"time"
)

// InventoryPlan uses only K, ordered routed buckets and public padded group
// widths. It is computed after private routing and before any material is
// claimed. The digest binds both clouds to exactly the same slot order.
func InventoryPlan(idx *targetpe.PartyIndex, in targetpe.TargetGroupMatches, tok targetrouting.QueryToken, p Packet) ([]int, [32]byte, error) {
	var zero [32]byte
	if idx == nil || p.state == nil || !p.inventory || p.party != idx.Party() || p.lineage != idx.Lineage() || tok.Party != idx.Party() || tok.Manifest != in.Manifest || in.Manifest != idx.Manifest() || tok.QueryID != in.QueryID || in.QueryID == [16]byte{} || in.LayoutID != idx.Lineage().LayoutID || len(tok.Position) != len(in.Occurrences) || len(in.Routes) != in.K*len(in.Occurrences) || in.K < 0 || in.K > idx.Lineage().N {
		return nil, zero, ErrBinding
	}
	if len(p.state.materials) != len(in.Occurrences) {
		return nil, zero, ErrBinding
	}
	counts := make([]int, len(in.Occurrences))
	h := sha256.New()
	h.Write([]byte("PMEQ-INV-PLAN-v3"))
	h.Write(in.Manifest.IndexID[:])
	h.Write(in.LayoutID[:])
	h.Write(in.CompactionID[:])
	h.Write(in.QueryID[:])
	d := idx.StructureDigest()
	h.Write(d[:])
	var buf [8]byte
	for i, o := range in.Occurrences {
		if o.OccurrenceID != uint32(i) || tok.Position[i].PID != p.state.materials[i].prep.PID || p.state.materials[i].prep.Bin != p.bin || o.Position > p.maxPosition {
			return nil, zero, ErrBinding
		}
		h.Write(tok.Position[i].PID[:])
	}
	for i, r := range in.Routes {
		if r.CandidateIndex != uint32(i/len(in.Occurrences)) || r.OccurrenceID != uint32(i%len(in.Occurrences)) {
			return nil, zero, ErrBinding
		}
		gs := idx.PositionGroups(r.BucketID)
		if len(gs) != r.GroupCount {
			return nil, zero, ErrBinding
		}
		binary.LittleEndian.PutUint32(buf[:4], r.CandidateIndex)
		h.Write(buf[:4])
		binary.LittleEndian.PutUint32(buf[:4], r.OccurrenceID)
		h.Write(buf[:4])
		binary.LittleEndian.PutUint32(buf[:4], r.BucketID)
		h.Write(buf[:4])
		for _, g := range gs {
			counts[r.OccurrenceID] += int(g.PadWidth)
			binary.LittleEndian.PutUint32(buf[:4], g.PadWidth)
			h.Write(buf[:4])
		}
	}
	for i, n := range counts {
		if n > p.state.materials[i].capacity {
			return nil, zero, ErrBinding
		}
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return counts, digest, nil
}

// BeginInventory opens each θ−η correction in one authenticated cloud exchange.
// The caller has already persistently claimed the same ordered unit range for
// both roles. The original user token is transformed locally for each slot.
func BeginInventory(idx *targetpe.PartyIndex, in targetpe.TargetGroupMatches, tok targetrouting.QueryToken, p Packet, backend anchorfilter.SCMPBackend, units []scmpstock.Unit, plan [32]byte, exchange func([]byte) ([]byte, error)) (*Session, error) {
	localStart := time.Now()
	counts, expected, e := InventoryPlan(idx, in, tok, p)
	if e != nil || plan != expected || backend == nil || exchange == nil {
		return nil, ErrBinding
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if len(units) != total {
		return nil, ErrBinding
	}
	occBySlot := make([]int, total)
	routeStarts := make([]int, len(in.Routes))
	off := 0
	for j, r := range in.Routes {
		routeStarts[j] = off
		for _, g := range idx.PositionGroups(r.BucketID) {
			for k := 0; k < int(g.PadWidth); k++ {
				occBySlot[off+k] = int(r.OccurrenceID)
			}
			off += int(g.PadWidth)
		}
	}
	if off != total {
		return nil, ErrBinding
	}
	ordered := sha256.New()
	for _, u := range units {
		ordered.Write(u.ID[:])
	}
	ids := ordered.Sum(nil)
	m := (uint32(1) << p.bin) - 1
	const header = 77
	msg := make([]byte, header+8*total)
	copy(msg[:8], "PMEQIV03")
	copy(msg[8:40], plan[:])
	copy(msg[40:72], ids)
	msg[72] = p.party
	binary.LittleEndian.PutUint32(msg[73:77], uint32(total))
	for i, u := range units {
		for side := 0; side < 2; side++ {
			if u.Theta[side] > m || u.Rho[side] > m || len(u.Key[side].Opaque()) != 88+28*int(p.bin) {
				return nil, ErrBinding
			}
			binary.LittleEndian.PutUint32(msg[header+8*i+4*side:], (u.Theta[side]-p.state.materials[occBySlot[i]].etaShare[side])&m)
		}
	}
	beforeWait := time.Since(localStart)
	waitStart := time.Now()
	peer, e := exchange(msg)
	wait := time.Since(waitStart)
	if e != nil {
		return nil, e
	}
	localStart = time.Now()
	if len(peer) != len(msg) || !bytes.Equal(peer[:8], msg[:8]) || !bytes.Equal(peer[8:72], msg[8:72]) || peer[72] != 1-p.party || binary.LittleEndian.Uint32(peer[73:77]) != uint32(total) {
		return nil, ErrBinding
	}
	converted := make([][][2]uint32, len(counts))
	for i, n := range counts {
		converted[i] = make([][2]uint32, 0, n)
	}
	for j, r := range in.Routes {
		_ = j
		n := 0
		for _, g := range idx.PositionGroups(r.BucketID) {
			n += int(g.PadWidth)
		}
		for k := 0; k < n; k++ {
			// Cursor follows the same candidate/occurrence/physical slot order
			// as Session.Next and its per-occurrence material cursors.
			i := routeStarts[j] + k
			u := units[i]
			h := int(r.OccurrenceID)
			prep := &p.state.materials[h].prep
			prep.RhoL = append(prep.RhoL, u.Rho[0])
			prep.RhoR = append(prep.RhoR, u.Rho[1])
			prep.Lower = append(prep.Lower, u.Key[0])
			prep.Upper = append(prep.Upper, u.Key[1])
			var t [2]uint32
			for side := 0; side < 2; side++ {
				v := binary.LittleEndian.Uint32(peer[header+8*i+4*side:])
				if v > m {
					return nil, ErrBinding
				}
				down := binary.LittleEndian.Uint32(msg[header+8*i+4*side:])
				t[side] = ([2]uint32{tok.Position[h].Ltilde, tok.Position[h].RplusTilde}[side] + down + v) & m
			}
			converted[h] = append(converted[h], t)
		}
	}
	s, e := Begin(idx, in, tok, p, backend)
	if e != nil {
		return nil, e
	}
	s.converted = converted
	s.inventoryLocal = beforeWait + time.Since(localStart)
	s.inventoryWait = wait
	return s, nil
}
