// Package gen is the trusted OFFLINE sidecar dealer. Cloud code must not
// import it. Both sealed party files are used here only to audit construction.
package gen

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"sort"

	"pmeq/internal/indexbuild"
	"pmeq/internal/targetaggregation"
)

type Audit struct {
	CheckedBuckets, CheckedGroups, CheckedPhysicalSlots, RealSlots uint64
	MaxAliases, MaxMultiplicity, ShortRecords                      int
	Errors                                                         int
}
type counted struct {
	w io.Writer
	n uint64
}

func (c *counted) Write(b []byte) (int, error) { n, e := c.w.Write(b); c.n += uint64(n); return n, e }

// Build authenticates both sealed PSMJ files before using any slot identities.
// Ordinals sort ALL alias IDs numerically within a join, including short names.
// They are not per-group ranks, and no actual join size enters either sidecar.
func Build(rawManifest []byte, files [2][]byte, aliases []indexbuild.AreaAliasRecord, outputs [2]io.Writer) (targetaggregation.SidecarManifest, Audit, error) {
	return BuildWithCapacity(rawManifest, files, aliases, outputs, 26)
}

// BuildWithCapacity rebuilds only capacity-dependent auxiliary state, never PSMJ.
func BuildWithCapacity(rawManifest []byte, files [2][]byte, aliases []indexbuild.AreaAliasRecord, outputs [2]io.Writer, d int) (targetaggregation.SidecarManifest, Audit, error) {
	var out targetaggregation.SidecarManifest
	var audit Audit
	if d != 16 && d != 26 {
		return out, audit, targetaggregation.ErrBinding
	}
	m, e := indexbuild.ReadTargetManifest(bytes.NewReader(rawManifest))
	if e != nil {
		return out, audit, e
	}
	var ps [2]indexbuild.PartyIndex
	for u := range ps {
		d := sha256.Sum256(files[u])
		if uint64(len(files[u])) != m.PartyBytes[u] || hex.EncodeToString(d[:]) != m.PartySHA256[u] {
			return out, audit, targetaggregation.ErrBinding
		}
		ps[u], e = indexbuild.ReadTargetParty(bytes.NewReader(files[u]), m, uint8(u))
		if e != nil {
			return out, audit, e
		}
	}
	joins := map[uint64][]uint64{}
	byID := map[uint64]indexbuild.AreaAliasRecord{}
	ordinal := map[uint64]int{}
	for _, a := range aliases {
		if _, ok := byID[a.ID]; ok {
			return out, audit, targetaggregation.ErrBinding
		}
		byID[a.ID] = a
		joins[a.Area] = append(joins[a.Area], a.ID)
		if len([]rune(a.Name)) < 4 {
			audit.ShortRecords++
		}
	}
	for _, ids := range joins {
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		audit.MaxAliases = max(audit.MaxAliases, len(ids))
		if len(ids) > d {
			return out, audit, targetaggregation.ErrBinding
		}
		for u, id := range ids {
			ordinal[id] = u
		}
	}
	bucketCount := 1 << m.TargetBucketBits
	var buckets [2][][]indexbuild.TargetPartyGroup
	for u := range ps {
		buckets[u] = make([][]indexbuild.TargetPartyGroup, bucketCount)
		for _, b := range ps[u].TargetBuckets {
			buckets[u][b.BucketID] = b.Groups
		}
	}
	digest := sha256.Sum256(rawManifest)
	out = targetaggregation.SidecarManifest{Version: 1, IndexID: m.IndexID, ManifestSHA256: hex.EncodeToString(digest[:]), DTarget: uint32(d), MaxMultiplicity: 3, IncidenceBytes: uint64(d) * m.PaddedSlots, TargetIDBytes: uint64(d) * 8 * m.LogicalGroups}
	var writers [2]*bufio.Writer
	var counters [2]*counted
	hashes := [2]io.Writer{}
	h0, h1 := sha256.New(), sha256.New()
	hashes[0], hashes[1] = h0, h1
	for u := range writers {
		counters[u] = &counted{w: io.MultiWriter(outputs[u], hashes[u])}
		writers[u] = bufio.NewWriterSize(counters[u], 65536)
		header := append([]byte(targetaggregation.SidecarMagic), byte(u))
		header = append(header, m.IndexID[:]...)
		header = append(header, digest[:]...)
		if _, e = writers[u].Write(header); e != nil {
			return out, audit, e
		}
	}
	structure := sha256.New()
	write := func(w io.Writer, v any) error { return binary.Write(w, binary.LittleEndian, v) }
	for bi := 0; bi < bucketCount; bi++ {
		gs, peer := buckets[0][bi], buckets[1][bi]
		if len(gs) != len(peer) {
			return out, audit, targetaggregation.ErrBinding
		}
		audit.CheckedBuckets++
		audit.CheckedGroups += uint64(len(gs))
		if m.TargetBucketBits > 16 {
			write(structure, uint32(bi))
		} else {
			write(structure, uint16(bi))
		}
		write(structure, uint32(len(gs)))
		for _, w := range writers {
			if e = write(w, uint32(len(gs))); e != nil {
				return out, audit, e
			}
		}
		coords := []int{}
		payload := make([]uint64, len(gs)*d)
		for gi, g := range gs {
			if g.PadWidth != peer[gi].PadWidth || len(g.Slots) != int(g.PadWidth) || len(peer[gi].Slots) != len(g.Slots) {
				return out, audit, targetaggregation.ErrBinding
			}
			write(structure, g.PadWidth)
			for _, w := range writers {
				if e = write(w, g.PadWidth); e != nil {
					return out, audit, e
				}
			}
			counts := map[uint64]int{}
			var join uint64
			found := false
			for si, s := range g.Slots {
				p := peer[gi].Slots[si]
				valid := bool(s.ValidityShare.Value().Add(p.ValidityShare.Value()))
				id := uint64(s.RecordIDShare.Value() + p.RecordIDShare.Value())
				coord := -1
				if valid {
					a, ok := byID[id]
					if !ok || len([]rune(a.Name)) < 4 {
						return out, audit, targetaggregation.ErrBinding
					}
					if found && join != a.Area {
						return out, audit, targetaggregation.ErrBinding
					}
					join = a.Area
					found = true
					coord = ordinal[id]
					counts[id]++
					audit.MaxMultiplicity = max(audit.MaxMultiplicity, counts[id])
					if counts[id] > 3 {
						return out, audit, targetaggregation.ErrBinding
					}
					audit.RealSlots++
				} else if id != 0 {
					return out, audit, targetaggregation.ErrBinding
				}
				coords = append(coords, coord)
				audit.CheckedPhysicalSlots++
			}
			if !found {
				return out, audit, targetaggregation.ErrBinding
			}
			for u, id := range joins[join] {
				payload[gi*d+u] = id
			}
		}
		// Both dense coefficient arrays contain independent fresh local masks,
		// including semantic zero, dummy columns and unused ordinals.
		a, b := make([]byte, d*len(coords)), make([]byte, d*len(coords))
		if _, e = rand.Read(a); e != nil {
			return out, audit, e
		}
		for j := range a {
			a[j] &= 127
			v := byte(0)
			if coords[j/d] == j%d {
				v = 1
			}
			b[j] = (v - a[j]) & 127
		}
		if _, e = writers[0].Write(a); e != nil {
			return out, audit, e
		}
		if _, e = writers[1].Write(b); e != nil {
			return out, audit, e
		}
		var rnd [8]byte
		for _, id := range payload {
			if _, e = rand.Read(rnd[:]); e != nil {
				return out, audit, e
			}
			v := binary.LittleEndian.Uint64(rnd[:])
			if e = write(writers[0], v); e != nil {
				return out, audit, e
			}
			if e = write(writers[1], id-v); e != nil {
				return out, audit, e
			}
		}
	}
	if audit.CheckedGroups != m.LogicalGroups || audit.CheckedPhysicalSlots != m.PaddedSlots || audit.RealSlots != m.RealPostings {
		return out, audit, targetaggregation.ErrBinding
	}
	copy(out.StructureDigest[:], structure.Sum(nil))
	for u, w := range writers {
		if e = w.Flush(); e != nil {
			return out, audit, e
		}
		out.PartyBytes[u] = counters[u].n
	}
	out.PartySHA256 = [2]string{hex.EncodeToString(h0.Sum(nil)), hex.EncodeToString(h1.Sum(nil))}
	return out, audit, nil
}
