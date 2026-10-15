package indexbuild

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"github.com/gtank/ristretto255"
	"pmeq/internal/anchorindex"
	"pmeq/internal/domain"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
)

// TargetBucketBits is the PHASE 7B production setting. Build's explicit widths
// remain available for controlled layout experiments and historical tests.
const TargetBucketBits = 16
const TargetArtifactVersion = 2
const TargetHeaderBytes = 74

var ErrTargetArtifact = errors.New("indexbuild: invalid target artifact or binding")

// TargetManifest is public metadata, provisioned by the trusted artifact owner.
// Hashes bind party files; this is integrity checking, not signature verification.
// A cloud receives only its own file. Neither file contains plaintext identity.
type TargetManifest struct {
	Version          uint32
	IndexID          [16]byte
	Q                uint32
	AnchorBucketBits uint8
	TargetBucketBits uint8
	Tiers            [9]uint32
	LogicalGroups    uint64
	RealPostings     uint64
	PaddedSlots      uint64
	NonemptyBuckets  uint32
	PartyBytes       [2]uint64
	PartySHA256      [2]string
}

func (m TargetManifest) Validate() error {
	if (m.Version != 1 && m.Version != TargetArtifactVersion) || m.IndexID == [16]byte{} || m.Q != Q || m.AnchorBucketBits != m.TargetBucketBits || m.TargetBucketBits < 14 || m.TargetBucketBits > 17 {
		return ErrTargetArtifact
	}
	for i, v := range tierLadder {
		if m.Version == 1 && i == 8 {
			if m.Tiers[i] != 0 {
				return ErrTargetArtifact
			}
			break
		}
		if m.Tiers[i] != uint32(v) {
			return ErrTargetArtifact
		}
	}
	if m.NonemptyBuckets > 1<<m.TargetBucketBits || m.RealPostings > m.PaddedSlots || m.LogicalGroups > m.PaddedSlots {
		return ErrTargetArtifact
	}
	return nil
}
func NewTargetManifest(id [16]byte, m PublicMetadata, s SideStats) (TargetManifest, error) {
	out := TargetManifest{Version: TargetArtifactVersion, IndexID: id, Q: m.Q, AnchorBucketBits: m.AnchorBucketBits, TargetBucketBits: m.TargetBucketBits, LogicalGroups: uint64(s.LogicalGroups), RealPostings: uint64(s.RealSlots), PaddedSlots: uint64(s.PaddedSlots), NonemptyBuckets: uint32(len(m.TargetBuckets))}
	for i, v := range tierLadder {
		out.Tiers[i] = uint32(v)
	}
	return out, out.Validate()
}

// BuildFinalTargetWithBits uses the selected complete-query bucket domain.
func BuildFinalTargetWithBits(aliases []AreaAliasRecord, kt targetcrypto.MasterKey, bits int) (PublicMetadata, PartyIndex, PartyIndex, BuildStats, error) {
	return Build(nil, aliases, anchorindex.Key{}, kt, bits, bits)
}
func ReadTargetManifest(r io.Reader) (TargetManifest, error) {
	var m TargetManifest
	d := json.NewDecoder(io.LimitReader(r, 16384))
	d.DisallowUnknownFields()
	if e := d.Decode(&m); e != nil {
		return m, e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return m, ErrTargetArtifact
	}
	return m, m.Validate()
}

// TargetEncodedBytes is the exact current encoding size, excluding its JSON manifest.
func TargetEncodedBytes(buckets, groups, slots uint64) uint64 {
	return TargetHeaderBytes + 14*buckets + 36*groups + 13*slots
}

func TargetEncodedBytesForBits(bits uint8, buckets, groups, slots uint64) uint64 {
	if bits > 16 {
		return TargetHeaderBytes + 16*buckets + 36*groups + 13*slots
	}
	return TargetEncodedBytes(buckets, groups, slots)
}

// WriteTargetParty encodes only one party's PSMJ. Callers must supply a trusted
// manifest; this routine never accepts a peer index or full group point.
func WriteTargetParty(w io.Writer, m TargetManifest, party uint8, p PartyIndex) error {
	if e := m.Validate(); e != nil {
		return e
	}
	if party > 1 || len(p.AnchorBuckets) != 0 || uint32(len(p.TargetBuckets)) != m.NonemptyBuckets {
		return ErrTargetArtifact
	}
	b := bufio.NewWriter(w)
	write := func(v any) error { return binary.Write(b, binary.LittleEndian, v) }
	if e := writeTargetHeader(b, m, party); e != nil {
		return e
	}
	var groups, slots uint64
	last := -1
	for _, bucket := range p.TargetBuckets {
		if int(bucket.BucketID) <= last || len(bucket.Groups) == 0 {
			return ErrTargetArtifact
		}
		last = int(bucket.BucketID)
		var total uint64
		for _, g := range bucket.Groups {
			total += uint64(g.PadWidth)
		}
		if m.TargetBucketBits > 16 {
			if e := write(bucket.BucketID); e != nil {
				return e
			}
		} else if e := write(uint16(bucket.BucketID)); e != nil {
			return e
		}
		if e := write(uint32(len(bucket.Groups))); e != nil {
			return e
		}
		if e := write(total); e != nil {
			return e
		}
		for _, g := range bucket.Groups {
			if !validManifestPad(m, g.PadWidth) || len(g.Slots) != int(g.PadWidth) {
				return ErrTargetArtifact
			}
			if _, e := ristretto255.NewElement().SetCanonicalBytes(g.TargetKeyShare[:]); e != nil {
				return e
			}
			if e := write(g.TargetKeyShare); e != nil {
				return e
			}
			if e := write(g.PadWidth); e != nil {
				return e
			}
			for _, s := range g.Slots {
				if e := write(uint64(s.RecordIDShare.Value())); e != nil {
					return e
				}
				if e := write(uint32(s.PositionShare.Value())); e != nil {
					return e
				}
				v := uint8(0)
				if bool(s.ValidityShare.Value()) {
					v = 1
				}
				if e := write(v); e != nil {
					return e
				}
			}
			groups++
			slots += uint64(g.PadWidth)
		}
	}
	if groups != m.LogicalGroups || slots != m.PaddedSlots {
		return ErrTargetArtifact
	}
	return b.Flush()
}
func validPad(p uint32) bool {
	for _, v := range tierLadder {
		if uint32(v) == p {
			return true
		}
	}
	return false
}

// ReadTargetParty verifies shape and canonical local points. The caller also
// verifies this file's SHA256 against the trusted manifest before using it.
func ReadTargetParty(r io.Reader, m TargetManifest, party uint8) (PartyIndex, error) {
	var out PartyIndex
	if e := m.Validate(); e != nil {
		return out, e
	}
	if party > 1 {
		return out, ErrTargetArtifact
	}
	b := bufio.NewReader(r)
	read := func(v any) error { return binary.Read(b, binary.LittleEndian, v) }
	if e := readTargetHeader(b, m, party); e != nil {
		return out, e
	}
	var groups, slots uint64
	last := -1
	for bi := uint32(0); bi < m.NonemptyBuckets; bi++ {
		var id uint32
		var count uint32
		var total uint64
		if m.TargetBucketBits > 16 {
			if e := read(&id); e != nil {
				return out, e
			}
		} else {
			var narrow uint16
			if e := read(&narrow); e != nil {
				return out, e
			}
			id = uint32(narrow)
		}
		if e := read(&count); e != nil {
			return out, e
		}
		if e := read(&total); e != nil {
			return out, e
		}
		if int(id) <= last || count == 0 || uint64(count) > m.LogicalGroups-groups || total > m.PaddedSlots-slots {
			return out, ErrTargetArtifact
		}
		last = int(id)
		bucket := TargetPartyBucket{BucketID: id}
		var actual uint64
		for gi := uint32(0); gi < count; gi++ {
			var g TargetPartyGroup
			if e := read(&g.TargetKeyShare); e != nil {
				return out, e
			}
			if e := read(&g.PadWidth); e != nil {
				return out, e
			}
			if !validManifestPad(m, g.PadWidth) || uint64(g.PadWidth) > total-actual {
				return out, ErrTargetArtifact
			}
			if _, e := ristretto255.NewElement().SetCanonicalBytes(g.TargetKeyShare[:]); e != nil {
				return out, e
			}
			g.Slots = make([]TargetPartySlot, g.PadWidth)
			for i := range g.Slots {
				var id uint64
				var pos uint32
				var v uint8
				if e := read(&id); e != nil {
					return out, e
				}
				if e := read(&pos); e != nil {
					return out, e
				}
				if e := read(&v); e != nil {
					return out, e
				}
				if v > 1 {
					return out, ErrTargetArtifact
				}
				g.Slots[i] = TargetPartySlot{share.NewRing64Share(domain.Ring64(id)), share.NewRing32Share(domain.Ring32(pos)), share.NewBitShare(domain.Bit(v == 1))}
			}
			actual += uint64(g.PadWidth)
			bucket.Groups = append(bucket.Groups, g)
		}
		if actual != total {
			return out, ErrTargetArtifact
		}
		groups += uint64(count)
		slots += total
		out.TargetBuckets = append(out.TargetBuckets, bucket)
	}
	if groups != m.LogicalGroups || slots != m.PaddedSlots {
		return out, ErrTargetArtifact
	}
	if _, e := b.ReadByte(); e != io.EOF {
		return out, ErrTargetArtifact
	}
	return out, nil
}

// BuildFinalTarget materializes the frozen Target-only artifact. Neither the
// query caller nor the outsourcing caller can select another production width.
func BuildFinalTarget(aliases []AreaAliasRecord, kt targetcrypto.MasterKey) (PublicMetadata, PartyIndex, PartyIndex, BuildStats, error) {
	return Build(nil, aliases, anchorindex.Key{}, kt, AnchorBucketBits, TargetBucketBits)
}

// v1 retains its exact 70-byte/eight-tier header. v2 physically writes nine
// tiers (74 bytes); old manifests and bytes are read without rewriting them.
func manifestTierCount(m TargetManifest) int {
	if m.Version == 1 {
		return 8
	}
	return 9
}
func validManifestPad(m TargetManifest, p uint32) bool {
	for _, v := range m.Tiers[:manifestTierCount(m)] {
		if v == p {
			return true
		}
	}
	return false
}
func writeTargetHeader(w io.Writer, m TargetManifest, u uint8) error {
	prefix := struct {
		Magic       [8]byte
		Version     uint32
		ID          [16]byte
		Party, Bits uint8
		Q           uint32
	}{[8]byte{'P', 'M', 'E', 'Q', 'P', 'S', '0', '1'}, m.Version, m.IndexID, u, m.TargetBucketBits, m.Q}
	if e := binary.Write(w, binary.LittleEndian, prefix); e != nil {
		return e
	}
	if e := binary.Write(w, binary.LittleEndian, m.Tiers[:manifestTierCount(m)]); e != nil {
		return e
	}
	return binary.Write(w, binary.LittleEndian, m.NonemptyBuckets)
}
func readTargetHeader(r io.Reader, m TargetManifest, u uint8) error {
	var p struct {
		Magic       [8]byte
		Version     uint32
		ID          [16]byte
		Party, Bits uint8
		Q           uint32
	}
	if e := binary.Read(r, binary.LittleEndian, &p); e != nil {
		return e
	}
	if string(p.Magic[:]) != "PMEQPS01" || p.Version != m.Version || p.ID != m.IndexID || p.Party != u || p.Bits != m.TargetBucketBits || p.Q != m.Q {
		return ErrTargetArtifact
	}
	var tiers [9]uint32
	if e := binary.Read(r, binary.LittleEndian, tiers[:manifestTierCount(m)]); e != nil {
		return e
	}
	var buckets uint32
	if e := binary.Read(r, binary.LittleEndian, &buckets); e != nil {
		return e
	}
	if tiers != m.Tiers || buckets != m.NonemptyBuckets {
		return ErrTargetArtifact
	}
	return nil
}
