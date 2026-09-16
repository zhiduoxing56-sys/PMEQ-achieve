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
const TargetArtifactVersion = 1
const TargetHeaderBytes = 70

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
	Tiers            [8]uint32
	LogicalGroups    uint64
	RealPostings     uint64
	PaddedSlots      uint64
	NonemptyBuckets  uint32
	PartyBytes       [2]uint64
	PartySHA256      [2]string
}

func (m TargetManifest) Validate() error {
	if m.Version != TargetArtifactVersion || m.IndexID == [16]byte{} || m.Q != Q || m.AnchorBucketBits != AnchorBucketBits || m.TargetBucketBits != TargetBucketBits {
		return ErrTargetArtifact
	}
	for i, v := range tierLadder {
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

// TargetEncodedBytes is the exact v1 encoding size, excluding its JSON manifest.
func TargetEncodedBytes(buckets, groups, slots uint64) uint64 {
	return TargetHeaderBytes + 14*buckets + 36*groups + 13*slots
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
	header := struct {
		Magic       [8]byte
		Version     uint32
		ID          [16]byte
		Party, Bits uint8
		Q           uint32
		Tiers       [8]uint32
		Buckets     uint32
	}{[8]byte{'P', 'M', 'E', 'Q', 'P', 'S', '0', '1'}, m.Version, m.IndexID, party, m.TargetBucketBits, m.Q, m.Tiers, m.NonemptyBuckets}
	if e := write(header); e != nil {
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
		if e := write(bucket.BucketID); e != nil {
			return e
		}
		if e := write(uint32(len(bucket.Groups))); e != nil {
			return e
		}
		if e := write(total); e != nil {
			return e
		}
		for _, g := range bucket.Groups {
			if !validPad(g.PadWidth) || len(g.Slots) != int(g.PadWidth) {
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
	var h struct {
		Magic       [8]byte
		Version     uint32
		ID          [16]byte
		Party, Bits uint8
		Q           uint32
		Tiers       [8]uint32
		Buckets     uint32
	}
	if e := read(&h); e != nil {
		return out, e
	}
	if string(h.Magic[:]) != "PMEQPS01" || h.Version != m.Version || h.ID != m.IndexID || h.Party != party || h.Bits != m.TargetBucketBits || h.Q != m.Q || h.Tiers != m.Tiers || h.Buckets != m.NonemptyBuckets {
		return out, ErrTargetArtifact
	}
	var groups, slots uint64
	last := -1
	for bi := uint32(0); bi < h.Buckets; bi++ {
		var id uint16
		var count uint32
		var total uint64
		if e := read(&id); e != nil {
			return out, e
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
			if !validPad(g.PadWidth) || uint64(g.PadWidth) > total-actual {
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
