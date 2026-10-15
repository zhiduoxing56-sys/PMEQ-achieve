// Package targetartifact serializes width-bound, party-local global payloads.
// It changes no aggregation, sharing, compaction, or routing algebra.
package targetartifact

import (
	"bufio"
	"encoding/binary"
	"github.com/gtank/ristretto255"
	"io"
	"pmeq/internal/aggregation"
	"pmeq/internal/domain"
	"pmeq/internal/indexbuild"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
)

const PayloadHeaderBytes = 46

// Payload encoding: magic8, IndexID16, LayoutID16, bits1, party1, N4;
// followed by N local (Ring64:8, scalar:32, BucketShare:2) tuples.
func WritePayload(w io.Writer, m indexbuild.TargetManifest, party uint8, p aggregation.PartyPayload) error {
	if e := m.Validate(); e != nil {
		return e
	}
	if party > 1 || p.LayoutID == [16]byte{} || uint64(len(p.Slots)) > 1<<32-1 {
		return indexbuild.ErrTargetArtifact
	}
	b := bufio.NewWriter(w)
	write := func(v any) error { return binary.Write(b, binary.LittleEndian, v) }
	h := struct {
		Magic             [8]byte
		IndexID, LayoutID [16]byte
		Bits, Party       uint8
		N                 uint32
	}{[8]byte{'P', 'M', 'E', 'Q', 'P', 'L', '0', '1'}, m.IndexID, p.LayoutID, m.TargetBucketBits, party, uint32(len(p.Slots))}
	if e := write(h); e != nil {
		return e
	}
	d, _ := targetcrypto.NewBucketDomain(int(m.TargetBucketBits))
	for _, s := range p.Slots {
		if _, e := ristretto255.NewScalar().SetCanonicalBytes(s.KappaJoinShare[:]); e != nil {
			return e
		}
		if e := d.Validate(s.BucketJoinShare); e != nil {
			return e
		}
		if e := write(uint64(s.RecordIDShare.Value())); e != nil {
			return e
		}
		if e := write(s.KappaJoinShare); e != nil {
			return e
		}
		if m.TargetBucketBits > 16 {
			if e := write(uint32(s.BucketJoinShare)); e != nil {
				return e
			}
		} else if e := write(uint16(s.BucketJoinShare)); e != nil {
			return e
		}
	}
	return b.Flush()
}
func ReadPayload(r io.Reader, m indexbuild.TargetManifest, party uint8, layoutID [16]byte, n uint32) (aggregation.PartyPayload, error) {
	var out aggregation.PartyPayload
	if e := m.Validate(); e != nil {
		return out, e
	}
	if party > 1 || layoutID == [16]byte{} {
		return out, indexbuild.ErrTargetArtifact
	}
	b := bufio.NewReader(r)
	read := func(v any) error { return binary.Read(b, binary.LittleEndian, v) }
	var h struct {
		Magic             [8]byte
		IndexID, LayoutID [16]byte
		Bits, Party       uint8
		N                 uint32
	}
	if e := read(&h); e != nil {
		return out, e
	}
	if string(h.Magic[:]) != "PMEQPL01" || h.IndexID != m.IndexID || h.LayoutID != layoutID || h.Bits != m.TargetBucketBits || h.Party != party || h.N != n {
		return out, indexbuild.ErrTargetArtifact
	}
	out = aggregation.PartyPayload{LayoutID: layoutID, Slots: make([]aggregation.PayloadShare, n)}
	d, _ := targetcrypto.NewBucketDomain(int(m.TargetBucketBits))
	for i := range out.Slots {
		s := &out.Slots[i]
		var id uint64
		if e := read(&id); e != nil {
			return out, e
		}
		s.RecordIDShare = share.NewRing64Share(domain.Ring64(id))
		if e := read(&s.KappaJoinShare); e != nil {
			return out, e
		}
		if _, e := ristretto255.NewScalar().SetCanonicalBytes(s.KappaJoinShare[:]); e != nil {
			return out, e
		}
		if m.TargetBucketBits > 16 {
			var v uint32
			if e := read(&v); e != nil {
				return out, e
			}
			s.BucketJoinShare = targetcrypto.BucketShare(v)
		} else {
			var v uint16
			if e := read(&v); e != nil {
				return out, e
			}
			s.BucketJoinShare = targetcrypto.BucketShare(v)
		}
		if e := d.Validate(s.BucketJoinShare); e != nil {
			return out, e
		}
	}
	if _, e := b.ReadByte(); e != io.EOF {
		return out, indexbuild.ErrTargetArtifact
	}
	return out, nil
}
