// Package targetaggregation implements the fixed 26-ordinal Target boundary.
package targetaggregation

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	"pmeq/internal/domain"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/share"
	"pmeq/internal/targetpe"
)

const DTarget = 26
const MaxOccurrences = 16
const MaxMultiplicity = 3
const SidecarMagic = "PMEQTG01"

var ErrBinding = errors.New("targetaggregation: invalid binding, domain, shape or lifecycle")

func Threshold(r, tau int) (int, error) {
	if r < 1 || r > MaxOccurrences || tau < 0 || tau >= r {
		return 0, ErrBinding
	}
	return r - tau, nil
}

// SidecarManifest is trusted-DO provisioning metadata. Its manifest digest
// binds the exact bytes of the sealed PSMJ manifest, including both file hashes.
type SidecarManifest struct {
	Version                       uint32
	IndexID                       [16]byte
	ManifestSHA256                string
	StructureDigest               [32]byte
	DTarget, MaxMultiplicity      uint32
	IncidenceBytes, TargetIDBytes uint64 // per-party semantic field bytes
	PartyBytes                    [2]uint64
	PartySHA256                   [2]string
}

type bucket struct {
	widths []uint32
	matrix *incidence.PartyMatrix
	ids    []share.Ring64Share
}
type PartySidecar struct {
	manifest SidecarManifest
	party    uint8
	buckets  []bucket
	bits     uint8
}

// LoadSidecar reads only the caller's hash-bound sidecar. It checks every
// bucket/group width against the already verified PSMJ PartyIndex, including
// empty buckets. No slot or group can be omitted/reordered on load.
func LoadSidecar(m SidecarManifest, sealedManifest []byte, idx *targetpe.PartyIndex, input io.Reader) (*PartySidecar, error) {
	if idx == nil {
		return nil, ErrBinding
	}
	sm, e := indexbuild.ReadTargetManifest(bytes.NewReader(sealedManifest))
	if e != nil {
		return nil, e
	}
	digest := sha256.Sum256(sealedManifest)
	if digest != idx.ManifestDigest() {
		return nil, ErrBinding
	}
	if m.Version != 1 || m.IndexID != sm.IndexID || m.IndexID != idx.Manifest().IndexID || m.ManifestSHA256 != hex.EncodeToString(digest[:]) || m.StructureDigest != idx.StructureDigest() || (m.DTarget != 16 && m.DTarget != 26) || m.MaxMultiplicity != MaxMultiplicity || m.IncidenceBytes != uint64(m.DTarget)*sm.PaddedSlots || m.TargetIDBytes != uint64(m.DTarget)*8*sm.LogicalGroups {
		return nil, ErrBinding
	}
	d := int(m.DTarget)
	expected := uint64(8+1+16+32) + uint64(1<<sm.TargetBucketBits)*4 + sm.LogicalGroups*4 + m.IncidenceBytes + m.TargetIDBytes
	u := idx.Party()
	if m.PartyBytes != ([2]uint64{expected, expected}) {
		return nil, ErrBinding
	}
	for _, value := range m.PartySHA256 {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			return nil, ErrBinding
		}
	}
	h := sha256.New()
	c := &countReader{r: io.TeeReader(io.LimitReader(input, int64(expected)+1), h)}
	r := bufio.NewReader(c)
	var header [57]byte
	if _, e = io.ReadFull(r, header[:]); e != nil {
		return nil, e
	}
	if string(header[:8]) != SidecarMagic || header[8] != u || !bytes.Equal(header[9:25], m.IndexID[:]) || !bytes.Equal(header[25:], digest[:]) {
		return nil, ErrBinding
	}
	out := &PartySidecar{manifest: m, party: u, bits: sm.TargetBucketBits, buckets: make([]bucket, 1<<sm.TargetBucketBits)}
	var n, width uint32
	for bi := range out.buckets {
		gs := idx.PositionGroups(uint32(bi))
		if e = binary.Read(r, binary.LittleEndian, &n); e != nil {
			return nil, e
		}
		if int(n) != len(gs) {
			return nil, ErrBinding
		}
		b := &out.buckets[bi]
		b.widths = make([]uint32, n)
		t := 0
		for gi, g := range gs {
			if e = binary.Read(r, binary.LittleEndian, &width); e != nil {
				return nil, e
			}
			if width != g.PadWidth {
				return nil, ErrBinding
			}
			b.widths[gi] = width
			t += int(width)
		}
		coeff := make([]byte, d*t)
		if _, e = io.ReadFull(r, coeff); e != nil {
			return nil, e
		}
		b.matrix, e = incidence.FromLocalCoefficients(d, t, coeff)
		if e != nil {
			return nil, e
		}
		b.ids = make([]share.Ring64Share, d*len(gs))
		var v uint64
		for j := range b.ids {
			if e = binary.Read(r, binary.LittleEndian, &v); e != nil {
				return nil, e
			}
			b.ids[j] = share.NewRing64Share(domain.Ring64(v))
		}
	}
	if _, e = r.ReadByte(); e != io.EOF {
		return nil, ErrBinding
	}
	if c.n != expected || hex.EncodeToString(h.Sum(nil)) != m.PartySHA256[u] {
		return nil, ErrBinding
	}
	return out, nil
}

type countReader struct {
	r io.Reader
	n uint64
}

func (r *countReader) Read(b []byte) (int, error) { n, e := r.r.Read(b); r.n += uint64(n); return n, e }

// Capacity is public static metadata, bound by the sealed manifest.
func (s *PartySidecar) Capacity() int { return int(s.manifest.DTarget) }
