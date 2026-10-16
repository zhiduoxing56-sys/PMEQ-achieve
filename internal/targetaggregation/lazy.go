package targetaggregation

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"

	"pmeq/internal/domain"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/share"
	"pmeq/internal/targetpe"
)

// OpenSidecarLazy validates the complete party file once, retains only public
// per-bucket offsets, and decodes matrix shares when a query routes to a bucket.
// The caller owns the returned open file and closes it with Close.
func OpenSidecarLazy(m SidecarManifest, sealedManifest []byte, idx *targetpe.PartyIndex, path string) (*PartySidecar, error) {
	if idx == nil || path == "" {
		return nil, ErrBinding
	}
	sm, err := indexbuild.ReadTargetManifest(bytes.NewReader(sealedManifest))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(sealedManifest)
	if digest != idx.ManifestDigest() || m.Version != 1 || m.IndexID != sm.IndexID || m.IndexID != idx.Manifest().IndexID || m.ManifestSHA256 != hex.EncodeToString(digest[:]) || m.StructureDigest != idx.StructureDigest() || m.DTarget < 1 || m.DTarget > 26 || m.MaxMultiplicity != MaxMultiplicity || m.IncidenceBytes != uint64(m.DTarget)*sm.PaddedSlots || m.TargetIDBytes != uint64(m.DTarget)*8*sm.LogicalGroups {
		return nil, ErrBinding
	}
	expected := uint64(57) + uint64(1<<sm.TargetBucketBits)*4 + sm.LogicalGroups*4 + m.IncidenceBytes + m.TargetIDBytes
	party := idx.Party()
	if m.PartyBytes != ([2]uint64{expected, expected}) {
		return nil, ErrBinding
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	valid := false
	defer func() {
		if !valid {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil || st.Size() != int64(expected) || !st.Mode().IsRegular() {
		return nil, ErrBinding
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil || hex.EncodeToString(h.Sum(nil)) != m.PartySHA256[party] {
		return nil, ErrBinding
	}
	var header [57]byte
	if _, err = f.ReadAt(header[:], 0); err != nil || string(header[:8]) != SidecarMagic || header[8] != party || !bytes.Equal(header[9:25], m.IndexID[:]) || !bytes.Equal(header[25:], digest[:]) {
		return nil, ErrBinding
	}
	count := 1 << sm.TargetBucketBits
	offsets := make([]int64, count+1)
	off := int64(len(header))
	for id := 0; id < count; id++ {
		offsets[id] = off
		gs := idx.PositionGroups(uint32(id))
		shape := make([]byte, 4+4*len(gs))
		if _, err = f.ReadAt(shape, off); err != nil || binary.LittleEndian.Uint32(shape[:4]) != uint32(len(gs)) {
			return nil, ErrBinding
		}
		var slots int
		for j, g := range gs {
			if binary.LittleEndian.Uint32(shape[4+4*j:]) != g.PadWidth {
				return nil, ErrBinding
			}
			slots += int(g.PadWidth)
		}
		off += int64(len(shape) + int(m.DTarget)*slots + int(m.DTarget)*8*len(gs))
		if off > int64(expected) {
			return nil, ErrBinding
		}
	}
	offsets[count] = off
	if off != int64(expected) {
		return nil, ErrBinding
	}
	valid = true
	return &PartySidecar{manifest: m, party: party, bits: sm.TargetBucketBits, buckets: make([]bucket, count), file: f, offsets: offsets}, nil
}

func (s *PartySidecar) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

func (s *PartySidecar) loadBucket(id uint32) (bucket, error) {
	if s == nil || int(id) >= len(s.buckets) {
		return bucket{}, ErrBinding
	}
	if s.file == nil {
		return s.buckets[id], nil
	}
	start, end := s.offsets[id], s.offsets[id+1]
	r := io.NewSectionReader(s.file, start, end-start)
	var n uint32
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return bucket{}, err
	}
	b := bucket{widths: make([]uint32, n)}
	var slots int
	for i := range b.widths {
		if err := binary.Read(r, binary.LittleEndian, &b.widths[i]); err != nil {
			return bucket{}, err
		}
		slots += int(b.widths[i])
	}
	d := int(s.manifest.DTarget)
	coeff := make([]byte, d*slots)
	if _, err := io.ReadFull(r, coeff); err != nil {
		return bucket{}, err
	}
	var err error
	b.matrix, err = incidence.FromLocalCoefficients(d, slots, coeff)
	if err != nil {
		return bucket{}, err
	}
	b.ids = make([]share.Ring64Share, d*int(n))
	for i := range b.ids {
		var v uint64
		if err = binary.Read(r, binary.LittleEndian, &v); err != nil {
			return bucket{}, err
		}
		b.ids[i] = share.NewRing64Share(domain.Ring64(v))
	}
	position, seekErr := r.Seek(0, io.SeekCurrent)
	if seekErr != nil || position != r.Size() {
		return bucket{}, ErrBinding
	}
	return b, nil
}
