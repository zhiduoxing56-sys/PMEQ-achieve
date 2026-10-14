package discovery

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorindex"
	"pmeq/internal/domain"
	"pmeq/internal/indexbuild"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/zeroagg"
)

// AnchorArtifact describes persisted original BSMJ, independent GF labels and compact
// permutation factors. It contains public layout sizes and hashes only.
type AnchorArtifact struct {
	Bucket       uint32
	D, T, Groups int
	Bytes        [2]uint64
	SHA256       [2]string
	// Index, labels, alignment bytes measured at the encoder boundaries.
	SectionBytes [2][3]uint64
}

type anchorHeader struct {
	Magic             [8]byte
	IndexID, LayoutID [16]byte
	Party             uint8
	Bucket            uint32
	N, D              uint32
	T                 uint64
	Groups            uint32
}

// WriteAnchorStatic persists a single party's existing state with original slots and alignment factors, plus directly generated GF labels.
func WriteAnchorStatic(w io.Writer, indexID, layoutID [16]byte, party uint8, n int, a AnchorStatic, sections ...*[3]uint64) error {
	if len(sections) > 1 {
		return ErrBinding
	}
	if party > 1 || n < 0 || indexID == [16]byte{} || layoutID == [16]byte{} || a.D > n || !validAnchorLabels(a) {
		return ErrBinding
	}
	if (party == 0 && (a.Stage0 == nil || a.Stage1 != nil || a.Stage0.LayoutID != layoutID || a.Stage0.BucketID != a.Bucket.BucketID)) || (party == 1 && (a.Stage1 == nil || a.Stage0 != nil || a.Stage1.LayoutID != layoutID || a.Stage1.BucketID != a.Bucket.BucketID || a.Stage1.GlobalRecords() != n)) {
		return ErrBinding
	}
	c := &artifactWriter{w: w}
	b := bufio.NewWriterSize(c, 1<<20)
	h := anchorHeader{[8]byte{'P', 'M', 'E', 'Q', 'B', 'S', '0', '2'}, indexID, layoutID, party, a.Bucket.BucketID, uint32(n), uint32(a.D), uint64(a.T), uint32(len(a.Bucket.Groups))}
	if e := binary.Write(b, binary.LittleEndian, h); e != nil {
		return e
	}
	var raw [47]byte
	t := 0
	for _, g := range a.Bucket.Groups {
		if len(g.Slots) != int(g.PadWidth) {
			return ErrBinding
		}
		if _, e := b.Write(g.Z[:]); e != nil {
			return e
		}
		if e := binary.Write(b, binary.LittleEndian, g.PadWidth); e != nil {
			return e
		}
		for _, s := range g.Slots {
			binary.LittleEndian.PutUint64(raw[:8], uint64(s.RecordIDShare.Value()))
			binary.LittleEndian.PutUint32(raw[8:12], uint32(s.PositionShare.Value()))
			raw[12] = 0
			if bool(s.ValidityShare.Value()) {
				raw[12] = 1
			}
			copy(raw[13:45], s.KappaJoinShare[:])
			if uint32(s.BucketJoinShare) >= 65536 {
				return ErrBinding
			}
			binary.LittleEndian.PutUint16(raw[45:], uint16(s.BucketJoinShare))
			if _, e := b.Write(raw[:]); e != nil {
				return e
			}
			t++
		}
	}
	if t != a.T {
		return ErrBinding
	}
	base := c.n + uint64(b.Buffered())
	labelID, e := hex.DecodeString(a.LabelID)
	if e != nil || len(labelID) != 16 {
		return ErrBinding
	}
	if _, e = b.Write(labelID); e != nil {
		return e
	}
	if e := binary.Write(b, binary.LittleEndian, a.Labels); e != nil {
		return e
	}
	labelBytes := c.n + uint64(b.Buffered()) - base
	if party == 0 {
		if _, e := b.Write(a.Stage0.RhoSeed[:]); e != nil {
			return e
		}
	} else {
		if e := a.Stage1.WriteSigma(b); e != nil {
			return e
		}
	}
	if e := b.Flush(); e != nil {
		return e
	}
	if len(sections) == 1 && sections[0] != nil {
		*sections[0] = [3]uint64{base, labelBytes, c.n - base - labelBytes}
	}
	return nil
}

// ReadAnchorStatic authenticates and restores only the caller's local state.
func ReadAnchorStatic(r io.Reader, indexID, layoutID [16]byte, party uint8, n int, m AnchorArtifact) (AnchorStatic, error) {
	var out AnchorStatic
	if party > 1 || n < 0 || m.D < 0 || m.D > n || m.D > 32768 || (m.D > 0 && m.D&(m.D-1) != 0) || m.T < 0 || m.T > 65536 || (m.T == 0) != (m.D == 0) || m.Groups < 0 {
		return out, ErrBinding
	}
	hash := sha256.New()
	c := &artifactCounter{r: io.TeeReader(r, hash)}
	b := bufio.NewReaderSize(c, 1<<20)
	var h anchorHeader
	if e := binary.Read(b, binary.LittleEndian, &h); e != nil {
		return out, e
	}
	if string(h.Magic[:]) != "PMEQBS02" || h.IndexID != indexID || h.LayoutID != layoutID || h.Party != party || h.Bucket != m.Bucket || h.N != uint32(n) || h.D != uint32(m.D) || h.T != uint64(m.T) || h.Groups != uint32(m.Groups) {
		return out, ErrBinding
	}
	out.Bucket = indexbuild.AnchorPartyBucket{BucketID: m.Bucket}
	if m.Groups > 0 {
		out.Bucket.Groups = make([]indexbuild.AnchorPartyGroup, m.Groups)
	}
	var raw [47]byte
	t := 0
	for i := range out.Bucket.Groups {
		g := &out.Bucket.Groups[i]
		if _, e := io.ReadFull(b, g.Z[:]); e != nil {
			return out, e
		}
		if e := binary.Read(b, binary.LittleEndian, &g.PadWidth); e != nil {
			return out, e
		}
		width, e := indexbuild.TierWidth(int(g.PadWidth))
		if e != nil || width != int(g.PadWidth) || int(g.PadWidth) > m.T-t {
			return out, ErrBinding
		}
		bucket, e := indexbuild.AnchorBucket(anchorindex.Value(g.Z), 16)
		if e != nil || bucket != m.Bucket {
			return out, ErrBinding
		}
		g.Slots = make([]indexbuild.AnchorPartySlot, g.PadWidth)
		for j := range g.Slots {
			if _, e := io.ReadFull(b, raw[:]); e != nil {
				return out, e
			}
			s := &g.Slots[j]
			s.RecordIDShare = share.NewRing64Share(domain.Ring64(binary.LittleEndian.Uint64(raw[:8])))
			s.PositionShare = share.NewRing32Share(domain.Ring32(binary.LittleEndian.Uint32(raw[8:12])))
			if raw[12] > 1 {
				return out, ErrBinding
			}
			s.ValidityShare = share.NewBitShare(domain.Bit(raw[12] != 0))
			copy(s.KappaJoinShare[:], raw[13:45])
			if _, e := targetcrypto.NewScalarShare(s.KappaJoinShare); e != nil {
				return out, e
			}
			s.BucketJoinShare = targetcrypto.BucketShare(binary.LittleEndian.Uint16(raw[45:]))
			t++
		}
	}
	if t != m.T {
		return out, ErrBinding
	}
	var e error
	out.D, out.T = m.D, m.T
	var labelID [16]byte
	if _, e = io.ReadFull(b, labelID[:]); e != nil { return out, e }
	out.LabelID = hex.EncodeToString(labelID[:])
	out.Labels = make([]zeroagg.F, m.T)
	e = binary.Read(b, binary.LittleEndian, out.Labels)
	if e != nil { return out, e }
	if !validAnchorLabels(out) { return out, ErrBinding }
	if party == 0 {
		s := &aggregation.Stage0{LayoutID: layoutID, BucketID: m.Bucket}
		if _, e = io.ReadFull(b, s.RhoSeed[:]); e != nil {
			return out, e
		}
		out.Stage0 = s
	} else {
		out.Stage1, e = aggregation.ReadSigma(b, layoutID, m.Bucket, n)
		if e != nil {
			return out, e
		}
	}
	if _, e = b.ReadByte(); e != io.EOF {
		return out, ErrBinding
	}
	if c.n != m.Bytes[party] || hex.EncodeToString(hash.Sum(nil)) != m.SHA256[party] {
		return out, ErrBinding
	}
	return out, nil
}

type artifactCounter struct {
	r io.Reader
	n uint64
}

func (c *artifactCounter) Read(b []byte) (int, error) {
	n, e := c.r.Read(b)
	c.n += uint64(n)
	return n, e
}

type artifactWriter struct {
	w io.Writer
	n uint64
}

func (c *artifactWriter) Write(b []byte) (int, error) {
	n, e := c.w.Write(b)
	c.n += uint64(n)
	return n, e
}
