// Package targetpe stops at secret group equality. It never opens Match or
// evaluates Target positions/aggregation, and accepts only party-local inputs.
package targetpe

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetrouting"
)

var ErrBinding = errors.New("targetpe: invalid artifact, lineage, query, packet or round")

type PayloadManifest struct {
	IndexID, LayoutID [16]byte
	TargetBucketBits  uint8
	N                 int
	Bytes             [2]int64
	SHA256            [2]string
}
type AlignmentLineage struct {
	IndexID, LayoutID [16]byte
	N                 int
}
type PartyIndex struct {
	manifest  indexbuild.TargetManifest
	lineage   AlignmentLineage
	party     uint8
	buckets   [65536][]indexbuild.TargetPartyGroup
	structure [32]byte
}

// Load verifies the trusted public manifests, own sealed PSMJ and own payload
// hashes, and the provisioned alignment lineage. No peer shares are accepted.
func Load(manifest, payloadManifest io.Reader, psmj, payload io.Reader, party uint8, alignment AlignmentLineage) (*PartyIndex, error) {
	if party > 1 {
		return nil, ErrBinding
	}
	m, e := indexbuild.ReadTargetManifest(manifest)
	if e != nil {
		return nil, e
	}
	var p PayloadManifest
	d := json.NewDecoder(io.LimitReader(payloadManifest, 16384))
	d.DisallowUnknownFields()
	if e = d.Decode(&p); e != nil {
		return nil, e
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return nil, ErrBinding
	}
	if p.IndexID != m.IndexID || p.TargetBucketBits != 16 || p.LayoutID == [16]byte{} || p.N != 120071 || alignment != (AlignmentLineage{m.IndexID, p.LayoutID, p.N}) {
		return nil, ErrBinding
	}
	// Verify the global payload header as well as its exact trusted file hash.
	h := sha256.New()
	var header [46]byte
	if _, e = io.ReadFull(io.TeeReader(payload, h), header[:]); e != nil {
		return nil, e
	}
	if string(header[:8]) != "PMEQPL01" || !bytes.Equal(header[8:24], m.IndexID[:]) || !bytes.Equal(header[24:40], p.LayoutID[:]) || header[40] != 16 || header[41] != party || binary.LittleEndian.Uint32(header[42:]) != uint32(p.N) {
		return nil, ErrBinding
	}
	n, e := io.Copy(h, payload)
	if e != nil {
		return nil, e
	}
	if n+46 != p.Bytes[party] || n != int64(42*p.N) || hex.EncodeToString(h.Sum(nil)) != p.SHA256[party] {
		return nil, ErrBinding
	}
	h = sha256.New()
	counter := &countReader{r: io.TeeReader(psmj, h)}
	idx, e := indexbuild.ReadTargetParty(counter, m, party)
	if e != nil {
		return nil, e
	}
	if uint64(counter.n) != m.PartyBytes[party] || hex.EncodeToString(h.Sum(nil)) != m.PartySHA256[party] {
		return nil, ErrBinding
	}
	out := &PartyIndex{manifest: m, lineage: alignment, party: party}
	for _, b := range idx.TargetBuckets {
		out.buckets[b.BucketID] = b.Groups
	}
	hash := sha256.New()
	for b, gs := range out.buckets {
		binary.Write(hash, binary.LittleEndian, uint16(b))
		binary.Write(hash, binary.LittleEndian, uint32(len(gs)))
		for _, g := range gs {
			binary.Write(hash, binary.LittleEndian, g.PadWidth)
		}
	}
	copy(out.structure[:], hash.Sum(nil))
	return out, nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(b []byte) (int, error) { n, e := c.r.Read(b); c.n += int64(n); return n, e }

// StructureDigest scans all 65536 buckets, group counts and PadWidth order.
// Its exchange reveals no secret T values. Hash-verified owner files bind ordinals.
func (p *PartyIndex) StructureDigest() [32]byte { return p.structure }
func (p *PartyIndex) Manifest() targetrouting.Manifest {
	return targetrouting.Manifest{IndexID: p.manifest.IndexID, TargetBucketBits: 16, Q: 4}
}
func (p *PartyIndex) Lineage() AlignmentLineage { return p.lineage }
