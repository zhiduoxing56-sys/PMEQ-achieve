package targetaggregation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"pmeq/internal/incidence"
	"pmeq/internal/zeroagg"
)

func zeroCapacity(d int) int {
	n := 1
	for n < d {
		n *= 2
	}
	return n
}

type zeroLabelFile struct {
	Version    int
	Party      uint8
	ID         string
	IndexID    [16]byte
	Structure  [32]byte
	MatrixHash string
	D          int
	Buckets    [][]zeroagg.F
}

// Private label digests are local integrity metadata, never part of a message.
type zeroLabelMeta struct {
	ID   string
	Hash string
}

func createJSON(path string, v any) error {
	raw, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = f.Write(raw); e != nil {
		return e
	}
	return f.Sync()
}

// MigrateZeroLabels is TRUSTED OFFLINE ONLY. Both old sidecars have already
// been authenticated by LoadSidecar. Recover only validated one-hot coordinates.
func MigrateZeroLabels(root string, a, b *PartySidecar) error {
	if a == nil || b == nil || a.party != 0 || b.party != 1 || a.manifest != b.manifest || len(a.buckets) != len(b.buckets) {
		return ErrBinding
	}
	if e := os.Mkdir(root, 0700); e != nil {
		return e
	}
	id := zeroagg.RandomID()
	meta := zeroLabelMeta{ID: id}
	fs := [2]zeroLabelFile{}
	for j := range fs {
		fs[j] = zeroLabelFile{1, uint8(j), id, a.manifest.IndexID, a.manifest.StructureDigest, a.manifest.PartySHA256[j], a.Capacity(), make([][]zeroagg.F, len(a.buckets))}
	}
	for bi := range a.buckets {
		ab, err := a.loadBucket(uint32(bi))
		if err != nil {
			return err
		}
		bb, err := b.loadBucket(uint32(bi))
		if err != nil {
			return err
		}
		x, y := ab.matrix, bb.matrix
		if x == nil || y == nil || x.T != y.T || x.D != y.D {
			return ErrBinding
		}
		if x.T > 65536 {
			return fmt.Errorf("public target bucket %d exceeds GF16 slot cap", bi)
		}
		var ax, by bytes.Buffer
		if e := x.WriteCoefficients(&ax); e != nil {
			return e
		}
		if e := y.WriteCoefficients(&by); e != nil {
			return e
		}
		coords := make([]int, x.T)
		for i := range coords {
			coords[i] = -1
			for j := 0; j < x.D; j++ {
				v := (ax.Bytes()[i*x.D+j] + by.Bytes()[i*x.D+j]) & 127
				if v > 1 || (v == 1 && coords[i] != -1) {
					return ErrBinding
				}
				if v == 1 {
					coords[i] = j
				}
			}
		}
		var e error
		fs[0].Buckets[bi], fs[1].Buckets[bi], e = zeroagg.ShareCoordinates(coords, zeroCapacity(x.D))
		if e != nil {
			return e
		}
	}
	for j := range fs {
		dir := filepath.Join(root, fmt.Sprintf("cs%d", j))
		if e := os.Mkdir(dir, 0700); e != nil {
			return e
		}
		path := filepath.Join(dir, "target-labels.json")
		if e := createJSON(path, fs[j]); e != nil {
			return e
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		h := sha256.Sum256(raw)
		ownMeta := zeroLabelMeta{ID: id, Hash: hex.EncodeToString(h[:])}
		if e = createJSON(filepath.Join(dir, "label-meta.json"), ownMeta); e != nil {
			return e
		}
	}
	return createJSON(filepath.Join(root, "label-meta.json"), struct{ ID string }{meta.ID})
}

func (s *PartySidecar) LoadZeroLabels(root string) error {
	raw, e := os.ReadFile(filepath.Join(root, fmt.Sprintf("cs%d/label-meta.json", s.party)))
	if e != nil {
		return e
	}
	var m zeroLabelMeta
	if e = json.Unmarshal(raw, &m); e != nil {
		return e
	}
	raw, e = os.ReadFile(filepath.Join(root, fmt.Sprintf("cs%d/target-labels.json", s.party)))
	if e != nil {
		return e
	}
	h := sha256.Sum256(raw)
	var public struct{ ID string }
	pub, e := os.ReadFile(filepath.Join(root, "label-meta.json"))
	if e != nil {
		return e
	}
	if e = json.Unmarshal(pub, &public); e != nil {
		return e
	}
	if public.ID != m.ID {
		return ErrBinding
	}
	if hex.EncodeToString(h[:]) != m.Hash {
		return ErrBinding
	}
	var f zeroLabelFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&f); e != nil {
		return e
	}
	if dec.Decode(new(any)) != io.EOF {
		return ErrBinding
	}
	if f.Version != 1 || f.Party != s.party || f.ID != m.ID || f.ID == "" || f.IndexID != s.manifest.IndexID || f.Structure != s.manifest.StructureDigest || f.MatrixHash != s.manifest.PartySHA256[s.party] || f.D != s.Capacity() || len(f.Buckets) != len(s.buckets) {
		return ErrBinding
	}
	for i, b := range s.buckets {
		if s.file != nil {
			loaded, err := s.loadBucket(uint32(i))
			if err != nil || len(f.Buckets[i]) != loaded.matrix.T {
				return ErrBinding
			}
			continue
		}
		if len(f.Buckets[i]) != b.matrix.T {
			return ErrBinding
		}
	}
	// Keep public shape and existing identifier payloads; release dense coefficients.
	if s.file == nil {
		for i := range s.buckets {
			b := &s.buckets[i]
			b.matrix = &incidence.PartyMatrix{D: b.matrix.D, T: b.matrix.T}
		}
	}
	s.labels, s.labelID = f.Buckets, f.ID
	return nil
}
func (s *PartySidecar) ZeroConfig() (int, string) {
	t := 0
	for _, labels := range s.labels {
		t = max(t, len(labels))
	}
	return t, s.labelID
}
