package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"pmeq/internal/imdbprod"
	"pmeq/internal/indexbuild"
	"sort"
	"syscall"
	"time"
)

// MovieAnchorStore is a party-local view of a sealed, content-addressed BS02
// catalog. Only a requested bucket is decoded; no sigma is cached here.
type MovieAnchorStore struct {
	root    string
	party   uint8
	catalog movieAnchorCatalog
	byID    map[uint32]AnchorArtifact
}

const movieAnchorStoreVersion = "IMDB-BS02-BUCKETS-v1"

type movieAnchorCatalog struct {
	Version  string           `json:"version"`
	Binding  string           `json:"binding_sha256"`
	IndexID  [16]byte         `json:"index_id"`
	LayoutID [16]byte         `json:"layout_id"`
	N        int              `json:"n"`
	Complete bool             `json:"complete"`
	Buckets  []AnchorArtifact `json:"buckets"`
}

// MovieAnchorWriter is trusted-DO only. A bucket is committed to the catalog
// only after both party files are fully written and synced. An interrupted
// write leaves at most unreferenced content-addressed files, never a half pair.
type MovieAnchorWriter struct {
	root           string
	catalog        movieAnchorCatalog
	lock           *os.File
	keyFingerprint string
	stats          MovieAnchorWriteStats
}

type MovieAnchorWriteStats struct {
	Buckets               int       `json:"buckets"`
	PartyBytes            [2]uint64 `json:"party_bytes"`
	MaxTemporaryFileBytes uint64    `json:"max_temporary_file_bytes"`
	WriteWallNS           int64     `json:"write_wall_ns"`
}

func (w *MovieAnchorWriter) Stats() MovieAnchorWriteStats {
	if w == nil {
		return MovieAnchorWriteStats{}
	}
	return w.stats
}

func NewMovieAnchorWriter(root string, binding imdbprod.Binding) (*MovieAnchorWriter, error) {
	digest, err := binding.Digest()
	if err != nil || root == "" {
		return nil, ErrBinding
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(root, ".writer.lock"), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, err
	}
	good := false
	defer func() {
		if !good {
			syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			lock.Close()
		}
	}()
	for _, party := range []string{"cs0", "cs1"} {
		if err = os.MkdirAll(filepath.Join(root, party), 0700); err != nil {
			return nil, err
		}
	}
	w := &MovieAnchorWriter{root: root, lock: lock, keyFingerprint: binding.KeyFingerprint, catalog: movieAnchorCatalog{
		Version: movieAnchorStoreVersion, Binding: hex.EncodeToString(digest[:]),
		IndexID: binding.IndexID, LayoutID: binding.LayoutID, N: imdbprod.AnchorObjects,
	}}
	raw, err := os.ReadFile(filepath.Join(root, "catalog.json"))
	if os.IsNotExist(err) {
		if err = w.save(); err != nil {
			return nil, err
		}
		good = true
		return w, nil
	}
	if err != nil {
		return nil, err
	}
	var old movieAnchorCatalog
	if json.Unmarshal(raw, &old) != nil || old.Version != w.catalog.Version || old.Binding != w.catalog.Binding || old.IndexID != w.catalog.IndexID || old.LayoutID != w.catalog.LayoutID || old.N != w.catalog.N || old.Complete || !validMovieAnchorEntries(old.Buckets) {
		return nil, ErrBinding
	}
	w.catalog = old
	// A resume must authenticate every committed bucket before skipping it.
	// A changed or missing file cannot silently survive into the final catalog.
	for _, entry := range old.Buckets {
		for party := uint8(0); party < 2; party++ {
			f, e := os.Open(movieAnchorPath(root, party, entry.Bucket, entry.SHA256[party]))
			if e != nil {
				return nil, e
			}
			loaded, readErr := ReadAnchorStatic(f, old.IndexID, old.LayoutID, party, old.N, entry)
			closeErr := f.Close()
			if loaded.Stage1 != nil {
				loaded.Stage1.Discard()
			}
			if readErr != nil {
				return nil, readErr
			}
			if closeErr != nil {
				return nil, closeErr
			}
		}
	}
	good = true
	return w, nil
}

func (w *MovieAnchorWriter) Close() error {
	if w == nil || w.lock == nil {
		return nil
	}
	err := syscall.Flock(int(w.lock.Fd()), syscall.LOCK_UN)
	closeErr := w.lock.Close()
	w.lock = nil
	if err != nil {
		return err
	}
	return closeErr
}

func validMovieAnchorEntries(entries []AnchorArtifact) bool {
	for i, e := range entries {
		if e.Bucket >= 1<<imdbprod.BucketBits || (i > 0 && entries[i-1].Bucket >= e.Bucket) || e.D < 1 || e.D > imdbprod.AnchorObjects || e.T < 1 || e.T > 65536 || e.Groups < 1 || e.Bytes[0] == 0 || e.Bytes[1] == 0 {
			return false
		}
		for p := 0; p < 2; p++ {
			v, err := hex.DecodeString(e.SHA256[p])
			if err != nil || len(v) != 32 {
				return false
			}
		}
	}
	return true
}

func (w *MovieAnchorWriter) save() error {
	raw, err := json.MarshalIndent(w.catalog, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	f, err := os.CreateTemp(w.root, ".catalog-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), filepath.Join(w.root, "catalog.json")); err != nil {
		return err
	}
	dir, err := os.Open(w.root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func movieAnchorPath(root string, party uint8, bucket uint32, digest string) string {
	return filepath.Join(root, fmt.Sprintf("cs%d", party), fmt.Sprintf("%05d-%s.bs02", bucket, digest))
}

func (w *MovieAnchorWriter) writeOne(party uint8, bucket uint32, a AnchorStatic) (uint64, string, [3]uint64, error) {
	var sections [3]uint64
	f, err := os.CreateTemp(filepath.Join(w.root, fmt.Sprintf("cs%d", party)), ".bucket-*")
	if err != nil {
		return 0, "", sections, err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return 0, "", sections, err
	}
	h := sha256.New()
	c := &artifactWriter{w: io.MultiWriter(f, h)}
	err = WriteAnchorStatic(c, w.catalog.IndexID, w.catalog.LayoutID, party, w.catalog.N, a, &sections)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return 0, "", sections, err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	final := movieAnchorPath(w.root, party, bucket, digest)
	// Link fails if an existing committed or orphan file has this name. Never
	// replace a file that a previously sealed catalog could still reference.
	if err = os.Link(f.Name(), final); os.IsExist(err) {
		var existing *os.File
		existing, err = os.Open(final)
		if err == nil {
			checkHash := sha256.New()
			var n int64
			n, err = io.Copy(checkHash, existing)
			existing.Close()
			if err == nil && (uint64(n) != c.n || hex.EncodeToString(checkHash.Sum(nil)) != digest) {
				err = ErrBinding
			}
		}
	}
	if err != nil {
		return 0, "", sections, err
	}
	dir, err := os.Open(filepath.Dir(final))
	if err != nil {
		return 0, "", sections, err
	}
	err = dir.Sync()
	dir.Close()
	return c.n, digest, sections, err
}

// PutPair writes and verifies one nonempty bucket. A committed bucket cannot
// be regenerated or replaced on resume; callers skip it using Has.
func (w *MovieAnchorWriter) PutPair(bucket uint32, a, b AnchorStatic) error {
	started := time.Now()
	if w == nil || w.lock == nil || w.catalog.Complete || bucket >= 1<<imdbprod.BucketBits || w.Has(bucket) || a.Bucket.BucketID != bucket || b.Bucket.BucketID != bucket || a.D != b.D || a.T != b.T || a.LabelID != b.LabelID || a.Stage0 == nil || a.Stage1 != nil || b.Stage0 != nil || b.Stage1 == nil || !validAnchorLabels(a) || !validAnchorLabels(b) || a.T == 0 || a.Stage0.LayoutID != w.catalog.LayoutID || b.Stage1.LayoutID != w.catalog.LayoutID || b.Stage1.GlobalRecords() != w.catalog.N {
		return ErrBinding
	}
	entry := AnchorArtifact{Bucket: bucket, D: a.D, T: a.T, Groups: len(a.Bucket.Groups)}
	if len(b.Bucket.Groups) != entry.Groups {
		return ErrBinding
	}
	for i, g := range a.Bucket.Groups {
		if g.Z != b.Bucket.Groups[i].Z || g.PadWidth != b.Bucket.Groups[i].PadWidth {
			return ErrBinding
		}
	}
	for p, state := range []AnchorStatic{a, b} {
		var err error
		entry.Bytes[p], entry.SHA256[p], entry.SectionBytes[p], err = w.writeOne(uint8(p), bucket, state)
		if err != nil {
			return err
		}
	}
	for party := uint8(0); party < 2; party++ {
		f, err := os.Open(movieAnchorPath(w.root, party, bucket, entry.SHA256[party]))
		if err != nil {
			return err
		}
		loaded, readErr := ReadAnchorStatic(f, w.catalog.IndexID, w.catalog.LayoutID, party, w.catalog.N, entry)
		closeErr := f.Close()
		if loaded.Stage1 != nil {
			loaded.Stage1.Discard()
		}
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	w.catalog.Buckets = append(w.catalog.Buckets, entry)
	sort.Slice(w.catalog.Buckets, func(i, j int) bool { return w.catalog.Buckets[i].Bucket < w.catalog.Buckets[j].Bucket })
	if err := w.save(); err != nil {
		for i, current := range w.catalog.Buckets {
			if current.Bucket == bucket {
				w.catalog.Buckets = append(w.catalog.Buckets[:i], w.catalog.Buckets[i+1:]...)
				break
			}
		}
		return err
	}
	w.stats.Buckets++
	w.stats.PartyBytes[0] += entry.Bytes[0]
	w.stats.PartyBytes[1] += entry.Bytes[1]
	for _, n := range entry.Bytes {
		if n > w.stats.MaxTemporaryFileBytes {
			w.stats.MaxTemporaryFileBytes = n
		}
	}
	w.stats.WriteWallNS += time.Since(started).Nanoseconds()
	return nil
}

func (w *MovieAnchorWriter) Has(bucket uint32) bool {
	if w == nil {
		return false
	}
	i := sort.Search(len(w.catalog.Buckets), func(i int) bool { return w.catalog.Buckets[i].Bucket >= bucket })
	return i < len(w.catalog.Buckets) && w.catalog.Buckets[i].Bucket == bucket
}

// Seal compares the completed catalog with the keyed public layout. The
// returned SHA256 is the trusted loader's expected catalog digest.
func (w *MovieAnchorWriter) Seal(expected []indexbuild.BucketMetadata) ([32]byte, error) {
	if w == nil || w.catalog.Complete || len(expected) != len(w.catalog.Buckets) {
		return [32]byte{}, ErrBinding
	}
	for i, meta := range expected {
		e := w.catalog.Buckets[i]
		if e.Bucket != meta.BucketID || e.Groups != int(meta.GroupCount) || e.T != int(meta.TotalSlots) {
			return [32]byte{}, ErrBinding
		}
	}
	w.catalog.Complete = true
	if err := w.save(); err != nil {
		w.catalog.Complete = false
		return [32]byte{}, err
	}
	raw, err := os.ReadFile(filepath.Join(w.root, "catalog.json"))
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

func OpenMovieAnchorStore(root string, party uint8, expected [32]byte, binding imdbprod.Binding) (*MovieAnchorStore, error) {
	digest, err := binding.Digest()
	if err != nil || party > 1 || expected == [32]byte{} {
		return nil, ErrBinding
	}
	raw, err := os.ReadFile(filepath.Join(root, "catalog.json"))
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(raw) != expected {
		return nil, ErrBinding
	}
	var catalog movieAnchorCatalog
	if json.Unmarshal(raw, &catalog) != nil || catalog.Version != movieAnchorStoreVersion || catalog.Binding != hex.EncodeToString(digest[:]) || catalog.IndexID != binding.IndexID || catalog.LayoutID != binding.LayoutID || catalog.N != imdbprod.AnchorObjects || !catalog.Complete || !validMovieAnchorEntries(catalog.Buckets) {
		return nil, ErrBinding
	}
	s := &MovieAnchorStore{root: root, party: party, catalog: catalog, byID: make(map[uint32]AnchorArtifact, len(catalog.Buckets))}
	for _, entry := range catalog.Buckets {
		s.byID[entry.Bucket] = entry
	}
	return s, nil
}

func (s *MovieAnchorStore) Meta(bucket uint32) (AnchorArtifact, bool) {
	if s == nil {
		return AnchorArtifact{}, false
	}
	m, ok := s.byID[bucket]
	return m, ok
}

func (s *MovieAnchorStore) BucketCount() int {
	if s == nil {
		return 0
	}
	return len(s.catalog.Buckets)
}

func (s *MovieAnchorStore) Load(bucket uint32) (AnchorStatic, error) {
	m, ok := s.Meta(bucket)
	if !ok {
		return AnchorStatic{}, ErrBinding
	}
	f, err := os.Open(movieAnchorPath(s.root, s.party, bucket, m.SHA256[s.party]))
	if err != nil {
		return AnchorStatic{}, err
	}
	defer f.Close()
	return ReadAnchorStatic(f, s.catalog.IndexID, s.catalog.LayoutID, s.party, s.catalog.N, m)
}
