package imdbprod

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"pmeq/internal/indexbuild"
	"strconv"
	"strings"
)

type Anchor struct {
	ID            uint64 `json:"anchor_id"`
	ObjectID      string `json:"objectId"`
	Tconst        string `json:"tconst"`
	JoinID        uint64 `json:"join_id"`
	AliasTitle    string `json:"aliasTitle"`
	ActorOrdering int64  `json:"actorOrdering"`
	DirectorID    string `json:"directorId"`
	AliasOrdering int64  `json:"aliasOrdering"`
}
type Target struct {
	SampleOrder   int    `json:"sample_order"`
	ID            uint64 `json:"target_id"`
	JoinID        uint64 `json:"join_id"`
	Tconst        string `json:"tconst"`
	PrimaryTitle  string `json:"primaryTitle"`
	OriginalTitle string `json:"originalTitle"`
}
type Mapping struct {
	Anchors    []Anchor
	Targets    []Target
	ByAnchorID map[uint64]int
	ByObjectID map[string]int
	ByMovieID  map[uint64]int
}

// MovieID preserves the IMDb tconst numeric suffix; the original spelling is
// retained in the trusted map for exact reverse lookup and leading zeroes.
func MovieID(tconst string) (uint64, error) {
	if !strings.HasPrefix(tconst, "tt") || len(tconst) < 3 {
		return 0, ErrContract
	}
	for _, c := range tconst[2:] {
		if c < '0' || c > '9' {
			return 0, ErrContract
		}
	}
	id, err := strconv.ParseUint(tconst[2:], 10, 64)
	if err != nil || id == 0 {
		return 0, ErrContract
	}
	return id, nil
}

func sequenceHash(ids []string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(ids, "\n"))))
}

// LoadMapping rejects reordered, duplicate, foreign and mismatched source
// identities before any production index receives numeric IDs.
func LoadMapping(anchorInput, targetInput io.Reader) (*Mapping, error) {
	m := &Mapping{ByAnchorID: map[uint64]int{}, ByObjectID: map[string]int{}, ByMovieID: map[uint64]int{}}
	var anchorIDs, targetIDs []string
	read := func(input io.Reader, visit func([]byte) error) error {
		s := bufio.NewScanner(input)
		s.Buffer(make([]byte, 64*1024), 1024*1024)
		for s.Scan() {
			if err := visit(s.Bytes()); err != nil {
				return err
			}
		}
		return s.Err()
	}
	if err := read(targetInput, func(b []byte) error {
		var t Target
		if json.Unmarshal(b, &t) != nil || t.SampleOrder != len(m.Targets)+1 {
			return ErrContract
		}
		id, e := MovieID(t.Tconst)
		if e != nil || id != t.ID || id != t.JoinID || t.PrimaryTitle == "" {
			return ErrContract
		}
		if _, ok := m.ByMovieID[id]; ok {
			return ErrContract
		}
		m.ByMovieID[id] = len(m.Targets)
		m.Targets = append(m.Targets, t)
		targetIDs = append(targetIDs, t.Tconst)
		return nil
	}); err != nil {
		return nil, err
	}
	if err := read(anchorInput, func(b []byte) error {
		var a Anchor
		if json.Unmarshal(b, &a) != nil || a.ID != uint64(len(m.Anchors)+1) {
			return ErrContract
		}
		id, e := MovieID(a.Tconst)
		if e != nil || id != a.JoinID || a.ObjectID == "" || a.AliasTitle == "" {
			return ErrContract
		}
		if a.ObjectID != fmt.Sprintf("mc1|%s|%d|%s|%d", a.Tconst, a.ActorOrdering, a.DirectorID, a.AliasOrdering) {
			return ErrContract
		}
		if _, ok := m.ByMovieID[id]; !ok {
			return ErrContract
		}
		if _, ok := m.ByObjectID[a.ObjectID]; ok {
			return ErrContract
		}
		m.ByAnchorID[a.ID], m.ByObjectID[a.ObjectID] = len(m.Anchors), len(m.Anchors)
		m.Anchors = append(m.Anchors, a)
		anchorIDs = append(anchorIDs, a.ObjectID)
		return nil
	}); err != nil {
		return nil, err
	}
	if len(m.Anchors) != AnchorObjects || len(m.Targets) != TargetObjects || sequenceHash(anchorIDs) != AnchorSequenceSHA256 || sequenceHash(targetIDs) != TargetSequenceSHA256 {
		return nil, ErrContract
	}
	return m, nil
}

func (m *Mapping) AnchorByID(id uint64) (Anchor, error) {
	if m == nil {
		return Anchor{}, ErrContract
	}
	i, ok := m.ByAnchorID[id]
	if !ok {
		return Anchor{}, ErrContract
	}
	return m.Anchors[i], nil
}
func (m *Mapping) TargetByID(id uint64) (Target, error) {
	if m == nil {
		return Target{}, ErrContract
	}
	i, ok := m.ByMovieID[id]
	if !ok {
		return Target{}, ErrContract
	}
	return m.Targets[i], nil
}
func (m *Mapping) DigestHex() (string, error) {
	if m == nil || len(m.Anchors) != AnchorObjects || len(m.Targets) != TargetObjects {
		return "", ErrContract
	}
	h := sha256.New()
	h.Write([]byte(Version))
	h.Write([]byte{0})
	h.Write([]byte(AnchorSequenceSHA256))
	h.Write([]byte{0})
	h.Write([]byte(TargetSequenceSHA256))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// IndexInputs gives the trusted DO its fixed movie projection. Each anchor
// source object keeps its own rank ID; every join and target ID uses MovieID.
func (m *Mapping) IndexInputs() ([]indexbuild.AreaRecord, []uint64, []indexbuild.AreaAliasRecord, error) {
	if m == nil || len(m.Anchors) != AnchorObjects || len(m.Targets) != TargetObjects {
		return nil, nil, nil, ErrContract
	}
	anchors := make([]indexbuild.AreaRecord, len(m.Anchors))
	joins := make([]uint64, len(m.Anchors))
	for i, a := range m.Anchors {
		anchors[i], joins[i] = indexbuild.AreaRecord{ID: a.ID, Name: a.AliasTitle}, a.JoinID
	}
	targets := make([]indexbuild.AreaAliasRecord, len(m.Targets))
	for i, v := range m.Targets {
		targets[i] = indexbuild.AreaAliasRecord{ID: v.ID, Name: v.PrimaryTitle, Area: v.JoinID}
	}
	return anchors, joins, targets, nil
}

type FileStamp struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type FreezeManifest struct {
	Version               string               `json:"version"`
	Seed                  int                  `json:"seed"`
	MotherDatabaseSHA256  string               `json:"mother_database_sha256"`
	SourceManifestSHA256  string               `json:"source_manifest_sha256"`
	AnchorCount           int                  `json:"anchor_count"`
	TargetCount           int                  `json:"target_count"`
	AnchorConnectedMovies int                  `json:"anchor_connected_movies"`
	AnchorSequenceSHA256  string               `json:"anchor_object_id_sequence_sha256"`
	TargetSequenceSHA256  string               `json:"target_tconst_sequence_sha256"`
	Files                 map[string]FileStamp `json:"files"`
}

// LoadFrozen authenticates the immutable mapping files and source provenance.
// The caller must put the resulting binding beside the generated IndexID and
// LayoutID; it must not reconstruct a map from untrusted cloud output.
func LoadFrozen(dir string) (*Mapping, FreezeManifest, error) {
	var fm FreezeManifest
	content, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fm, err
	}
	if json.Unmarshal(content, &fm) != nil || fm.Version != Version || fm.Seed != SampleSeed || fm.AnchorCount != AnchorObjects || fm.TargetCount != TargetObjects || fm.AnchorConnectedMovies != 8895 || fm.AnchorSequenceSHA256 != AnchorSequenceSHA256 || fm.TargetSequenceSHA256 != TargetSequenceSHA256 || fm.SourceManifestSHA256 != SourceManifestSHA256 || fm.MotherDatabaseSHA256 != MotherDatabaseSHA256 || fm.Files["identity_map.jsonl"].SHA256 != IdentityMapSHA256 || fm.Files["target_map.jsonl"].SHA256 != TargetMapSHA256 {
		return nil, fm, ErrContract
	}
	files := map[string][]byte{}
	for _, name := range []string{"identity_map.jsonl", "target_map.jsonl", "MOVIECAST.parquet", "MOVIE.parquet", "MOVIECAST_SOURCE.parquet", "repeated_sources.jsonl"} {
		stamp, ok := fm.Files[name]
		if !ok {
			return nil, fm, ErrContract
		}
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			return nil, fm, e
		}
		d := sha256.Sum256(b)
		if int64(len(b)) != stamp.Bytes || hex.EncodeToString(d[:]) != stamp.SHA256 {
			return nil, fm, ErrContract
		}
		if name == "identity_map.jsonl" || name == "target_map.jsonl" {
			files[name] = b
		}
	}
	m, err := LoadMapping(strings.NewReader(string(files["identity_map.jsonl"])), strings.NewReader(string(files["target_map.jsonl"])))
	return m, fm, err
}

// Binding includes the actual frozen file/source list and the generated
// cryptographic layout. It is suitable for a new versioned manifest header.
type Binding struct {
	Version              string   `json:"version"`
	ContractSHA256       string   `json:"contract_sha256"`
	SourceManifestSHA256 string   `json:"source_manifest_sha256"`
	MotherDatabaseSHA256 string   `json:"mother_database_sha256"`
	IdentityMapSHA256    string   `json:"identity_map_sha256"`
	TargetMapSHA256      string   `json:"target_map_sha256"`
	KeyFingerprint       string   `json:"key_fingerprint"`
	IndexID              [16]byte `json:"index_id"`
	LayoutID             [16]byte `json:"layout_id"`
}

func (fm FreezeManifest) Bind(indexID, layoutID [16]byte, keyFingerprint string) (Binding, error) {
	if indexID == [16]byte{} || layoutID == [16]byte{} || fm.Version != Version || fm.AnchorSequenceSHA256 != AnchorSequenceSHA256 || fm.TargetSequenceSHA256 != TargetSequenceSHA256 || fm.SourceManifestSHA256 != SourceManifestSHA256 || fm.MotherDatabaseSHA256 != MotherDatabaseSHA256 || fm.Files["identity_map.jsonl"].SHA256 != IdentityMapSHA256 || fm.Files["target_map.jsonl"].SHA256 != TargetMapSHA256 {
		return Binding{}, ErrContract
	}
	digest, e := Production().DigestHex()
	if e != nil {
		return Binding{}, e
	}
	if _, e := validFingerprint(keyFingerprint); e != nil {
		return Binding{}, e
	}
	return Binding{Version: Version, ContractSHA256: digest, SourceManifestSHA256: fm.SourceManifestSHA256, MotherDatabaseSHA256: fm.MotherDatabaseSHA256,
		IdentityMapSHA256: fm.Files["identity_map.jsonl"].SHA256, TargetMapSHA256: fm.Files["target_map.jsonl"].SHA256,
		KeyFingerprint: keyFingerprint, IndexID: indexID, LayoutID: layoutID}, nil
}

func validFingerprint(s string) ([32]byte, error) {
	var out [32]byte
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 || s != hex.EncodeToString(b) {
		return out, ErrContract
	}
	copy(out[:], b)
	if out == [32]byte{} {
		return out, ErrContract
	}
	return out, nil
}

func (b Binding) Digest() ([32]byte, error) {
	p, err := Production().DigestHex()
	if err != nil || b.Version != Version || b.ContractSHA256 != p || b.IndexID == [16]byte{} || b.LayoutID == [16]byte{} || b.SourceManifestSHA256 != SourceManifestSHA256 || b.MotherDatabaseSHA256 != MotherDatabaseSHA256 || b.IdentityMapSHA256 != IdentityMapSHA256 || b.TargetMapSHA256 != TargetMapSHA256 {
		return [32]byte{}, ErrContract
	}
	if _, err = validFingerprint(b.KeyFingerprint); err != nil {
		return [32]byte{}, err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(raw), nil
}
