// Package discovery runs the supported PMEQ protocol using party-local state.
// The local coordinator is a transport/user harness, never a cloud principal.
package discovery

import (
	"encoding/hex"
	"errors"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"pmeq/internal/f2beaver"
	"pmeq/internal/imdbkeys"
	"pmeq/internal/imdbprod"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/material"
	"pmeq/internal/scmpstock"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
	"pmeq/internal/targetrouting"
	"pmeq/internal/zeroagg"
	"sync"
)

var ErrDomain = errors.New("discovery: query outside q=4, tau_i<r_i, Anchor r<=14, Target r<=16 domain")
var ErrCandidateCapacity = errors.New("discovery: actual K exceeds public candidate capacity C; no truncation")

var ErrBinding = errors.New("discovery: invalid binding, capacity, transcript or consumed packet")

type Query struct {
	Anchor, Target       string
	TauAnchor, TauTarget int
}

func Validate(q Query) error {
	if _, e := aggregation.Threshold(len(anchorfilter.QueryChunks(q.Anchor)), q.TauAnchor); e != nil {
		return ErrDomain
	}
	if _, e := targetaggregation.Threshold(len(anchorfilter.QueryChunks(q.Target)), q.TauTarget); e != nil {
		return ErrDomain
	}
	return nil
}

type UserKeys struct {
	Anchor anchorindex.Key
	Target targetcrypto.MasterKey
}

// LoadMovieUserKeys is for the authorized DO/query-user process only. A cloud
// receives the binding digest, never this returned pair.
func LoadMovieUserKeys(path string) (UserKeys, string, error) {
	p, err := imdbkeys.Load(path)
	if err != nil {
		return UserKeys{}, "", err
	}
	return UserKeys{Anchor: p.Anchor, Target: p.Target}, p.Fingerprint, nil
}

// AnchorStatic is a single party's offline authenticated bucket extension.
// Exactly one of Stage0/Stage1 is nonnil, according to party identity.
type AnchorStatic struct {
	Bucket  indexbuild.AnchorPartyBucket
	D, T    int
	Labels  []zeroagg.F
	LabelID string
	Stage0  *aggregation.Stage0
	Stage1  *aggregation.Stage1
}

// Every anchor state is complete GF-label state. Missing labels cannot be deferred.
func validAnchorLabels(a AnchorStatic) bool {
	id, e := hex.DecodeString(a.LabelID)
	return e == nil && len(id) == 16 && hex.EncodeToString(id) == a.LabelID && a.LabelID != "00000000000000000000000000000000" && len(a.Labels) == a.T && a.T >= 0 && a.T <= 65536 && a.D >= 0 && a.D <= 32768 && (a.D == 0 || a.D&(a.D-1) == 0) && ((a.T == 0) == (a.D == 0))
}

type Static struct {
	party          uint8
	anchor         map[uint32]AnchorStatic
	anchorStore    *MovieAnchorStore
	payload        aggregation.PartyPayload
	target         *targetpe.PartyIndex
	sidecar        *targetaggregation.PartySidecar
	auxiliarySeal  [32]byte
	movieBinding   [32]byte
	productionSeal [32]byte
	keyFingerprint string
}

// TargetManifestDigestForTicket is public lineage metadata for the trusted
// ticket issuer and user. It contains no target share or master key.
func (s *Static) TargetManifestDigestForTicket() [32]byte {
	if s == nil || s.target == nil {
		return [32]byte{}
	}
	return s.target.ManifestDigest()
}

// PublicAnchorSlotUpperBound caps the number of candidates that can survive
// any query requiring at least one anchor hit. Each candidate must originate
// in one of these public padded bucket slots. Repeated buckets may overcount.
// Callers must use the full public candidate capacity when zero hits qualify.
func (s *Static) PublicAnchorSlotUpperBound(buckets []uint32, candidateCapacity int) (int, error) {
	if s == nil || candidateCapacity < 0 || len(buckets) == 0 {
		return 0, ErrBinding
	}
	upper := 0
	for _, id := range buckets {
		var n int
		if s.anchorStore != nil {
			if meta, ok := s.anchorStore.Meta(id); ok {
				n = meta.T
			}
		} else if a, ok := s.anchor[id]; ok {
			n = a.T
		}
		if n < 0 {
			return 0, ErrBinding
		}
		if n >= candidateCapacity-upper {
			return candidateCapacity, nil
		}
		upper += n
	}
	return upper, nil
}

// Experiment-only target labels live outside the sealed production index.
func BuildTargetZeroLabels(a, b *Static, root string) error {
	if a == nil || b == nil || a.party != 0 || b.party != 1 || a.productionSeal == [32]byte{} || a.productionSeal != b.productionSeal {
		return ErrBinding
	}
	return targetaggregation.MigrateZeroLabels(root, a.sidecar, b.sidecar)
}

func (s *Static) LoadTargetZeroLabels(root string) error {
	if s == nil || s.productionSeal == [32]byte{} {
		return ErrBinding
	}
	return s.sidecar.LoadZeroLabels(root)
}

// Close releases the lazy target matrix file after a cloud stops accepting
// queries. In-flight queries must finish before the owner calls Close.
func (s *Static) Close() error {
	if s == nil || s.sidecar == nil {
		return nil
	}
	return s.sidecar.Close()
}

// UseTargetAuxiliary switches one verified cloud static to an independently
// sealed public-D sidecar. The main production index and anchor store remain
// unchanged; the auxiliary digest is bound in the new ticket alongside the
// original production seal.
func (s *Static) UseTargetAuxiliary(manifest targetaggregation.SidecarManifest, sealedTarget []byte, path string, auxiliarySeal [32]byte) error {
	if s == nil || s.target == nil || s.sidecar == nil || auxiliarySeal == [32]byte{} || s.productionSeal == [32]byte{} || manifest.DTarget < 1 || manifest.DTarget > 26 {
		return ErrBinding
	}
	side, err := targetaggregation.OpenSidecarLazy(manifest, sealedTarget, s.target, path)
	if err != nil {
		return err
	}
	if err := s.sidecar.Close(); err != nil {
		side.Close()
		return err
	}
	s.sidecar = side
	s.auxiliarySeal = auxiliarySeal
	return nil
}

// anchorFor returns an invocation-owned bucket. Store-backed statics never
// insert the decoded sigma into the long-lived Static map.
func (s *Static) anchorFor(id uint32) (AnchorStatic, error) {
	if s == nil {
		return AnchorStatic{}, ErrBinding
	}
	if s.anchorStore != nil {
		return s.anchorStore.Load(id)
	}
	a, ok := s.anchor[id]
	if !ok {
		return AnchorStatic{}, ErrBinding
	}
	return a, nil
}

// anchorForPacket keeps the Stage0 instance authenticated during ticket
// decoding. PermPrep0 binds to that exact pointer; a lazy store read creates
// a new pointer even when the sealed bytes are identical.
func (s *Static) anchorForPacket(p *anchorPacket, id uint32) (AnchorStatic, error) {
	a, err := s.anchorFor(id)
	if err != nil {
		return a, err
	}
	if p == nil || (s.anchorStore != nil && s.party == 0 && p.stage0 == nil) {
		return AnchorStatic{}, ErrBinding
	}
	if s.party == 0 && p.stage0 != nil {
		if a.Stage0 == nil || *a.Stage0 != *p.stage0 {
			return AnchorStatic{}, ErrBinding
		}
		a.Stage0 = p.stage0
	}
	return a, nil
}

func NewStatic(party uint8, anchor map[uint32]AnchorStatic, payload aggregation.PartyPayload, target *targetpe.PartyIndex, sidecar *targetaggregation.PartySidecar) (*Static, error) {
	if party > 1 || target == nil || sidecar == nil || target.Party() != party || payload.LayoutID != target.Lineage().LayoutID || target.Lineage().N < 0 || uint64(target.Lineage().N) > uint64(^uint32(0)) || len(payload.Slots) != target.Lineage().N {
		return nil, ErrBinding
	}
	for id, a := range anchor {
		if a.Bucket.BucketID != id || a.D < 0 || a.D > len(payload.Slots) || (party == 0 && (a.Stage0 == nil || a.Stage1 != nil || a.Stage0.LayoutID != payload.LayoutID || a.Stage0.BucketID != id)) || (party == 1 && (a.Stage1 == nil || a.Stage0 != nil || a.Stage1.LayoutID != payload.LayoutID || a.Stage1.BucketID != id || a.Stage1.GlobalRecords() != len(payload.Slots))) {
			return nil, ErrBinding
		}
		n := 0
		for _, g := range a.Bucket.Groups {
			n += len(g.Slots)
			if int(g.PadWidth) != len(g.Slots) {
				return nil, ErrBinding
			}
		}
		if n != a.T || a.D > 32768 || a.T > 65536 || !validAnchorLabels(a) {
			return nil, ErrBinding
		}
	}
	return &Static{party: party, anchor: anchor, payload: payload, target: target, sidecar: sidecar}, nil
}

// NewMovieStatic accepts only a frozen IMDb sample/layout binding. The new
// token domain carries its digest, so an old QU12 token cannot run on it.
func NewMovieStatic(party uint8, anchor map[uint32]AnchorStatic, payload aggregation.PartyPayload, target *targetpe.PartyIndex, sidecar *targetaggregation.PartySidecar, binding imdbprod.Binding) (*Static, error) {
	digest, err := binding.Digest()
	if err != nil || target == nil || sidecar == nil || target.Lineage().IndexID != binding.IndexID || target.Lineage().LayoutID != binding.LayoutID || target.Lineage().N != imdbprod.AnchorObjects || target.Manifest().TargetBucketBits != imdbprod.BucketBits || target.Manifest().Q != imdbprod.Q || sidecar.Capacity() != imdbprod.TargetDimension || sidecar.Multiplicity() != imdbprod.TargetMultiplicity {
		return nil, ErrBinding
	}
	s, err := NewStatic(party, anchor, payload, target, sidecar)
	if err != nil {
		return nil, err
	}
	// The offline S/G reservation uses this fixed public bucket envelope.
	// A different keyed layout is rejected before allocating a query batch.
	for bucket := uint32(0); bucket < 1<<imdbprod.BucketBits; bucket++ {
		groups := target.PositionGroups(bucket)
		if len(groups) > imdbprod.TargetBucketGroups {
			return nil, ErrBinding
		}
		slots := 0
		for _, group := range groups {
			slots += int(group.PadWidth)
		}
		if slots > imdbprod.TargetBucketSlots {
			return nil, ErrBinding
		}
	}
	s.movieBinding = digest
	s.keyFingerprint = binding.KeyFingerprint
	return s, nil
}

// NewMovieStaticFromStore is the production cloud constructor. The trusted
// expected catalog digest must come from the DO's sealed publication manifest.
func NewMovieStaticFromStore(party uint8, store *MovieAnchorStore, payload aggregation.PartyPayload, target *targetpe.PartyIndex, sidecar *targetaggregation.PartySidecar, binding imdbprod.Binding, sealHash [32]byte) (*Static, error) {
	if store == nil || store.party != party || store.catalog.IndexID != binding.IndexID || store.catalog.LayoutID != binding.LayoutID || store.catalog.N != imdbprod.AnchorObjects || payload.LayoutID != binding.LayoutID || sealHash == [32]byte{} {
		return nil, ErrBinding
	}
	s, err := NewMovieStatic(party, nil, payload, target, sidecar, binding)
	if err != nil {
		return nil, err
	}
	s.anchorStore = store
	s.productionSeal = sealHash
	return s, nil
}

type guard struct {
	mu       sync.Mutex
	used     bool
	reserved bool
	ledger   string
	id       [16]byte
}

func (g *guard) claim() error {
	if g == nil {
		return ErrBinding
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.used {
		return ErrBinding
	}
	if g.ledger != "" && !g.reserved {
		if e := material.ClaimPersistent(g.ledger, g.id); e != nil {
			return e
		}
	}
	g.used = true
	return nil
}

type anchorPacket struct {
	zero     *zeroagg.Party
	zeroRef  *zeroReference
	stage0   *aggregation.Stage0 // invocation-local pointer bound to PermPrep0
	bucket   uint32
	empty    bool
	position anchorfilter.PartyPreprocessing
	and      [2]f2beaver.PartyBatch
	z        *incidence.PartyTriples
	p0       *aggregation.PermPrep0
	p1       *aggregation.PermPrep1
}
type PartyPacket struct {
	g              *guard
	id             [16]byte
	party          uint8
	anchor         []anchorPacket
	keep           *aggregation.ComparisonParty
	c0             *aggregation.Compaction0
	c1             *aggregation.Compaction1
	pe             targetpe.Packet
	position       targetposition.Packet
	agg            targetaggregation.Packet
	output         *aggregation.PairPermutation
	capacity       int
	movieBinding   [32]byte
	interruptZero  bool
	persistentRefs []zeroReference
	inventoryV3    bool
	bankID         [16]byte
	stock          *scmpstock.Pool
}
type UserPacket struct {
	g                      *guard
	id, compaction, layout [16]byte
	anchor                 []anchorfilter.UserPreprocessing
	buckets                []uint32
	keep                   *aggregation.BoundMask
	target                 []anchorfilter.UserPreprocessing
	agg                    *targetaggregation.UserMaterial
	movieBinding           [32]byte
	keyFingerprint         string
	inventoryV3            bool
	bankID                 [16]byte
}
type cloudToken struct {
	packet       [16]byte
	anchor       []anchorfilter.PartyQuery
	keep         uint32
	target       targetrouting.QueryToken
	agg          targetaggregation.ThresholdToken
	movieBinding [32]byte
}
type OfflineBytes struct{ AnchorPosition, AnchorAggregation, Compaction, TargetPE, TargetPosition, TargetAggregation, OutputPermutation uint64 }
type fail struct{ err error }

func check(e error) {
	if e != nil {
		panic(fail{e})
	}
}
func caught(e *error) {
	if p := recover(); p != nil {
		if f, ok := p.(fail); ok {
			*e = f.err
		} else {
			panic(p)
		}
	}
}
