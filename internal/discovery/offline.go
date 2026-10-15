package discovery

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/f2beaver"
	"pmeq/internal/imdbprod"
	"pmeq/internal/incidence"
	"pmeq/internal/share"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
	"pmeq/internal/zeroagg"
)

type counter struct {
	b     anchorfilter.SCMPBackend
	bytes uint64
}

func (c *counter) KeyGen(bin uint8, x, y uint32, o domain.Bit) (anchorfilter.SCMPKeyShare, anchorfilter.SCMPKeyShare, error) {
	a, b, e := c.b.KeyGen(bin, x, y, o)
	if e == nil {
		c.bytes += uint64(len(a.Opaque()) + len(b.Opaque()) + 2)
	}
	return a, b, e
}
func (c *counter) Eval(p uint8, k anchorfilter.SCMPKeyShare, x, y uint32) (share.BitShare, error) {
	return c.b.Eval(p, k, x, y)
}

// Provision is TRUSTED OFFLINE ONLY and must finish before RunLocal starts.
// Bucket classes and Target K/S/G capacities are public offline pool choices.
// No query string, threshold, Hit, Keep or oracle result is accepted here.
func Provision(a, b *Static, buckets []uint32, capacities []int, shape targetaggregation.Shape, backend anchorfilter.SCMPBackend) (u *UserPacket, p0, p1 *PartyPacket, cost OfflineBytes, err error) {
	return provision(a, b, buckets, capacities, shape, backend, false)
}

func ProvisionTargetZero(a, b *Static, buckets []uint32, capacities []int, shape targetaggregation.Shape, backend anchorfilter.SCMPBackend) (u *UserPacket, p0, p1 *PartyPacket, cost OfflineBytes, err error) {
	return provision(a, b, buckets, capacities, shape, backend, true)
}

func provision(a, b *Static, buckets []uint32, capacities []int, shape targetaggregation.Shape, backend anchorfilter.SCMPBackend, targetZero bool) (u *UserPacket, p0, p1 *PartyPacket, cost OfflineBytes, err error) {
	defer caught(&err)
	if a == nil || b == nil || a.party != 0 || b.party != 1 || a.target == nil || b.target == nil || a.target.Lineage() != b.target.Lineage() || a.target.ManifestDigest() != b.target.ManifestDigest() || len(buckets) < 1 || len(buckets) > 14 || len(capacities) != shape.R || backend == nil {
		return nil, nil, nil, cost, ErrBinding
	}
	if a.movieBinding != b.movieBinding || a.keyFingerprint != b.keyFingerprint {
		return nil, nil, nil, cost, ErrBinding
	}
	movie := a.movieBinding != [32]byte{}
	if movie {
		if len(buckets) != imdbprod.AnchorSignatures || shape.K != imdbprod.CandidateCapacity || shape.R != imdbprod.TargetSignatures || shape.Capacity() != imdbprod.TargetDimension || shape.S != imdbprod.TargetSignatures*imdbprod.TargetGroupCapacity || shape.G != imdbprod.TargetGroupCapacity {
			return nil, nil, nil, cost, ErrBinding
		}
		for _, capacity := range capacities {
			if capacity != imdbprod.TargetGroupCapacity {
				return nil, nil, nil, cost, ErrBinding
			}
		}
	}
	if a.sidecar.Capacity() != shape.Capacity() || b.sidecar.Capacity() != shape.Capacity() {
		return nil, nil, nil, cost, ErrBinding
	}
	n := len(a.payload.Slots)
	if n != a.target.Lineage().N || len(b.payload.Slots) != n || a.payload.LayoutID != a.target.Lineage().LayoutID || b.payload.LayoutID != a.payload.LayoutID || shape.K < 0 || shape.K > n {
		return nil, nil, nil, cost, ErrBinding
	}
	u = &UserPacket{g: &guard{}, layout: a.payload.LayoutID, buckets: append([]uint32(nil), buckets...), movieBinding: a.movieBinding, keyFingerprint: a.keyFingerprint}
	_, err = rand.Read(u.id[:])
	check(err)
	p0 = &PartyPacket{g: &guard{}, id: u.id, party: 0, movieBinding: a.movieBinding}
	p1 = &PartyPacket{g: &guard{}, id: u.id, party: 1, movieBinding: a.movieBinding}
	cb := &counter{b: backend}
	for _, id := range buckets {
		// Bucket presence is public. An empty bucket contributes the zero
		// vector and needs no sigma, zero-polynomial gates, or alignment masks.
		if movie && a.anchorStore != nil && b.anchorStore != nil {
			_, aok := a.anchorStore.Meta(id)
			_, bok := b.anchorStore.Meta(id)
			if aok != bok {
				check(ErrBinding)
			}
			if !aok {
				user, v, w, e := anchorfilter.Preprocess(0, imdbprod.PositionBin, cb)
				check(e)
				u.anchor = append(u.anchor, user)
				p0.anchor = append(p0.anchor, anchorPacket{bucket: id, empty: true, position: v})
				p1.anchor = append(p1.anchor, anchorPacket{bucket: id, empty: true, position: w})
				continue
			}
		}
		as, e := a.anchorFor(id)
		check(e)
		bs, e := b.anchorFor(id)
		check(e)
		if as.Stage0 == nil || bs.Stage1 == nil || bs.Stage1.GlobalRecords() != n || as.D < 0 || as.D > n || as.D != bs.D || as.T != bs.T {
			check(ErrBinding)
		}
		t, d := as.T, as.D
		if !validAnchorLabels(as) || !validAnchorLabels(bs) || as.LabelID != bs.LabelID {
			check(ErrBinding)
		}
		x, y := anchorPacket{bucket: id}, anchorPacket{bucket: id}
		start := cb.bytes
		bin := uint8(7)
		if movie {
			bin = imdbprod.PositionBin
		}
		user, v, w, e := anchorfilter.Preprocess(t, bin, cb)
		check(e)
		x.position, y.position = v, w
		u.anchor = append(u.anchor, user)
		cost.AnchorPosition += cb.bytes - start + uint64(16*t)
		for i := 0; i < 2; i++ {
			x.and[i], y.and[i], err = f2beaver.Preprocess(t)
			check(err)
			cost.AnchorPosition += uint64(6 * t)
		}
		var tripleBytes int
		x.zero, y.zero, tripleBytes = zeroagg.Prepare(t, d)
		cost.AnchorAggregation += uint64(tripleBytes)
		x.z, y.z, err = incidence.Preprocess(d, 1)
		check(err)
		cost.AnchorAggregation += uint64(6 * d)
		x.p0, y.p1, err = aggregation.PreprocessPermutation(as.Stage0, bs.Stage1)
		check(err)
		x.stage0 = as.Stage0
		if b.anchorStore != nil {
			bs.Stage1.Discard()
		}
		cost.AnchorAggregation += uint64(6 * n)
		p0.anchor = append(p0.anchor, x)
		p1.anchor = append(p1.anchor, y)
	}
	start := cb.bytes
	u.keep, p0.keep, p1.keep, err = aggregation.PreprocessComparison(n, cb)
	check(err)
	cost.AnchorAggregation += cb.bytes - start + uint64(2*n)
	p0.c0, p1.c1, err = aggregation.PreprocessCompactionWithBucketBits(a.payload.LayoutID, n, int(a.target.Manifest().TargetBucketBits))
	check(err)
	u.compaction = p0.c0.ID()
	shuffleTupleBytes := 43
	if a.target.Manifest().TargetBucketBits > 16 {
		shuffleTupleBytes = 45
	}
	cost.Compaction = uint64((6*shuffleTupleBytes + 8) * n)
	p0.pe, p1.pe, err = targetpe.Preprocess(a.target.Lineage(), shape.G)
	check(err)
	cost.TargetPE = uint64(12240 * targetpe.Words(shape.G))
	var pos targetposition.OfflineBytes
	if movie {
		u.target, p0.position, p1.position, pos, err = targetposition.PreprocessWithDomain(a.target.Lineage(), capacities, imdbprod.PositionBin, imdbprod.PositionMax, backend)
	} else {
		u.target, p0.position, p1.position, pos, err = targetposition.Preprocess(a.target.Lineage(), capacities, backend)
	}
	check(err)
	cost.TargetPosition = 2 * (pos.SCMP + pos.Beaver)
	var ag targetaggregation.OfflineBody
	if targetZero {
		maxT, labelID := a.sidecar.ZeroConfig()
		otherT, otherID := b.sidecar.ZeroConfig()
		if maxT < 1 || maxT != otherT || labelID == "" || labelID != otherID {
			check(ErrBinding)
		}
		u.agg, p0.agg, p1.agg, ag, err = targetaggregation.PreprocessZero(a.target.Lineage(), shape, backend, maxT, labelID)
	} else {
		u.agg, p0.agg, p1.agg, ag, err = targetaggregation.Preprocess(a.target.Lineage(), shape, backend)
	}
	check(err)
	cost.TargetAggregation = ag.Z128 + ag.SCMP + ag.Ring64 + ag.F2 + ag.GF16
	if shape.Capacity() == 16 {
		h := sha256.New()
		d := a.target.ManifestDigest()
		h.Write(d[:])
		h.Write(a.payload.LayoutID[:])
		for _, v := range []int{shape.K, shape.R, shape.S, shape.G, shape.Capacity()} {
			binary.Write(h, binary.LittleEndian, uint64(v))
		}
		h.Write([]byte("F2xRing64xRing64-v1"))
		var binding [32]byte
		copy(binding[:], h.Sum(nil))
		p0.output, p1.output, err = aggregation.PreprocessPairPermutation(u.layout, binding, 16*shape.K)
		check(err)
		cost.OutputPermutation = uint64(110*16*shape.K + 170)
	}
	p0.capacity, p1.capacity = shape.K, shape.K
	return
}
