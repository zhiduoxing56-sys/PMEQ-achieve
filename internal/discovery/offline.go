package discovery

import (
	"crypto/rand"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/f2beaver"
	"pmeq/internal/incidence"
	"pmeq/internal/share"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
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
func Provision(a, b *Static, buckets []uint16, capacities []int, shape targetaggregation.Shape, backend anchorfilter.SCMPBackend) (u *UserPacket, p0, p1 *PartyPacket, cost OfflineBytes, err error) {
	defer caught(&err)
	if a == nil || b == nil || a.party != 0 || b.party != 1 || a.target.Lineage() != b.target.Lineage() || a.target.ManifestDigest() != b.target.ManifestDigest() || len(buckets) < 1 || len(buckets) > 14 || len(capacities) != shape.R || backend == nil {
		return nil, nil, nil, cost, ErrBinding
	}
	u = &UserPacket{g: &guard{}, layout: a.payload.LayoutID, buckets: append([]uint16(nil), buckets...)}
	_, err = rand.Read(u.id[:])
	check(err)
	p0 = &PartyPacket{g: &guard{}, id: u.id, party: 0}
	p1 = &PartyPacket{g: &guard{}, id: u.id, party: 1}
	cb := &counter{b: backend}
	n := aggregation.CandidateCount
	for _, id := range buckets {
		as, ok := a.anchor[id]
		if !ok {
			check(ErrBinding)
		}
		bs, ok := b.anchor[id]
		if !ok || as.Incidence.D != bs.Incidence.D || as.Incidence.T != bs.Incidence.T {
			check(ErrBinding)
		}
		t, d := as.Incidence.T, as.Incidence.D
		x, y := anchorPacket{bucket: id}, anchorPacket{bucket: id}
		start := cb.bytes
		user, v, w, e := anchorfilter.Preprocess(t, 7, cb)
		check(e)
		x.position, y.position = v, w
		u.anchor = append(u.anchor, user)
		cost.AnchorPosition += cb.bytes - start + uint64(16*t)
		for i := 0; i < 2; i++ {
			x.and[i], y.and[i], err = f2beaver.Preprocess(t)
			check(err)
			cost.AnchorPosition += uint64(6 * t)
		}
		x.hit, y.hit, err = incidence.Preprocess(t, 1)
		check(err)
		cost.AnchorAggregation += uint64(6 * t)
		if d > 0 {
			for off := 0; off < t; off += 64 {
				z0, z1, e := incidence.Preprocess(min(64, t-off), d)
				check(e)
				x.inc = append(x.inc, z0)
				y.inc = append(y.inc, z1)
				cost.AnchorAggregation += uint64(z0.StorageBytes() + z1.StorageBytes())
			}
		}
		start = cb.bytes
		f, f0, f1, e := aggregation.PreprocessComparison(d, cb)
		check(e)
		u.f = append(u.f, f)
		x.f, y.f = f0, f1
		cost.AnchorAggregation += cb.bytes - start + uint64(2*d)
		x.z, y.z, err = incidence.Preprocess(d, 1)
		check(err)
		cost.AnchorAggregation += uint64(6 * d)
		x.p0, y.p1, err = aggregation.PreprocessPermutation(as.Stage0, bs.Stage1)
		check(err)
		cost.AnchorAggregation += uint64(6 * n)
		p0.anchor = append(p0.anchor, x)
		p1.anchor = append(p1.anchor, y)
	}
	start := cb.bytes
	u.keep, p0.keep, p1.keep, err = aggregation.PreprocessComparison(n, cb)
	check(err)
	cost.AnchorAggregation += cb.bytes - start + uint64(2*n)
	p0.c0, p1.c1, err = aggregation.PreprocessCompactionWithBucketBits(a.payload.LayoutID, n, 16)
	check(err)
	u.compaction = p0.c0.ID()
	cost.Compaction = uint64((6*43 + 8) * n)
	p0.pe, p1.pe, err = targetpe.Preprocess(a.target.Lineage(), shape.G)
	check(err)
	cost.TargetPE = uint64(12240 * targetpe.Words(shape.G))
	var pos targetposition.OfflineBytes
	u.target, p0.position, p1.position, pos, err = targetposition.Preprocess(a.target.Lineage(), capacities, backend)
	check(err)
	cost.TargetPosition = 2 * (pos.SCMP + pos.Beaver)
	var ag targetaggregation.OfflineBody
	u.agg, p0.agg, p1.agg, ag, err = targetaggregation.Preprocess(a.target.Lineage(), shape, backend)
	check(err)
	cost.TargetAggregation = ag.Z128 + ag.SCMP + ag.Ring64 + ag.F2
	return
}
