package targetrouting_test

import (
	"github.com/gtank/ristretto255"
	"pmeq/internal/aggregation"
	"pmeq/internal/domain"
	"pmeq/internal/indexbuild"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetquery"
	r "pmeq/internal/targetrouting"
	"reflect"
	"slices"
	"testing"
)

func must(t testing.TB, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func key(t testing.TB) targetcrypto.MasterKey {
	k, e := targetcrypto.NewMasterKey([32]byte{7})
	must(t, e)
	return k
}
func manifest(t testing.TB, bits int) r.Manifest {
	m, e := r.FromMetadata([16]byte{7}, indexbuild.PublicMetadata{Q: 4, AnchorBucketBits: 16, TargetBucketBits: uint8(bits)})
	must(t, e)
	return m
}
func handoff(c aggregation.CompactedCandidates) r.Candidates {
	return r.Candidates{LayoutID: c.LayoutID, CompactionID: c.CompactionID, TargetBucketBits: c.TargetBucketBits, K: c.K, RecordIDShare: c.RecordIDShare, KappaJoinShare: c.KappaJoinShare, BucketJoinShare: c.BucketJoinShare}
}
func fixtures(t testing.TB, n, k, bits int) (aggregation.CandidateInput, aggregation.CandidateInput) {
	ids := make([]uint64, n)
	for i := range ids {
		ids[i] = uint64(i + 1)
	}
	_, a, b, e := aggregation.GeneratePayload(ids, key(t), bits)
	must(t, e)
	u, v := aggregation.CandidateInput{LayoutID: a.LayoutID, Payload: a.Slots, KeepShare: make([]share.BitShare, n)}, aggregation.CandidateInput{LayoutID: a.LayoutID, Payload: b.Slots, KeepShare: make([]share.BitShare, n)}
	for i := 0; i < k; i++ {
		u.KeepShare[i] = share.NewBitShare(domain.BitOne)
	}
	return u, v
}
func compact(t testing.TB, a, b aggregation.CandidateInput, bits int) (r.Candidates, r.Candidates) {
	p, q, e := aggregation.PreprocessCompactionWithBucketBits(a.LayoutID, len(a.Payload), bits)
	must(t, e)
	d, e := q.Begin(b)
	must(t, e)
	must(t, p.Stage1(a, d))
	v, e := p.BeginStage2()
	must(t, e)
	must(t, q.Stage2(v))
	o, e := p.OpenKeep()
	must(t, e)
	w, e := q.OpenKeep()
	must(t, e)
	x, e := p.Extract(w)
	must(t, e)
	y, e := q.Extract(o)
	must(t, e)
	return handoff(x), handoff(y)
}
func point(t testing.TB, a, b targetcrypto.PointShare) *ristretto255.Element {
	u, e := ristretto255.NewElement().SetCanonicalBytes(a[:])
	must(t, e)
	v, e := ristretto255.NewElement().SetCanonicalBytes(b[:])
	must(t, e)
	return ristretto255.NewElement().Add(u, v)
}
func TestRoutingDomainsFreshOrderAndEmpty(t *testing.T) {
	for _, bits := range []int{1, 8, 16, 17} {
		m := manifest(t, bits)
		for _, k := range []int{0, 1, 32} {
			a, b := fixtures(t, 32, k, bits)
			var oldIDs []uint64
			var oldComp [16]byte
			for run := 0; run < 2; run++ {
				c, d := compact(t, a, b, bits)
				u, v, e := targetquery.GenerateTokens(m, key(t), "天地玄黄天地玄黄尾")
				must(t, e)
				if len(u.Words) != 2 || u.Words[1].Position != 4 || u.Words[0].WordPointShare == u.Words[1].WordPointShare {
					t.Fatal("chunks/fresh sharing")
				}
				if point(t, u.Words[0].WordPointShare, v.Words[0].WordPointShare).Equal(point(t, u.Words[1].WordPointShare, v.Words[1].WordPointShare)) != 1 {
					t.Fatal("repeated word")
				}
				for _, workers := range []int{1, 4, 8, 16} {
					wa, e := r.EncodeToken(u)
					must(t, e)
					wb, e := r.EncodeToken(v)
					must(t, e)
					if len(wa) != r.TokenBytesForBits(uint8(bits), 2) || len(wb) != len(wa) {
						t.Fatal("token bytes")
					}
					du, e := r.DecodeToken(m, 0, wa)
					must(t, e)
					dv, e := r.DecodeToken(m, 1, wb)
					must(t, e)
					p, pm, e := r.Prepare(m, 0, c, du, workers)
					must(t, e)
					q, qm, e := r.Prepare(m, 1, d, dv, workers)
					must(t, e)
					if k == 0 && (len(pm) != 0 || len(qm) != 0) {
						t.Fatal("empty access")
					}
					wireWidth := 2
					if bits > 16 {
						wireWidth = 4
					}
					if k > 0 && len(pm) != r.OpeningHeaderBytes+2*wireWidth*k {
						t.Fatal("wire width")
					}
					x, e := p.Finish(qm)
					must(t, e)
					y, e := q.Finish(pm)
					must(t, e)
					if _, e = p.Finish(qm); e == nil {
						t.Fatal("replayed finish")
					}
					if x.CompactionID != c.CompactionID || !slices.Equal(x.AnchorRecordIDShare, c.RecordIDShare) || len(x.Routes) != 2*k {
						t.Fatal("association")
					}
					for ci := 0; ci < k; ci++ {
						id := uint64(c.RecordIDShare[ci].Value() + d.RecordIDShare[ci].Value())
						expected, e := targetcrypto.DeriveTargetGroupPoint(key(t), id, "天地玄黄")
						must(t, e)
						j, e := targetcrypto.JoinBucketComponent(key(t), id, bits)
						must(t, e)
						w, e := targetcrypto.WordBucketComponent(key(t), "天地玄黄", bits)
						must(t, e)
						want := uint32(targetcrypto.CombineBucketComponents(j, w))
						for h := 0; h < 2; h++ {
							i := ci*2 + h
							if point(t, x.Routes[i].Y, y.Routes[i].Y).Equal(expected) != 1 || x.Routes[i].BucketID != want || y.Routes[i].BucketID != want || x.Routes[i].CandidateIndex != uint32(ci) || x.Routes[i].OccurrenceID != uint32(h) {
								t.Fatal("oracle")
							}
						}
					}
				}
				ids := make([]uint64, k)
				for i := range ids {
					ids[i] = uint64(c.RecordIDShare[i].Value() + d.RecordIDShare[i].Value())
				}
				if run > 0 && (c.CompactionID == oldComp || k == 32 && reflect.DeepEqual(ids, oldIDs)) {
					t.Fatal("stable compaction order")
				}
				oldIDs = ids
				oldComp = c.CompactionID
			}
		}
	}
}
func TestBindingsAndShortTarget(t *testing.T) {
	m := manifest(t, 8)
	a, b := fixtures(t, 2, 2, 8)
	c, d := compact(t, a, b, 8)
	u, v, e := targetquery.GenerateTokens(m, key(t), "abcd")
	must(t, e)
	bad := c
	bad.TargetBucketBits = 16
	if _, _, e = r.Prepare(m, 0, bad, u, 1); e == nil {
		t.Fatal("width binding")
	}
	bad = c
	bad.BucketJoinShare = append([]targetcrypto.BucketShare(nil), c.BucketJoinShare...)
	bad.BucketJoinShare[0] = 256
	if _, _, e = r.Prepare(m, 0, bad, u, 1); e == nil {
		t.Fatal("out of domain")
	}
	if _, _, e = r.Prepare(m, 1, c, u, 1); e == nil {
		t.Fatal("party")
	}
	if _, _, e = r.Prepare(m, 0, c, u, 0); e == nil {
		t.Fatal("worker bound")
	}
	p, pm, e := r.Prepare(m, 0, c, u, 1)
	must(t, e)
	q, qm, e := r.Prepare(m, 1, d, v, 1)
	must(t, e)
	invalid := append([]byte(nil), qm...)
	invalid[42] ^= 1
	if _, e = p.Finish(invalid); e == nil {
		t.Fatal("CompactionID binding")
	}
	invalid = append([]byte(nil), qm...)
	invalid[83] = 1
	if _, e = p.Finish(invalid); e == nil {
		t.Fatal("bucket width")
	}
	_, e = p.Finish(qm)
	must(t, e)
	_, e = q.Finish(pm)
	must(t, e)
	token, e := r.EncodeToken(u)
	must(t, e)
	wrong := m
	wrong.IndexID[0]++
	if _, e = r.DecodeToken(wrong, 0, token); e == nil {
		t.Fatal("index binding")
	}
	if _, e = r.DecodeToken(m, 0, token[:len(token)-1]); e == nil {
		t.Fatal("truncation")
	}
	u, v, e = targetquery.GenerateTokens(m, key(t), "短")
	must(t, e)
	p, pm, e = r.Prepare(m, 0, c, u, 1)
	must(t, e)
	q, qm, e = r.Prepare(m, 1, d, v, 1)
	must(t, e)
	x, e := p.Finish(qm)
	must(t, e)
	_, e = q.Finish(pm)
	must(t, e)
	if len(x.Routes) != 0 || x.K != 2 || len(pm) != 0 {
		t.Fatal("short no routes")
	}
}
