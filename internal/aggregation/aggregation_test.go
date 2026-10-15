package aggregation

import (
	"bytes"
	"math/rand"
	"os"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"pmeq/internal/anchorquery"
	"pmeq/internal/domain"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/preprocess"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
	"reflect"
	"runtime"
	"sort"
	"testing"
	"time"
)

// TEST ORACLE FOR COMPOSITION ONLY: masks encoded here are deliberately NOT
// safe cloud key material. No timings of this backend are SCMP performance.
type referenceSCMP struct{}

var compositionSCMP anchorfilter.SCMPBackend = referenceSCMP{}

func (referenceSCMP) KeyGen(bin uint8, x, y uint32, o domain.Bit) (anchorfilter.SCMPKeyShare, anchorfilter.SCMPKeyShare, error) {
	a, b, e := preprocess.SplitBit(o)
	raw := []byte{byte(x), byte(y)}
	return anchorfilter.NewSCMPKeyShare(raw, a), anchorfilter.NewSCMPKeyShare(raw, b), e
}
func (referenceSCMP) Eval(p uint8, k anchorfilter.SCMPKeyShare, x, y uint32) (share.BitShare, error) {
	b := k.Opaque()
	a, c := int((x-uint32(b[0]))&127), int((y-uint32(b[1]))&127)
	if a >= 64 {
		a -= 128
	}
	if c >= 64 {
		c -= 128
	}
	v := k.OutputMaskShare()
	if p == 0 {
		v = share.LocalAddBit(v, share.NewBitShare(domain.Bit(a >= c)))
	}
	return v, nil
}
func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func compare(t *testing.T, a, b []incidence.Share, threshold int) ([]share.BitShare, []share.BitShare) {
	u, p, q, e := PreprocessComparison(len(a), compositionSCMP)
	must(t, e)
	bound, e := u.Mask(threshold)
	must(t, e)
	v, e := p.Prepare(a)
	must(t, e)
	w, e := q.Prepare(b)
	must(t, e)
	o, e := OpenComparison(v, w)
	must(t, e)
	x, e := p.Finish(o, bound, compositionSCMP)
	must(t, e)
	y, e := q.Finish(o, bound, compositionSCMP)
	must(t, e)
	return x, y
}
func b2a(t *testing.T, a, b []share.BitShare) ([]incidence.Share, []incidence.Share, time.Duration) {
	p, q, e := incidence.Preprocess(len(a), 1)
	must(t, e)
	st := time.Now()
	s, m, e := incidence.BeginB2A(a, p)
	must(t, e)
	v, n, e := incidence.BeginB2A(b, q)
	must(t, e)
	o, e := incidence.OpenMasked(m, n)
	must(t, e)
	x, e := s.Finish(o)
	must(t, e)
	y, e := v.Finish(o)
	must(t, e)
	return x, y, time.Since(st)
}
func TestComparisonDomainAndMasks(t *testing.T) {
	for bound := 1; bound <= 14; bound++ {
		a, b := make([]incidence.Share, 64), make([]incidence.Share, 64)
		for i := range a {
			var e error
			a[i], b[i], e = incidence.Split(incidence.Z128(i))
			must(t, e)
		}
		x, y := compare(t, a, b, bound)
		for i := range x {
			if bool(x[i].Value().Add(y[i].Value())) != (i >= bound) {
				t.Fatal("compare", i, bound)
			}
		}
	}
	if _, e := Threshold(1, 1); e == nil {
		t.Fatal("tau gate")
	}
}
func TestPartyStateSchemas(t *testing.T) {
	for typ, want := range map[reflect.Type][]string{reflect.TypeOf(Stage0{}): {"LayoutID", "BucketID", "RhoSeed"}, reflect.TypeOf(Stage1{}): {"LayoutID", "BucketID", "sigma"}, reflect.TypeOf(PartyPayload{}): {"LayoutID", "Slots"}, reflect.TypeOf(PermPrep0{}): {"c1", "a2", "b2", "use", "stage"}, reflect.TypeOf(PermPrep1{}): {"a1", "b1", "c2", "use", "stage"}} {
		if typ.NumField() != len(want) {
			t.Fatal(typ)
		}
		for i, n := range want {
			if typ.Field(i).Name != n {
				t.Fatal(typ, n)
			}
		}
	}
}
func TestPermutationCorrectnessAndOneTime(t *testing.T) {
	for _, n := range []int{1, 3, 17, 129} {
		pi, e := permutation(n)
		must(t, e)
		p, q, e := SplitPermutation([16]byte{}, 0, pi)
		must(t, e)
		u, v, e := PreprocessPermutation(p, q)
		must(t, e)
		a, b := make([]incidence.Share, n), make([]incidence.Share, n)
		for i := range a {
			a[i], b[i], e = incidence.Split(incidence.Z128(i))
			must(t, e)
		}
		m, e := v.Message1(b)
		must(t, e)
		m2, y0, e := p.Message2(u, a, m)
		must(t, e)
		y1, e := q.Finish(v, m2)
		must(t, e)
		for i, j := range pi {
			if y0[j].Value().Add(y1[j].Value()) != incidence.Z128(i&127) {
				t.Fatal("permutation")
			}
		}
		if _, e = v.Message1(b); e == nil {
			t.Fatal("reuse")
		}
	}
}

type provenance struct {
	id   uint64
	pos  uint32
	q    string
	real bool
}

var harnessTargetBits = 16
var realHarnessSetup func(*testing.T, *harness)
var beforeRoutingQuery func(*testing.T, *harness, string, int) any
var afterRoutingQuery func(*testing.T, *harness, CompactedCandidates, CompactedCandidates, any)
var finishRoutingQueries func(*testing.T)

type harness struct {
	kb                 anchorindex.Key
	kt                 targetcrypto.MasterKey
	global             *DealerLayout
	payload0, payload1 PartyPayload
	b0, b1             map[uint32]indexbuild.AnchorPartyBucket
	slots              map[uint32][]provenance
	words              map[string][]provenance
	areas              []indexbuild.AreaRecord
}

func newHarness(t *testing.T, areas []indexbuild.AreaRecord) *harness {
	var kb, kt [32]byte
	for i := range kb {
		kb[i] = byte(i + 1)
		kt[i] = byte(255 - i)
	}
	h := &harness{areas: areas, b0: map[uint32]indexbuild.AnchorPartyBucket{}, b1: map[uint32]indexbuild.AnchorPartyBucket{}, slots: map[uint32][]provenance{}, words: map[string][]provenance{}}
	var e error
	h.kb, e = anchorindex.NewKey(kb)
	must(t, e)
	h.kt, e = targetcrypto.NewMasterKey(kt)
	must(t, e)
	_, a, b, _, e := indexbuild.Build(areas, nil, h.kb, h.kt, 16, harnessTargetBits)
	must(t, e)
	for _, v := range a.AnchorBuckets {
		h.b0[v.BucketID] = v
	}
	for _, v := range b.AnchorBuckets {
		h.b1[v.BucketID] = v
	}
	byZ := map[anchorindex.Value][]provenance{}
	ids := make([]uint64, len(areas))
	for i, r := range areas {
		ids[i] = r.ID
		indexbuild.VisitQGrams(r.Name, func(q string, p uint32) {
			z, e := anchorindex.Encode(h.kb, q)
			must(t, e)
			v := provenance{r.ID, p, q, true}
			byZ[z] = append(byZ[z], v)
			h.words[q] = append(h.words[q], v)
		})
	}
	for id, bucket := range h.b0 {
		for _, g := range bucket.Groups {
			h.slots[id] = append(h.slots[id], byZ[g.Z]...)
			for i := len(byZ[g.Z]); i < len(g.Slots); i++ {
				h.slots[id] = append(h.slots[id], provenance{})
			}
		}
	}
	h.global, h.payload0, h.payload1, e = GeneratePayload(ids, h.kt, harnessTargetBits)
	must(t, e)
	for id, j := range h.global.gamma {
		a, b := h.payload0.Slots[j], h.payload1.Slots[j]
		if uint64(a.RecordIDShare.Value()+b.RecordIDShare.Value()) != id {
			t.Fatal("payload ID")
		}
		k, e := targetcrypto.KJoin(h.kt, id)
		must(t, e)
		s, e := targetcrypto.CombineScalarShare(a.KappaJoinShare, b.KappaJoinShare)
		must(t, e)
		if !bytes.Equal(s[:], k.Bytes()) {
			t.Fatal("payload kappa")
		}
		v, e := targetcrypto.JoinBucketComponent(h.kt, id, harnessTargetBits)
		must(t, e)
		if a.BucketJoinShare.Value()^b.BucketJoinShare.Value() != v {
			t.Fatal("payload bucket")
		}
	}
	return h
}

type measurement struct {
	XF, Perm, Sum, B2AZ   time.Duration
	FComparisons, R, T, P int
	K                     int
	Peak                  uint64
}

func (h *harness) query(t *testing.T, Q string, tau int) measurement {
	var routingContext any
	if beforeRoutingQuery != nil {
		routingContext = beforeRoutingQuery(t, h, Q, tau)
	}
	chunks := anchorfilter.QueryChunks(Q)
	lambda, e := Threshold(len(chunks), tau)
	must(t, e)
	m := measurement{R: len(chunks)}
	c0, c1 := NewCount(h.global.LayoutID, h.global.N), NewCount(h.global.LayoutID, h.global.N)
	wantC := map[uint64]int{}
	for _, chunk := range chunks {
		z, e := anchorindex.Encode(h.kb, chunk.QGram)
		must(t, e)
		id, e := indexbuild.AnchorBucket(z, 16)
		must(t, e)
		prov := h.slots[id]
		n := len(prov)
		bucket0, ok := h.b0[id]
		if !ok {
			bucket0 = indexbuild.AnchorPartyBucket{BucketID: id}
		}
		bucket1, ok := h.b1[id]
		if !ok {
			bucket1 = indexbuild.AnchorPartyBucket{BucketID: id}
		}
		// Trusted offline incidence and alignment preprocessing, excluded online time.
		slots := make([]incidence.Posting, n)
		for i, p := range prov {
			slots[i] = incidence.Posting{RecordID: p.id, Real: p.real}
		}
		local, e := incidence.PrepareLayout(slots)
		must(t, e)
		a0, a1, e := incidence.ShareIncidence(local)
		must(t, e)
		stage0, stage1, e := h.global.Alignment(id, local, slots)
		must(t, e)
		perm0, perm1, e := PreprocessPermutation(stage0, stage1)
		must(t, e)
		user, pp0, pp1, e := anchorfilter.Preprocess(n, 7, compositionSCMP)
		must(t, e)
		q0, q1, e := anchorquery.MakeOccurrence(h.kb, chunk, uint32(tau), 62, 16, &user)
		must(t, e)
		pr0, e := anchorfilter.PrepareParty(bucket0, q0, pp0)
		must(t, e)
		pr1, e := anchorfilter.PrepareParty(bucket1, q1, pp1)
		must(t, e)
		opened, e := anchorfilter.OpenMaskedPositions(pr0.PL, pr0.PR, pr1.PL, pr1.PR, 7)
		must(t, e)
		pos0, e := anchorfilter.EvalPosition(0, q0, pp0, opened, compositionSCMP)
		must(t, e)
		pos1, e := anchorfilter.EvalPosition(1, q1, pp1, opened, compositionSCMP)
		must(t, e)
		x0, x1, e := anchorfilter.ComposeHits(pr0, pr1, pos0, pos1)
		must(t, e)
		expected := make([]incidence.Z128, local.D)
		l, r := anchorfilter.Bounds(chunk.Position, uint32(tau), 62)
		for i, p := range prov {
			hit := p.real && p.q == chunk.QGram && p.pos >= l && p.pos <= r
			if bool(x0[i].Value().Add(x1[i].Value())) != hit {
				t.Fatal("phase4 hit")
			}
			if hit {
				expected[local.Coordinates[i]] = expected[local.Coordinates[i]].Add(1)
			}
		}
		ar0, ar1, tm := b2a(t, x0, x1)
		m.XF += tm
		setupStarted := time.Now()
		g0, e := incidence.NewAggregator(0, a0, 64)
		must(t, e)
		g1, e := incidence.NewAggregator(1, a1, 64)
		must(t, e)
		m.XF += time.Since(setupStarted)
		for off := 0; off < n; off += 64 {
			end := min(off+64, n)
			tr0, tr1, e := incidence.Preprocess(end-off, local.D)
			must(t, e)
			st := time.Now()
			v0, e := g0.BeginChunk(ar0[off:end], tr0)
			must(t, e)
			v1, e := g1.BeginChunk(ar1[off:end], tr1)
			must(t, e)
			o, e := incidence.OpenMasked(v0, v1)
			must(t, e)
			must(t, g0.FinishChunk(o))
			must(t, g1.FinishChunk(o))
			m.XF += time.Since(st)
		}
		resultStarted := time.Now()
		f0, e := g0.Result()
		must(t, e)
		f1, e := g1.Result()
		must(t, e)
		m.XF += time.Since(resultStarted)
		for j, w := range expected {
			if f0[j].Value().Add(f1[j].Value()) != w {
				t.Fatal("F")
			}
		}
		zz0, zz1 := compare(t, f0, f1, 1)
		for j, w := range expected {
			if bool(zz0[j].Value().Add(zz1[j].Value())) != (w > 0) {
				t.Fatal("z")
			}
		}
		az0, az1, tm := b2a(t, zz0, zz1)
		m.B2AZ += tm
		st := time.Now()
		d1, e := perm1.Message1(az1)
		must(t, e)
		d2, y0, e := stage0.Message2(perm0, az0, d1)
		must(t, e)
		y1, e := stage1.Finish(perm1, d2)
		must(t, e)
		m.Perm += time.Since(st)
		wantY := map[uint32]bool{}
		for _, p := range h.words[chunk.QGram] {
			if p.pos >= l && p.pos <= r {
				wantY[h.global.gamma[p.id]] = true
			}
		}
		for j := range y0 {
			w := incidence.Z128(0)
			if wantY[uint32(j)] {
				w = 1
			}
			if y0[j].Value().Add(y1[j].Value()) != w {
				t.Fatal("Y", Q, j)
			}
		}
		for id, gamma := range h.global.gamma {
			if wantY[gamma] {
				wantC[id]++
			}
		}
		st = time.Now()
		must(t, c0.Add(h.global.LayoutID, y0))
		must(t, c1.Add(h.global.LayoutID, y1))
		m.Sum += time.Since(st)
		m.T += n
		m.P += n * local.D
		m.FComparisons += local.D
	}
	v0, v1 := c0.Values(), c1.Values()
	for id, j := range h.global.gamma {
		if int(v0[j].Value().Add(v1[j].Value())) != wantC[id] {
			t.Fatal("C")
		}
	}
	k0, k1 := compare(t, v0, v1, lambda)
	out0, e := AlignOutput(h.payload0, h.global.LayoutID, k0)
	must(t, e)
	out1, e := AlignOutput(h.payload1, h.global.LayoutID, k1)
	must(t, e)
	for id, j := range h.global.gamma {
		if bool(out0.KeepShare[j].Value().Add(out1.KeepShare[j].Value())) != (wantC[id] >= lambda) {
			t.Fatal("Keep", Q, id)
		}
		if uint64(out0.Payload[j].RecordIDShare.Value()+out1.Payload[j].RecordIDShare.Value()) != id {
			t.Fatal("alignment")
		}
	}
	cp, cq, e := PreprocessCompactionWithBucketBits(h.global.LayoutID, h.global.N, harnessTargetBits)
	must(t, e)
	x, y, _, _ := compactPrepared(t, cp, cq, out0, out1)
	verifyCompaction(t, out0, out1, x, y)
	m.K = x.K
	if afterRoutingQuery != nil {
		afterRoutingQuery(t, h, x, y, routingContext)
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.Peak = ms.HeapAlloc
	return m
}
func TestCompleteSynthetic(t *testing.T) {
	h := newHarness(t, []indexbuild.AreaRecord{{ID: 1, Name: "aaaaa"}, {ID: 2, Name: "aaaaaaaa"}, {ID: 3, Name: "abcdefgh"}, {ID: 4, Name: "abcdxxxxefgh"}, {ID: 5, Name: "abc"}, {ID: 6, Name: "abcdefgh"}, {ID: 7, Name: "abcdefgh"}, {ID: 8, Name: "abcdefgh"}})
	for _, q := range []string{"aaaa", "aaaaaaaa", "abcdefgh", "zzzz"} {
		for tau := 0; tau < len(anchorfilter.QueryChunks(q)); tau++ {
			h.query(t, q, tau)
		}
	}
}
func TestReal1000Queries(t *testing.T) {
	if os.Getenv("PMEQ_AGG_FULL") != "1" {
		t.Skip("set PMEQ_AGG_FULL=1")
	}
	f, e := os.Open("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area")
	must(t, e)
	areas, e := indexbuild.LoadArea(f, 0)
	f.Close()
	must(t, e)
	h := newHarness(t, areas)
	if realHarnessSetup != nil {
		realHarnessSetup(t, h)
	}
	type query struct {
		q string
		p int
	}
	qs := []query{}
	for _, a := range areas {
		cs := anchorfilter.QueryChunks(a.Name)
		if len(cs) == 0 {
			continue
		}
		p := 0
		for _, c := range cs {
			posts := h.words[c.QGram]
			ids := map[uint64]bool{}
			for _, v := range posts {
				ids[v.id] = true
			}
			d, e := incidence.RecordCapacity(len(ids))
			must(t, e)
			w, e := indexbuild.TierWidth(len(posts))
			must(t, e)
			p += d * w
		}
		qs = append(qs, query{a.Name, p})
	}
	sort.Slice(qs, func(i, j int) bool {
		if qs[i].p != qs[j].p {
			return qs[i].p < qs[j].p
		}
		return qs[i].q < qs[j].q
	})
	rng := rand.New(rand.NewSource(502))
	order := rng.Perm(len(qs))
	// Provision party-local lifecycle tickets offline. Correlated material is
	// generated by the trusted test coordinator before each online stage, as in
	// PHASE5B2; neither online party consults that coordinator or raw records.
	packetCount := 3
	if os.Getenv("PMEQ_AGG_ONLY_BENCH") != "1" {
		packetCount += 1000
	}
	pool0 := NewPartyPool(h.global.LayoutID, PoolConfig{uint64(packetCount)})
	pool1 := NewPartyPool(h.global.LayoutID, PoolConfig{uint64(packetCount)})
	packets := make([]PacketID, packetCount)
	for i := range packets {
		packets[i], e = NewPacketID()
		must(t, e)
		must(t, pool0.Provision(packets[i]))
		must(t, pool1.Provision(packets[i]))
	}
	pool0.Seal()
	pool1.Seal()
	nextPacket := 0
	consume := func() {
		must(t, pool0.Consume(packets[nextPacket]))
		must(t, pool1.Consume(packets[nextPacket]))
		nextPacket++
	}
	ks := []int{}
	if os.Getenv("PMEQ_AGG_ONLY_BENCH") != "1" {
		for i, j := range order[:1000] {
			q := qs[j].q
			consume()
			m := h.query(t, q, rng.Intn(len(anchorfilter.QueryChunks(q))))
			ks = append(ks, m.K)
			if i%50 == 0 {
				t.Logf("real queries %d/1000", i)
			}
		}
	}
	if len(ks) > 0 {
		sort.Ints(ks)
		t.Logf("PHASE6 K n=%d min=%d p50=%d p90=%d p95=%d p99=%d max=%d", len(ks), ks[0], ks[499], ks[899], ks[949], ks[989], ks[999])
	}
	for _, pct := range []float64{.5, .95, .99} {
		q := qs[int(float64(len(qs)-1)*pct+.999999)]
		consume()
		m := h.query(t, q.q, 0)
		t.Logf("COMPONENT pct=%.2f query=%q intrinsic=%d stats=%+v", pct, q.q, q.p, m)
	}
	if pool0.Remaining() != 0 || pool1.Remaining() != 0 {
		t.Fatal("pool accounting")
	}
	if os.Getenv("PMEQ_AGG_ONLY_BENCH") != "1" {
		t.Log("1000 random + 3 workload-quantile real queries: zero errors")
		if finishRoutingQueries != nil {
			finishRoutingQueries(t)
		}
	} else {
		t.Log("3 workload-quantile real queries: zero errors")
	}
}
func TestPermutation120071Benchmark(t *testing.T) {
	if os.Getenv("PMEQ_AGG_FULL") != "1" {
		t.Skip("set PMEQ_AGG_FULL=1")
	}
	n := 120071
	pi, e := permutation(n)
	must(t, e)
	p, q, e := SplitPermutation([16]byte{}, 0, pi)
	must(t, e)
	x, y := make([]incidence.Share, n), make([]incidence.Share, n)
	for _, r := range []int{1, 2, 4, 6} {
		var online, offline time.Duration
		for h := 0; h < r; h++ {
			st := time.Now()
			a, b, e := PreprocessPermutation(p, q)
			must(t, e)
			offline += time.Since(st)
			st = time.Now()
			m, e := b.Message1(y)
			must(t, e)
			m2, y0, e := p.Message2(a, x, m)
			must(t, e)
			y1, e := q.Finish(b, m2)
			must(t, e)
			online += time.Since(st)
			for i := range y0 {
				if y0[i].Value().Add(y1[i].Value()) != 0 {
					t.Fatal("bench correctness")
				}
			}
		}
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		t.Logf("PERM r=%d N=%d online=%s offline=%s wire=%d correlated=%d heap=%d", r, n, online, offline, 2*n*r, 6*n*r, ms.HeapAlloc)
	}
}
