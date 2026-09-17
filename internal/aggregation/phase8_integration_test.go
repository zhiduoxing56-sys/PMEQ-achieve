//go:build phase8integration || phase9integration

package aggregation

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"github.com/gtank/ristretto255"
	"io"
	"os"
	"path/filepath"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/indexbuild"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetquery"
	"pmeq/internal/targetrouting"
	"sort"
	"testing"
)

type peWorkload struct {
	Query  int
	Anchor string
	Tau    int
	Target string
	Joins  []uint64
	Words  []anchorfilter.QueryChunk
}
type peIdentity struct {
	j uint64
	w string
}
type peExperiment struct {
	trace                              []peWorkload
	idx                                [2]*targetpe.PartyIndex
	packets                            [2][]targetpe.Packet
	keys                               map[uint16][]peIdentity
	queries, routes, groups, zero, one int
	counts                             []int
}

var peExp *peExperiment
var setupPostingOracle func(*testing.T, *harness, [2]indexbuild.PartyIndex)
var preparePostingToken func(*testing.T, *harness, peWorkload) (targetrouting.QueryToken, targetrouting.QueryToken)
var afterGroupPE func(*testing.T, targetpe.TargetGroupMatches, targetpe.TargetGroupMatches, peContext, []uint64)
var finishPosting func(*testing.T)

func init() {
	harnessTargetBits = 16
	realHarnessSetup = setupPE
	beforeRoutingQuery = beforePE
	afterRoutingQuery = afterPE
	finishRoutingQueries = finishPE
}
func peArtifactDir() string {
	if p := os.Getenv("PMEQ_PE_ARTIFACT"); p != "" {
		return p
	}
	return "../../artifacts/phase7b"
}
func readPEPayload(t *testing.T, dir string, u int, m targetpe.PayloadManifest) PartyPayload {
	name := "cs0.payload.bin"
	if u == 1 {
		name = "cs1.payload.bin"
	}
	f, e := os.Open(filepath.Join(dir, name))
	must(t, e)
	defer f.Close()
	b := bufio.NewReader(f)
	header := make([]byte, 46)
	_, e = io.ReadFull(b, header)
	must(t, e)
	p := PartyPayload{m.LayoutID, make([]PayloadShare, m.N)}
	for i := range p.Slots {
		var id uint64
		must(t, binary.Read(b, binary.LittleEndian, &id))
		p.Slots[i].RecordIDShare = share.NewRing64Share(domain.Ring64(id))
		must(t, binary.Read(b, binary.LittleEndian, &p.Slots[i].KappaJoinShare))
		must(t, binary.Read(b, binary.LittleEndian, &p.Slots[i].BucketJoinShare))
	}
	return p
}
func setupPE(t *testing.T, h *harness) {
	x := &peExperiment{keys: map[uint16][]peIdentity{}}
	dir := peArtifactDir()
	raw, e := os.ReadFile(filepath.Join(dir, "payload-manifest.json"))
	must(t, e)
	var pm targetpe.PayloadManifest
	must(t, json.Unmarshal(raw, &pm))
	lineage := targetpe.AlignmentLineage{IndexID: pm.IndexID, LayoutID: pm.LayoutID, N: pm.N}
	// Restore this SAME final offline layout in the trusted dealer before any
	// Alignment() call. This is NOT a cloud reconstruction or a new payload.
	h.payload0 = readPEPayload(t, dir, 0, pm)
	h.payload1 = readPEPayload(t, dir, 1, pm)
	h.global = &DealerLayout{LayoutID: pm.LayoutID, N: pm.N, gamma: map[uint64]uint32{}}
	for i, a := range h.payload0.Slots {
		b := h.payload1.Slots[i]
		id := uint64(a.RecordIDShare.Value() + b.RecordIDShare.Value())
		if _, ok := h.global.gamma[id]; ok {
			t.Fatal("duplicate layout ID")
		}
		h.global.gamma[id] = uint32(i)
	}
	for _, a := range h.areas {
		if _, ok := h.global.gamma[a.ID]; !ok {
			t.Fatal("lineage missing record")
		}
	}
	if len(h.global.gamma) != 120071 {
		t.Fatal("lineage N")
	}
	for u := 0; u < 2; u++ {
		name := "cs0"
		if u == 1 {
			name = "cs1"
		}
		mf, e := os.Open(filepath.Join(dir, "manifest.json"))
		must(t, e)
		pf, e := os.Open(filepath.Join(dir, "payload-manifest.json"))
		must(t, e)
		sf, e := os.Open(filepath.Join(dir, name+".psmj.bin"))
		must(t, e)
		gf, e := os.Open(filepath.Join(dir, name+".payload.bin"))
		must(t, e)
		x.idx[u], e = targetpe.Load(mf, pf, sf, gf, uint8(u), lineage)
		must(t, e)
		mf.Close()
		pf.Close()
		sf.Close()
		gf.Close()
	}
	if x.idx[0].StructureDigest() != x.idx[1].StructureDigest() {
		t.Fatal("65536-bucket structure mismatch")
	}
	t.Log("SEALED hashes/manifest/lineage PASS; full 65536-bucket public structure PASS")
	f, e := os.Open("../../results/phase7b-workload.jsonl.gz")
	must(t, e)
	z, e := gzip.NewReader(f)
	must(t, e)
	scan := bufio.NewScanner(z)
	scan.Buffer(make([]byte, 65536), 4<<20)
	for scan.Scan() {
		var q peWorkload
		must(t, json.Unmarshal(scan.Bytes(), &q))
		x.trace = append(x.trace, q)
	}
	must(t, scan.Err())
	z.Close()
	f.Close()
	if len(x.trace) != 1003 {
		t.Fatal("trace count")
	}
	f, e = os.Open("../../results/phase7b-loads.json.gz")
	must(t, e)
	z, e = gzip.NewReader(f)
	must(t, e)
	var loads []struct {
		Bits    int
		Queries []struct{ GroupComparisons int }
	}
	must(t, json.NewDecoder(z).Decode(&loads))
	z.Close()
	f.Close()
	for _, l := range loads {
		if l.Bits == 16 {
			for _, q := range l.Queries {
				a, b, e := targetpe.Preprocess(lineage, q.GroupComparisons)
				must(t, e)
				x.packets[0] = append(x.packets[0], a)
				x.packets[1] = append(x.packets[1], b)
			}
		}
	}
	if len(x.packets[0]) != 1003 {
		t.Fatal("offline pool size")
	}
	// Raw alias access below is ONLY the trusted correctness oracle. Cloud
	// runtime uses loaded sealed files, never Build/area_alias or derived keys.
	f, e = os.Open("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area_alias")
	must(t, e)
	aliases, e := indexbuild.LoadAreaAlias(f, 0)
	must(t, e)
	f.Close()
	logical := map[peIdentity]bool{}
	points := map[[32]byte]peIdentity{}
	for _, a := range aliases {
		indexbuild.VisitQGrams(a.Name, func(w string, _ uint32) { logical[peIdentity{a.Area, w}] = true })
	}
	for key := range logical {
		p, e := targetcrypto.DeriveTargetGroupPoint(h.kt, key.j, key.w)
		must(t, e)
		var enc [32]byte
		copy(enc[:], p.Bytes())
		points[enc] = key
	}
	manifestRaw, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	must(t, e)
	m, e := indexbuild.ReadTargetManifest(bytes.NewReader(manifestRaw))
	must(t, e)
	var ps [2]indexbuild.PartyIndex
	for u := 0; u < 2; u++ {
		name := "cs0.psmj.bin"
		if u == 1 {
			name = "cs1.psmj.bin"
		}
		f, e = os.Open(filepath.Join(dir, name))
		must(t, e)
		ps[u], e = indexbuild.ReadTargetParty(f, m, uint8(u))
		must(t, e)
		f.Close()
	}
	for bi, b := range ps[0].TargetBuckets {
		for gi, g := range b.Groups {
			a, e := ristretto255.NewElement().SetCanonicalBytes(g.TargetKeyShare[:])
			must(t, e)
			v := ps[1].TargetBuckets[bi].Groups[gi].TargetKeyShare
			c, e := ristretto255.NewElement().SetCanonicalBytes(v[:])
			must(t, e)
			var enc [32]byte
			copy(enc[:], ristretto255.NewElement().Add(a, c).Bytes())
			key, ok := points[enc]
			if !ok {
				t.Fatal("sealed group oracle")
			}
			x.keys[b.BucketID] = append(x.keys[b.BucketID], key)
		}
	}
	if len(points) != 310331 {
		t.Fatal("logical groups")
	}
	peExp = x
	if setupPostingOracle != nil {
		setupPostingOracle(t, h, ps)
	}
}

type peContext struct {
	a, b targetrouting.QueryToken
	q    peWorkload
}

func beforePE(t *testing.T, h *harness, Q string, tau int) any {
	q := peExp.trace[peExp.queries]
	if q.Anchor != Q || q.Tau != tau {
		t.Fatal("seeded workload mismatch", peExp.queries, Q, tau)
	}
	if preparePostingToken != nil {
		a, b := preparePostingToken(t, h, q)
		return peContext{a, b, q}
	}
	a, b, e := targetquery.GenerateTokens(peExp.idx[0].Manifest(), h.kt, q.Target)
	must(t, e)
	return peContext{a, b, q}
}
func afterPE(t *testing.T, h *harness, a, b CompactedCandidates, ctx any) {
	x := peExp
	c := ctx.(peContext)
	if a.LayoutID != x.idx[0].Lineage().LayoutID || b.LayoutID != a.LayoutID {
		t.Fatal("compaction lineage")
	}
	actual := make([]uint64, a.K)
	for i := range actual {
		actual[i] = uint64(a.RecordIDShare[i].Value() + b.RecordIDShare[i].Value())
	}
	sorted := append([]uint64(nil), actual...)
	want := append([]uint64(nil), c.q.Joins...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if len(want) != len(sorted) {
		t.Fatal("candidate K")
	}
	for i := range want {
		if want[i] != sorted[i] {
			t.Fatal("candidate set")
		}
	}
	cv := func(v CompactedCandidates) targetrouting.Candidates {
		return targetrouting.Candidates{LayoutID: v.LayoutID, CompactionID: v.CompactionID, TargetBucketBits: v.TargetBucketBits, K: v.K, RecordIDShare: v.RecordIDShare, KappaJoinShare: v.KappaJoinShare, BucketJoinShare: v.BucketJoinShare}
	}
	u, ma, e := targetrouting.Prepare(x.idx[0].Manifest(), 0, cv(a), c.a, 16)
	must(t, e)
	v, mb, e := targetrouting.Prepare(x.idx[1].Manifest(), 1, cv(b), c.b, 16)
	must(t, e)
	r0, e := u.Finish(mb)
	must(t, e)
	r1, e := v.Finish(ma)
	must(t, e)
	s0, e := x.idx[0].Begin(r0, x.packets[0][x.queries], targetpe.RecommendedWorkers)
	must(t, e)
	s1, e := x.idx[1].Begin(r1, x.packets[1][x.queries], targetpe.RecommendedWorkers)
	must(t, e)
	g := 0
	for _, r := range r0.Routes {
		g += len(x.keys[r.BucketID])
	}
	if g > 0 {
		for round := 0; round < 8; round++ {
			m0, e := s0.Next()
			must(t, e)
			m1, e := s1.Next()
			must(t, e)
			must(t, s0.Accept(m1))
			must(t, s1.Accept(m0))
		}
	}
	o0, e := s0.Output()
	must(t, e)
	o1, e := s1.Output()
	must(t, e)
	if len(o0.MatchShares) != g {
		t.Fatal("output shape")
	}
	for ri, r := range o0.Routes {
		hits := 0
		w := c.q.Words[r.OccurrenceID].QGram
		j := actual[r.CandidateIndex]
		for gi, key := range x.keys[r.BucketID] {
			at := r.MatchOffset + gi
			hit := bool(o0.MatchShares[at].Value().Add(o1.MatchShares[at].Value()))
			expected := key.j == j && key.w == w
			if hit != expected {
				t.Fatal("PE oracle", x.queries, ri, gi)
			}
			if hit {
				hits++
			}
		}
		if hits > 1 {
			t.Fatal("multiple group matches")
		}
		if hits == 0 {
			x.zero++
		} else {
			x.one++
		}
	}
	m0, m1 := s0.Metrics(), s1.Metrics()
	if m0.PayloadBytes+m1.PayloadBytes != uint64(8160*targetpe.Words(g)) {
		t.Fatal("codec accounting")
	}
	if afterGroupPE != nil {
		afterGroupPE(t, o0, o1, c, actual)
	}
	x.queries++
	x.routes += len(o0.Routes)
	x.groups += g
	x.counts = append(x.counts, g)
}
func finishPE(t *testing.T) {
	x := peExp
	if finishPosting != nil {
		finishPosting(t)
	}
	sort.Ints(x.counts)
	pct := func(n int) int { return x.counts[(len(x.counts)*n+99)/100-1] }
	if x.queries != 1003 || x.routes != 466105 || x.groups != 2209949 || x.one != 2554 || x.zero != 463551 {
		t.Fatal("regression totals", x.queries, x.routes, x.groups, x.one, x.zero)
	}
	t.Logf("PRIVATE_EQUALITY queries=%d routes=%d totalG=%d zero=%d one=%d multi=0 errors=0 G min=%d p50=%d p90=%d p95=%d p99=%d max=%d", x.queries, x.routes, x.groups, x.zero, x.one, x.counts[0], pct(50), pct(90), pct(95), pct(99), x.counts[len(x.counts)-1])
}
