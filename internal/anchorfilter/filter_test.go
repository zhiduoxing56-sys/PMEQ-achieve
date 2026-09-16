package anchorfilter

import (
	"encoding/binary"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"pmeq/internal/anchorindex"
	"pmeq/internal/domain"
	"pmeq/internal/dpf128"
	"pmeq/internal/dpf128/gen"
	"pmeq/internal/f2beaver"
	"pmeq/internal/indexbuild"
	"pmeq/internal/preprocess"
	"pmeq/internal/reconstruct"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
)

const (
	realAreaPath  = "/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area"
	realAliasPath = "/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area_alias"
)

// referenceSCMP is a TEST ORACLE FOR COMPOSITION ONLY. It is never used for
// performance claims or production filtering.
type referenceSCMP struct{}

func (referenceSCMP) KeyGen(bin uint8, xm, ym uint32, omega domain.Bit) (SCMPKeyShare, SCMPKeyShare, error) {
	r0, r1, e := preprocess.SplitBit(omega)
	if e != nil {
		return SCMPKeyShare{}, SCMPKeyShare{}, e
	}
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint32(raw, xm)
	binary.LittleEndian.PutUint32(raw[4:], ym)
	return NewSCMPKeyShare(raw, r0), NewSCMPKeyShare(raw, r1), nil
}
func (referenceSCMP) Eval(party uint8, k SCMPKeyShare, x, y uint32) (share.BitShare, error) {
	m := binary.LittleEndian.Uint32(k.opaque)
	n := binary.LittleEndian.Uint32(k.opaque[4:])
	pred := domain.Bit((x-m)&127 >= (y-n)&127)
	v := k.rb.Value()
	if party == 0 {
		v = v.Add(pred)
	}
	return share.NewBitShare(v), nil
}

func testKeys(t *testing.T) (anchorindex.Key, targetcrypto.MasterKey) {
	t.Helper()
	var kb [32]byte
	var kt [32]byte
	for i := range kb {
		kb[i] = byte(i + 1)
		kt[i] = byte(255 - i)
	}
	a, e := anchorindex.NewKey(kb)
	if e != nil {
		t.Fatal(e)
	}
	b, e := targetcrypto.NewMasterKey(kt)
	if e != nil {
		t.Fatal(e)
	}
	return a, b
}

func TestQueryChunks(t *testing.T) {
	cases := []struct {
		q    string
		want []QueryChunk
	}{{"abcdefgh", []QueryChunk{{"abcd", 0}, {"efgh", 4}}}, {"abcdefghi", []QueryChunk{{"abcd", 0}, {"efgh", 4}}}, {"abcdefghij", []QueryChunk{{"abcd", 0}, {"efgh", 4}}}, {"abcdefghijk", []QueryChunk{{"abcd", 0}, {"efgh", 4}}}, {"aaaaaaaa", []QueryChunk{{"aaaa", 0}, {"aaaa", 4}}}}
	for _, c := range cases {
		if got := QueryChunks(c.q); !reflect.DeepEqual(got, c.want) {
			t.Fatalf("%q: %#v", c.q, got)
		}
	}
}

func TestPositionTruthTable(t *testing.T) {
	const u = 62
	for _, tau := range []uint32{0, 1, 2} {
		for q := uint32(0); q <= u; q++ {
			l, r := Bounds(q, tau, u)
			for p := uint32(0); p <= u; p++ {
				backend := referenceSCMP{}
				kl0, kl1, err := backend.KeyGen(7, 17, 23, domain.Bit((p+q)&1 == 1))
				if err != nil {
					t.Fatal(err)
				}
				kr0, kr1, err := backend.KeyGen(7, 29, 31, domain.Bit((p+q)&2 == 2))
				if err != nil {
					t.Fatal(err)
				}
				eL0, _ := backend.Eval(0, kl0, (p+17)&127, (l+23)&127)
				eL1, _ := backend.Eval(1, kl1, (p+17)&127, (l+23)&127)
				eR0, _ := backend.Eval(0, kr0, (p+29)&127, (r+1+31)&127)
				eR1, _ := backend.Eval(1, kr1, (p+29)&127, (r+1+31)&127)
				got := share.LocalSubBit(eL0, kl0.rb).Value().Add(share.LocalSubBit(eL1, kl1.rb).Value()) != share.LocalSubBit(eR0, kr0.rb).Value().Add(share.LocalSubBit(eR1, kr1.rb).Value())
				want := p >= l && p <= r
				if got != want {
					t.Fatalf("p=%d q=%d tau=%d", p, q, tau)
				}
			}
		}
	}
}

func TestPartySchemasExcludePlaintextAndPeerState(t *testing.T) {
	for typ, want := range map[reflect.Type][]string{reflect.TypeOf(PartyQuery{}): {"PID", "BucketID", "DPFKey", "Ltilde", "RplusTilde"}, reflect.TypeOf(PartyPreprocessing{}): {"PID", "Bin", "RhoL", "RhoR", "Lower", "Upper"}} {
		if typ.NumField() != len(want) {
			t.Fatalf("%s fields=%d", typ, typ.NumField())
		}
		for i, n := range want {
			if typ.Field(i).Name != n {
				t.Fatalf("%s field %d=%s", typ, i, typ.Field(i).Name)
			}
		}
	}
}

func TestRing32ReductionHomomorphism100k(t *testing.T) {
	const bin = 7
	m := mask(bin)
	edges := []uint32{0, 1, m, m + 1, ^uint32(0), ^uint32(0) - m}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 100000; i++ {
		p := rng.Uint32()
		if i < len(edges) {
			p = edges[i]
		}
		a, b, e := SplitPosition(p)
		if e != nil {
			t.Fatal(e)
		}
		ar, e := ReducePosition(a, bin)
		if e != nil {
			t.Fatal(e)
		}
		br, e := ReducePosition(b, bin)
		if e != nil {
			t.Fatal(e)
		}
		if (ar+br)&m != p&m {
			t.Fatalf("case %d", i)
		}
	}
}

func TestRBRemovalRegression(t *testing.T) {
	b := referenceSCMP{}
	k0, k1, e := b.KeyGen(7, 17, 31, domain.BitOne)
	if e != nil {
		t.Fatal(e)
	}
	e0, _ := b.Eval(0, k0, 20, 35)
	e1, _ := b.Eval(1, k1, 20, 35)
	raw := e0.Value().Add(e1.Value())
	corrected := share.LocalSubBit(e0, k0.rb).Value().Add(share.LocalSubBit(e1, k1.rb).Value())
	if raw == corrected || corrected != domain.BitZero {
		t.Fatalf("raw=%v corrected=%v", raw, corrected)
	}
}

func findBucket(t *testing.T, idx indexbuild.PartyIndex, id uint16) indexbuild.AnchorPartyBucket {
	t.Helper()
	for _, b := range idx.AnchorBuckets {
		if b.BucketID == id {
			return b
		}
	}
	t.Fatalf("bucket %d absent", id)
	return indexbuild.AnchorPartyBucket{}
}

func makeQueryTest(t *testing.T, kb anchorindex.Key, c QueryChunk, tau, u uint32, bits int, user *UserPreprocessing) (PartyQuery, PartyQuery) {
	t.Helper()
	z, e := anchorindex.Encode(kb, c.QGram)
	if e != nil {
		t.Fatal(e)
	}
	id, e := indexbuild.AnchorBucket(z, bits)
	if e != nil {
		t.Fatal(e)
	}
	k0, k1, e := gen.Gen(dpf128.PointFromAnchorValue(z))
	if e != nil {
		t.Fatal(e)
	}
	pid, l, r, e := user.ConsumeBounds(c.Position, tau, u)
	if e != nil {
		t.Fatal(e)
	}
	return PartyQuery{PID: pid, BucketID: id, DPFKey: k0, Ltilde: l, RplusTilde: r}, PartyQuery{PID: pid, BucketID: id, DPFKey: k1, Ltilde: l, RplusTilde: r}
}

func runOccurrence(t *testing.T, kb anchorindex.Key, u uint32, bits int, c QueryChunk, tau uint32, a, b indexbuild.PartyIndex) (int, int) {
	t.Helper()
	z, e := anchorindex.Encode(kb, c.QGram)
	if e != nil {
		t.Fatal(e)
	}
	id, e := indexbuild.AnchorBucket(z, bits)
	if e != nil {
		t.Fatal(e)
	}
	b0 := findBucket(t, a, id)
	b1 := findBucket(t, b, id)
	n := 0
	for _, g := range b0.Groups {
		n += len(g.Slots)
	}
	bin, e := DeriveBin(u)
	if e != nil {
		t.Fatal(e)
	}
	user, p0, p1, e := Preprocess(n, bin, referenceSCMP{})
	if e != nil {
		t.Fatal(e)
	}
	q0, q1 := makeQueryTest(t, kb, c, tau, u, bits, &user)
	a0, e := PrepareParty(b0, q0, p0)
	if e != nil {
		t.Fatal(e)
	}
	a1, e := PrepareParty(b1, q1, p1)
	if e != nil {
		t.Fatal(e)
	}
	opened, e := OpenMaskedPositions(a0.PL, a0.PR, a1.PL, a1.PR, bin)
	if e != nil {
		t.Fatal(e)
	}
	pos0, e := EvalPosition(0, q0, p0, opened, referenceSCMP{})
	if e != nil {
		t.Fatal(e)
	}
	pos1, e := EvalPosition(1, q1, p1, opened, referenceSCMP{})
	if e != nil {
		t.Fatal(e)
	}
	x0, x1, e := ComposeHits(a0, a1, pos0, pos1)
	if e != nil {
		t.Fatal(e)
	}
	errors, dummyErrors, j := 0, 0, 0
	l, r := Bounds(c.Position, tau, u)
	for gi, g := range b0.Groups {
		for si, s0 := range g.Slots {
			valid := reconstruct.RecoverBit(s0.ValidityShare, b1.Groups[gi].Slots[si].ValidityShare)
			pos := uint32(reconstruct.RecoverRing32(s0.PositionShare, b1.Groups[gi].Slots[si].PositionShare))
			want := g.Z == z && valid == domain.BitOne && pos >= l && pos <= r
			got := x0[j].Value().Add(x1[j].Value()) == domain.BitOne
			if got != want {
				errors++
			}
			if valid == domain.BitZero && got {
				dummyErrors++
			}
			j++
		}
	}
	return errors, dummyErrors
}

func TestRepeatedOccurrenceAndDummySuppression(t *testing.T) {
	kb, kt := testKeys(t)
	areas := []indexbuild.AreaRecord{{ID: 1, Name: "aaaaa"}}
	_, a, b, _, e := indexbuild.Build(areas, nil, kb, kt, 8, 8)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []QueryChunk{{"aaaa", 0}, {"aaaa", 4}} {
		errors, dummy := runOccurrence(t, kb, 62, 8, c, 3, a, b)
		if errors != 0 || dummy != 0 {
			t.Fatalf("chunk=%+v errors=%d dummy=%d", c, errors, dummy)
		}
	}
}

func TestRealMusicBrainz5000(t *testing.T) {
	f, e := os.Open(realAreaPath)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	areas, e := indexbuild.LoadArea(f, 5000)
	if e != nil {
		t.Fatal(e)
	}
	kb, kt := testKeys(t)
	for _, bits := range []int{8, 14} {
		_, a, b, _, e := indexbuild.Build(areas, nil, kb, kt, bits, bits)
		if e != nil {
			t.Fatal(e)
		}
		total, dummy := 0, 0
		for _, q := range []string{areas[10].Name, areas[100].Name, "aaaaaaaa"} {
			for _, c := range QueryChunks(q) {
				for _, tau := range []uint32{0, 1, 2} {
					x, d := runOccurrence(t, kb, 62, bits, c, tau, a, b)
					total += x
					dummy += d
				}
			}
		}
		if total != 0 || dummy != 0 {
			t.Fatalf("k=%d errors=%d dummy=%d", bits, total, dummy)
		}
		t.Logf("k=%d errors=0 dummy_errors=0", bits)
	}
}

func TestFullMusicBrainzPositionDomain(t *testing.T) {
	af, e := os.Open(realAreaPath)
	if e != nil {
		t.Fatal(e)
	}
	areas, _, e := indexbuild.LoadAreaWithStats(af, 0)
	af.Close()
	if e != nil {
		t.Fatal(e)
	}
	tf, e := os.Open(realAliasPath)
	if e != nil {
		t.Fatal(e)
	}
	aliases, _, e := indexbuild.LoadAreaAliasWithStats(tf, 0)
	tf.Close()
	if e != nil {
		t.Fatal(e)
	}
	maxA, maxT, lenA, lenT := 0, 0, 0, 0
	for _, r := range areas {
		n := len([]rune(r.Name))
		if n >= 4 && n > lenA {
			lenA = n
		}
		if n >= 4 && n-4 > maxA {
			maxA = n - 4
		}
	}
	for _, r := range aliases {
		n := len([]rune(r.Name))
		if n >= 4 && n > lenT {
			lenT = n
		}
		if n >= 4 && n-4 > maxT {
			maxT = n - 4
		}
	}
	u := maxA
	if maxT > u {
		u = maxT
	}
	bin, e := DeriveBin(uint32(u))
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("position_domain anchor_max=%d target_max=%d anchor_max_indexed_runes=%d target_max_indexed_runes=%d U_pos=%d Bin=%d", maxA, maxT, lenA, lenT, u, bin)
}

func TestAnchorComponentTimings(t *testing.T) {
	if os.Getenv("PMEQ_PHASE4_TIMING") != "1" {
		t.Skip("set PMEQ_PHASE4_TIMING=1")
	}
	f, err := os.Open(realAreaPath)
	if err != nil {
		t.Fatal(err)
	}
	areas, err := indexbuild.LoadArea(f, 0)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	kb, kt := testKeys(t)
	layout, err := indexbuild.AnalyzeTierLayout(areas, nil, kb, kt, 14, 14)
	if err != nil {
		t.Fatal(err)
	}
	b := append([]indexbuild.BucketMetadata(nil), layout.Metadata.AnchorBuckets...)
	sort.Slice(b, func(i, j int) bool { return b[i].TotalSlots < b[j].TotalSlots })
	chosen := []struct {
		name string
		m    indexbuild.BucketMetadata
	}{{"median", b[len(b)/2]}, {"p95", b[(95*len(b))/100]}, {"worst", b[len(b)-1]}}
	for _, c := range chosen {
		alpha := dpf128.Point{}
		k0, _, err := gen.Gen(alpha)
		if err != nil {
			t.Fatal(err)
		}
		points := make([]dpf128.Point, c.m.GroupCount)
		start := time.Now()
		const reps = 200
		for r := 0; r < reps; r++ {
			for _, p := range points {
				_ = dpf128.Eval(k0, p)
			}
		}
		dpfTime := time.Since(start) / reps
		n := int(c.m.TotalSlots)
		zeros := make([]share.BitShare, n)
		t0, t1, err := f2beaver.Preprocess(n)
		if err != nil {
			t.Fatal(err)
		}
		andLayer := func() time.Duration {
			start := time.Now()
			d0, e0, _ := f2beaver.Mask(zeros, zeros, t0)
			d1, e1, _ := f2beaver.Mask(zeros, zeros, t1)
			o, _ := f2beaver.Open(d0, e0, d1, e1)
			_, _ = f2beaver.Finish(0, t0, o)
			_, _ = f2beaver.Finish(1, t1, o)
			return time.Since(start)
		}
		and1, and2 := andLayer(), andLayer()
		t.Logf("component bucket=%s id=%d groups=%d slots=%d dpf_eval=%s two_and_layers=%s", c.name, c.m.BucketID, c.m.GroupCount, c.m.TotalSlots, dpfTime, and1+and2)
	}
}
