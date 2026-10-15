package indexbuild

import (
	"os"
	"testing"
)

func TestAggregationFullDomain(t *testing.T) {
	f, e := os.Open(realAreaPath)
	if e != nil {
		t.Fatal(e)
	}
	a, e := LoadArea(f, 0)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	mx := 0
	maxChunks := 0
	var name, word string
	for _, r := range a {
		if n := len([]rune(r.Name)) / Q; n > maxChunks {
			maxChunks = n
		}
		counts := map[string]int{}
		VisitQGrams(r.Name, func(q string, p uint32) {
			counts[q]++
			if counts[q] > mx {
				mx = counts[q]
				name = r.Name
				word = q
			}
		})
	}
	t.Logf("max F upper bound=%d name=%q qgram=%q records=%d", mx, name, word, len(a))
	if mx >= 64 {
		t.Fatal("signed SCMP domain exceeded")
	}
	if maxChunks != 14 {
		t.Fatal("query domain regression", maxChunks)
	}
	t.Logf("max normal query r=%d => C<=%d", maxChunks, maxChunks)
	kb, kt := testKeys(t)
	groups, _, _, e := buildLogical(a, nil, kb, kt, 16, 16)
	if e != nil {
		t.Fatal(e)
	}
	totals := map[uint32]int{}
	records := map[uint32]map[uint64]bool{}
	for _, g := range groups {
		w, e := TierWidth(len(g.postings))
		if e != nil {
			t.Fatal(e)
		}
		totals[g.bucket] += w
		if records[g.bucket] == nil {
			records[g.bucket] = map[uint64]bool{}
		}
		for _, p := range g.postings {
			records[g.bucket][p.recordID] = true
		}
	}
	products := uint64(0)
	for id, T := range totals {
		D := 1
		for D < len(records[id]) {
			D *= 2
		}
		products += uint64(D * T)
	}
	t.Logf("STATIC full A shares bytes=%d; nonempty=%d; old rho/sigma arrays bytes=%d; PHASE5B3 CS0 seed bytes=%d CS1 sigma bytes=%d combined=%d (full table not materialized)", 2*products, len(totals), uint64(len(totals))*120071*16, uint64(len(totals))*32, uint64(len(totals))*120071*4, uint64(len(totals))*(32+120071*4))
}

func TestAggregationNewFullLayout(t *testing.T) {
	if os.Getenv("PMEQ_AGG_STATS") != "1" {
		t.Skip("set PMEQ_AGG_STATS=1")
	}
	f, e := os.Open(realAreaPath)
	if e != nil {
		t.Fatal(e)
	}
	a, e := LoadArea(f, 0)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	f, e = os.Open(realAliasPath)
	if e != nil {
		t.Fatal(e)
	}
	b, e := LoadAreaAlias(f, 0)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	kb, kt := testKeys(t)
	v, e := AnalyzeTierLayout(a, b, kb, kt, 16, 16)
	if e != nil {
		t.Fatal(e)
	}
	if v.Anchor.RealSlots != 906584 || v.Target.RealSlots != 480945 || v.Anchor.PaddedSlots != 1961824 || v.Target.PaddedSlots != 1317260 {
		t.Fatal("new tier regression", v.Anchor, v.Target)
	}
	t.Logf("ANCHOR %s", formatSide(v.Anchor))
	t.Logf("TARGET %s", formatSide(v.Target))
	t.Logf("tiers Anchor=%+v Target=%+v", v.AnchorTiers, v.TargetTiers)
}
