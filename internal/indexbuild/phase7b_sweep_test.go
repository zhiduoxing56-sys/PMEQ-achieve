package indexbuild

import (
	"encoding/json"
	"os"
	"pmeq/internal/anchorindex"
	"pmeq/internal/targetcrypto"
	"testing"
)

type sweepBucket struct {
	ID                   uint32
	Groups, Slots, Joins int
}
type sweepLayout struct {
	Bits    int
	Stats   SideStats
	Buckets []sweepBucket
}

func phase7bKeys(t *testing.T) (anchorindex.Key, targetcrypto.MasterKey) {
	t.Helper()
	var a, b [32]byte
	for i := range a {
		a[i] = byte(i + 1)
		b[i] = byte(255 - i)
	}
	kb, e := anchorindex.NewKey(a)
	if e != nil {
		t.Fatal(e)
	}
	kt, e := targetcrypto.NewMasterKey(b)
	if e != nil {
		t.Fatal(e)
	}
	return kb, kt
}
func phase7bAliases(t *testing.T) []AreaAliasRecord {
	t.Helper()
	f, e := os.Open("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area_alias")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	v, e := LoadAreaAlias(f, 0)
	if e != nil {
		t.Fatal(e)
	}
	return v
}

// Analysis remains trusted test-only. No plaintext grouping or route oracle is
// linked into a cloud runtime. All six layouts reuse one logical grouping pass.
func TestPhase7BSweep(t *testing.T) {
	path := os.Getenv("PMEQ_7B_SWEEP")
	if path == "" {
		t.Skip("explicit full-data experiment")
	}
	kb, kt := phase7bKeys(t)
	aliases := phase7bAliases(t)
	_, groups, stats, e := buildLogical(nil, aliases, kb, kt, 16, 16)
	if e != nil {
		t.Fatal(e)
	}
	if len(aliases) != 67896 || len(groups) != 310331 || stats.Target.QGramOccurrences != 480945 {
		t.Fatal("dataset counts", stats)
	}
	layouts := []sweepLayout{}
	for _, k := range []int{8, 10, 12, 14, 15, 16} {
		joins := make([]map[uint64]bool, 1<<k)
		for i := range groups {
			g := &groups[i]
			j, e := targetcrypto.JoinBucketComponent(kt, g.joinID, k)
			if e != nil {
				t.Fatal(e)
			}
			w, e := targetcrypto.WordBucketComponent(kt, g.qgram, k)
			if e != nil {
				t.Fatal(e)
			}
			g.bucket = uint32(targetcrypto.CombineBucketComponents(j, w))
			if joins[g.bucket] == nil {
				joins[g.bucket] = map[uint64]bool{}
			}
			joins[g.bucket][g.joinID] = true
		}
		a, e := analyzeTierFromLogical(nil, groups, stats, 16, k)
		if e != nil {
			t.Fatal(e)
		}
		row := sweepLayout{Bits: k, Stats: a.Target, Buckets: make([]sweepBucket, 1<<k)}
		for i := range row.Buckets {
			row.Buckets[i] = sweepBucket{ID: uint32(i), Joins: len(joins[i])}
		}
		for _, b := range a.Metadata.TargetBuckets {
			row.Buckets[b.BucketID].Groups = int(b.GroupCount)
			row.Buckets[b.BucketID].Slots = int(b.TotalSlots)
		}
		if row.Stats.PaddedSlots != 1317260 {
			t.Fatal("padding changed", k, row.Stats)
		}
		layouts = append(layouts, row)
		t.Logf("bits=%d nonempty=%d slots=%d bytes/party=%d", k, row.Stats.NonemptyBuckets, row.Stats.PaddedSlots, TargetEncodedBytes(uint64(row.Stats.NonemptyBuckets), 310331, 1317260))
	}
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = json.NewEncoder(f).Encode(layouts); e != nil {
		t.Fatal(e)
	}
}
