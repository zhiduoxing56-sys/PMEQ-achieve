package targetartifact

import (
	"bufio"
	"encoding/json"
	"os"
	"pmeq/internal/targetcrypto"
	"testing"
)

type bucketLayout struct {
	Bits    int
	Buckets []struct {
		ID                   uint16
		Groups, Slots, Joins int
	}
}
type queryLoad struct {
	Query, K, R, Routes, GroupComparisons, TouchedSlots, DistinctBuckets int
	Reuse                                                                float64
}
type layoutLoad struct {
	Bits    int
	Queries []queryLoad
}

func TestPhase7BWorkloadSweep(t *testing.T) {
	layoutsPath, trace, out := os.Getenv("PMEQ_7B_LAYOUTS"), os.Getenv("PMEQ_7B_WORKLOAD"), os.Getenv("PMEQ_7B_LOADS")
	if layoutsPath == "" || trace == "" || out == "" {
		t.Skip("explicit workload sweep")
	}
	raw, e := os.ReadFile(layoutsPath)
	must(t, e)
	var layouts []bucketLayout
	must(t, json.Unmarshal(raw, &layouts))
	f, e := os.Open(trace)
	must(t, e)
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 65536), 4<<20)
	var qs []workloadQuery
	routes := 0
	for scan.Scan() {
		var q workloadQuery
		must(t, json.Unmarshal(scan.Bytes(), &q))
		if q.Query != len(qs) {
			t.Fatal("query order")
		}
		qs = append(qs, q)
		routes += len(q.Joins) * len(q.Words)
	}
	must(t, scan.Err())
	if len(qs) != 1003 || routes != 466105 {
		t.Fatal("replay incomplete", len(qs), routes)
	}
	var key [32]byte
	for i := range key {
		key[i] = byte(255 - i)
	}
	kt, e := targetcrypto.NewMasterKey(key)
	must(t, e)
	results := []layoutLoad{}
	for _, layout := range layouts {
		row := layoutLoad{Bits: layout.Bits}
		totalG, totalS := 0, 0
		for _, q := range qs {
			load := queryLoad{Query: q.Query, K: len(q.Joins), R: len(q.Words), Routes: len(q.Joins) * len(q.Words)}
			accessed := map[uint16]bool{}
			for _, j := range q.Joins {
				for _, w := range q.Words {
					jb, e := targetcrypto.JoinBucketComponent(kt, j, layout.Bits)
					must(t, e)
					wb, e := targetcrypto.WordBucketComponent(kt, w.QGram, layout.Bits)
					must(t, e)
					beta := uint16(targetcrypto.CombineBucketComponents(jb, wb))
					bucket := layout.Buckets[beta]
					if bucket.ID != beta {
						t.Fatal("layout bucket order")
					}
					load.GroupComparisons += bucket.Groups
					load.TouchedSlots += bucket.Slots
					accessed[beta] = true
				}
			}
			load.DistinctBuckets = len(accessed)
			if load.DistinctBuckets > 0 {
				load.Reuse = float64(load.Routes) / float64(load.DistinctBuckets)
			}
			row.Queries = append(row.Queries, load)
			totalG += load.GroupComparisons
			totalS += load.TouchedSlots
		}
		results = append(results, row)
		t.Logf("bits=%d queries=%d routes=%d comparisons=%d touched=%d", layout.Bits, len(qs), routes, totalG, totalS)
	}
	raw, e = json.Marshal(results)
	must(t, e)
	must(t, os.WriteFile(out, append(raw, '\n'), 0600))
}
