//go:build phase6native

package discovery_test

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"pmeq/internal/candidatequery"
	"pmeq/internal/discovery"
	"pmeq/internal/scmpnative"
	"runtime"
	"strconv"
	"testing"
)

// This test is experiment orchestration. All index, token, and online protocol
// operations are delegated to the frozen production helpers.
func TestBucketCountCandidateExperiment(t *testing.T) {
	dir := os.Getenv("PMEQ_BUCKET_COUNT_OUTPUT")
	if dir == "" {
		t.Skip("requires an exclusive output directory")
	}
	root, err := filepath.Abs("../..")
	must(t, err)
	if root != "/home/tenggn/projects/clean_pmeq" || !filepath.IsAbs(dir) || !filepath.IsLocal(relPath(t, root, dir)) {
		t.Fatal("repository/output boundary")
	}
	areas, aliases, _, _ := dbReadInputs(t)
	if len(areas) != 120071 || len(aliases) != 67896 {
		t.Fatal("full database cardinality mismatch")
	}
	trace, ref, base, valid := formalTrace(t)
	buildDir := filepath.Join(dir, "build")
	must(t, os.Mkdir(buildDir, 0700))
	f, built := dbBuild(t, buildDir, 100, areas, aliases, trace, ref)
	built.Phase = "bucket-count-16"
	dbWrite(t, dir, "build-and-storage.json", built)

	baseline := map[int][]candidatequery.Pair{}
	bf, err := os.Open("../../results/n-domain-regression-pilot-20260920/regression-100-queries.jsonl")
	must(t, err)
	scanner := bufio.NewScanner(bf)
	scanner.Buffer(make([]byte, 65536), 4<<20)
	for scanner.Scan() {
		var item struct {
			Query     int
			Recovered []candidatequery.Pair
		}
		must(t, json.Unmarshal(scanner.Bytes(), &item))
		if _, exists := baseline[item.Query]; exists {
			t.Fatal("duplicate baseline query", item.Query)
		}
		baseline[item.Query] = item.Recovered
	}
	must(t, scanner.Err())
	must(t, bf.Close())
	if len(baseline) != 854 {
		t.Fatal("default-bucket baseline coverage", len(baseline))
	}
	file, err := os.OpenFile(filepath.Join(dir, "candidate-raw.csv"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, err)
	defer file.Close()
	w := csv.NewWriter(file)
	must(t, w.Write([]string{"bucket_bits", "bucket_count", "query_id", "tau_anchor", "tau_target", "trial", "local_e2e_ns", "user_to_cloud_bytes", "cs_to_cs_bytes", "cloud_to_user_bytes", "total_online_bytes", "K", "routes", "groups", "target_slots", "final_pairs", "oracle_pairs", "FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id", "matches_default_bucket_result", "pair_sha256", "packet_id_sha256"}))
	packetIDs := map[string]bool{}
	for order, id := range valid {
		item := trace[id]
		q := discovery.Query{Anchor: item.Anchor, Target: item.Target, TauAnchor: item.Tau, TauTarget: item.Tau}
		if discovery.Validate(q) != nil || base[id].Rejected {
			t.Fatal("legal query changed", id)
		}
		want := f.oracle(item)
		wantPairs := dbSortedPairs(want)
		wantHash := candidatePairHash(wantPairs)
		if candidatePairHash(baseline[id]) != wantHash {
			dbWrite(t, dir, "first-difference.json", map[string]any{"query": id, "field": "saved default versus plaintext", "default": baseline[id], "plaintext": wantPairs})
			t.Fatal("saved default-bucket candidate result differs from plaintext", id)
		}
		statics, buckets := f.prepareStatic(t, item)
		for trial := 1; trial <= 3; trial++ {
			u, packets, _ := dbProvision(t, f, item, statics, buckets)
			packetHash := formalPacketID(u)
			if packetIDs[packetHash] {
				t.Fatal("reused one-time packet", id, trial)
			}
			packetIDs[packetHash] = true
			got, m, err := discovery.RunLocal(context.Background(), q, f.keys, u, statics, packets, scmpnative.Backend{})
			must(t, err)
			errors, recovered := formalErrors(want, got.Pairs)
			if errors != (dbErrors{}) || candidatePairHash(recovered) != wantHash {
				dbWrite(t, dir, "first-difference.json", map[string]any{"query": id, "trial": trial, "field": "secure versus plaintext", "errors": errors, "recovered": recovered, "plaintext": wantPairs})
				t.Fatal("secure candidate result differs from plaintext", id, trial)
			}
			if m.K != base[id].Metrics.K || m.Routes != base[id].Metrics.Routes || m.Groups != base[id].Metrics.Groups || m.Slots != base[id].Metrics.Slots || len(got.Pairs) != base[id].Pairs || m.LocalE2E <= 0 {
				dbWrite(t, dir, "first-difference.json", map[string]any{"query": id, "trial": trial, "field": "default workload", "K": m.K, "routes": m.Routes, "groups": m.Groups, "slots": m.Slots, "pairs": len(got.Pairs)})
				t.Fatal("default-bucket workload differs", id, trial)
			}
			user := m.UserToCloud[0] + m.UserToCloud[1]
			cloud := m.CloudToUser[0] + m.CloudToUser[1]
			total := user + m.ServerBytes + cloud
			row := []string{"16", "65536", strconv.Itoa(id), strconv.Itoa(item.Tau), strconv.Itoa(item.Tau), strconv.Itoa(trial), strconv.FormatInt(m.LocalE2E.Nanoseconds(), 10), strconv.FormatUint(user, 10), strconv.FormatUint(m.ServerBytes, 10), strconv.FormatUint(cloud, 10), strconv.FormatUint(total, 10), strconv.Itoa(m.K), strconv.Itoa(m.Routes), strconv.Itoa(m.Groups), strconv.Itoa(m.Slots), strconv.Itoa(len(got.Pairs)), strconv.Itoa(len(wantPairs)), "0", "0", "0", "0", "0", "true", wantHash, packetHash}
			must(t, w.Write(row))
			w.Flush()
			must(t, w.Error())
		}
		statics = [2]*discovery.Static{}
		runtime.GC()
		if (order+1)%25 == 0 {
			t.Logf("BUCKET-16 progress=%d/%d trials=%d", order+1, len(valid), 3*(order+1))
		}
	}
	if len(packetIDs) != 3*len(valid) {
		t.Fatal("trial coverage")
	}
	t.Logf("BUCKET-16 complete queries=%d trials=%d", len(valid), len(packetIDs))
}
