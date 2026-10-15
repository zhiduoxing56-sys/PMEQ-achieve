//go:build phase6native

package discovery_test

import (
	"context"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"pmeq/internal/discovery"
	"pmeq/internal/scmpnative"
	"runtime"
	"strconv"
	"testing"
)

// Rebuilds each complete state before measuring one bucket configuration.
func TestBucketCountFinal(t *testing.T) {
	dir := os.Getenv("PMEQ_BUCKET_FINAL_OUTPUT")
	if dir == "" {
		t.Skip("explicit output required")
	}
	bits, err := strconv.Atoi(os.Getenv("PMEQ_BUCKET_FINAL_BITS"))
	must(t, err)
	if bits < 14 || bits > 17 {
		t.Fatal("bucket width")
	}
	limit := 854
	if x := os.Getenv("PMEQ_BUCKET_FINAL_SMOKE"); x != "" {
		limit, err = strconv.Atoi(x)
		must(t, err)
		if limit < 1 || limit > 854 {
			t.Fatal("smoke limit")
		}
	}
	root, err := filepath.Abs("../..")
	must(t, err)
	if root != "/home/tenggn/projects/clean_pmeq" || !filepath.IsAbs(dir) || !filepath.IsLocal(relPath(t, root, dir)) {
		t.Fatal("output boundary")
	}
	areas, aliases, _, _ := dbReadInputs(t)
	if len(areas) != 120071 || len(aliases) != 67896 {
		t.Fatal("full database")
	}
	trace, ref, _, valid := formalTrace(t)
	if len(valid) != 854 {
		t.Fatal("legal coverage")
	}
	buildDir := filepath.Join(dir, "build")
	must(t, os.Mkdir(buildDir, 0700))
	f, built := dbBuildBits(t, buildDir, 100, bits, areas, aliases, trace, ref)
	built.Phase = "bucket-count-final"
	dbWrite(t, dir, "build-and-storage.json", built)
	baseline := map[int]string{}
	bf, err := os.Open("../../results/bucket-count-candidate-20260923/candidate-raw.csv")
	must(t, err)
	br := csv.NewReader(bf)
	header, err := br.Read()
	must(t, err)
	cols := map[string]int{}
	for i, name := range header {
		cols[name] = i
	}
	for _, name := range []string{"query_id", "pair_sha256", "FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id"} {
		if _, ok := cols[name]; !ok {
			t.Fatal("missing default column", name)
		}
	}
	for {
		row, e := br.Read()
		if e == io.EOF {
			break
		}
		must(t, e)
		id, e := strconv.Atoi(row[cols["query_id"]])
		must(t, e)
		for _, name := range []string{"FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id"} {
			if row[cols[name]] != "0" {
				t.Fatal("default correctness", id, name)
			}
		}
		hash := row[cols["pair_sha256"]]
		if previous, ok := baseline[id]; ok && previous != hash {
			t.Fatal("default trial mismatch", id)
		}
		baseline[id] = hash
	}
	must(t, bf.Close())
	if len(baseline) != 854 {
		t.Fatal("baseline coverage")
	}
	out, err := os.OpenFile(filepath.Join(dir, "candidate-raw.csv"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, err)
	defer out.Close()
	w := csv.NewWriter(out)
	must(t, w.Write([]string{"B", "b", "query_id", "tau_anchor", "tau_target", "trial", "candidate_discovery_ms", "online_bytes", "K", "route_count", "target_slots", "groups", "final_pairs", "oracle_pairs", "FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id", "matches_default", "pair_sha256", "packet_id_sha256"}))
	ids := map[string]bool{}
	for order, id := range valid[:limit] {
		item := trace[id]
		q := discovery.Query{Anchor: item.Anchor, Target: item.Target, TauAnchor: item.Tau, TauTarget: item.Tau}
		want := f.oracle(item)
		wantHash := candidatePairHash(dbSortedPairs(want))
		if baseline[id] != wantHash {
			t.Fatal("default/plaintext mismatch", id)
		}
		st, buckets := f.prepareStatic(t, item)
		for trial := 1; trial <= 3; trial++ {
			u, p, _ := dbProvision(t, f, item, st, buckets)
			packetHash := formalPacketID(u)
			if ids[packetHash] {
				t.Fatal("reused packet", id, trial)
			}
			ids[packetHash] = true
			got, m, e := discovery.RunLocal(context.Background(), q, f.keys, u, st, p, scmpnative.Backend{})
			must(t, e)
			errors, recovered := formalErrors(want, got.Pairs)
			if errors != (dbErrors{}) || candidatePairHash(recovered) != wantHash {
				dbWrite(t, dir, "first-difference.json", map[string]any{"query": id, "trial": trial, "errors": errors, "recovered": recovered, "expected": dbSortedPairs(want)})
				t.Fatal("candidate mismatch", id, trial)
			}
			bytes := m.UserToCloud[0] + m.UserToCloud[1] + m.ServerBytes + m.CloudToUser[0] + m.CloudToUser[1]
			row := []string{strconv.Itoa(1 << bits), strconv.Itoa(bits), strconv.Itoa(id), strconv.Itoa(item.Tau), strconv.Itoa(item.Tau), strconv.Itoa(trial), strconv.FormatFloat(float64(m.LocalE2E.Nanoseconds())/1e6, 'f', 9, 64), strconv.FormatUint(bytes, 10), strconv.Itoa(m.K), strconv.Itoa(m.Routes), strconv.Itoa(m.Slots), strconv.Itoa(m.Groups), strconv.Itoa(len(got.Pairs)), strconv.Itoa(len(want)), "0", "0", "0", "0", "0", "true", wantHash, packetHash}
			must(t, w.Write(row))
			w.Flush()
			must(t, w.Error())
		}
		st = [2]*discovery.Static{}
		runtime.GC()
		if (order+1)%25 == 0 {
			t.Logf("BUCKET b=%d progress=%d/%d", bits, order+1, limit)
		}
	}
	if len(ids) != 3*limit {
		t.Fatal("trial coverage")
	}
	t.Logf("BUCKET b=%d complete queries=%d trials=%d", bits, limit, len(ids))
}
