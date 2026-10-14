//go:build phase6native

package discovery_test

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/candidatequery"
	"pmeq/internal/discovery"
	"pmeq/internal/scmpnative"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetcrypto"
	"runtime"
	"sort"
	"strconv"
	"testing"
)

type candidateSignatureCase struct {
	CaseID           int    `json:"case_id"`
	PairIndex        int    `json:"pair_index"`
	VariableSide     string `json:"variable_side"`
	AnchorSignatures int    `json:"anchor_signatures"`
	TargetSignatures int    `json:"target_signatures"`
	AnchorID         uint64 `json:"anchor_id"`
	TargetID         uint64 `json:"target_id"`
	AnchorName       string `json:"anchor_name"`
	TargetName       string `json:"target_name"`
	AnchorQuery      string `json:"anchor_query"`
	TargetQuery      string `json:"target_query"`
	TauAnchor        int    `json:"tau_anchor"`
	TauTarget        int    `json:"tau_target"`
}

type candidateSignatureSet struct {
	Label             string                   `json:"label"`
	Seed              int64                    `json:"seed"`
	EligiblePairs     int                      `json:"eligible_pairs"`
	SampledPairs      int                      `json:"sampled_pairs"`
	FullAnchorRecords int                      `json:"full_anchor_records"`
	FullTargetRecords int                      `json:"full_target_records"`
	Q                 int                      `json:"q"`
	BucketBits        int                      `json:"bucket_bits"`
	Cases             []candidateSignatureCase `json:"cases"`
}

type candidateCapacity struct {
	buckets    []uint32
	shape      targetaggregation.Shape
	capacities []int
}

func candidateExpectedCapacity(t *testing.T, f *fixture, c candidateSignatureCase, buckets []uint32) candidateCapacity {
	t.Helper()
	words := anchorfilter.QueryChunks(c.TargetQuery)
	cap := candidateCapacity{buckets: buckets, shape: targetaggregation.Shape{R: len(words)}, capacities: make([]int, len(words))}
	for _, a := range f.areas {
		if !matches(a.Name, c.AnchorQuery, 1) {
			continue
		}
		cap.shape.K++
		join, err := targetcrypto.JoinBucketComponent(f.keys.Target, a.ID, 16)
		must(t, err)
		for h, w := range words {
			word, err := targetcrypto.WordBucketComponent(f.keys.Target, w.QGram, 16)
			must(t, err)
			for _, g := range f.idx[0].PositionGroups(uint32(join) ^ uint32(word)) {
				cap.shape.G++
				cap.shape.S += int(g.PadWidth)
				cap.capacities[h] += int(g.PadWidth)
			}
		}
	}
	return cap
}

func candidatePairHash(pairs []candidatequery.Pair) string {
	b, err := json.Marshal(pairs)
	if err != nil {
		panic(err)
	}
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h)
}

func TestSignatureCandidateDiscoveryExperiment(t *testing.T) {
	outdir := os.Getenv("PMEQ_SIGNATURE_CANDIDATE_OUTPUT")
	setpath := os.Getenv("PMEQ_SIGNATURE_CANDIDATE_QUERYSET")
	if outdir == "" || setpath == "" {
		t.Skip("requires explicit new output and saved query set")
	}
	b, err := os.ReadFile(setpath)
	must(t, err)
	var set candidateSignatureSet
	must(t, json.Unmarshal(b, &set))
	full := os.Getenv("PMEQ_SIGNATURE_FULL") == "1"
	validSet := set.Label == "length-controlled constructed query set" && set.Seed == 20260923 && set.SampledPairs == 50
	if full { validSet = set.Label == "full length-controlled constructed query set" && set.Seed == 0 && set.EligiblePairs == 644 && set.SampledPairs == 644 }
	if !validSet || set.Q != 4 || set.BucketBits != 16 || set.FullAnchorRecords != 120071 || set.FullTargetRecords != 67896 || len(set.Cases) != 8*set.SampledPairs {
		t.Fatal("saved construction metadata changed")
	}
	f := loadFixture(t)
	if len(f.areas) != set.FullAnchorRecords {
		t.Fatal("not full Anchor data")
	}
	area := map[uint64]string{}
	for _, a := range f.areas {
		area[a.ID] = a.Name
	}
	for i, c := range set.Cases {
		if c.CaseID != i || c.PairIndex < 0 || c.PairIndex >= set.SampledPairs || c.TauAnchor != 1 || c.TauTarget != 1 || (c.VariableSide != "anchor" && c.VariableSide != "target") || len(anchorfilter.QueryChunks(c.AnchorQuery)) != c.AnchorSignatures || len(anchorfilter.QueryChunks(c.TargetQuery)) != c.TargetSignatures || discovery.Validate(discovery.Query{Anchor: c.AnchorQuery, Target: c.TargetQuery, TauAnchor: 1, TauTarget: 1}) != nil {
			t.Fatal("saved query invalid", i)
		}
		if area[c.AnchorID] != c.AnchorName {
			t.Fatal("Anchor source mismatch", i)
		}
		joined := false
		for _, a := range f.aliases[c.AnchorID] {
			if a.ID == c.TargetID && a.Name == c.TargetName {
				joined = true
				break
			}
		}
		if !joined {
			t.Fatal("Target source/join mismatch", i)
		}
		if c.AnchorQuery != string([]rune(c.AnchorName)[:4*c.AnchorSignatures]) || c.TargetQuery != string([]rune(c.TargetName)[:4*c.TargetSignatures]) {
			t.Fatal("query prefix changed", i)
		}
	}
	// Reuse a static state only while the same Anchor query is active. Its
	// construction is outside RunLocal and is not a cached candidate answer.
	groups := map[string][]candidateSignatureCase{}
	var names []string
	shardCount, shardIndex := 1, 0
	if os.Getenv("PMEQ_SIGNATURE_FULL") == "1" && os.Getenv("PMEQ_SIGNATURE_SHARD_COUNT") != "" {
		shardCount, err = strconv.Atoi(os.Getenv("PMEQ_SIGNATURE_SHARD_COUNT")); must(t, err)
		shardIndex, err = strconv.Atoi(os.Getenv("PMEQ_SIGNATURE_SHARD_INDEX")); must(t, err)
		if shardCount < 1 || shardIndex < 0 || shardIndex >= shardCount { t.Fatal("invalid signature shard") }
	}
	for _, c := range set.Cases {
		if c.PairIndex%shardCount != shardIndex { continue }
		if _, ok := groups[c.AnchorQuery]; !ok {
			names = append(names, c.AnchorQuery)
		}
		groups[c.AnchorQuery] = append(groups[c.AnchorQuery], c)
	}
	sort.Strings(names)
	raw, err := os.OpenFile(filepath.Join(outdir, "candidate-raw.csv"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, err)
	defer raw.Close()
	w := csv.NewWriter(raw)
	must(t, w.Write([]string{"case_id", "pair_index", "variable_side", "anchor_signatures", "target_signatures", "trial", "local_e2e_ns", "candidate_discovery_ns", "user_to_cloud_bytes", "cs_to_cs_bytes", "cloud_to_user_bytes", "total_online_bytes", "K", "routes", "groups", "target_slots", "final_pairs", "oracle_pairs", "FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id", "pair_sha256"}))
	checks, err := os.OpenFile(filepath.Join(outdir, "correctness.csv"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, err)
	defer checks.Close()
	cw := csv.NewWriter(checks)
	must(t, cw.Write([]string{"case_id", "pair_index", "variable_side", "anchor_signatures", "target_signatures", "oracle_pairs", "trial1_pairs", "trial2_pairs", "trial3_pairs", "all_three_equal_oracle", "FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id", "oracle_pair_sha256"}))
	completed := 0
	for _, name := range names {
		first := groups[name][0]
		q0 := workload{Anchor: first.AnchorQuery, Target: first.TargetQuery, Tau: 1}
		statics, buckets := f.prepareStatic(t, q0)
		for _, c := range groups[name] {
			q := discovery.Query{Anchor: c.AnchorQuery, Target: c.TargetQuery, TauAnchor: 1, TauTarget: 1}
			work := workload{Anchor: c.AnchorQuery, Target: c.TargetQuery, Tau: 1}
			want := f.oracle(work)
			wantPairs := dbSortedPairs(want)
			wantHash := candidatePairHash(wantPairs)
			capacity := candidateExpectedCapacity(t, f, c, buckets)
			counts := [3]int{}
			for trial := 1; trial <= 3; trial++ {
				u, p0, p1, _, err := discovery.Provision(statics[0], statics[1], capacity.buckets, capacity.capacities, capacity.shape, scmpnative.Backend{})
				must(t, err)
				got, m, err := discovery.RunLocal(context.Background(), q, f.keys, u, statics, [2]*discovery.PartyPacket{p0, p1}, scmpnative.Backend{})
				must(t, err)
				errors, recovered := formalErrors(want, got.Pairs)
				if errors != (dbErrors{}) || len(got.Pairs) != len(wantPairs) || candidatePairHash(recovered) != wantHash {
					t.Fatalf("plaintext mismatch case=%d trial=%d errors=%+v", c.CaseID, trial, errors)
				}
				if m.K != capacity.shape.K || m.Routes != capacity.shape.K*capacity.shape.R || m.Groups != capacity.shape.G || m.Slots != capacity.shape.S {
					t.Fatalf("workload mismatch case=%d trial=%d measured=%d,%d,%d,%d planned=%+v", c.CaseID, trial, m.K, m.Routes, m.Groups, m.Slots, capacity.shape)
				}
				if m.LocalE2E <= 0 {
					t.Fatal("missing timing")
				}
				user := m.UserToCloud[0] + m.UserToCloud[1]
				cloud := m.CloudToUser[0] + m.CloudToUser[1]
				total := user + m.ServerBytes + cloud
				counts[trial-1] = len(got.Pairs)
				if m.Cloud <= 0 || m.Recovery <= 0 || m.Token <= 0 { t.Fatal("missing protocol stage timing") }
				record := []string{strconv.Itoa(c.CaseID), strconv.Itoa(c.PairIndex), c.VariableSide, strconv.Itoa(c.AnchorSignatures), strconv.Itoa(c.TargetSignatures), strconv.Itoa(trial), strconv.FormatInt(m.LocalE2E.Nanoseconds(), 10), strconv.FormatInt((m.Cloud+m.Recovery).Nanoseconds(), 10), strconv.FormatUint(user, 10), strconv.FormatUint(m.ServerBytes, 10), strconv.FormatUint(cloud, 10), strconv.FormatUint(total, 10), strconv.Itoa(m.K), strconv.Itoa(m.Routes), strconv.Itoa(m.Groups), strconv.Itoa(m.Slots), strconv.Itoa(len(got.Pairs)), strconv.Itoa(len(wantPairs)), "0", "0", "0", "0", "0", wantHash}
				must(t, w.Write(record))
				w.Flush()
				must(t, w.Error())
			}
			correct := []string{strconv.Itoa(c.CaseID), strconv.Itoa(c.PairIndex), c.VariableSide, strconv.Itoa(c.AnchorSignatures), strconv.Itoa(c.TargetSignatures), strconv.Itoa(len(wantPairs)), strconv.Itoa(counts[0]), strconv.Itoa(counts[1]), strconv.Itoa(counts[2]), "true", "0", "0", "0", "0", "0", wantHash}
			must(t, cw.Write(correct))
			cw.Flush()
			must(t, cw.Error())
			completed++
			if completed%10 == 0 {
				t.Logf("SIGNATURE CANDIDATE shard=%d/%d progress=%d", shardIndex, shardCount, completed)
			}
		}
		statics = [2]*discovery.Static{}
		runtime.GC()
	}
	t.Logf("SIGNATURE CANDIDATE complete cases=%d trials=%d", completed, 3*completed)
}
