//go:build phase6native

package discovery_test

import (
	"context"
	"encoding/csv"
	"encoding/json"
	mathrand "math/rand"
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

const thresholdSeed int64 = 20260923

type thresholdOriginalQuery struct {
	QueryID          int    `json:"query_id"`
	Anchor           string `json:"anchor"`
	Target           string `json:"target"`
	OriginalTau      int    `json:"original_tau"`
	AnchorSignatures int    `json:"anchor_signatures"`
	TargetSignatures int    `json:"target_signatures"`
}

type thresholdQuerySubset struct {
	Label                string                   `json:"label"`
	Seed                 int64                    `json:"seed"`
	OriginalLegalQueries int                      `json:"original_legal_queries"`
	EligibleQueries      int                      `json:"eligible_queries"`
	SelectedQueries      int                      `json:"selected_queries"`
	FullAnchorRecords    int                      `json:"full_anchor_records"`
	FullTargetRecords    int                      `json:"full_target_records"`
	Q                    int                      `json:"q"`
	BucketBits           int                      `json:"bucket_bits"`
	Queries              []thresholdOriginalQuery `json:"queries"`
}

func thresholdOracle(f *fixture, q discovery.Query) map[candidatequery.Pair]bool {
	out := map[candidatequery.Pair]bool{}
	for _, a := range f.areas {
		if !matches(a.Name, q.Anchor, q.TauAnchor) {
			continue
		}
		for _, alias := range f.aliases[a.ID] {
			if matches(alias.Name, q.Target, q.TauTarget) {
				out[candidatequery.Pair{AnchorRecordID: a.ID, TargetRecordID: alias.ID}] = true
			}
		}
	}
	return out
}

func thresholdCapacity(t *testing.T, f *fixture, q discovery.Query, buckets []uint32) candidateCapacity {
	t.Helper()
	words := anchorfilter.QueryChunks(q.Target)
	cap := candidateCapacity{buckets: buckets, shape: targetaggregation.Shape{R: len(words)}, capacities: make([]int, len(words))}
	for _, a := range f.areas {
		if !matches(a.Name, q.Anchor, q.TauAnchor) {
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

func thresholdSelection(t *testing.T, f *fixture) thresholdQuerySubset {
	t.Helper()
	var eligible []thresholdOriginalQuery
	legal := 0
	for _, q := range f.trace {
		base := discovery.Query{Anchor: q.Anchor, Target: q.Target, TauAnchor: q.Tau, TauTarget: q.Tau}
		valid := discovery.Validate(base) == nil
		if valid == f.ref[q.Query].Rejected {
			t.Fatalf("original legality mismatch query=%d", q.Query)
		}
		if !valid {
			continue
		}
		legal++
		ra, rt := len(anchorfilter.QueryChunks(q.Anchor)), len(anchorfilter.QueryChunks(q.Target))
		if ra < 4 || rt < 4 {
			continue
		}
		all := true
		for _, side := range []string{"anchor", "target"} {
			for tau := 0; tau <= 3; tau++ {
				a, b := 1, 1
				if side == "anchor" {
					a = tau
				} else {
					b = tau
				}
				if discovery.Validate(discovery.Query{Anchor: q.Anchor, Target: q.Target, TauAnchor: a, TauTarget: b}) != nil {
					all = false
				}
			}
		}
		if all {
			eligible = append(eligible, thresholdOriginalQuery{q.Query, q.Anchor, q.Target, q.Tau, ra, rt})
		}
	}
	if legal != 854 || len(eligible) == 0 {
		t.Fatalf("unexpected source query counts legal=%d eligible=%d", legal, len(eligible))
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].QueryID < eligible[j].QueryID })
	count := len(eligible)
	if len(eligible) > 50 {
		rng := mathrand.New(mathrand.NewSource(thresholdSeed))
		rng.Shuffle(len(eligible), func(i, j int) { eligible[i], eligible[j] = eligible[j], eligible[i] })
		eligible = eligible[:50]
	}
	return thresholdQuerySubset{"original-854 fixed threshold query subset", thresholdSeed, legal, count, len(eligible), len(f.areas), 67896, 4, 16, eligible}
}

func TestThresholdCandidateDiscoveryExperiment(t *testing.T) {
	outdir := os.Getenv("PMEQ_THRESHOLD_OUTPUT")
	if outdir == "" {
		t.Skip("requires explicit exclusive experiment output")
	}
	f := loadFixture(t)
	subset := thresholdSelection(t, f)
	if subset.FullAnchorRecords != 120071 || subset.FullTargetRecords != 67896 {
		t.Fatal("not the current full database")
	}
	qf, err := os.OpenFile(filepath.Join(outdir, "fixed-query-subset.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, err)
	enc := json.NewEncoder(qf)
	enc.SetIndent("", "  ")
	must(t, enc.Encode(subset))
	must(t, qf.Close())
	raw, err := os.OpenFile(filepath.Join(outdir, "candidate-raw.csv"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, err)
	defer raw.Close()
	w := csv.NewWriter(raw)
	must(t, w.Write([]string{"case_id", "query_id", "variable_side", "tau_anchor", "tau_target", "anchor_signatures", "target_signatures", "trial", "local_e2e_ns", "user_to_cloud_bytes", "cs_to_cs_bytes", "cloud_to_user_bytes", "total_online_bytes", "K", "routes", "groups", "target_slots", "final_pairs", "oracle_pairs", "FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id", "pair_sha256", "packet_id_sha256"}))
	checks, err := os.OpenFile(filepath.Join(outdir, "correctness.csv"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	must(t, err)
	defer checks.Close()
	cw := csv.NewWriter(checks)
	must(t, cw.Write([]string{"case_id", "query_id", "variable_side", "tau_anchor", "tau_target", "oracle_pairs", "trial1_pairs", "trial2_pairs", "trial3_pairs", "all_three_equal_oracle", "FP", "FN", "duplicates", "wrong_anchor_id", "wrong_target_id", "oracle_pair_sha256"}))
	packetIDs := map[string]bool{}
	caseID := 0
	for qi, item := range subset.Queries {
		statics, buckets := f.prepareStatic(t, workload{Anchor: item.Anchor, Target: item.Target, Tau: 1})
		caps := map[int]candidateCapacity{}
		for tau := 0; tau <= 3; tau++ {
			caps[tau] = thresholdCapacity(t, f, discovery.Query{Anchor: item.Anchor, Target: item.Target, TauAnchor: tau, TauTarget: 1}, buckets)
		}
		for _, side := range []string{"anchor", "target"} {
			for tau := 0; tau <= 3; tau++ {
				a, b := 1, 1
				if side == "anchor" {
					a = tau
				} else {
					b = tau
				}
				q := discovery.Query{Anchor: item.Anchor, Target: item.Target, TauAnchor: a, TauTarget: b}
				if discovery.Validate(q) != nil {
					t.Fatal("illegal saved configuration", caseID)
				}
				want := thresholdOracle(f, q)
				wantPairs := dbSortedPairs(want)
				wantHash := candidatePairHash(wantPairs)
				cap := caps[a]
				counts := [3]int{}
				for trial := 1; trial <= 3; trial++ {
					u, p0, p1, _, err := discovery.Provision(statics[0], statics[1], cap.buckets, cap.capacities, cap.shape, scmpnative.Backend{})
					must(t, err)
					packetHash := formalPacketID(u)
					if packetIDs[packetHash] {
						t.Fatal("reused one-time packet", caseID, trial)
					}
					packetIDs[packetHash] = true
					got, m, err := discovery.RunLocal(context.Background(), q, f.keys, u, statics, [2]*discovery.PartyPacket{p0, p1}, scmpnative.Backend{})
					must(t, err)
					errors, recovered := formalErrors(want, got.Pairs)
					if errors != (dbErrors{}) || len(got.Pairs) != len(wantPairs) || candidatePairHash(recovered) != wantHash {
						t.Fatalf("plaintext mismatch case=%d trial=%d errors=%+v", caseID, trial, errors)
					}
					if m.K != cap.shape.K || m.Routes != cap.shape.K*cap.shape.R || m.Groups != cap.shape.G || m.Slots != cap.shape.S || m.LocalE2E <= 0 {
						t.Fatalf("workload/timer mismatch case=%d trial=%d measured=%d,%d,%d,%d planned=%+v", caseID, trial, m.K, m.Routes, m.Groups, m.Slots, cap.shape)
					}
					user := m.UserToCloud[0] + m.UserToCloud[1]
					cloud := m.CloudToUser[0] + m.CloudToUser[1]
					total := user + m.ServerBytes + cloud
					counts[trial-1] = len(got.Pairs)
					record := []string{strconv.Itoa(caseID), strconv.Itoa(item.QueryID), side, strconv.Itoa(a), strconv.Itoa(b), strconv.Itoa(item.AnchorSignatures), strconv.Itoa(item.TargetSignatures), strconv.Itoa(trial), strconv.FormatInt(m.LocalE2E.Nanoseconds(), 10), strconv.FormatUint(user, 10), strconv.FormatUint(m.ServerBytes, 10), strconv.FormatUint(cloud, 10), strconv.FormatUint(total, 10), strconv.Itoa(m.K), strconv.Itoa(m.Routes), strconv.Itoa(m.Groups), strconv.Itoa(m.Slots), strconv.Itoa(len(got.Pairs)), strconv.Itoa(len(wantPairs)), "0", "0", "0", "0", "0", wantHash, packetHash}
					must(t, w.Write(record))
					w.Flush()
					must(t, w.Error())
				}
				correct := []string{strconv.Itoa(caseID), strconv.Itoa(item.QueryID), side, strconv.Itoa(a), strconv.Itoa(b), strconv.Itoa(len(wantPairs)), strconv.Itoa(counts[0]), strconv.Itoa(counts[1]), strconv.Itoa(counts[2]), "true", "0", "0", "0", "0", "0", wantHash}
				must(t, cw.Write(correct))
				cw.Flush()
				must(t, cw.Error())
				caseID++
			}
		}
		statics = [2]*discovery.Static{}
		runtime.GC()
		t.Logf("THRESHOLD CANDIDATE progress=%d/%d cases=%d", qi+1, len(subset.Queries), caseID)
	}
	t.Logf("THRESHOLD CANDIDATE complete eligible=%d selected=%d cases=%d trials=%d", subset.EligibleQueries, subset.SelectedQueries, caseID, 3*caseID)
}
