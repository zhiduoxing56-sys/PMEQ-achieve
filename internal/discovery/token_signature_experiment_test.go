//go:build phase6native

package discovery

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpnative"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
	"pmeq/internal/targetrouting"
	"sort"
	"strconv"
	"testing"
	"time"
)

const signatureSeed int64 = 20260923

type signaturePair struct {
	AnchorID   uint64 `json:"anchor_id"`
	TargetID   uint64 `json:"target_id"`
	AnchorName string `json:"anchor_name"`
	TargetName string `json:"target_name"`
}

type signatureCase struct {
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

func signaturePrefix(name string, count int) string {
	return string([]rune(name)[:4*count])
}

func signaturePairs(t *testing.T, raw string) ([]signaturePair, int) {
	t.Helper()
	a, err := os.Open(filepath.Join(raw, "area"))
	if err != nil {
		t.Fatal(err)
	}
	areas, astats, err := indexbuild.LoadAreaWithStats(a, 0)
	a.Close()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Open(filepath.Join(raw, "area_alias"))
	if err != nil {
		t.Fatal(err)
	}
	aliases, bstats, err := indexbuild.LoadAreaAliasWithStats(b, 0)
	b.Close()
	if err != nil {
		t.Fatal(err)
	}
	if astats.UsableRows != 120071 || bstats.UsableRows != 67896 {
		t.Fatalf("not current full database: Anchor=%d Target=%d", astats.UsableRows, bstats.UsableRows)
	}
	lookup := make(map[uint64]string, len(areas))
	for _, a := range areas {
		if len([]rune(a.Name)) >= 24 {
			lookup[a.ID] = a.Name
		}
	}
	var eligible []signaturePair
	for _, b := range aliases {
		if a, ok := lookup[b.Area]; ok && len([]rune(b.Name)) >= 24 {
			eligible = append(eligible, signaturePair{b.Area, b.ID, a, b.Name})
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].AnchorID != eligible[j].AnchorID {
			return eligible[i].AnchorID < eligible[j].AnchorID
		}
		return eligible[i].TargetID < eligible[j].TargetID
	})
	// Stable seed and sorted source order give a repeatable sample without
	// deriving any cryptographic material from this sampling RNG.
	count := len(eligible)
	if count == 0 {
		t.Fatal("no eligible real joined pairs")
	}
	if os.Getenv("PMEQ_SIGNATURE_FULL") == "1" {
		if count != 644 {
			t.Fatalf("expected 644 eligible pairs, got %d", count)
		}
		return eligible, count
	}
	sampleSignaturePairs(eligible)
	if len(eligible) > 50 {
		eligible = eligible[:50]
	}
	return eligible, count
}

func sampleSignaturePairs(pairs []signaturePair) {
	rng := mathrand.New(mathrand.NewSource(signatureSeed))
	rng.Shuffle(len(pairs), func(i, j int) { pairs[i], pairs[j] = pairs[j], pairs[i] })
}

func freshSignatureUser(t *testing.T, q Query, key UserKeys, manifest targetrouting.Manifest, lineage targetpe.AlignmentLineage) *UserPacket {
	t.Helper()
	b := scmpnative.Backend{}
	u := &UserPacket{g: &guard{}}
	if _, err := rand.Read(u.id[:]); err != nil {
		t.Fatal(err)
	}
	for _, chunk := range anchorfilter.QueryChunks(q.Anchor) {
		z, err := anchorindex.Encode(key.Anchor, chunk.QGram)
		if err != nil {
			t.Fatal(err)
		}
		bucket, err := indexbuild.AnchorBucket(z, 16)
		if err != nil {
			t.Fatal(err)
		}
		user, _, _, err := anchorfilter.Preprocess(0, 7, b)
		if err != nil {
			t.Fatal(err)
		}
		mask, _, _, err := aggregation.PreprocessComparison(0, b)
		if err != nil {
			t.Fatal(err)
		}
		u.buckets = append(u.buckets, bucket)
		u.anchor = append(u.anchor, user)
		u.f = append(u.f, mask)
	}
	var err error
	u.keep, _, _, err = aggregation.PreprocessComparison(0, b)
	if err != nil {
		t.Fatal(err)
	}
	r := len(anchorfilter.QueryChunks(q.Target))
	u.target, _, _, _, err = targetposition.Preprocess(lineage, make([]int, r), b)
	if err != nil {
		t.Fatal(err)
	}
	u.agg, _, _, _, err = targetaggregation.Preprocess(lineage, targetaggregation.Shape{K: 0, R: r, S: 0, G: 0}, b)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.IndexID != lineage.IndexID || manifest.TargetBucketBits != 16 || manifest.Q != 4 {
		t.Fatal("manifest mismatch")
	}
	return u
}

func TestTokenSignatureCountExperiment(t *testing.T) {
	output := os.Getenv("PMEQ_SIGNATURE_OUTPUT")
	raw := os.Getenv("PMEQ_SIGNATURE_RAW")
	if output == "" || raw == "" {
		t.Skip("requires explicit output and full raw database")
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatal(err)
	}
	pairs, eligible := signaturePairs(t, raw)
	full := os.Getenv("PMEQ_SIGNATURE_FULL") == "1"
	if full {
		pf, err := os.OpenFile(filepath.Join(output, "source-pairs.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil { t.Fatal(err) }
		pe := json.NewEncoder(pf)
		pe.SetIndent("", "  ")
		if err := pe.Encode(pairs); err != nil { t.Fatal(err) }
		if err := pf.Close(); err != nil { t.Fatal(err) }
	}
	mf, err := os.Open("../../artifacts/phase7b/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	meta, err := indexbuild.ReadTargetManifest(mf)
	mf.Close()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../artifacts/phase7b/payload-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var payload targetpe.PayloadManifest
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.N != 120071 || payload.TargetBucketBits != 16 || payload.IndexID != meta.IndexID {
		t.Fatal("full database payload mismatch")
	}
	lineage := targetpe.AlignmentLineage{IndexID: meta.IndexID, LayoutID: payload.LayoutID, N: payload.N}
	manifest := targetrouting.Manifest{IndexID: meta.IndexID, TargetBucketBits: meta.TargetBucketBits, Q: meta.Q}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	var kb, kt [32]byte
	for i := range kb {
		kb[i] = byte(i + 1)
		kt[i] = byte(255 - i)
	}
	aKey, err := anchorindex.NewKey(kb)
	if err != nil {
		t.Fatal(err)
	}
	tKey, err := targetcrypto.NewMasterKey(kt)
	if err != nil {
		t.Fatal(err)
	}
	keys := UserKeys{Anchor: aKey, Target: tKey}
	var cases []signatureCase
	for pairIndex, pair := range pairs {
		for _, side := range []string{"anchor", "target"} {
			for _, r := range []int{2, 3, 4, 6} {
				ar, tr := 4, 4
				if side == "anchor" {
					ar = r
				} else {
					tr = r
				}
				c := signatureCase{CaseID: len(cases), PairIndex: pairIndex, VariableSide: side, AnchorSignatures: ar, TargetSignatures: tr, AnchorID: pair.AnchorID, TargetID: pair.TargetID, AnchorName: pair.AnchorName, TargetName: pair.TargetName, AnchorQuery: signaturePrefix(pair.AnchorName, ar), TargetQuery: signaturePrefix(pair.TargetName, tr), TauAnchor: 1, TauTarget: 1}
				if len(anchorfilter.QueryChunks(c.AnchorQuery)) != ar || len(anchorfilter.QueryChunks(c.TargetQuery)) != tr || Validate(Query{Anchor: c.AnchorQuery, Target: c.TargetQuery, TauAnchor: 1, TauTarget: 1}) != nil {
					t.Fatal("signature count/domain mismatch")
				}
				cases = append(cases, c)
			}
		}
	}
	set := struct {
		Label             string          `json:"label"`
		Seed              int64           `json:"seed"`
		EligiblePairs     int             `json:"eligible_pairs"`
		SampledPairs      int             `json:"sampled_pairs"`
		FullAnchorRecords int             `json:"full_anchor_records"`
		FullTargetRecords int             `json:"full_target_records"`
		Q                 int             `json:"q"`
		BucketBits        int             `json:"bucket_bits"`
		Cases             []signatureCase `json:"cases"`
	}{"length-controlled constructed query set", signatureSeed, eligible, len(pairs), 120071, 67896, 4, 16, cases}
	if full { set.Label = "full length-controlled constructed query set"; set.Seed = 0 }
	qf, err := os.OpenFile(filepath.Join(output, "constructed-queries.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(qf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(set); err != nil {
		t.Fatal(err)
	}
	if err := qf.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(output, "token-raw.csv"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	w := csv.NewWriter(f)
	if err := w.Write([]string{"case_id", "pair_index", "variable_side", "anchor_signatures", "target_signatures", "trial", "generation_ns", "cs0_token_bytes", "cs1_token_bytes", "total_token_bytes", "cs0_token_sha256", "cs1_token_sha256"}); err != nil {
		t.Fatal(err)
	}
	seenPackets, seenQueries, seenTokens := map[[16]byte]bool{}, map[[16]byte]bool{}, map[[32]byte]bool{}
	for _, c := range cases {
		q := Query{Anchor: c.AnchorQuery, Target: c.TargetQuery, TauAnchor: 1, TauTarget: 1}
		for trial := 1; trial <= 3; trial++ {
			u := freshSignatureUser(t, q, keys, manifest, lineage)
			if seenPackets[u.id] {
				t.Fatal("reused packet ID")
			}
			seenPackets[u.id] = true
			start := time.Now()
			tokens, err := generate(q, keys, u, manifest)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			if len(tokens[0]) == 0 || len(tokens[1]) == 0 || len(tokens[0]) != len(tokens[1]) {
				t.Fatal("invalid encoded token lengths")
			}
			x, err := decodeToken(tokens[0], manifest, 0)
			if err != nil {
				t.Fatal(err)
			}
			y, err := decodeToken(tokens[1], manifest, 1)
			if err != nil {
				t.Fatal(err)
			}
			if x.target.QueryID != y.target.QueryID || x.target.QueryID == [16]byte{} || seenQueries[x.target.QueryID] || len(x.anchor) != c.AnchorSignatures || len(x.target.Words) != c.TargetSignatures {
				t.Fatal("decoded token mismatch or repeated query ID")
			}
			seenQueries[x.target.QueryID] = true
			h0, h1 := sha256.Sum256(tokens[0]), sha256.Sum256(tokens[1])
			if seenTokens[h0] || seenTokens[h1] {
				t.Fatal("reused encoded token")
			}
			seenTokens[h0] = true
			seenTokens[h1] = true
			record := []string{strconv.Itoa(c.CaseID), strconv.Itoa(c.PairIndex), c.VariableSide, strconv.Itoa(c.AnchorSignatures), strconv.Itoa(c.TargetSignatures), strconv.Itoa(trial), strconv.FormatInt(elapsed.Nanoseconds(), 10), strconv.Itoa(len(tokens[0])), strconv.Itoa(len(tokens[1])), strconv.Itoa(len(tokens[0]) + len(tokens[1])), fmt.Sprintf("%x", h0), fmt.Sprintf("%x", h1)}
			if err := w.Write(record); err != nil {
				t.Fatal(err)
			}
			w.Flush()
			if err := w.Error(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("signature token experiment completed: eligible=%d sampled=%d cases=%d trials=%d", eligible, len(pairs), len(cases), len(cases)*3)
}
