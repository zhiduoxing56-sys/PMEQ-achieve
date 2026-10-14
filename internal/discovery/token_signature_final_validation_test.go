//go:build phase6native

package discovery

import (
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"pmeq/internal/aggregation"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	dpfcodec "pmeq/internal/dpf128/codec"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpnative"
	"pmeq/internal/targetaggregation"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetpe"
	"pmeq/internal/targetposition"
	"pmeq/internal/targetrouting"
	"strconv"
	"testing"
)

// A structure-only validation. It does not time tokens or execute a query.
// The nonzero profile tests whether public offline capacities can add token
// fields; actual full-query wire lengths are checked against saved RunLocal data
// by the companion validation script.
func formalCapacityProbeUser(t *testing.T, q Query, keys UserKeys, lineage targetpe.AlignmentLineage) *UserPacket {
	t.Helper()
	b := scmpnative.Backend{}
	u := &UserPacket{g: &guard{}}
	if _, e := rand.Read(u.id[:]); e != nil { t.Fatal(e) }
	for _, chunk := range anchorfilter.QueryChunks(q.Anchor) {
		z, e := anchorindex.Encode(keys.Anchor, chunk.QGram); if e != nil { t.Fatal(e) }
		bucket, e := indexbuild.AnchorBucket(z, 16); if e != nil { t.Fatal(e) }
		user, _, _, e := anchorfilter.Preprocess(1, 7, b); if e != nil { t.Fatal(e) }
		mask, _, _, e := aggregation.PreprocessComparison(1, b); if e != nil { t.Fatal(e) }
		u.buckets = append(u.buckets, bucket)
		u.anchor = append(u.anchor, user)
		u.f = append(u.f, mask)
	}
	var e error
	u.keep, _, _, e = aggregation.PreprocessComparison(1, b); if e != nil { t.Fatal(e) }
	r := len(anchorfilter.QueryChunks(q.Target))
	caps := make([]int, r)
	for i := range caps { caps[i] = 1 }
	u.target, _, _, _, e = targetposition.Preprocess(lineage, caps, b); if e != nil { t.Fatal(e) }
	u.agg, _, _, _, e = targetaggregation.Preprocess(lineage, targetaggregation.Shape{K: 1, R: r, S: r, G: r}, b); if e != nil { t.Fatal(e) }
	return u
}

func TestTokenSignatureFinalFieldValidation(t *testing.T) {
	out := os.Getenv("PMEQ_SIGNATURE_FINAL_VALIDATION_OUTPUT")
	if out == "" { t.Skip("explicit field-validation output required") }
	raw, e := os.ReadFile("../../results/query-signature-count-20260923/constructed-queries.json"); if e != nil { t.Fatal(e) }
	var set struct { Cases []signatureCase `json:"cases"`; SampledPairs int `json:"sampled_pairs"` }
	if e = json.Unmarshal(raw, &set); e != nil { t.Fatal(e) }
	if len(set.Cases) != 400 || set.SampledPairs != 50 { t.Fatal("constructed query coverage") }
	metaFile, e := os.Open("../../artifacts/phase7b/manifest.json"); if e != nil { t.Fatal(e) }
	meta, e := indexbuild.ReadTargetManifest(metaFile); if e != nil { t.Fatal(e) }; metaFile.Close()
	payloadRaw, e := os.ReadFile("../../artifacts/phase7b/payload-manifest.json"); if e != nil { t.Fatal(e) }
	var pm targetpe.PayloadManifest
	if e = json.Unmarshal(payloadRaw, &pm); e != nil { t.Fatal(e) }
	manifest := targetrouting.Manifest{IndexID: meta.IndexID, TargetBucketBits: meta.TargetBucketBits, Q: meta.Q}
	lineage := targetpe.AlignmentLineage{IndexID: pm.IndexID, LayoutID: pm.LayoutID, N: pm.N}
	if manifest.IndexID != lineage.IndexID || manifest.TargetBucketBits != 16 || manifest.Q != 4 || lineage.N != 120071 { t.Fatal("full index lineage") }
	var kb, kt [32]byte
	for i := range kb { kb[i] = byte(i+1); kt[i] = byte(255-i) }
	aKey, e := anchorindex.NewKey(kb); if e != nil { t.Fatal(e) }
	tKey, e := targetcrypto.NewMasterKey(kt); if e != nil { t.Fatal(e) }
	keys := UserKeys{Anchor: aKey, Target: tKey}
	f, e := os.OpenFile(filepath.Join(out, "token-field-validation.csv"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); if e != nil { t.Fatal(e) }
	defer f.Close()
	w := csv.NewWriter(f)
	if e = w.Write([]string{"case_id","variation_side","anchor_r","target_r","profile","party","packet_id_fields","anchor_occurrences","dpf_keys","anchor_position_materials","anchor_bucket_ids","anchor_threshold_fields","target_words","target_word_point_shares","target_bucket_word_shares","target_position_materials","target_threshold_fields","routing_manifest_fields","serialized_bytes","expected_serialized_bytes"}); e != nil { t.Fatal(e) }
	for _, c := range set.Cases {
		q := Query{Anchor:c.AnchorQuery, Target:c.TargetQuery, TauAnchor:c.TauAnchor, TauTarget:c.TauTarget}
		if Validate(q) != nil || len(anchorfilter.QueryChunks(q.Anchor)) != c.AnchorSignatures || len(anchorfilter.QueryChunks(q.Target)) != c.TargetSignatures { t.Fatal("saved query shape", c.CaseID) }
		for _, profile := range []string{"zero_capacity", "nonzero_capacity"} {
			var u *UserPacket
			if profile == "zero_capacity" { u = freshSignatureUser(t,q,keys,manifest,lineage) } else { u = formalCapacityProbeUser(t,q,keys,lineage) }
			tokens, e := generate(q,keys,u,manifest); if e != nil { t.Fatal(c.CaseID,profile,e) }
			for party := 0; party < 2; party++ {
				d, e := decodeToken(tokens[party],manifest,uint8(party)); if e != nil { t.Fatal(c.CaseID,profile,party,e) }
				if len(d.anchor) != c.AnchorSignatures || len(d.f) != c.AnchorSignatures || len(d.target.Words) != c.TargetSignatures || len(d.target.Position) != c.TargetSignatures || d.agg.R != c.TargetSignatures || d.packet == [16]byte{} || d.target.QueryID == [16]byte{} || d.agg.PacketID == [16]byte{} || d.agg.QueryID != d.target.QueryID || d.keep > 127 || d.agg.FBound > 127 || d.agg.KeepBound > 127 { t.Fatal("field count or binding",c.CaseID,profile,party) }
				for _, a := range d.anchor { if len(dpfcodec.EncodeKey(a.DPFKey)) != dpfcodec.KeyBytes { t.Fatal("DPF key encoding",c.CaseID) } }
				for _, word := range d.target.Words { if len(word.WordPointShare) != 32 { t.Fatal("point share",c.CaseID) } }
				expected := 122 + 2352*c.AnchorSignatures + 66*c.TargetSignatures
				if len(tokens[party]) != expected { t.Fatal("serialized field accounting",c.CaseID,profile,party,len(tokens[party]),expected) }
				row := []string{strconv.Itoa(c.CaseID),c.VariableSide,strconv.Itoa(c.AnchorSignatures),strconv.Itoa(c.TargetSignatures),profile,strconv.Itoa(party),"1",strconv.Itoa(len(d.anchor)),strconv.Itoa(len(d.anchor)),strconv.Itoa(len(d.anchor)),strconv.Itoa(len(d.anchor)),strconv.Itoa(1+len(d.f)),strconv.Itoa(len(d.target.Words)),strconv.Itoa(len(d.target.Words)),strconv.Itoa(len(d.target.Words)),strconv.Itoa(len(d.target.Position)),"2","1",strconv.Itoa(len(tokens[party])),strconv.Itoa(expected)}
				if e = w.Write(row); e != nil { t.Fatal(e) }
			}
		}
	}
	w.Flush(); if e = w.Error(); e != nil { t.Fatal(e) }
	t.Logf("token field validation complete: cases=%d profiles=2 parties=2 rows=%d",len(set.Cases),4*len(set.Cases))
}
