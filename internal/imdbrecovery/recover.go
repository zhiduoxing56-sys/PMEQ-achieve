// Package imdbrecovery is the authorized IMDb user boundary after the two
// real cryptographic cloud result shares have arrived over authenticated links.
package imdbrecovery

import (
	"pmeq/internal/candidatequery"
	"pmeq/internal/imdbprod"
)

type Pair struct {
	Anchor imdbprod.Anchor
	Target imdbprod.Target
}
type Result struct {
	QueryID [16]byte
	Pairs   []Pair
}

// Recover opens only the existing D26 result shares. The frozen trusted map
// then rejects foreign IDs or a pair whose two independently encoded tconsts
// differ. No plaintext search result is used to alter the cloud decision.
func Recover(mapping *imdbprod.Mapping, freeze imdbprod.FreezeManifest, production imdbprod.Binding, wire candidatequery.Binding, left, right []byte) (Result, error) {
	want, err := freeze.Bind(production.IndexID, production.LayoutID, production.KeyFingerprint)
	if err != nil || want != production || mapping == nil || wire.Manifest.IndexID != production.IndexID || wire.LayoutID != production.LayoutID || wire.Manifest.TargetBucketBits != imdbprod.BucketBits || wire.Manifest.Q != imdbprod.Q {
		return Result{}, imdbprod.ErrContract
	}
	opened, err := candidatequery.RecoverForDomain(wire, left, right, imdbprod.AnchorObjects)
	if err != nil {
		return Result{}, err
	}
	if len(opened.Pairs) > imdbprod.CandidateCapacity {
		return Result{}, imdbprod.ErrContract
	}
	out := Result{QueryID: opened.QueryID, Pairs: make([]Pair, 0, len(opened.Pairs))}
	for _, item := range opened.Pairs {
		a, err := mapping.AnchorByID(item.AnchorRecordID)
		if err != nil {
			return Result{}, err
		}
		b, err := mapping.TargetByID(item.TargetRecordID)
		if err != nil || a.JoinID != b.JoinID || a.Tconst != b.Tconst {
			return Result{}, imdbprod.ErrContract
		}
		out.Pairs = append(out.Pairs, Pair{Anchor: a, Target: b})
	}
	return out, nil
}
