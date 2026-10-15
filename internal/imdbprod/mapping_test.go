package imdbprod

import (
	"path/filepath"
	"testing"
)

func TestFrozenMappingRoundTrip(t *testing.T) {
	m, manifest, err := LoadFrozen(filepath.Join("..", "..", "imdb_production_20261015"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Anchors) != AnchorObjects || len(m.Targets) != TargetObjects {
		t.Fatal("sample size")
	}
	anchorInput, joins, targetInput, err := m.IndexInputs()
	if err != nil || len(anchorInput) != AnchorObjects || len(joins) != AnchorObjects || len(targetInput) != TargetObjects {
		t.Fatal("DO projection", err)
	}
	if anchorInput[0].ID != m.Anchors[0].ID || joins[0] != m.Anchors[0].JoinID || targetInput[0].ID != m.Targets[0].ID || targetInput[0].Area != m.Targets[0].JoinID {
		t.Fatal("object/join projection")
	}
	for _, a := range m.Anchors {
		back, err := m.AnchorByID(a.ID)
		if err != nil || back != a {
			t.Fatal("anchor reverse map", a.ID)
		}
		movie, err := m.TargetByID(a.JoinID)
		if err != nil || movie.Tconst != a.Tconst || movie.ID != movie.JoinID {
			t.Fatal("shared movie join ID", a.ID)
		}
	}
	for _, target := range m.Targets {
		back, err := m.TargetByID(target.ID)
		if err != nil || back != target {
			t.Fatal("target reverse map", target.ID)
		}
	}
	fingerprint := KeyFingerprint([32]byte{1}, [32]byte{2})
	b, err := manifest.Bind([16]byte{1}, [16]byte{2}, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Digest(); err != nil {
		t.Fatal(err)
	}
	if _, err = manifest.Bind([16]byte{}, [16]byte{2}, fingerprint); err == nil {
		t.Fatal("zero index ID accepted")
	}
	if _, err = manifest.Bind([16]byte{1}, [16]byte{2}, ""); err == nil {
		t.Fatal("missing key identity accepted")
	}
	if err = Production().CheckCandidates(10001); err == nil {
		t.Fatal("candidate overflow accepted")
	}
	if err = Production().CheckCandidates(10000); err != nil {
		t.Fatal(err)
	}
}

func TestMovieIDCanonicalDomain(t *testing.T) {
	for _, bad := range []string{"", "tt", "tt0", "nm1", "tt+1", "tt1x", "tt18446744073709551616"} {
		if _, err := MovieID(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	id, err := MovieID("tt0000009")
	if err != nil || id != 9 {
		t.Fatal(id, err)
	}
}

func TestMovieV2BucketCapacityAndOldBindingRejection(t *testing.T) {
	if TargetBucketGroups != 12 || TargetBucketSlots != 48 ||
		TargetGroupCapacity != 480000 || TargetSignatures*TargetGroupCapacity != 1920000 {
		t.Fatal("public target envelope mismatch")
	}
	p := Production()
	p.TargetBucketGroups = 11
	p.TargetBucketSlots = 44
	if err := p.Validate(); err == nil {
		t.Fatal("old capacity contract accepted")
	}
	fingerprint := KeyFingerprint([32]byte{1}, [32]byte{2})
	b := Binding{Version: SampleVersion, KeyFingerprint: fingerprint}
	if _, err := b.Digest(); err == nil {
		t.Fatal("old sample-version binding accepted as production v2")
	}
}
