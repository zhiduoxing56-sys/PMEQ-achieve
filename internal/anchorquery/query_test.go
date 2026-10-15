package anchorquery

import (
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"testing"
)

func TestTokenOmitsPlaintextAndConsumesPID(t *testing.T) {
	var raw [32]byte
	raw[0] = 1
	k, err := anchorindex.NewKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	u, _, _, err := anchorfilter.Preprocess(0, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, b, err := MakeOccurrence(k, anchorfilter.QueryChunk{QGram: "abcd", Position: 4}, 1, 62, 8, &u)
	if err != nil {
		t.Fatal(err)
	}
	if a.BucketID != b.BucketID || a.PID != b.PID || a.Ltilde != ((3+u.EtaL)&127) || a.RplusTilde != ((6+u.EtaR)&127) {
		t.Fatal("party token mismatch")
	}
	if _, _, err = MakeOccurrence(k, anchorfilter.QueryChunk{QGram: "abcd", Position: 4}, 1, 62, 8, &u); err == nil {
		t.Fatal("pid reuse accepted")
	}
}
