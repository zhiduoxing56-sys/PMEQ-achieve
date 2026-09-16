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
	u := anchorfilter.UserPreprocessing{PID: [16]byte{1}, EtaL: 3, EtaR: 5}
	a, b, err := MakeOccurrence(k, anchorfilter.QueryChunk{QGram: "abcd", Position: 4}, 1, 62, 8, &u)
	if err != nil {
		t.Fatal(err)
	}
	if a.BucketID != b.BucketID || a.PID != b.PID || a.Ltilde != 6 || a.RplusTilde != 11 {
		t.Fatal("party token mismatch")
	}
	if _, _, err = MakeOccurrence(k, anchorfilter.QueryChunk{QGram: "abcd", Position: 4}, 1, 62, 8, &u); err == nil {
		t.Fatal("pid reuse accepted")
	}
}
