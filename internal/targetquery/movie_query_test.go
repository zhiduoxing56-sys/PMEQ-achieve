package targetquery

import (
	"pmeq/internal/anchorfilter"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetrouting"
	"testing"
)

func TestMovieFourSignaturesAndTenBitBounds(t *testing.T) {
	k, err := targetcrypto.NewMasterKey([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	m := targetrouting.Manifest{IndexID: [16]byte{1}, TargetBucketBits: 16, Q: 4}
	users := make([]anchorfilter.UserPreprocessing, 4)
	for i := range users {
		users[i], _, _, err = anchorfilter.Preprocess(0, 10, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	a, b, err := GenerateMoviePositionTokens(m, k, "abcdefghijklmnopqrst", 1, users)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Words) != 4 || len(b.Words) != 4 || len(a.Position) != 4 || len(b.Position) != 4 {
		t.Fatal("signature count")
	}
	for i := 0; i < 4; i++ {
		if a.Words[i].Occurrence.Position != uint32(4*i) || b.Words[i].Occurrence != a.Words[i].Occurrence || a.Position[i] != b.Position[i] || a.Position[i].Ltilde > 1023 || a.Position[i].RplusTilde > 1023 {
			t.Fatal("position or mask", i)
		}
		word, err := targetcrypto.MovieWordBucketComponent(k, "abcdefghijklmnop"[4*i:4*i+4], 16)
		if err != nil || a.Words[i].BucketWordShare.Value()^b.Words[i].BucketWordShare.Value() != word {
			t.Fatal("movie word routing", i)
		}
	}
}
