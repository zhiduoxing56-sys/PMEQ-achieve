package targetquery

import (
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetrouting"
	"testing"
)

func TestShortTargetPositionExplicit(t *testing.T) {
	for _, s := range []string{"", "a", "甲乙丙"} {
		_, _, e := GeneratePositionTokens(targetrouting.Manifest{}, targetcrypto.MasterKey{}, s, 0, nil)
		if e != ErrShortTarget {
			t.Fatal("short target silently accepted", s, e)
		}
	}
}
