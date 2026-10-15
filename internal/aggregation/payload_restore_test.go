package aggregation

import (
	"pmeq/internal/targetcrypto"
	"testing"
)

func TestRestoreDealerLayoutFromSealedShares(t *testing.T) {
	ids := []uint64{3, 7, 11, 19}
	joins := []uint64{31, 37, 41, 43}
	d, a, b, err := GeneratePayloadWithJoins(ids, joins, targetcrypto.MasterKey{1}, 16)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreDealerLayoutFromPayload(ids, a, b)
	if err != nil || restored.LayoutID != d.LayoutID || restored.N != d.N {
		t.Fatal("restore rejected original payload", err)
	}
	for _, id := range ids {
		if restored.gamma[id] != d.gamma[id] {
			t.Fatal("global permutation changed", id)
		}
	}
	bad := append([]uint64(nil), ids...)
	bad[0] = 99
	if _, err = RestoreDealerLayoutFromPayload(bad, a, b); err == nil {
		t.Fatal("foreign sample identity accepted")
	}
	if _, err = RestoreDealerLayoutFromPayload(ids, a, a); err == nil {
		t.Fatal("same party supplied twice")
	}
}
