package targetaggregation

import (
	"pmeq/internal/targetpe"
	"testing"
)

func TestPreprocessActualDomain(t *testing.T) {
	for _, n := range []int{0, 1, 7, 120071, 1000000} {
		for _, k := range []int{0, min(n, 2)} {
			shape := Shape{K: k, R: 1}
			l := targetpe.AlignmentLineage{IndexID: [16]byte{1}, LayoutID: [16]byte{2}, N: n}
			u, a, b, cost, e := Preprocess(l, shape, oracleBackend{})
			must(t, e)
			if a.lineage.N != n || b.lineage.N != n || a.shape.K != k || u.shape.K != k {
				t.Fatal("domain binding")
			}
			if cost.Z128 != uint64(6*k*26) {
				t.Fatal("capacity accounting")
			}
		}
		if (Shape{K: n, R: 1}).validate(n) != nil {
			t.Fatal("K=N")
		}
		if (Shape{K: n + 1, R: 1}).validate(n) == nil {
			t.Fatal("K>N")
		}
		l := targetpe.AlignmentLineage{IndexID: [16]byte{1}, LayoutID: [16]byte{2}, N: n}
		if _, _, _, _, e := Preprocess(l, Shape{K: n + 1, R: 1}, oracleBackend{}); e == nil {
			t.Fatal("preprocess K>N")
		}
	}
	if (Shape{R: 1}).validate(-1) == nil {
		t.Fatal("negative domain")
	}
}
