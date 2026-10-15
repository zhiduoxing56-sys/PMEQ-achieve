package aggregation

import (
	"fmt"
	"testing"

	"pmeq/internal/incidence"
)

func TestRestoreDealerActualDomain(t *testing.T) {
	for _, n := range []int{0, 1, 7, 257, CandidateCount} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			ids := make([]uint64, n)
			for i := range ids {
				ids[i] = 1<<40 + uint64(i)*17
			}
			d, e := RestoreDealerLayout([16]byte{1}, ids)
			must(t, e)
			if d.N != n || len(d.gamma) != n {
				t.Fatal("domain", d.N)
			}
			for i, id := range ids {
				if d.gamma[id] != uint32(i) {
					t.Fatal("coordinate", i)
				}
			}
		})
	}
	if _, e := RestoreDealerLayout([16]byte{}, []uint64{1}); e == nil {
		t.Fatal("zero layout")
	}
	if _, e := RestoreDealerLayout([16]byte{1}, []uint64{9, 9}); e == nil {
		t.Fatal("duplicate ID")
	}
}

func TestAlignmentActualDomain(t *testing.T) {
	for _, n := range []int{4, 17, 65} {
		ids := make([]uint64, n)
		for i := range ids {
			ids[i] = 1000 + uint64(i)*19
		}
		d, e := RestoreDealerLayout([16]byte{1}, ids)
		must(t, e)
		posts := []incidence.Posting{{RecordID: ids[0], Real: true}, {RecordID: ids[n-1], Real: true}, {}}
		local, e := incidence.PrepareLayout(posts)
		must(t, e)
		a, b, e := d.Alignment(9, local, posts)
		must(t, e)
		if b.GlobalRecords() != n {
			t.Fatal("alignment N")
		}
		p, q, e := PreprocessPermutation(a, b)
		must(t, e)
		if len(p.a2) != n || len(q.a1) != n {
			t.Fatal("offline N")
		}
		x, y := make([]incidence.Share, local.D), make([]incidence.Share, local.D)
		for i := range x {
			x[i], y[i], e = incidence.Split(0)
			must(t, e)
		}
		want := make([]incidence.Z128, n)
		for slot, value := range []incidence.Z128{2, 3} {
			x[local.Coordinates[slot]], y[local.Coordinates[slot]], e = incidence.Split(value)
			must(t, e)
			want[d.gamma[posts[slot].RecordID]] = value
		}
		m1, e := q.Message1(y)
		must(t, e)
		m2, z0, e := a.Message2(p, x, m1)
		must(t, e)
		z1, e := b.Finish(q, m2)
		must(t, e)
		if len(m1) != n || len(m2) != n || len(z0) != n || len(z1) != n {
			t.Fatal("online N")
		}
		for i := range want {
			if z0[i].Value().Add(z1[i].Value()) != want[i] {
				t.Fatal("alignment", n, i)
			}
		}
		count := NewCount(d.LayoutID, n)
		must(t, count.Add(d.LayoutID, z0))
		if len(count.Values()) != n || count.Add(d.LayoutID, z0[:n-1]) == nil {
			t.Fatal("count domain")
		}
		if _, e := b.Finish(q, m2); e == nil {
			t.Fatal("reused alignment")
		}
	}
}
