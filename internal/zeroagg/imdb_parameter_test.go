package zeroagg

import (
	"bytes"
	"testing"
)

func TestIMDbNewOperatorDuplicateAndDummyLabels(t *testing.T) {
	coords := []int{0, 0, 1, -1, 2, 1, 3, -1}
	for mask := 0; mask < 256; mask++ {
		l, k, e := ShareCoordinates(coords, 4)
		if e != nil {
			t.Fatal(e)
		}
		x, y := make([]F, len(coords)), make([]F, len(coords))
		want := []byte{0}
		for i, j := range coords {
			x[i] = F(0xb7b0 + i)
			hit := F((mask >> i) & 1)
			y[i] = x[i] ^ hit
			if j >= 0 && hit != 0 {
				want[0] |= 1 << j
			}
		}
		a, b, _ := Prepare(len(coords), 4)
		channels := [2]chan []byte{make(chan []byte, 1), make(chan []byte, 1)}
		out := make(chan []byte, 2)
		for id, p := range []*Party{a, b} {
			go func(id int, p *Party) {
				p.Bind(func(v []byte) []byte { channels[id] <- v; return <-channels[1-id] })
				if id == 0 {
					out <- p.Aggregate(x, l)
				} else {
					out <- p.Aggregate(y, k)
				}
			}(id, p)
		}
		u, v := <-out, <-out
		for i := range u {
			u[i] ^= v[i]
		}
		if !bytes.Equal(u, want) {
			t.Fatal("new OR differs from source objects", mask, u, want)
		}
		if a.GatesUsed() != a.TotalGates() || b.GatesUsed() != b.TotalGates() {
			t.Fatal("one-use material accounting")
		}
	}
	for _, coords := range [][]int{{-2}, {4}} {
		if _, _, e := ShareCoordinates(coords, 4); e == nil {
			t.Fatal("out of range label accepted")
		}
	}
	t.Log("256 real shared zero-aggregation cases; duplicate roots and dummy hits verified")
}
