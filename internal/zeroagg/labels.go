package zeroagg

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// ShareCoordinates is trusted DO-only. Dummy coordinate -1 maps to zero;
// original object coordinate j maps to j+1. Every slot gets independent entropy.
func ShareCoordinates(coords []int, d int) ([]F, []F, error) {
	if d < 0 || d > 32768 || (d > 0 && d&(d-1) != 0) || len(coords) > 65536 || (d == 0 && len(coords) != 0) {
		return nil, nil, fmt.Errorf("unsupported public label shape")
	}
	a, b := make([]F, len(coords)), make([]F, len(coords))
	raw := make([]byte, 2*len(coords))
	defer clear(raw)
	if _, e := rand.Read(raw); e != nil {
		return nil, nil, e
	}
	for i, j := range coords {
		if j < -1 || j >= d {
			return nil, nil, fmt.Errorf("invalid DO coordinate")
		}
		a[i] = F(binary.LittleEndian.Uint16(raw[2*i:]))
		b[i] = a[i] ^ F(j+1)
	}
	return a, b, nil
}
