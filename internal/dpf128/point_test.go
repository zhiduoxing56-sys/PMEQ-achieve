package dpf128

import (
	"testing"

	"pmeq/internal/anchorindex"
	"pmeq/internal/domain"
	"pmeq/internal/dpf128/internal/core"
)

func TestPointFromAnchorValueExactBytes(t *testing.T) {
	value := anchorindex.Value{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	if got := PointFromAnchorValue(value); got != Point(value) {
		t.Fatalf("point = %x, want exact bytes %x", got, value)
	}
}

func TestPointBitOrder(t *testing.T) {
	point := Point{0x80, 0x01}
	wantOne := map[int]bool{0: true, 15: true}
	for level := 0; level < core.Depth; level++ {
		want := domain.Bit(wantOne[level])
		if got := core.PointBit([16]byte(point), level); got != want {
			t.Fatalf("bit %d = %v, want %v", level, got, want)
		}
	}
}
