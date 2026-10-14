// Package dpf128 implements local evaluation of the frozen 128-bit Anchor DPF.
package dpf128

import "pmeq/internal/anchorindex"

// Point is the DPF's exact 128-bit input path.
type Point [16]byte

// PointFromAnchorValue copies an Anchor value without integer interpretation,
// hashing, truncation, or byte-order transformation.
func PointFromAnchorValue(value anchorindex.Value) Point {
	return Point(value)
}
