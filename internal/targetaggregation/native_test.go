//go:build phase6native

package targetaggregation

import (
	"pmeq/internal/scmpnative"
	"testing"
)

func TestNativeFixedPairs(t *testing.T) {
	for _, r := range []int{1, 16} {
		for _, tau := range []int{0, r - 1} {
			for _, n := range []int{0, 1, 26} {
				runFixture(t, makeFixture(t, 2, r, n), tau, scmpnative.Backend{})
			}
		}
	}
}

func TestNativeCapacityPrefixes(t *testing.T) {
	for _, r := range []int{1, 16} {
		f := makeFixture(t, 2, r, 26)
		runFixtureCapacity(t, f, r-1, scmpnative.Backend{}, Shape{K: 3, R: r, S: f.shape.S + 128*r, G: f.shape.G + 2*r})
	}
}
