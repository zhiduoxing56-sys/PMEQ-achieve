//go:build phase6native

package targetposition

import (
	"pmeq/internal/scmpnative"
	"testing"
)

func TestNativePositionBoundsAndComposition(t *testing.T) {
	testBounds(t, scmpnative.Backend{})
	testComposition(t, scmpnative.Backend{})
}
