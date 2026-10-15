//go:build phase6native

package discovery

import (
	"pmeq/internal/scmpnative"
	"testing"
)

func TestRestoredNestedMaterialsRunTwoCloudProtocolNative(t *testing.T) {
	runRestoredNestedMaterials(t, scmpnative.Backend{})
}
