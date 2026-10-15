//go:build phase6native

package discovery

import (
	"pmeq/internal/scmpnative"
	"testing"
)

func TestIntegratedActualDomainNative(t *testing.T) {
	for _, n := range []int{1, 7, 65} {
		for _, present := range []bool{false, true} {
			runDomainFixture(t, newDomainFixture(t, n, present), scmpnative.Backend{})
		}
	}
}

// Reuse the existing million-record exact-K verification without its file
// writer or experiment loop. Every selected ID/scalar/bucket is checked by it.
func TestExistingMillionCompactionDomain(t *testing.T) {
	s := scaleRun(1000000, "exact_k", "median", scaleProfile{}, 7, 10)
	if s.Status != "ok" || s.N != 1000000 || s.K != 7 || s.Rounds != ([2]uint32{3, 3}) {
		t.Fatal(s)
	}
}
