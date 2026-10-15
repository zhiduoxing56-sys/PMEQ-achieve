package imdbowner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"pmeq/internal/imdbkeys"
	"pmeq/internal/imdbprod"
)

func TestGuardedAnchorBuildStopsBeforeCreatingArtifacts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "production")
	blocked := errors.New("resource floor failed")
	gate := Preflight{Mapping: &imdbprod.Mapping{}, Keys: imdbkeys.Pair{Fingerprint: "identity"}}
	checks := 0
	_, err := BuildAnchorStageGuarded(root, gate, func() error {
		checks++
		return blocked
	})
	if !errors.Is(err, blocked) || checks != 1 {
		t.Fatalf("resource check not enforced: checks=%d err=%v", checks, err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("denied build created artifacts: %v", err)
	}
}
