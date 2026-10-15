package gen

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"pmeq/internal/indexbuild"
	"testing"
)

func TestBuildRealSidecars(t *testing.T) {
	if os.Getenv("PMEQ_TARGET_SIDECARS") != "1" {
		t.Skip("offline full-data generation opt-in")
	}
	root := "../../.."
	src := filepath.Join(root, "artifacts/phase7b")
	dst := filepath.Join(root, "artifacts/phase10b")
	m, e := os.ReadFile(filepath.Join(src, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	var files [2][]byte
	for u, name := range []string{"cs0.psmj.bin", "cs1.psmj.bin"} {
		files[u], e = os.ReadFile(filepath.Join(src, name))
		if e != nil {
			t.Fatal(e)
		}
	}
	f, e := os.Open("/home/tenggn/projects/new-pmeq/data/musicbrainz/20260905-002519/area_tables/mbdump/area_alias")
	if e != nil {
		t.Fatal(e)
	}
	aliases, e := indexbuild.LoadAreaAlias(f, 0)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(dst, 0700); e != nil {
		t.Fatal(e)
	}
	a, e := os.OpenFile(filepath.Join(dst, "cs0.aggregation.bin"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := os.OpenFile(filepath.Join(dst, "cs1.aggregation.bin"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	out, audit, e := Build(m, files, aliases, [2]io.Writer{a, b})
	if e != nil {
		t.Fatal(e)
	}
	if audit.MaxAliases != 26 || audit.MaxMultiplicity != 3 || audit.ShortRecords != 4047 || audit.CheckedBuckets != 65536 || audit.CheckedGroups != 310331 || audit.CheckedPhysicalSlots != 1317260 || audit.Errors != 0 {
		t.Fatalf("audit %+v", audit)
	}
	for name, v := range map[string]any{"manifest.json": out, "build-audit.json": audit} {
		raw, e := json.MarshalIndent(v, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dst, name), append(raw, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
	t.Logf("AUDIT %+v MANIFEST %+v", audit, out)
}
