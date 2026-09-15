package dpf128

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"pmeq/internal/share"
)

func TestKeyHasNoExportedProtocolFields(t *testing.T) {
	typ := reflect.TypeOf(Key{})
	if typ.Kind() != reflect.Struct || typ.NumField() != 4 {
		t.Fatalf("opaque key shape = %v with %d fields", typ.Kind(), typ.NumField())
	}
	wantNames := []string{"rootSeed", "rootControl", "corrections", "finalCW"}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.IsExported() || field.Name != wantNames[i] {
			t.Fatalf("key field %d = %q exported=%v", i, field.Name, field.IsExported())
		}
	}
	correction := typ.Field(2).Type.Elem()
	wantCorrectionNames := []string{"seedCW", "tcwLeft", "tcwRight"}
	if correction.NumField() != len(wantCorrectionNames) {
		t.Fatalf("correction field count = %d", correction.NumField())
	}
	for i, name := range wantCorrectionNames {
		field := correction.Field(i)
		if field.IsExported() || field.Name != name {
			t.Fatalf("correction field %d = %q exported=%v", i, field.Name, field.IsExported())
		}
	}
}

func TestEvalSignatureIsSingleParty(t *testing.T) {
	typ := reflect.TypeOf(Eval)
	wantKey := reflect.TypeOf(Key{})
	wantPoint := reflect.TypeOf(Point{})
	wantOutput := reflect.TypeOf(share.BitShare{})
	if typ.NumIn() != 2 || typ.In(0) != wantKey || typ.In(1) != wantPoint {
		t.Fatalf("Eval inputs = %v, want one Key and one Point", typ)
	}
	if typ.NumOut() != 1 || typ.Out(0) != wantOutput {
		t.Fatalf("Eval output = %v, want one BitShare", typ)
	}
}

func TestEvaluationAPIInventory(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Dir(here)
	files, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			switch item := declaration.(type) {
			case *ast.GenDecl:
				for _, spec := range item.Specs {
					if named, ok := spec.(*ast.TypeSpec); ok && named.Name.IsExported() {
						got = append(got, "type:"+named.Name.Name)
					}
				}
			case *ast.FuncDecl:
				if item.Recv == nil && item.Name.IsExported() {
					got = append(got, "func:"+item.Name.Name)
				}
			}
		}
	}
	want := []string{"func:Eval", "func:PointFromAnchorValue", "type:Key", "type:Point"}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evaluation API mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestEvaluationImportsRemainMinimal(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Dir(here)
	allowed := map[string]bool{
		"pmeq/internal/anchorindex":          true,
		"pmeq/internal/dpf128/internal/core": true,
		"pmeq/internal/share":                true,
	}
	files, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			name := strings.Trim(imported.Path.Value, "\"")
			if !allowed[name] {
				t.Errorf("%s imports unexpected package %q", path, name)
			}
		}
	}
}

func TestNoProtocolStatePresentationMethods(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Dir(here)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if ok && fn.Recv != nil && (fn.Name.Name == "String" || fn.Name.Name == "GoString") {
				t.Errorf("protocol presentation method in %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
