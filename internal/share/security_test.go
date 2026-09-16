package share

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

	"pmeq/internal/domain"
)

func TestSinglePartyShareStructure(t *testing.T) {
	types := []struct {
		name string
		typ  reflect.Type
		want reflect.Type
	}{
		{"BitShare", reflect.TypeOf(BitShare{}), reflect.TypeOf(domain.BitZero)},
		{"Ring32Share", reflect.TypeOf(Ring32Share{}), reflect.TypeOf(domain.Ring32(0))},
		{"Ring64Share", reflect.TypeOf(Ring64Share{}), reflect.TypeOf(domain.Ring64(0))},
	}
	for _, tc := range types {
		if tc.typ.NumField() != 1 {
			t.Fatalf("%s has %d fields, want exactly one", tc.name, tc.typ.NumField())
		}
		field := tc.typ.Field(0)
		if field.Name != "value" || field.IsExported() || field.Type != tc.want {
			t.Fatalf("%s field = %s exported=%v type=%v", tc.name, field.Name, field.IsExported(), field.Type)
		}
	}
}

func TestProductionImportBoundary(t *testing.T) {
	root := internalRoot(t)
	allowed := map[string]map[string]bool{
		"domain": {},
		"share":  {"pmeq/internal/domain": true},
		"preprocess": {
			"crypto/rand":          true,
			"encoding/binary":      true,
			"io":                   true,
			"pmeq/internal/domain": true,
			"pmeq/internal/share":  true,
		},
		"reconstruct": {
			"pmeq/internal/domain": true,
			"pmeq/internal/share":  true,
		},
	}
	for pkg, imports := range allowed {
		files, err := filepath.Glob(filepath.Join(root, pkg, "*.go"))
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
			for _, spec := range file.Imports {
				name := strings.Trim(spec.Path.Value, "\"")
				if !imports[name] {
					t.Errorf("%s imports unexpected package %q", path, name)
				}
			}
		}
	}
}

func TestExportedShareAPIInventory(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	files, err := filepath.Glob(filepath.Join(filepath.Dir(here), "*.go"))
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
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if ts, ok := spec.(*ast.TypeSpec); ok && ts.Name.IsExported() {
						got = append(got, "type:"+ts.Name.Name)
					}
				}
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				if d.Recv == nil {
					got = append(got, "func:"+d.Name.Name)
					continue
				}
				recv := receiverName(d.Recv.List[0].Type)
				got = append(got, "method:"+recv+"."+d.Name.Name)
			}
		}
	}
	want := []string{
		"func:LocalAddBit", "func:LocalAddRing32", "func:LocalAddRing64",
		"func:LocalSubBit", "func:LocalSubRing32", "func:LocalSubRing64",
		"func:NewBitShare", "func:NewRing32Share", "func:NewRing64Share",
		"method:BitShare.Value", "method:Ring32Share.Value", "method:Ring64Share.Value",
		"type:BitShare", "type:Ring32Share", "type:Ring64Share",
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exported API mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestShareProductionStructsArePartyLocal(t *testing.T) {
	root := internalRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "share", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			st, ok := node.(*ast.StructType)
			if !ok {
				return true
			}
			if len(st.Fields.List) != 1 {
				t.Errorf("share struct in %s has %d fields, want one party-local value", path, len(st.Fields.List))
			}
			return true
		})
	}
}

func TestPreprocessEntropyAPIInventory(t *testing.T) {
	path := filepath.Join(internalRoot(t), "preprocess", "split.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if strings.Count(text, "rand.Reader") != 3 {
		t.Fatalf("production entropy entry count = %d, want 3", strings.Count(text, "rand.Reader"))
	}
	if strings.Count(text, "io.ReadFull") != 3 {
		t.Fatalf("complete entropy read count = %d, want 3", strings.Count(text, "io.ReadFull"))
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var functions []string
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			functions = append(functions, fn.Name.Name)
		}
	}
	want := []string{
		"SplitBit", "SplitRing32", "SplitRing64",
		"splitBitWithReader", "splitRing32WithReader", "splitRing64WithReader",
	}
	sort.Strings(functions)
	sort.Strings(want)
	if !reflect.DeepEqual(functions, want) {
		t.Fatalf("preprocess function inventory mismatch\n got: %v\nwant: %v", functions, want)
	}
}

func receiverName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return "?"
}

func internalRoot(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	return filepath.Dir(filepath.Dir(here))
}
