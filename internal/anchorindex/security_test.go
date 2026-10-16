package anchorindex

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("injected entropy failure")
}

func TestNewKeyAndEncodeRejectZeroKey(t *testing.T) {
	if _, err := NewKey([32]byte{}); !errors.Is(err, errZeroKey) {
		t.Fatalf("NewKey error = %v, want %v", err, errZeroKey)
	}
	if _, err := Encode(Key{}, "test"); !errors.Is(err, errZeroKey) {
		t.Fatalf("Encode error = %v, want %v", err, errZeroKey)
	}
}

func TestGenerateKeyImmediateReaderFailure(t *testing.T) {
	if key, err := generateKeyWithReader(failingReader{}); err == nil || key != (Key{}) {
		t.Fatalf("failed entropy read returned key=%v error=%v", key.valid(), err)
	}
}

func TestGenerateKeyShortReaderFailure(t *testing.T) {
	if key, err := generateKeyWithReader(bytes.NewReader(make([]byte, 31))); err == nil || key != (Key{}) {
		t.Fatalf("short entropy read returned key=%v error=%v", key.valid(), err)
	}
}

func TestGenerateKeyFreshnessWiringRegression(t *testing.T) {
	first, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	changed := false
	for i := 0; i < 8; i++ {
		next, err := GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		changed = changed || next != first
	}
	if !changed {
		t.Fatal("GenerateKey returned a fixed value across all attempts")
	}
	// This is an RNG wiring regression, not a statistical security proof.
}

func TestKeyAndValueAreFixedWidthByteArrays(t *testing.T) {
	keyType := reflect.TypeOf(Key{})
	valueType := reflect.TypeOf(Value{})
	if keyType.Kind() != reflect.Array || keyType.Len() != 32 || keyType.Elem().Kind() != reflect.Uint8 {
		t.Fatal("Key is not an exact 32-byte array")
	}
	if valueType.Kind() != reflect.Array || valueType.Len() != 16 || valueType.Elem().Kind() != reflect.Uint8 {
		t.Fatal("Value is not an exact 16-byte array")
	}
}

func TestKeyDoesNotImplementFormattingInterfaces(t *testing.T) {
	keyType := reflect.TypeOf(Key{})
	if keyType.Implements(reflect.TypeOf((*fmt.Stringer)(nil)).Elem()) {
		t.Fatal("Key implements a formatting interface")
	}
	if keyType.Implements(reflect.TypeOf((*fmt.GoStringer)(nil)).Elem()) {
		t.Fatal("Key implements a Go formatting interface")
	}
}

func TestAnchorIndexExportedAPIInventory(t *testing.T) {
	dir := packageDirectory(t)
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
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
				if item.Name.IsExported() {
					if item.Recv == nil {
						got = append(got, "func:"+item.Name.Name)
					} else {
						got = append(got, "method:"+item.Name.Name)
					}
				}
			}
		}
	}
	want := []string{"func:Encode", "func:EncodeMovie", "func:EncodeMovieTitle", "func:GenerateKey", "func:NewKey", "type:Key", "type:Value"}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exported API mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestAnchorIndexProductionImportBoundary(t *testing.T) {
	allowed := map[string]bool{
		"crypto/hmac":     true,
		"crypto/rand":     true,
		"crypto/sha256":   true,
		"encoding/binary": true,
		"errors":          true,
		"io":              true,
		"unicode/utf8":    true,
	}
	files, err := filepath.Glob(filepath.Join(packageDirectory(t), "*.go"))
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
			if !allowed[name] {
				t.Errorf("%s imports unexpected package %q", filepath.Base(path), name)
			}
		}
	}
}

func packageDirectory(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate package source")
	}
	return filepath.Dir(here)
}
