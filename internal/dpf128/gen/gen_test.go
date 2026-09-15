package gen

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"pmeq/internal/domain"
	"pmeq/internal/dpf128"
	"pmeq/internal/dpf128/internal/core"
)

var errEntropy = errors.New("test entropy failure")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errEntropy }

type shortReader struct {
	done bool
}

func (r *shortReader) Read(buffer []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	n := 15
	for i := 0; i < n && i < len(buffer); i++ {
		buffer[i] = byte(i)
	}
	return n, nil
}

func TestGenImmediateRandomFailure(t *testing.T) {
	if _, _, err := genWithReader(dpf128.Point{}, failingReader{}); !errors.Is(err, errEntropy) {
		t.Fatalf("error = %v, want entropy failure", err)
	}
}

func TestGenShortReadFailure(t *testing.T) {
	if _, _, err := genWithReader(dpf128.Point{}, &shortReader{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want unexpected EOF", err)
	}
}

func TestGenFreshnessRegression(t *testing.T) {
	alpha := dpf128.Point{0x7f}
	key0, key1, err := Gen(alpha)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 15; i++ {
		next0, next1, err := Gen(alpha)
		if err != nil {
			t.Fatal(err)
		}
		if next0 == key0 && next1 == key1 {
			t.Fatal("production key generation repeated both keys")
		}
		key0, key1 = next0, next1
	}
}

func TestDPFRandomPoints(t *testing.T) {
	const cases = 100_000
	for i := 0; i < cases; i++ {
		alpha := derivedPoint("alpha", i)
		root0 := core.Seed(derivedPoint("root0", i))
		root1 := core.Seed(derivedPoint("root1", i))
		key0, key1, err := genWithRootSeeds(alpha, root0, root1)
		if err != nil {
			t.Fatal(err)
		}
		if got := combine(key0, key1, alpha); got != domain.BitOne {
			t.Fatalf("case %d match = %v, want 1", i, got)
		}
		off := alpha
		off[i%len(off)] ^= byte(1 << (i % 8))
		if got := combine(key0, key1, off); got != domain.BitZero {
			t.Fatalf("case %d non-match = %v, want 0", i, got)
		}
	}
}

func derivedPoint(label string, counter int) (point dpf128.Point) {
	prefix := []byte(label)
	input := make([]byte, len(prefix)+8)
	copy(input, prefix)
	value := counter
	for i := 0; i < 8; i++ {
		input[len(prefix)+7-i] = byte(value)
		value >>= 8
	}
	digest := sha256.Sum256(input)
	copy(point[:], digest[:16])
	return point
}

func combine(key0, key1 dpf128.Key, point dpf128.Point) domain.Bit {
	return dpf128.Eval(key0, point).Value().Add(dpf128.Eval(key1, point).Value())
}

func TestReaderConsumesTwoCompleteSeeds(t *testing.T) {
	material := bytes.Repeat([]byte{0x5a}, 32)
	if _, _, err := genWithReader(dpf128.Point{}, bytes.NewReader(material)); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratorAPIAndEntropyBoundary(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(here), "gen.go")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(source), "rand.Reader") != 1 || strings.Count(string(source), "io.ReadFull") != 2 {
		t.Fatal("generator entropy boundary changed")
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var exported []string
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv == nil && function.Name.IsExported() {
			exported = append(exported, function.Name.Name)
		}
	}
	sort.Strings(exported)
	if !reflect.DeepEqual(exported, []string{"Gen"}) {
		t.Fatalf("generator API = %v, want only Gen", exported)
	}
}
