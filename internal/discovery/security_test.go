package discovery

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"pmeq/internal/anchorfilter"
	"strings"
	"sync"
	"testing"
)

func TestInvalidDomainRejectedBeforeState(t *testing.T) {
	for _, q := range []Query{{"abc", "abcd", 0, 0}, {"abcd", "abc", 0, 0}, {"abcd", "abcd", 1, 0}, {"abcd", "abcd", 0, 1}, {"abcd", "abcd", -1, 0}, {"abcd", "abcd", 0, -1}, {strings.Repeat("a", 60), "abcd", 0, 0}, {"abcd", strings.Repeat("a", 68), 0, 0}} {
		_, m, e := RunLocal(context.Background(), q, UserKeys{}, nil, [2]*Static{}, [2]*PartyPacket{}, nil)
		if e != ErrDomain || m.ServerBytes != 0 || m.LocalE2E != 0 {
			t.Fatal(q, e, m)
		}
	}
	for _, q := range []Query{{"abcd", "abcd", 0, 0}, {strings.Repeat("a", 56), strings.Repeat("b", 64), 13, 15}} {
		if e := Validate(q); e != nil {
			t.Fatal(e)
		}
	}
}
func TestCopiedPacketSingleClaim(t *testing.T) {
	g := &guard{}
	var wg sync.WaitGroup
	results := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- g.claim() }()
	}
	wg.Wait()
	close(results)
	n := 0
	for e := range results {
		if e == nil {
			n++
		}
	}
	if n != 1 {
		t.Fatal(n)
	}
}
func TestProductionBoundary(t *testing.T) {
	for _, name := range []string{"cloud.go", "local.go"} {
		f, e := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if s, ok := call.Fun.(*ast.SelectorExpr); ok {
					switch s.Sel.Name {
					case "Preprocess", "PreprocessComparison", "PreprocessCompaction", "PreprocessPermutation", "GeneratePayload", "KeyGen", "Build", "ComposeHits", "BatchAND", "SplitBit", "SplitRing64":
						t.Error("online dealer call", name, s.Sel.Name)
					}
				}
			}
			return true
		})
	}
	b, e := os.ReadFile("cloud.go")
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"candidatequery.Recover", "CombineScalarShare", "FullEval", "os.", "oracle", "UserKeys", "*UserPacket"} {
		if strings.Contains(string(b), bad) {
			t.Fatal("cloud forbidden", bad)
		}
	}
}

type unreachableBackend struct{ anchorfilter.SCMPBackend }

func TestZeroConfigurationFailsClosed(t *testing.T) {
	_, m, e := RunLocal(context.Background(), Query{Anchor: "abcd", Target: "abcd"}, UserKeys{}, &UserPacket{}, [2]*Static{{}, {}}, [2]*PartyPacket{{}, {}}, unreachableBackend{})
	if e != ErrBinding || m.LocalE2E != 0 {
		t.Fatal("zero configuration", e, m)
	}
}

func TestCloudLauncherHasOnlyOwnState(t *testing.T) {
	f, e := parser.ParseFile(token.NewFileSet(), "local.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		g, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}
		fn, ok := g.Call.Fun.(*ast.FuncLit)
		if !ok || len(fn.Type.Params.List) == 0 || fn.Type.Params.List[0].Names[0].Name != "party" {
			return true
		}
		found = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				switch id.Name {
				case "statics", "packets", "tokens", "results", "keys", "u":
					t.Error("cloud launcher captures coordinator state", id.Name)
				}
			}
			return true
		})
		directions := map[string]ast.ChanDir{"outgoing": ast.SEND, "incoming": ast.RECV, "sink": ast.SEND}
		for _, field := range fn.Type.Params.List {
			for _, name := range field.Names {
				if dir, ok := directions[name.Name]; ok {
					ch, ok := field.Type.(*ast.ChanType)
					if !ok || ch.Dir != dir {
						t.Error("endpoint direction", name.Name)
					}
					delete(directions, name.Name)
				}
			}
		}
		if len(directions) != 0 {
			t.Fatal("missing directional endpoints")
		}
		return true
	})
	if !found {
		t.Fatal("cloud launcher missing")
	}
}
