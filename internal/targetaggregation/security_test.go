package targetaggregation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestProductionCloudBoundary(t *testing.T) {
	// Inspect the online source separately from trusted preprocessing/gen.
	f, e := parser.ParseFile(token.NewFileSet(), "protocol.go", nil, 0)
	must(t, e)
	for _, i := range f.Imports {
		p, e := strconv.Unquote(i.Path.Value)
		must(t, e)
		if p == "os" || p == "log" || p == "fmt" || strings.Contains(p, "/gen") || strings.Contains(p, "/reconstruct") || strings.Contains(p, "/indexbuild") || strings.Contains(p, "/targetcrypto") {
			t.Fatal("online forbidden dependency", p)
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if x, ok := n.(*ast.CallExpr); ok {
			if s, ok := x.Fun.(*ast.SelectorExpr); ok {
				if strings.HasPrefix(s.Sel.Name, "Preprocess") || strings.HasPrefix(s.Sel.Name, "Split") || s.Sel.Name == "KeyGen" {
					t.Error("online preprocessing", s.Sel.Name)
				}
			}
		}
		return true
	})
	typ := reflect.TypeOf(CandidatePairShares{})
	want := []string{"Manifest", "LayoutID", "CompactionID", "QueryID", "K", "DTarget", "PairKeepShares", "AnchorIDShares", "TargetIDShares"}
	if typ.NumField() != len(want) {
		t.Fatal("output field count")
	}
	for i, n := range want {
		if typ.Field(i).Name != n {
			t.Fatal("output field", i)
		}
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(PartySidecar{}), reflect.TypeOf(Packet{}), reflect.TypeOf(bucket{})} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.PkgPath == "" {
				t.Error("exported party state", typ, f.Name)
			}
			for _, bad := range []string{"join", "alias", "ordinal", "peer", "raw", "gamma"} {
				if strings.Contains(strings.ToLower(f.Name), bad) {
					t.Error("forbidden state field", typ, f.Name)
				}
			}
		}
	}
	defaultAudit, e := os.ReadFile("audit_off.go")
	must(t, e)
	if strings.Contains(string(defaultAudit), "auditSink") || strings.Contains(string(defaultAudit), "SetAudit") {
		t.Fatal("production audit sink")
	}
}

func TestMixedTranscriptFailsClosed(t *testing.T) {
	f := makeFixture(t, 1, 1, 1)
	u, p, _, _, e := Preprocess(f.lineage, f.shape, oracleBackend{})
	must(t, e)
	tok, e := u.Token(f.hits[0].QueryID, 0)
	must(t, e)
	_, _, e = Run(f.side[0], f.hits[0], f.groups[0], p, tok, oracleBackend{}, func(m []byte) ([]byte, error) {
		peer := append([]byte(nil), m...)
		peer[36] = 1
		peer[0] ^= 1
		return peer, nil
	})
	if e == nil {
		t.Fatal("wrong binding accepted")
	}
}
