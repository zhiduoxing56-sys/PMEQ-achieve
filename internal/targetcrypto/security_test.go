package targetcrypto

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// errReader fails every read, so that a missing random source cannot be
// mistaken for success.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

var errRandomSource = errors.New("test: random source unavailable")

// forbiddenMethodPrefixes are the single-party-visible entry points that must
// never exist on a share type. `CanonicalBytes` is not on this list: a party
// must be able to serialize its own share.
var forbiddenMethodPrefixes = []string{
	"Recover", "Open", "Reveal", "Peer", "Secret", "Decode", "Unmarshal",
	"String", "GoString", "Marshal", "Format",
}

// TestShareTypesHoldOnlyOneLocalValue is the structural single-party audit. The
// repository policy forbids production struct declarations outside the
// foundational share package, so every party-local share here is a scalar value
// type holding exactly one local value and nothing composite.
func TestShareTypesHoldOnlyOneLocalValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  reflect.Type
		kind reflect.Kind
		size uintptr
	}{
		{"ScalarShare", reflect.TypeOf(ScalarShare{}), reflect.Array, 32},
		{"PointShare", reflect.TypeOf(PointShare{}), reflect.Array, 32},
		{"BucketShare", reflect.TypeOf(BucketShare(0)), reflect.Uint16, 2},
	} {
		if tc.typ.Kind() != tc.kind {
			t.Fatalf("%s kind = %v, want %v", tc.name, tc.typ.Kind(), tc.kind)
		}
		if tc.typ.Size() != tc.size {
			t.Fatalf("%s size = %d, want %d", tc.name, tc.typ.Size(), tc.size)
		}
		if tc.typ.Kind() == reflect.Array {
			if tc.typ.Elem().Kind() != reflect.Uint8 {
				t.Fatalf("%s element kind = %v, want uint8", tc.name, tc.typ.Elem().Kind())
			}
		}
		if tc.typ == reflect.TypeOf(MasterKey{}) {
			t.Fatalf("%s must not be a master key", tc.name)
		}
	}
}

// TestPackageDeclaresNoStructType mirrors the repository-wide policy enforced
// by the foundational share package: production share types are plain value
// types, so no single type can grow a second party's state.
func TestPackageDeclaresNoStructType(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if _, ok := node.(*ast.StructType); ok {
				t.Errorf("production struct declaration found in %s", path)
			}
			return true
		})
	}
}

// TestShareTypesExposeNoSecretEntryPoint enumerates the exported method set of
// every share type and rejects any reconstruction, opening, or formatting entry
// point.
func TestShareTypesExposeNoSecretEntryPoint(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  reflect.Type
	}{
		{"ScalarShare", reflect.TypeOf(ScalarShare{})},
		{"PointShare", reflect.TypeOf(PointShare{})},
		{"BucketShare", reflect.TypeOf(BucketShare(0))},
		{"MasterKey", reflect.TypeOf(MasterKey{})},
	} {
		for i := 0; i < tc.typ.NumMethod(); i++ {
			name := tc.typ.Method(i).Name
			for _, prefix := range forbiddenMethodPrefixes {
				if strings.HasPrefix(name, prefix) {
					t.Fatalf("%s exposes forbidden method %q", tc.name, name)
				}
			}
		}
	}
}

// TestBucketShareHoldsOnlyItsOwnShare checks that a bucket share never carries
// the peer share or a full component above its declared width.
func TestBucketShareHoldsOnlyItsOwnShare(t *testing.T) {
	for k := MinBucketBits; k <= MaxBucketBits; k++ {
		full := BucketComponent(0xFFFF & ((1 << uint(k)) - 1))
		left, right, err := SplitBucketComponent(full, k)
		if err != nil {
			t.Fatalf("k=%d: SplitBucketComponent: %v", k, err)
		}
		mask := uint16(1)<<uint(k) - 1
		if uint16(left.Value())&^mask != 0 || uint16(right.Value())&^mask != 0 {
			t.Fatalf("k=%d: a share carries bits above its width", k)
		}
		if left.Value()^right.Value() != full {
			t.Fatalf("k=%d: shares do not XOR to the component", k)
		}
	}
}

// TestBucketComponentWidths checks that every supported width produces a value
// inside its own space and that the prefix is taken in MSB-first order.
func TestBucketComponentWidths(t *testing.T) {
	digest := []byte{0xF3, 0x5C, 0x00, 0x00}
	for _, tc := range []struct {
		k    int
		want BucketComponent
	}{
		{1, 1}, {2, 3}, {3, 7}, {4, 15},
		{5, 0x1E}, {6, 0x3C}, {7, 0x79}, {8, 0xF3},
		{9, 0x1E6}, {10, 0x3CD}, {11, 0x79A}, {12, 0xF35},
		{13, 0x1E6B}, {14, 0x3CD7}, {15, 0x79AE}, {16, 0xF35C},
	} {
		if got := prefixBits(digest, tc.k); got != tc.want {
			t.Fatalf("k=%d: prefixBits = %#x, want %#x", tc.k, uint16(got), uint16(tc.want))
		}
	}
}

// TestBucketWidthBounds rejects widths outside the supported range.
func TestBucketWidthBounds(t *testing.T) {
	key, err := NewMasterKey(katMasterKey)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	for _, k := range []int{-1, 0, MaxBucketBits + 1, 64} {
		if _, err := JoinBucketComponent(key, 42, k); !errors.Is(err, ErrBucketBits) {
			t.Fatalf("k=%d: expected ErrBucketBits, got %v", k, err)
		}
		if _, err := WordBucketComponent(key, "area", k); !errors.Is(err, ErrBucketBits) {
			t.Fatalf("k=%d: expected ErrBucketBits, got %v", k, err)
		}
		if _, _, err := SplitBucketComponent(0, k); !errors.Is(err, ErrBucketBits) {
			t.Fatalf("k=%d: expected ErrBucketBits, got %v", k, err)
		}
	}
}

// TestZeroMasterKeyRejected locks the "unset key must not reach production"
// rule.
func TestZeroMasterKeyRejected(t *testing.T) {
	if _, err := NewMasterKey([32]byte{}); !errors.Is(err, errZeroMasterKey) {
		t.Fatalf("all-zero master key must be rejected, got %v", err)
	}
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	if key == (MasterKey{}) {
		t.Fatalf("GenerateMasterKey must not return the zero key")
	}
}

// TestRandomSourceFailurePropagates checks that a failing random source is
// reported and never silently replaced by a degenerate split.
func TestRandomSourceFailurePropagates(t *testing.T) {
	failing := errReader{err: errRandomSource}

	if _, err := generateMasterKeyWithReader(failing); !errors.Is(err, errRandomSource) {
		t.Fatalf("generateMasterKeyWithReader: got %v, want the reader error", err)
	}

	secret, err := KJoin(MasterKey(katMasterKey), 42)
	if err != nil {
		t.Fatalf("KJoin: %v", err)
	}
	if _, _, err := splitScalarWithReader(failing, secret); !errors.Is(err, errRandomSource) {
		t.Fatalf("splitScalarWithReader: got %v, want the reader error", err)
	}

	target := FullEval(secret)
	if _, _, err := splitPointWithReader(failing, target); !errors.Is(err, errRandomSource) {
		t.Fatalf("splitPointWithReader: got %v, want the reader error", err)
	}

	if _, _, err := splitBucketComponentWithReader(failing, 0, 8); !errors.Is(err, errRandomSource) {
		t.Fatalf("splitBucketComponentWithReader: got %v, want the reader error", err)
	}
}

// TestPartialRandomSourceFailurePropagates checks that a source that fails
// partway through a read is also reported.
func TestPartialRandomSourceFailurePropagates(t *testing.T) {
	secret, err := KJoin(MasterKey(katMasterKey), 42)
	if err != nil {
		t.Fatalf("KJoin: %v", err)
	}
	partial := io.MultiReader(io.LimitReader(bytes.NewReader(make([]byte, 128)), 10), errReader{err: errRandomSource})
	if _, _, err := splitScalarWithReader(partial, secret); !errors.Is(err, errRandomSource) {
		t.Fatalf("partial read failure must propagate, got %v", err)
	}
}

// TestSplitFreshness checks that repeated splits of the same secret produce
// independent shares. A deterministic or reused share would let one cloud link
// posting occurrences of the same record.
func TestSplitFreshness(t *testing.T) {
	secret, err := KJoin(MasterKey(katMasterKey), 42)
	if err != nil {
		t.Fatalf("KJoin: %v", err)
	}
	target := FullEval(secret)

	seenScalar := map[[32]byte]bool{}
	seenPoint := map[[32]byte]bool{}
	seenBucket := map[BucketComponent]bool{}

	// Scalar and point shares live in a 2^252 space, so byte-level uniqueness is
	// expected. Bucket shares live in a 2^16 space, so the check there is that
	// the draws are spread rather than repeated.
	const draws = 256
	for i := 0; i < draws; i++ {
		scalarLeft, _, err := SplitScalar(secret)
		if err != nil {
			t.Fatalf("SplitScalar: %v", err)
		}
		if key := scalarLeft.CanonicalBytes(); seenScalar[key] {
			t.Fatalf("SplitScalar reused a party-local share")
		} else {
			seenScalar[key] = true
		}

		pointLeft, _, err := SplitPoint(target)
		if err != nil {
			t.Fatalf("SplitPoint: %v", err)
		}
		if key := pointLeft.CanonicalBytes(); seenPoint[key] {
			t.Fatalf("SplitPoint reused a party-local share")
		} else {
			seenPoint[key] = true
		}

		bucketLeft, _, err := SplitBucketComponent(0, MaxBucketBits)
		if err != nil {
			t.Fatalf("SplitBucketComponent: %v", err)
		}
		seenBucket[bucketLeft.Value()] = true
	}
	if len(seenBucket) < draws-16 {
		t.Fatalf("SplitBucketComponent produced only %d distinct shares over %d draws", len(seenBucket), draws)
	}
}

// TestCanonicalWordRejectsInvalidQGram checks the q-gram contract.
func TestCanonicalWordRejectsInvalidQGram(t *testing.T) {
	invalidUTF8 := string([]byte{0xff, 0xfe, 0xfd, 0xfc})
	if _, err := CanonicalWord(wordScalarDomain, invalidUTF8); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("invalid UTF-8 must be rejected, got %v", err)
	}
	for _, qgram := range []string{"", "a", "ab", "abc", "abcde", "中文", "中文字"} {
		if _, err := CanonicalWord(wordScalarDomain, qgram); !errors.Is(err, ErrInvalidQ) {
			t.Fatalf("qgram %q: expected ErrInvalidQ, got %v", qgram, err)
		}
	}
	// Multi-byte code points count as one code point each.
	for _, qgram := range []string{"中文北京", "🙂🙂🙂🙂", "éøßñ"} {
		if _, err := CanonicalWord(wordScalarDomain, qgram); err != nil {
			t.Fatalf("qgram %q must be accepted, got %v", qgram, err)
		}
	}
}

// TestShareConstructorsRejectNonCanonicalEncodings checks that a malformed
// party-file share cannot be wrapped into a share value.
func TestShareConstructorsRejectNonCanonicalEncodings(t *testing.T) {
	// Group order l is not a canonical scalar encoding.
	groupOrder := [32]byte{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
	}
	if _, err := NewScalarShare(groupOrder); !errors.Is(err, ErrShareEncoding) {
		t.Fatalf("non-canonical scalar must be rejected, got %v", err)
	}
	// 0xff... is not a canonical Ristretto encoding.
	allOnes := [32]byte{}
	for i := range allOnes {
		allOnes[i] = 0xff
	}
	if _, err := NewPointShare(allOnes); !errors.Is(err, ErrShareEncoding) {
		t.Fatalf("non-canonical point must be rejected, got %v", err)
	}
}

// TestBasePointDerivationStable checks that the locked base point is a constant
// of the package and not recomputed differently per call.
func TestBasePointDerivationStable(t *testing.T) {
	first := TargetBasePoint()
	for i := 0; i < 8; i++ {
		if !bytes.Equal(first.Bytes(), TargetBasePoint().Bytes()) {
			t.Fatalf("TargetBasePoint returned different values across calls")
		}
	}
	// Mutating the returned copy must not affect the package constant.
	first.Add(first, first)
	if bytes.Equal(first.Bytes(), TargetBasePoint().Bytes()) {
		t.Fatalf("TargetBasePoint leaked its internal value")
	}
}

// TestPartEvalMatchesFullEvalForASingleShare checks that partial evaluation is
// consistent with full evaluation when one share is the whole scalar.
func TestPartEvalMatchesFullEvalForASingleShare(t *testing.T) {
	secret, err := KJoin(MasterKey(katMasterKey), 42)
	if err != nil {
		t.Fatalf("KJoin: %v", err)
	}
	partial, err := PartEval(scalarShareFromScalar(secret))
	if err != nil {
		t.Fatalf("PartEval: %v", err)
	}
	if !bytes.Equal(partial.Bytes(), FullEval(secret).Bytes()) {
		t.Fatalf("PartEval and FullEval disagree on a single-share input")
	}
}

// TestMasterKeyHasNoFormattingSurface locks the absence of any formatting entry
// point on MasterKey. Formatting a key is forbidden by
// SECURITY_INVARIANTS.md; the type deliberately offers no way to make that
// convenient.
func TestMasterKeyHasNoFormattingSurface(t *testing.T) {
	typ := reflect.TypeOf(MasterKey{})
	if typ.NumMethod() != 0 {
		t.Fatalf("MasterKey must expose no methods, has %d", typ.NumMethod())
	}
	// Sanity: the package directory must not mention fmt/log formatting of a
	// master key. This is a source-level guard, not a proof.
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, needle := range []string{"fmt.Print", "log.Print", "println("} {
			if bytes.Contains(source, []byte(needle)) {
				t.Fatalf("%s contains %q", path, needle)
			}
		}
	}
}
