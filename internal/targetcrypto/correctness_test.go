package targetcrypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/gtank/ristretto255"
)

// longCaseCount is the number of randomized cases required by the PHASE 3B
// commit gate. `go test -short` reduces it so that a developer loop stays fast;
// the gate run uses the full count.
const longCaseCount = 100_000

func caseCount(t *testing.T) int {
	t.Helper()
	if testing.Short() {
		return 1_000
	}
	return longCaseCount
}

// testAlphabet mixes single-byte and multi-byte code points so that the q-gram
// encoding is exercised across UTF-8 widths.
var testAlphabet = []rune{
	'a', 'b', 'c', 'z', 'A', 'Z', '0', '9', '-', ' ', '.',
	'é', 'ø', 'ß', 'ñ', 'ü',
	'я', 'ж', 'Ω', 'λ',
	'中', '京', 'カ', '한',
	'𝔘', '🙂',
}

// testTuple deterministically derives a (join value, q-gram) pair. The join
// value stays inside the real MusicBrainz area identifier range.
func testTuple(i int) (uint64, string) {
	digest := sha256.Sum256([]byte(fmt.Sprintf("pmeq-targetcrypto-case-%d", i)))
	joinID := binary.BigEndian.Uint64(digest[0:8])%121155 + 1
	runes := make([]rune, targetQ)
	for j := 0; j < targetQ; j++ {
		runes[j] = testAlphabet[int(digest[8+j])%len(testAlphabet)]
	}
	return joinID, string(runes)
}

// mustScalar and mustElement decode a party-local share inside the test only.
// The package exposes no production reconstruction entry point.
func mustScalar(t *testing.T, s ScalarShare) *ristretto255.Scalar {
	t.Helper()
	value, err := s.scalar()
	if err != nil {
		t.Fatalf("invalid scalar share: %v", err)
	}
	return value
}

func mustElement(t *testing.T, p PointShare) *ristretto255.Element {
	t.Helper()
	value, err := p.element()
	if err != nil {
		t.Fatalf("invalid point share: %v", err)
	}
	return value
}

func reconstructScalar(t *testing.T, a, b ScalarShare) *ristretto255.Scalar {
	t.Helper()
	return ristretto255.NewScalar().Add(mustScalar(t, a), mustScalar(t, b))
}

func reconstructPoint(t *testing.T, a, b PointShare) *ristretto255.Element {
	t.Helper()
	return ristretto255.NewElement().Add(mustElement(t, a), mustElement(t, b))
}

func equalPoint(a, b *ristretto255.Element) bool {
	return bytes.Equal(a.Bytes(), b.Bytes())
}

// partialEvaluate combines one party's own kappa_J and kappa_w shares and
// evaluates only that party's partial point.
func partialEvaluate(t *testing.T, joinShare, wordShare ScalarShare) *ristretto255.Element {
	t.Helper()
	combined, err := CombineScalarShare(joinShare, wordShare)
	if err != nil {
		t.Fatalf("CombineScalarShare: %v", err)
	}
	partial, err := PartEval(combined)
	if err != nil {
		t.Fatalf("PartEval: %v", err)
	}
	return partial
}

// TestRoutingConsistency checks that two parties holding fresh additive shares
// of kappa_J and kappa_w, each combining only their own shares and evaluating
// only their own partial point, produce point shares that recombine to the full
// Target group point.
func TestRoutingConsistency(t *testing.T) {
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	n := caseCount(t)
	for i := 0; i < n; i++ {
		joinID, qgram := testTuple(i)

		joinScalar, err := KJoin(key, joinID)
		if err != nil {
			t.Fatalf("case %d: KJoin: %v", i, err)
		}
		wordScalar, err := KWord(key, qgram)
		if err != nil {
			t.Fatalf("case %d: KWord: %v", i, err)
		}

		join0, join1, err := SplitScalar(joinScalar)
		if err != nil {
			t.Fatalf("case %d: SplitScalar(join): %v", i, err)
		}
		word0, word1, err := SplitScalar(wordScalar)
		if err != nil {
			t.Fatalf("case %d: SplitScalar(word): %v", i, err)
		}

		partial0 := partialEvaluate(t, join0, word0)
		partial1 := partialEvaluate(t, join1, word1)

		// The data owner holds the complete point.
		target := FullEval(CombineScalar(joinScalar, wordScalar))

		if !equalPoint(ristretto255.NewElement().Add(partial0, partial1), target) {
			t.Fatalf("case %d: Y0+Y1 != T (join=%d qgram=%q)", i, joinID, qgram)
		}
	}
}

// TestOptionFourEqual checks the approved PHASE 3B equality identity: when the
// query point equals the stored group point, the two parties' locally encoded
// differences are byte-identical.
func TestOptionFourEqual(t *testing.T) {
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	n := caseCount(t)
	for i := 0; i < n; i++ {
		joinID, qgram := testTuple(i)

		joinScalar, err := KJoin(key, joinID)
		if err != nil {
			t.Fatalf("case %d: KJoin: %v", i, err)
		}
		wordScalar, err := KWord(key, qgram)
		if err != nil {
			t.Fatalf("case %d: KWord: %v", i, err)
		}
		join0, join1, err := SplitScalar(joinScalar)
		if err != nil {
			t.Fatalf("case %d: SplitScalar(join): %v", i, err)
		}
		word0, word1, err := SplitScalar(wordScalar)
		if err != nil {
			t.Fatalf("case %d: SplitScalar(word): %v", i, err)
		}
		partial0 := partialEvaluate(t, join0, word0)
		partial1 := partialEvaluate(t, join1, word1)

		// The stored group point is the query point itself (the equal case).
		target := FullEval(CombineScalar(joinScalar, wordScalar))
		stored0, stored1, err := SplitPoint(target)
		if err != nil {
			t.Fatalf("case %d: SplitPoint: %v", i, err)
		}
		if !equalPoint(reconstructPoint(t, stored0, stored1), target) {
			t.Fatalf("case %d: T0+T1 != T", i)
		}

		// CS0: D0 = Y0 - T0 ; CS1: D1 = T1 - Y1.
		d0 := ristretto255.NewElement().Subtract(partial0, mustElement(t, stored0))
		d1 := ristretto255.NewElement().Subtract(mustElement(t, stored1), partial1)

		if !bytes.Equal(d0.Bytes(), d1.Bytes()) {
			t.Fatalf("case %d: Enc(D0) != Enc(D1) on the equal case", i)
		}
	}
}

// TestOptionFourUnequal checks the complementary direction: when the stored
// group point comes from a different logical tuple, the two encodings differ.
func TestOptionFourUnequal(t *testing.T) {
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	n := caseCount(t)
	for i := 0; i < n; i++ {
		joinID, qgram := testTuple(i)
		otherJoinID, otherQGram := testTuple(i + 7_000_003)

		joinScalar, err := KJoin(key, joinID)
		if err != nil {
			t.Fatalf("case %d: KJoin: %v", i, err)
		}
		wordScalar, err := KWord(key, qgram)
		if err != nil {
			t.Fatalf("case %d: KWord: %v", i, err)
		}
		join0, join1, err := SplitScalar(joinScalar)
		if err != nil {
			t.Fatalf("case %d: SplitScalar(join): %v", i, err)
		}
		word0, word1, err := SplitScalar(wordScalar)
		if err != nil {
			t.Fatalf("case %d: SplitScalar(word): %v", i, err)
		}
		partial0 := partialEvaluate(t, join0, word0)
		partial1 := partialEvaluate(t, join1, word1)

		// A stored group point that belongs to a different tuple.
		otherTarget, err := DeriveTargetGroupPoint(key, otherJoinID, otherQGram)
		if err != nil {
			t.Fatalf("case %d: DeriveTargetGroupPoint: %v", i, err)
		}
		stored0, stored1, err := SplitPoint(otherTarget)
		if err != nil {
			t.Fatalf("case %d: SplitPoint: %v", i, err)
		}

		d0 := ristretto255.NewElement().Subtract(partial0, mustElement(t, stored0))
		d1 := ristretto255.NewElement().Subtract(mustElement(t, stored1), partial1)
		if bytes.Equal(d0.Bytes(), d1.Bytes()) {
			t.Fatalf("case %d: Enc(D0) == Enc(D1) on the unequal case (join=%d/%d qgram=%q/%q)",
				i, joinID, otherJoinID, qgram, otherQGram)
		}
	}
}

// TestSplitScalarReconstructs runs the scalar-share reconstruction check.
func TestSplitScalarReconstructs(t *testing.T) {
	n := caseCount(t)
	for i := 0; i < n; i++ {
		secret, err := uniformScalar(bytes.NewReader(deriveTestBytes(i, 64)))
		if err != nil {
			t.Fatalf("case %d: uniformScalar: %v", i, err)
		}
		left, right, err := SplitScalar(secret)
		if err != nil {
			t.Fatalf("case %d: SplitScalar: %v", i, err)
		}
		if reconstructScalar(t, left, right).Equal(secret) != 1 {
			t.Fatalf("case %d: share recombination failed", i)
		}
	}
}

// TestSplitPointReconstructs runs the required 100k point-share
// reconstruction check on independently sampled points.
func TestSplitPointReconstructs(t *testing.T) {
	n := caseCount(t)
	for i := 0; i < n; i++ {
		scalar, err := uniformScalar(bytes.NewReader(deriveTestBytes(i, 64)))
		if err != nil {
			t.Fatalf("case %d: uniformScalar: %v", i, err)
		}
		point := FullEval(scalar)
		left, right, err := SplitPoint(point)
		if err != nil {
			t.Fatalf("case %d: SplitPoint: %v", i, err)
		}
		if !equalPoint(reconstructPoint(t, left, right), point) {
			t.Fatalf("case %d: point share recombination failed", i)
		}
	}
}

// deriveTestBytes produces deterministic pseudo-random bytes for test inputs.
func deriveTestBytes(i, n int) []byte {
	out := make([]byte, 0, n)
	for counter := 0; len(out) < n; counter++ {
		digest := sha256.Sum256([]byte(fmt.Sprintf("pmeq-targetcrypto-bytes-%d-%d", i, counter)))
		out = append(out, digest[:]...)
	}
	return out[:n]
}

// TestTupleSeparation records fixed regression expectations for the four tuple
// relations. These are wiring regressions only: they do not assert, and must
// not be read as asserting, any collision-resistance property.
func TestTupleSeparation(t *testing.T) {
	key, err := NewMasterKey(katMasterKey)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	pointFor := func(joinID uint64, qgram string) *ristretto255.Element {
		t.Helper()
		point, err := DeriveTargetGroupPoint(key, joinID, qgram)
		if err != nil {
			t.Fatalf("DeriveTargetGroupPoint(%d,%q): %v", joinID, qgram, err)
		}
		return point
	}
	bucketFor := func(joinID uint64, qgram string) (BucketComponent, BucketComponent) {
		t.Helper()
		jb, err := JoinBucketComponent(key, joinID, 16)
		if err != nil {
			t.Fatalf("JoinBucketComponent: %v", err)
		}
		wb, err := WordBucketComponent(key, qgram, 16)
		if err != nil {
			t.Fatalf("WordBucketComponent: %v", err)
		}
		return jb, wb
	}

	// same join + same qgram => identical derivation
	if !equalPoint(pointFor(42, "area"), pointFor(42, "area")) {
		t.Fatalf("identical tuple must derive an identical point")
	}
	// same join + different qgram
	if equalPoint(pointFor(42, "area"), pointFor(42, "park")) {
		t.Fatalf("different qgram must derive a different point (regression)")
	}
	// different join + same qgram
	if equalPoint(pointFor(42, "area"), pointFor(43, "area")) {
		t.Fatalf("different join value must derive a different point (regression)")
	}
	// different join + different qgram
	if equalPoint(pointFor(42, "area"), pointFor(43, "park")) {
		t.Fatalf("different tuple must derive a different point (regression)")
	}

	jb1, wb1 := bucketFor(42, "area")
	jb2, _ := bucketFor(43, "area")
	_, wb3 := bucketFor(42, "park")
	if jb1 == jb2 {
		t.Fatalf("different join value must derive a different bucket component (regression)")
	}
	if wb1 == wb3 {
		t.Fatalf("different qgram must derive a different bucket component (regression)")
	}
}
