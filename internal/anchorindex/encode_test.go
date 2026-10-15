package anchorindex

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

const (
	katKeyHex       = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	katQgram        = "Café"
	katCanonicalHex = "0000000442534d4a0000000461726561000000046e616d6500000002696400000005436166c3a9"
	katHMAC256Hex   = "18eb26e539633a391dfbd186f5d7bc3e6df4ea2bbbf42e96e9e3d62163c97281"
	katValueHex     = "18eb26e539633a391dfbd186f5d7bc3e"
	secondKeyHex    = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
	secondValueHex  = "e47ba5b880b407724dd744dda0fed9c8"
)

func TestEncodeKnownAnswerAndCanonicalEncoding(t *testing.T) {
	key := mustKeyHex(t, katKeyHex)
	canonical, err := canonicalAnchorLogicalKey(katQgram)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(canonical); got != katCanonicalHex {
		t.Fatalf("canonical bytes = %s, want %s", got, katCanonicalHex)
	}

	mac := hmac.New(sha256.New, mustDecodeHex(t, katKeyHex))
	_, _ = mac.Write([]byte(anchorIndexDomain))
	_, _ = mac.Write(canonical)
	if got := hex.EncodeToString(mac.Sum(nil)); got != katHMAC256Hex {
		t.Fatalf("full HMAC = %s, want %s", got, katHMAC256Hex)
	}

	value, err := Encode(key, katQgram)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(value[:]); got != katValueHex {
		t.Fatalf("Value = %s, want %s", got, katValueHex)
	}
}

func TestEncodeDeterminism(t *testing.T) {
	key := mustKeyHex(t, katKeyHex)
	first, err := Encode(key, katQgram)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encode(key, katQgram)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("same key and qgram produced different values")
	}
}

func TestEncodeKeySensitivityFixedVectors(t *testing.T) {
	first, err := Encode(mustKeyHex(t, katKeyHex), katQgram)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encode(mustKeyHex(t, secondKeyHex), katQgram)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(second[:]); got != secondValueHex {
		t.Fatalf("second-key Value = %s, want %s", got, secondValueHex)
	}
	if first == second {
		t.Fatal("different fixed keys produced the same value")
	}
}

func TestEncodeQgramCodePointSensitivity(t *testing.T) {
	key := mustKeyHex(t, katKeyHex)
	base, err := Encode(key, katQgram)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{"Bafé", "Cbfé", "Cagé", "Cafè"} {
		got, err := Encode(key, changed)
		if err != nil {
			t.Fatalf("Encode(%q): %v", changed, err)
		}
		if got == base {
			t.Fatalf("changing a code point in %q did not change Value", changed)
		}
	}
}

func TestKeyAndValueExactWidths(t *testing.T) {
	if got := reflect.TypeOf(Key{}).Size(); got != 32 {
		t.Fatalf("Key width = %d, want 32", got)
	}
	if got := reflect.TypeOf(Value{}).Size(); got != 16 {
		t.Fatalf("Value width = %d, want 16", got)
	}
}

func TestLengthPrefixesSeparateFieldBoundaries(t *testing.T) {
	left, err := encodeLengthDelimited("ab", "c")
	if err != nil {
		t.Fatal(err)
	}
	right, err := encodeLengthDelimited("a", "bc")
	if err != nil {
		t.Fatal(err)
	}
	if "ab"+"c" != "a"+"bc" {
		t.Fatal("test setup does not have an ambiguous raw concatenation")
	}
	if bytes.Equal(left, right) {
		t.Fatal("length-delimited encodings did not separate field boundaries")
	}
}

func TestEncodeRejectsInvalidUTF8(t *testing.T) {
	invalid := string([]byte{'a', 'b', 'c', 0xff})
	if _, err := Encode(mustKeyHex(t, katKeyHex), invalid); !errors.Is(err, errInvalidUTF8) {
		t.Fatalf("invalid UTF-8 error = %v, want %v", err, errInvalidUTF8)
	}
}

func TestEncodeEnforcesFourCodePoints(t *testing.T) {
	key := mustKeyHex(t, katKeyHex)
	for _, invalid := range []string{"", "a", "abc", "abcde"} {
		if _, err := Encode(key, invalid); !errors.Is(err, errInvalidQ) {
			t.Fatalf("Encode(%q) error = %v, want %v", invalid, err, errInvalidQ)
		}
	}
	for _, valid := range []string{"test", "音乐脑库"} {
		if _, err := Encode(key, valid); err != nil {
			t.Fatalf("Encode(%q): %v", valid, err)
		}
	}
}

func TestCanonicalEncodingDoesNotNormalizeUnicode(t *testing.T) {
	precomposed, err := canonicalAnchorLogicalKey("éabc")
	if err != nil {
		t.Fatal(err)
	}
	decomposed, err := canonicalAnchorLogicalKey("e\u0301ab")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(precomposed, decomposed) {
		t.Fatal("distinct Unicode code-point sequences were normalized")
	}
}

func mustKeyHex(t *testing.T, encoded string) Key {
	t.Helper()
	raw := mustDecodeHex(t, encoded)
	var material [32]byte
	if len(raw) != len(material) {
		t.Fatalf("key vector has %d bytes", len(raw))
	}
	copy(material[:], raw)
	key, err := NewKey(material)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustDecodeHex(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
