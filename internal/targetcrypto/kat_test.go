package targetcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/gtank/ristretto255"
)

// Known-answer vectors for the PHASE 3B Target routing foundation.
//
// Independent sources for every expected value below:
//
//   - HMAC-SHA512 / HMAC-SHA256 digests, canonical frame bytes, and the SHA-512
//     preimage of the base point: computed with the Python standard library
//     only (`hmac`, `hashlib`, `struct`), independently of this repository.
//   - Scalar reduction, the base point, the combined scalar, and the group point
//     encoding: computed with curve25519-dalek 4.1.3 (Rust), an independent
//     Ristretto255 implementation, from the Python-produced digests. No value
//     below was produced by the implementation under test.
//
// Fixed inputs: master key 000102...1f, join value 42, q-gram "area".
var katMasterKey = [32]byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

const (
	katJoinID = uint64(42)
	katQGram  = "area"

	katJoinFrameHex = "0000001a504d45512d5441524745542d4a4f494e2d5343414c41522d563100000008000000000000002a"
	katWordFrameHex = "0000001a504d45512d5441524745542d574f52442d5343414c41522d56310000000450534d4a0000000a617265615f616c696173000000046e616d6500000004617265610000000461726561"

	katJoinDigestHex = "4cf40f00725361764e15c15baa0b9ff4d83cf31584b496a82972832d65ed0d1da9f6b5613cbb429d16acab99ce5e6da96833dc2754a76d35d1a84222f24600a3"
	katWordDigestHex = "5373b9bdf061a7b784ef28c30012e4f07ff5f2ab3bf262d5a296c6a504a2328fefcc6825c6e83968a624ea9c5591f60e2aa7e6f4ce57e4d6380e828152d99f81"

	katJoinScalarHex  = "a09e0540387d475f5912039e45774d76bb643104eadaa1afec1986ad8203d403"
	katWordScalarHex  = "55684bbead1759fef11d51b4e5069fa5a769f76a40edd127fab066da67500604"
	katKappaScalarHex = "f50651fee594a05d4b3054522b7eec1b63ce286f2ac873d7e6caec87ea53da07"

	// The locked canonical encoding of the fixed KHPRF base point.
	katBasePointHex  = "44bc37cc66414c556078145a5e869039ced44c8056a05eeccc0b66600f9f175f"
	katGroupPointHex = "4287b740ce326e32d78aaf7ada678b9e509a705819a14997708f7e9d1947e12f"

	katBucketJoinDigestHex = "a678d41e83ba7ab0c74fb0b7225555d596f0a63ad8bef3abd96f6da2d3c92913"
	katBucketWordDigestHex = "bbd98bcb49f8ce44406aa2add4ee33a5e165721eba4d50a6d1d3cb8a802297de"

	katJoinDigestDomainHex = "b884abfcef0df910721688697ef80d84dbf54c288121ab0c59c31f349b29cd41a13866f4ea37986f0fc420c393431f75a965d8644351c6090773ee48841cf33c"
)

func TestKATCanonicalFrames(t *testing.T) {
	joinFrame, err := CanonicalJoin(joinScalarDomain, katJoinID)
	if err != nil {
		t.Fatalf("CanonicalJoin: %v", err)
	}
	if got := hex.EncodeToString(joinFrame); got != katJoinFrameHex {
		t.Fatalf("join frame mismatch\n got %s\nwant %s", got, katJoinFrameHex)
	}

	wordFrame, err := CanonicalWord(wordScalarDomain, katQGram)
	if err != nil {
		t.Fatalf("CanonicalWord: %v", err)
	}
	if got := hex.EncodeToString(wordFrame); got != katWordFrameHex {
		t.Fatalf("word frame mismatch\n got %s\nwant %s", got, katWordFrameHex)
	}

	// The bucket domains must frame identically but under their own label, so a
	// scalar frame and a bucket frame can never collide.
	bucketJoinFrame, err := CanonicalJoin(joinBucketDomain, katJoinID)
	if err != nil {
		t.Fatalf("CanonicalJoin(bucket): %v", err)
	}
	scalarDomain := []byte(joinScalarDomain)
	bucketDomain := []byte(joinBucketDomain)
	if len(scalarDomain) != len(bucketDomain) {
		t.Fatalf("KAT assumes equal-length join domains")
	}
	if string(bucketJoinFrame[4:4+len(bucketDomain)]) != joinBucketDomain {
		t.Fatalf("bucket join frame does not carry its own domain")
	}
	if string(bucketJoinFrame) == string(joinFrame) {
		t.Fatalf("scalar frame and bucket frame must differ")
	}
}

func TestKATScalarMapping(t *testing.T) {
	key, err := NewMasterKey(katMasterKey)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	joinScalar, err := KJoin(key, katJoinID)
	if err != nil {
		t.Fatalf("KJoin: %v", err)
	}
	if got := hex.EncodeToString(joinScalar.Bytes()); got != katJoinScalarHex {
		t.Fatalf("kappa_J mismatch\n got %s\nwant %s", got, katJoinScalarHex)
	}

	wordScalar, err := KWord(key, katQGram)
	if err != nil {
		t.Fatalf("KWord: %v", err)
	}
	if got := hex.EncodeToString(wordScalar.Bytes()); got != katWordScalarHex {
		t.Fatalf("kappa_w mismatch\n got %s\nwant %s", got, katWordScalarHex)
	}

	kappa := CombineScalar(joinScalar, wordScalar)
	if got := hex.EncodeToString(kappa.Bytes()); got != katKappaScalarHex {
		t.Fatalf("kappa mismatch\n got %s\nwant %s", got, katKappaScalarHex)
	}
}

func TestKATBasePoint(t *testing.T) {
	// The base point must be the domain-separated hash-to-group point, locked to
	// an exact encoding. The expected value is never updated to fit the
	// implementation.
	if got := hex.EncodeToString(TargetBasePoint().Bytes()); got != katBasePointHex {
		t.Fatalf("base point mismatch\n got %s\nwant %s", got, katBasePointHex)
	}

	identity := ristretto255.NewIdentityElement()
	if TargetBasePoint().Equal(identity) == 1 {
		t.Fatalf("base point must not be the identity")
	}
	if TargetBasePoint().Equal(ristretto255.NewGeneratorElement()) == 1 {
		t.Fatalf("base point must not be the canonical generator")
	}
}

func TestKATTargetGroupPoint(t *testing.T) {
	key, err := NewMasterKey(katMasterKey)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	target, err := DeriveTargetGroupPoint(key, katJoinID, katQGram)
	if err != nil {
		t.Fatalf("DeriveTargetGroupPoint: %v", err)
	}
	if got := hex.EncodeToString(target.Bytes()); got != katGroupPointHex {
		t.Fatalf("T mismatch\n got %s\nwant %s", got, katGroupPointHex)
	}
}

func TestKATBucketComponents(t *testing.T) {
	key, err := NewMasterKey(katMasterKey)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	for _, tc := range []struct {
		k            int
		joinWant     BucketComponent
		wordWant     BucketComponent
		combinedWant BucketComponent
	}{
		{k: 8, joinWant: 166, wordWant: 187, combinedWant: 29},
		{k: 14, joinWant: 10654, wordWant: 12022, combinedWant: 1896},
	} {
		joinComponent, err := JoinBucketComponent(key, katJoinID, tc.k)
		if err != nil {
			t.Fatalf("JoinBucketComponent(k=%d): %v", tc.k, err)
		}
		if joinComponent != tc.joinWant {
			t.Fatalf("k=%d beta_J = %d, want %d", tc.k, joinComponent, tc.joinWant)
		}
		wordComponent, err := WordBucketComponent(key, katQGram, tc.k)
		if err != nil {
			t.Fatalf("WordBucketComponent(k=%d): %v", tc.k, err)
		}
		if wordComponent != tc.wordWant {
			t.Fatalf("k=%d beta_w = %d, want %d", tc.k, wordComponent, tc.wordWant)
		}
		if got := CombineBucketComponents(joinComponent, wordComponent); got != tc.combinedWant {
			t.Fatalf("k=%d beta = %d, want %d", tc.k, got, tc.combinedWant)
		}
		// A component must never carry bits above the declared width.
		if uint32(joinComponent) >= 1<<uint(tc.k) || uint32(wordComponent) >= 1<<uint(tc.k) {
			t.Fatalf("k=%d component exceeds its width", tc.k)
		}
	}
}

func TestBucketSeventeenBitPrefixExtendsSixteen(t *testing.T) {
	key, err := NewMasterKey(katMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, derive := range []func(int) (BucketComponent, error){
		func(bits int) (BucketComponent, error) { return JoinBucketComponent(key, katJoinID, bits) },
		func(bits int) (BucketComponent, error) { return WordBucketComponent(key, katQGram, bits) },
	} {
		sixteen, err := derive(16)
		if err != nil {
			t.Fatal(err)
		}
		seventeen, err := derive(17)
		if err != nil {
			t.Fatal(err)
		}
		if seventeen>>1 != sixteen || seventeen >= 1<<17 {
			t.Fatal("17-bit MSB prefix")
		}
	}
}

// TestKATSeparateDomains locks the fact that the join and word derivations are
// domain-separated: the same bytes under the other domain must not collide.
func TestKATSeparateDomains(t *testing.T) {
	key, err := NewMasterKey(katMasterKey)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	joinScalar, err := KJoin(key, katJoinID)
	if err != nil {
		t.Fatalf("KJoin: %v", err)
	}
	// "area" is a valid q-gram, so the same key over the word domain with the
	// KAT q-gram must derive an unrelated scalar.
	wordScalar, err := KWord(key, katQGram)
	if err != nil {
		t.Fatalf("KWord: %v", err)
	}
	if joinScalar.Equal(wordScalar) == 1 {
		t.Fatalf("join and word derivations collided")
	}

	// The bucket domains must also be separated from each other.
	joinComponent, err := JoinBucketComponent(key, katJoinID, 16)
	if err != nil {
		t.Fatalf("JoinBucketComponent: %v", err)
	}
	wordComponent, err := WordBucketComponent(key, katQGram, 16)
	if err != nil {
		t.Fatalf("WordBucketComponent: %v", err)
	}
	if joinComponent == wordComponent {
		t.Fatalf("bucket domains collided")
	}
}

// TestKATIntermediateDigests pins the layer between the canonical frame and the
// scalar: the HMAC digests produced here must equal the values computed by the
// Python standard library. This is what makes the scalar expectations above
// independently checkable rather than trust-on-first-use.
func TestKATIntermediateDigests(t *testing.T) {
	key, err := NewMasterKey(katMasterKey)
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	joinFrame, err := CanonicalJoin(joinScalarDomain, katJoinID)
	if err != nil {
		t.Fatalf("CanonicalJoin: %v", err)
	}
	joinMAC := hmac.New(sha512.New, key[:])
	if _, err := joinMAC.Write(joinFrame); err != nil {
		t.Fatalf("hmac write: %v", err)
	}
	if got := hex.EncodeToString(joinMAC.Sum(nil)); got != katJoinDigestHex {
		t.Fatalf("join HMAC-SHA512 mismatch\n got %s\nwant %s", got, katJoinDigestHex)
	}

	wordFrame, err := CanonicalWord(wordScalarDomain, katQGram)
	if err != nil {
		t.Fatalf("CanonicalWord: %v", err)
	}
	wordMAC := hmac.New(sha512.New, key[:])
	if _, err := wordMAC.Write(wordFrame); err != nil {
		t.Fatalf("hmac write: %v", err)
	}
	if got := hex.EncodeToString(wordMAC.Sum(nil)); got != katWordDigestHex {
		t.Fatalf("word HMAC-SHA512 mismatch\n got %s\nwant %s", got, katWordDigestHex)
	}

	bucketJoinFrame, err := CanonicalJoin(joinBucketDomain, katJoinID)
	if err != nil {
		t.Fatalf("CanonicalJoin(bucket): %v", err)
	}
	bucketJoinMAC := hmac.New(sha256.New, key[:])
	if _, err := bucketJoinMAC.Write(bucketJoinFrame); err != nil {
		t.Fatalf("hmac write: %v", err)
	}
	if got := hex.EncodeToString(bucketJoinMAC.Sum(nil)); got != katBucketJoinDigestHex {
		t.Fatalf("bucket join HMAC-SHA256 mismatch\n got %s\nwant %s", got, katBucketJoinDigestHex)
	}

	bucketWordFrame, err := CanonicalWord(wordBucketDomain, katQGram)
	if err != nil {
		t.Fatalf("CanonicalWord(bucket): %v", err)
	}
	bucketWordMAC := hmac.New(sha256.New, key[:])
	if _, err := bucketWordMAC.Write(bucketWordFrame); err != nil {
		t.Fatalf("hmac write: %v", err)
	}
	if got := hex.EncodeToString(bucketWordMAC.Sum(nil)); got != katBucketWordDigestHex {
		t.Fatalf("bucket word HMAC-SHA256 mismatch\n got %s\nwant %s", got, katBucketWordDigestHex)
	}

	// The base point preimage is a plain SHA-512 of the domain literal.
	preimage := sha512.Sum512([]byte(targetPointDomain))
	if got := hex.EncodeToString(preimage[:]); got != katJoinDigestDomainHex {
		t.Fatalf("base point preimage mismatch\n got %s\nwant %s", got, katJoinDigestDomainHex)
	}
}
