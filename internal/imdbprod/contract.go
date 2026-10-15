// Package imdbprod defines the sole approved IMDb production sample contract.
// Its digest belongs in every new index, offline packet, token and recovery
// manifest. Legacy experiment formats have no implicit conversion to it.
package imdbprod

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const (
	Version              = "IMDB-100K-10K-20261015-v1"
	SampleSeed           = 20261015
	AnchorObjects        = 100000
	TargetObjects        = 10000
	CandidateCapacity    = 10000
	Q                    = 4
	AnchorSignatures     = 4
	TargetSignatures     = 4
	BucketBits           = 16
	TargetDimension      = 26
	PositionBin          = 10
	PositionMax          = 270
	TargetMultiplicity   = 4
	TargetBucketGroups   = 11
	TargetBucketSlots    = 44
	TargetGroupCapacity  = CandidateCapacity * TargetBucketSlots
	AnchorSequenceSHA256 = "7a31b5cc73af844a2a9fec83d964fd7e7927d4aee597047b10c2c241eede4fb7"
	TargetSequenceSHA256 = "b9f050071281497cdc123321be8aa498af77dc30e8ff494d43574f47e3d0b488"
	MotherDatabaseSHA256 = "e790ed19ba571ae1143efcc13239e0c6e0c290637c5aa02ef04a4e475820ba76"
	SourceManifestSHA256 = "2cd4cf314d77f541a4f94fdc281d0122ff3d4ab2b471a913aa4493108b6ae077"
	IdentityMapSHA256    = "858452800d3814dd37e3ad474823409fc1455340bd5a53a84dfa1f80f305b85d"
	TargetMapSHA256      = "9397fbe9c902ac31501e07994bda7a44e3b8e88427fd4efb39c9ea13a25b4ba0"
)

var ErrContract = errors.New("imdbprod: sample, domain or capacity does not match production contract")

// Public contains only immutable public parameters and domain labels. Ring64
// object IDs, Ring32 positions, GF16 anchor labels, Z128 counts and F2 hits
// retain the existing protocol's mathematical domains.
type Public struct {
	Version              string `json:"version"`
	AnchorObjects        int    `json:"anchor_objects"`
	TargetObjects        int    `json:"target_objects"`
	CandidateCapacity    int    `json:"candidate_capacity"`
	Q                    int    `json:"q"`
	AnchorSignatures     int    `json:"anchor_signatures"`
	TargetSignatures     int    `json:"target_signatures"`
	BucketBits           int    `json:"bucket_bits"`
	TargetDimension      int    `json:"target_dimension"`
	PositionBin          uint8  `json:"position_bin"`
	PositionMax          uint32 `json:"position_max"`
	TargetMultiplicity   int    `json:"target_multiplicity"`
	TargetBucketGroups   int    `json:"target_bucket_groups"`
	TargetBucketSlots    int    `json:"target_bucket_slots"`
	AnchorTable          string `json:"anchor_table"`
	AnchorObject         string `json:"anchor_object"`
	AnchorSearch         string `json:"anchor_search"`
	AnchorJoin           string `json:"anchor_join"`
	TargetTable          string `json:"target_table"`
	TargetObject         string `json:"target_object"`
	TargetSearch         string `json:"target_search"`
	TargetJoin           string `json:"target_join"`
	AnchorSequenceSHA256 string `json:"anchor_sequence_sha256"`
	TargetSequenceSHA256 string `json:"target_sequence_sha256"`
}

func Production() Public {
	return Public{Version, AnchorObjects, TargetObjects, CandidateCapacity, Q,
		AnchorSignatures, TargetSignatures, BucketBits, TargetDimension, PositionBin,
		PositionMax, TargetMultiplicity, TargetBucketGroups, TargetBucketSlots, "MOVIECAST", "objectId", "aliasTitle", "tconst",
		"MOVIE", "tconst", "primaryTitle", "tconst", AnchorSequenceSHA256, TargetSequenceSHA256}
}

func (p Public) Validate() error {
	if p != Production() {
		return ErrContract
	}
	return nil
}

func (p Public) Digest() ([32]byte, error) {
	if err := p.Validate(); err != nil {
		return [32]byte{}, err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

func (p Public) DigestHex() (string, error) {
	h, err := p.Digest()
	return hex.EncodeToString(h[:]), err
}

// KeyFingerprint is a public, stable identity for the two 256-bit production
// keys. It reveals neither key and is independent of the key file's formatting.
func KeyFingerprint(anchor, target [32]byte) string {
	h := sha256.New()
	h.Write([]byte("PMEQ-IMDB-KEYPAIR-v1"))
	h.Write(anchor[:])
	h.Write(target[:])
	return hex.EncodeToString(h.Sum(nil))
}

// CheckCandidates is called before reserving or allocating shape-dependent
// material. The public 10000 never follows the observed secret K.
func (p Public) CheckCandidates(k int) error {
	if p.Validate() != nil || k < 0 || k > CandidateCapacity {
		return ErrContract
	}
	return nil
}

func (p Public) CheckQuery(anchor, target string, tauAnchor, tauTarget int) error {
	if p.Validate() != nil || len([]rune(anchor)) < Q*AnchorSignatures || len([]rune(target)) < Q*TargetSignatures || tauAnchor < 0 || tauAnchor >= AnchorSignatures || tauTarget < 0 || tauTarget >= TargetSignatures {
		return ErrContract
	}
	return nil
}
