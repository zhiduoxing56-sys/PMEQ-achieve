// Package targetrouting implements only private point-share routing and public
// bucket opening. No equality, target position, or target aggregation exists here.
package targetrouting

import (
	"errors"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetcrypto"
)

var ErrBinding = errors.New("targetrouting: invalid shape, manifest, party, or query binding")

// IndexID identifies the trusted index artifact/configuration. Anchor width is
// intentionally absent. Neither width nor ID may be supplied by an untrusted peer.
type Manifest struct {
	IndexID          [16]byte
	TargetBucketBits uint8
	Q                uint32
}

func FromMetadata(id [16]byte, m indexbuild.PublicMetadata) (Manifest, error) {
	out := Manifest{id, m.TargetBucketBits, m.Q}
	return out, out.Validate()
}
func (m Manifest) Validate() error {
	if m.Q != 4 {
		return ErrBinding
	}
	_, e := targetcrypto.NewBucketDomain(int(m.TargetBucketBits))
	return e
}

type Occurrence struct{ OccurrenceID, Position uint32 }
type WordToken struct {
	Occurrence
	WordPointShare  targetcrypto.PointShare
	BucketWordShare targetcrypto.BucketShare
}
type QueryToken struct {
	Manifest Manifest
	QueryID  [16]byte
	Party    uint8
	Words    []WordToken
	Position []anchorfilter.PositionToken
}
