package targetrouting

import (
	"io"
	"pmeq/internal/indexbuild"
)

// BoundIndex is the production entry point. Its width comes only from a
// validated final artifact manifest, never from a query or peer message.
// The generic Manifest/Prepare API remains the historical experiment primitive.
type BoundIndex struct{ manifest Manifest }

func LoadIndex(r io.Reader) (BoundIndex, error) {
	m, e := indexbuild.ReadTargetManifest(r)
	if e != nil {
		return BoundIndex{}, e
	}
	return BoundIndex{Manifest{m.IndexID, m.TargetBucketBits, m.Q}}, nil
}
func (b BoundIndex) TokenManifest() Manifest { return b.manifest }
func (b BoundIndex) Prepare(party uint8, c Candidates, t QueryToken, workers int) (*Pending, []byte, error) {
	if b.manifest.IndexID == [16]byte{} || b.manifest.TargetBucketBits != indexbuild.TargetBucketBits {
		return nil, nil, ErrBinding
	}
	return Prepare(b.manifest, party, c, t, workers)
}
