// Package aggregation completes the Anchor record boundary. Dealer functions
// may hold both shares; online methods consume only a single party's state.
package aggregation

import (
	"crypto/rand"
	"errors"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/share"
)

const AnchorBucketBits = indexbuild.AnchorBucketBits
const ComparisonBin = 7

var ErrShape = errors.New("aggregation: invalid shape, domain, or consumed preprocessing")

func randomBytes(n int) ([]byte, error) { b := make([]byte, n); _, e := rand.Read(b); return b, e }

// BoundMask belongs to the authorized user, not either cloud.
type BoundMask struct {
	eta  byte
	used bool
}

func (u *BoundMask) Mask(bound int) (uint32, error) {
	if u.used || bound < 0 || bound >= 64 {
		return 0, ErrShape
	}
	u.used = true
	return uint32((byte(bound) + u.eta) & 127), nil
}

type ComparisonParty struct {
	party           uint8
	masks           []incidence.Share
	keys            []anchorfilter.SCMPKeyShare
	begun, finished bool
}

// PreprocessComparison is independent of the value and threshold. LLAMA keys
// are opaque party-local keys. Bout=1 and fresh output masks are mandatory.
func PreprocessComparison(n int, b anchorfilter.SCMPBackend) (*BoundMask, *ComparisonParty, *ComparisonParty, error) {
	if n < 0 || b == nil {
		return nil, nil, nil, ErrShape
	}
	rnd, e := randomBytes(1 + 3*n)
	if e != nil {
		return nil, nil, nil, e
	}
	u := &BoundMask{eta: rnd[0] & 127}
	p := &ComparisonParty{party: 0, masks: make([]incidence.Share, n), keys: make([]anchorfilter.SCMPKeyShare, n)}
	q := &ComparisonParty{party: 1, masks: make([]incidence.Share, n), keys: make([]anchorfilter.SCMPKeyShare, n)}
	for i := 0; i < n; i++ {
		r, a := rnd[1+3*i]&127, rnd[2+3*i]&127
		p.masks[i] = incidence.NewShare(incidence.Z128(a))
		q.masks[i] = incidence.NewShare(incidence.Z128(r - a))
		p.keys[i], q.keys[i], e = b.KeyGen(7, uint32(r), uint32(u.eta), domain.Bit(rnd[3+3*i]&1 != 0))
		if e != nil {
			return nil, nil, nil, e
		}
	}
	return u, p, q, nil
}

// Prepare exposes only a local share of v+R; it never reconstructs v.
func (p *ComparisonParty) Prepare(v []incidence.Share) ([]incidence.Z128, error) {
	if p.begun || len(v) != len(p.masks) {
		return nil, ErrShape
	}
	p.begun = true
	o := make([]incidence.Z128, len(v))
	for i := range v {
		o[i] = v[i].Value().Add(p.masks[i].Value())
	}
	return o, nil
}
func OpenComparison(a, b []incidence.Z128) ([]incidence.Z128, error) {
	if len(a) != len(b) {
		return nil, ErrShape
	}
	o := make([]incidence.Z128, len(a))
	for i := range a {
		o[i] = a[i].Add(b[i])
	}
	return o, nil
}
func (p *ComparisonParty) Finish(open []incidence.Z128, bound uint32, b anchorfilter.SCMPBackend) ([]share.BitShare, error) {
	if !p.begun || p.finished || len(open) != len(p.keys) || bound > 127 {
		return nil, ErrShape
	}
	p.finished = true
	o := make([]share.BitShare, len(open))
	for i, x := range open {
		v, e := b.Eval(p.party, p.keys[i], uint32(x), bound)
		if e != nil {
			return nil, e
		}
		o[i] = share.LocalSubBit(v, p.keys[i].OutputMaskShare())
	}
	return o, nil
}

type CountParty struct {
	LayoutID [16]byte
	values   []incidence.Share
	r        int
}

func NewCount(id [16]byte, n int) *CountParty {
	return &CountParty{LayoutID: id, values: make([]incidence.Share, n)}
}
func (c *CountParty) Add(id [16]byte, y []incidence.Share) error {
	if id != c.LayoutID || len(y) != len(c.values) || c.r >= 14 {
		return ErrShape
	}
	for i := range y {
		c.values[i] = incidence.Add(c.values[i], y[i])
	}
	c.r++
	return nil
}
func (c *CountParty) Values() []incidence.Share { return append([]incidence.Share(nil), c.values...) }
func Threshold(r, tau int) (int, error) {
	if r < 1 || r > 14 || tau < 0 || tau >= r {
		return 0, ErrShape
	}
	return r - tau, nil
}
