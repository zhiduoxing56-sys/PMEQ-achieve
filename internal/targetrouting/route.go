package targetrouting

import (
	"encoding/binary"
	"github.com/gtank/ristretto255"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
	"sync"
)

// RecommendedWorkers is the measured choice on the PHASE7 host; callers
// explicitly pass a supported count and may retune on other machines.
const RecommendedWorkers = 16

// Candidates is the PHASE6 handoff, with explicit bucket-domain metadata.
// Each invocation receives ONE party's arrays; IDs are retained without opening.
type Candidates struct {
	LayoutID, CompactionID [16]byte
	TargetBucketBits       uint8
	K                      int
	RecordIDShare          []share.Ring64Share
	KappaJoinShare         []targetcrypto.ScalarShare
	BucketJoinShare        []targetcrypto.BucketShare
}
type Route struct {
	CandidateIndex, OccurrenceID uint32
	BucketID                     uint32
	Y                            targetcrypto.PointShare
}
type RoutedCandidates struct {
	Manifest                        Manifest
	LayoutID, CompactionID, QueryID [16]byte
	K                               int
	AnchorRecordIDShare             []share.Ring64Share
	Occurrences                     []Occurrence
	Routes                          []Route // row-major c*r+h; index c is scoped to CompactionID
}
type Pending struct {
	mu      sync.Mutex
	party   uint8
	used    bool
	output  RoutedCandidates
	buckets []targetcrypto.BucketShare
}

func parallel(n, workers int, fn func(int) error) error {
	if workers != 1 && workers != 4 && workers != 8 && workers != 16 {
		return ErrBinding
	}
	if workers == 1 {
		for i := 0; i < n; i++ {
			if e := fn(i); e != nil {
				return e
			}
		}
		return nil
	}
	workers = min(workers, max(1, n))
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := n * w / workers; i < n*(w+1)/workers; i++ {
				if e := fn(i); e != nil {
					errs[w] = e
					return
				}
			}
		}(w)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// Prepare computes J_u once per candidate and keeps every Y_u local. Only the
// encoded bucket opening message is exported to the peer.
func Prepare(m Manifest, party uint8, c Candidates, t QueryToken, workers int) (*Pending, []byte, error) {
	if e := m.Validate(); e != nil {
		return nil, nil, e
	}
	if party > 1 || t.Party != party || t.Manifest != m || c.TargetBucketBits != m.TargetBucketBits || c.K < 0 || len(c.RecordIDShare) != c.K || len(c.KappaJoinShare) != c.K || len(c.BucketJoinShare) != c.K {
		return nil, nil, ErrBinding
	}
	r := len(t.Words)
	if uint64(c.K) > uint64(^uint32(0)) || uint64(r) > uint64(^uint32(0))/4 || r != 0 && c.K > int(^uint(0)>>1)/r {
		return nil, nil, ErrBinding
	}
	domain, _ := targetcrypto.NewBucketDomain(int(m.TargetBucketBits))
	words := make([]*ristretto255.Element, r)
	occurrences := make([]Occurrence, r)
	for h, w := range t.Words {
		if w.OccurrenceID != uint32(h) || w.Position != uint32(4*h) {
			return nil, nil, ErrBinding
		}
		if e := domain.Validate(w.BucketWordShare); e != nil {
			return nil, nil, e
		}
		p, e := ristretto255.NewElement().SetCanonicalBytes(w.WordPointShare[:])
		if e != nil {
			return nil, nil, e
		}
		words[h] = p
		occurrences[h] = w.Occurrence
	}
	for _, v := range c.BucketJoinShare {
		if e := domain.Validate(v); e != nil {
			return nil, nil, e
		}
	}
	out := RoutedCandidates{Manifest: m, LayoutID: c.LayoutID, CompactionID: c.CompactionID, QueryID: t.QueryID, K: c.K, AnchorRecordIDShare: append([]share.Ring64Share(nil), c.RecordIDShare...), Occurrences: occurrences, Routes: make([]Route, c.K*r)}
	p := &Pending{party: party, output: out, buckets: make([]targetcrypto.BucketShare, len(out.Routes))}
	if len(out.Routes) == 0 {
		if workers != 1 && workers != 4 && workers != 8 && workers != 16 {
			return nil, nil, ErrBinding
		}
		return p, nil, nil
	}
	joins := make([]*ristretto255.Element, c.K)
	e := parallel(c.K, workers, func(i int) error { v, e := targetcrypto.PartEval(c.KappaJoinShare[i]); joins[i] = v; return e })
	if e != nil {
		return nil, nil, e
	}
	e = parallel(len(out.Routes), workers, func(i int) error {
		ci, h := i/r, i%r
		y := ristretto255.NewElement().Add(joins[ci], words[h])
		row := &p.output.Routes[i]
		row.CandidateIndex = uint32(ci)
		row.OccurrenceID = uint32(h)
		copy(row.Y[:], y.Bytes())
		b, e := domain.XOR(c.BucketJoinShare[ci], t.Words[h].BucketWordShare)
		p.buckets[i] = b
		return e
	})
	if e != nil {
		return nil, nil, e
	}
	return p, p.message(), nil
}

// Fixed codec: magic(4), party(1), bits(1), Q(4), IndexID/LayoutID/
// CompactionID/QueryID(4*16), K(4), r(4), then one LE16 bucket share/pair.
const OpeningHeaderBytes = 82

func (p *Pending) message() []byte {
	o := p.output
	w := bucketWireBytes(o.Manifest.TargetBucketBits)
	b := make([]byte, OpeningHeaderBytes+w*len(p.buckets))
	copy(b, "PR07")
	b[4] = p.party
	b[5] = o.Manifest.TargetBucketBits
	binary.LittleEndian.PutUint32(b[6:10], o.Manifest.Q)
	copy(b[10:26], o.Manifest.IndexID[:])
	copy(b[26:42], o.LayoutID[:])
	copy(b[42:58], o.CompactionID[:])
	copy(b[58:74], o.QueryID[:])
	binary.LittleEndian.PutUint32(b[74:78], uint32(o.K))
	binary.LittleEndian.PutUint32(b[78:82], uint32(len(o.Occurrences)))
	for i, v := range p.buckets {
		if w == 4 {
			binary.LittleEndian.PutUint32(b[82+w*i:], uint32(v))
		} else {
			binary.LittleEndian.PutUint16(b[82+w*i:], uint16(v))
		}
	}
	return b
}

// Finish opens only combined beta. Y is never included in any peer message.
func (p *Pending) Finish(peer []byte) (RoutedCandidates, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used {
		return RoutedCandidates{}, ErrBinding
	}
	if len(p.buckets) == 0 {
		if len(peer) != 0 {
			return RoutedCandidates{}, ErrBinding
		}
		p.used = true
		out := p.output
		p.output = RoutedCandidates{}
		return out, nil
	}
	mine := p.message()
	if len(peer) != len(mine) || peer[4] != 1-p.party {
		return RoutedCandidates{}, ErrBinding
	}
	for i := 0; i < OpeningHeaderBytes; i++ {
		if i != 4 && peer[i] != mine[i] {
			return RoutedCandidates{}, ErrBinding
		}
	}
	domain, _ := targetcrypto.NewBucketDomain(int(p.output.Manifest.TargetBucketBits))
	w := bucketWireBytes(p.output.Manifest.TargetBucketBits)
	peerShare := func(i int) targetcrypto.BucketShare {
		if w == 4 {
			return targetcrypto.BucketShare(binary.LittleEndian.Uint32(peer[82+w*i:]))
		}
		return targetcrypto.BucketShare(binary.LittleEndian.Uint16(peer[82+w*i:]))
	}
	// Validate the entire message before changing any public bucket field.
	for i := range p.buckets {
		if e := domain.Validate(peerShare(i)); e != nil {
			return RoutedCandidates{}, e
		}
	}
	for i, v := range p.buckets {
		b, e := domain.Open(v, peerShare(i))
		if e != nil {
			return RoutedCandidates{}, e
		}
		p.output.Routes[i].BucketID = uint32(b)
	}
	out := p.output
	p.output = RoutedCandidates{}
	clear(p.buckets)
	p.buckets = nil
	p.used = true
	return out, nil
}

// TokenBytes specifies the query-user wire schema: same manifest/query header
// (IndexID16, bits1,Q4,QueryID16,party1,r4) plus h4,pos4,point32,bucket2.
func TokenBytes(r int) int                    { return 42 + 42*r }
func TokenBytesForBits(bits uint8, r int) int { return 42 + (40+bucketWireBytes(bits))*r }
func bucketWireBytes(bits uint8) int {
	if bits > 16 {
		return 4
	}
	return 2
}
