package targetpe

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"github.com/gtank/ristretto255"
	"pmeq/internal/domain"
	"pmeq/internal/f2beaver"
	"pmeq/internal/share"
	"pmeq/internal/targetcrypto"
	"pmeq/internal/targetrouting"
	"sync"
	"time"
)

const Rounds = 8
const HeaderBytes = 62
const RecommendedWorkers = 1

type Route struct {
	CandidateIndex, OccurrenceID uint32
	BucketID                     uint32
	MatchOffset, GroupCount      int
}
type TargetGroupMatches struct {
	Manifest                        targetrouting.Manifest
	LayoutID, CompactionID, QueryID [16]byte
	K                               int
	Occurrences                     []targetrouting.Occurrence
	AnchorRecordIDShare             []share.Ring64Share
	Routes                          []Route
	MatchShares                     []share.BitShare
}
type Metrics struct {
	DifferenceEncoding, Compute, Messages, Output time.Duration
	PayloadBytes, FramingBytes                    uint64
}
type packetState struct {
	sync.Mutex
	used    bool
	triples f2beaver.PackedBatch
}

// Packet is one party's ONE-TIME Q_pool material. Copies share the same guard.
type Packet struct {
	state   *packetState
	ID      [16]byte
	lineage AlignmentLineage
	party   uint8
	G       int
}

func Words(g int) int {
	if g <= 0 {
		return 0
	}
	return (g-1)/64 + 1
}
func TripleWords(g int) int { return 255 * Words(g) }

// Preprocess is a trusted OFFLINE capacity reservation. Online Begin consumes
// the 255*ceil(actualG/64) prefix and burns the whole packet, including unused
// capacity. Pools may provision public upper bounds without knowing a query.
// Online Begin/Next/Accept never contact this dealer.
func Preprocess(lineage AlignmentLineage, g int) (Packet, Packet, error) {
	if g < 0 || g > int(^uint(0)>>1)/6120 || lineage.LayoutID == [16]byte{} || lineage.IndexID == [16]byte{} {
		return Packet{}, Packet{}, ErrBinding
	}
	a, b, e := f2beaver.PreprocessPacked(TripleWords(g))
	if e != nil {
		return Packet{}, Packet{}, e
	}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		return Packet{}, Packet{}, e
	}
	return Packet{&packetState{triples: a}, id, lineage, 0, g}, Packet{&packetState{triples: b}, id, lineage, 1, g}, nil
}
func parallel(n, workers int, f func(int, int)) {
	if workers == 1 || n < workers {
		f(0, n)
		return
	}
	var wg sync.WaitGroup
	for u := 0; u < workers; u++ {
		lo, hi := n*u/workers, n*(u+1)/workers
		wg.Add(1)
		go func() { defer wg.Done(); f(lo, hi) }()
	}
	wg.Wait()
}

// DifferenceEncoding operates only on this party's existing shares.
func DifferenceEncoding(party uint8, y, t targetcrypto.PointShare) ([32]byte, error) {
	if party > 1 {
		return [32]byte{}, ErrBinding
	}
	a, e := targetcrypto.NewPointShare(y.CanonicalBytes())
	if e != nil {
		return [32]byte{}, e
	}
	b, e := targetcrypto.NewPointShare(t.CanonicalBytes())
	if e != nil {
		return [32]byte{}, e
	}
	yp, e := ristretto255.NewElement().SetCanonicalBytes(a[:])
	if e != nil {
		return [32]byte{}, e
	}
	tp, e := ristretto255.NewElement().SetCanonicalBytes(b[:])
	if e != nil {
		return [32]byte{}, e
	}
	d := ristretto255.NewElement()
	if party == 0 {
		d.Subtract(yp, tp)
	} else {
		d.Subtract(tp, yp)
	}
	var raw [32]byte
	copy(raw[:], d.Bytes())
	v, e := targetcrypto.NewPointShare(raw)
	if e != nil {
		return [32]byte{}, e
	}
	return v.CanonicalBytes(), nil
}

type Session struct {
	sync.Mutex
	party                             uint8
	workers, g, w, round, usedTriples int
	packetID                          [16]byte
	binding                           [32]byte
	triples                           f2beaver.PackedBatch
	cur, d, e                         []uint64
	pending, done                     bool
	out                               TargetGroupMatches
	metrics                           Metrics
}

func (p *PartyIndex) Begin(r targetrouting.RoutedCandidates, packet Packet, workers int) (*Session, error) {
	if workers != 1 && workers != 4 && workers != 8 && workers != 16 {
		return nil, ErrBinding
	}
	if r.Manifest != p.Manifest() || r.LayoutID != p.lineage.LayoutID || r.CompactionID == [16]byte{} || r.QueryID == [16]byte{} || r.K < 0 || r.K > p.lineage.N || len(r.AnchorRecordIDShare) != r.K || r.K > int(^uint(0)>>1)/max(1, len(r.Occurrences)) || len(r.Routes) != r.K*len(r.Occurrences) {
		return nil, ErrBinding
	}
	for i, o := range r.Occurrences {
		if o.OccurrenceID != uint32(i) || o.Position != uint32(4*i) {
			return nil, ErrBinding
		}
	}
	layoutStart := time.Now()
	out := TargetGroupMatches{Manifest: r.Manifest, LayoutID: r.LayoutID, CompactionID: r.CompactionID, QueryID: r.QueryID, K: r.K, Occurrences: append([]targetrouting.Occurrence(nil), r.Occurrences...), AnchorRecordIDShare: append([]share.Ring64Share(nil), r.AnchorRecordIDShare...)}
	h := sha256.New()
	h.Write(p.structure[:])
	h.Write(r.Manifest.IndexID[:])
	h.Write(r.LayoutID[:])
	h.Write(r.CompactionID[:])
	h.Write(r.QueryID[:])
	binary.Write(h, binary.LittleEndian, uint64(r.K))
	binary.Write(h, binary.LittleEndian, uint64(len(r.Occurrences)))
	g := 0
	for i, v := range r.Routes {
		if v.CandidateIndex != uint32(i/len(r.Occurrences)) || v.OccurrenceID != uint32(i%len(r.Occurrences)) {
			return nil, ErrBinding
		}
		count := len(p.buckets[v.BucketID])
		if g > int(^uint(0)>>1)-count {
			return nil, ErrBinding
		}
		out.Routes = append(out.Routes, Route{v.CandidateIndex, v.OccurrenceID, v.BucketID, g, count})
		g += count
		binary.Write(h, binary.LittleEndian, v.CandidateIndex)
		binary.Write(h, binary.LittleEndian, v.OccurrenceID)
		binary.Write(h, binary.LittleEndian, v.BucketID)
		binary.Write(h, binary.LittleEndian, uint32(count))
	}
	if packet.state == nil || packet.lineage != p.lineage || packet.party != p.party || packet.G < g {
		return nil, ErrBinding
	}
	packet.state.Lock()
	defer packet.state.Unlock()
	if packet.state.used || packet.state.triples.Len() != TripleWords(packet.G) {
		return nil, ErrBinding
	}
	packet.state.used = true
	s := &Session{party: p.party, workers: workers, g: g, w: Words(g), packetID: packet.ID, triples: packet.state.triples.Slice(0, TripleWords(g)), out: out}
	packet.state.triples = f2beaver.PackedBatch{}
	copy(s.binding[:], h.Sum(nil))
	s.metrics.Output = time.Since(layoutStart)
	enc := make([][32]byte, g)
	start := time.Now()
	for i, v := range r.Routes {
		for j, t := range p.buckets[v.BucketID] {
			e, err := DifferenceEncoding(p.party, v.Y, t.TargetKeyShare)
			if err != nil {
				return nil, err
			}
			enc[out.Routes[i].MatchOffset+j] = e
		}
	}
	s.metrics.DifferenceEncoding = time.Since(start)
	s.initialize(enc)
	return s, nil
}
func (s *Session) initialize(enc [][32]byte) {
	start := time.Now()
	s.cur = make([]uint64, 256*s.w)
	parallel(s.w, s.workers, func(lo, hi int) {
		for word := lo; word < hi; word++ {
			for lane := 0; lane < 64 && word*64+lane < s.g; lane++ {
				v := enc[word*64+lane]
				for bit := 0; bit < 256; bit++ {
					x := (v[bit/8] >> uint(bit%8)) & 1
					if s.party == 0 {
						x ^= 1
					}
					s.cur[bit*s.w+word] |= uint64(x) << uint(lane)
				}
			}
		}
	})
	s.metrics.Compute += time.Since(start)
	if s.g == 0 {
		s.round = 8
	}
}
func (s *Session) Next() ([]byte, error) {
	s.Lock()
	defer s.Unlock()
	if s.done || s.pending || s.round >= 8 {
		return nil, ErrBinding
	}
	n := (128 >> s.round) * s.w
	t := s.triples.Slice(s.usedTriples, s.usedTriples+n)
	start := time.Now()
	s.d = make([]uint64, n)
	s.e = make([]uint64, n)
	parallel(n, s.workers, func(lo, hi int) {
		for i := lo; i < hi; i++ {
			gate, word := i/s.w, i%s.w
			s.d[i], s.e[i] = t.MaskAt(i, s.cur[2*gate*s.w+word], s.cur[(2*gate+1)*s.w+word])
		}
	})
	s.metrics.Compute += time.Since(start)
	start = time.Now()
	msg := make([]byte, HeaderBytes+16*n)
	copy(msg, "PMEQPE01")
	copy(msg[8:40], s.binding[:])
	copy(msg[40:56], s.packetID[:])
	msg[56] = s.party
	msg[57] = byte(s.round)
	binary.LittleEndian.PutUint32(msg[58:62], uint32(n))
	for i := 0; i < n; i++ {
		binary.LittleEndian.PutUint64(msg[62+8*i:], s.d[i])
		binary.LittleEndian.PutUint64(msg[62+8*n+8*i:], s.e[i])
	}
	s.pending = true
	s.metrics.Messages += time.Since(start)
	s.metrics.PayloadBytes += uint64(16 * n)
	s.metrics.FramingBytes += HeaderBytes
	return msg, nil
}
func (s *Session) Accept(msg []byte) error {
	s.Lock()
	defer s.Unlock()
	if !s.pending || s.done {
		return ErrBinding
	}
	start := time.Now()
	n := len(s.d)
	if len(msg) != HeaderBytes+16*n || string(msg[:8]) != "PMEQPE01" || string(msg[8:40]) != string(s.binding[:]) || string(msg[40:56]) != string(s.packetID[:]) || msg[56] != 1-s.party || msg[57] != byte(s.round) || int(binary.LittleEndian.Uint32(msg[58:])) != n {
		return ErrBinding
	}
	d, e := make([]uint64, n), make([]uint64, n)
	for i := range d {
		d[i] = s.d[i] ^ binary.LittleEndian.Uint64(msg[62+8*i:])
		e[i] = s.e[i] ^ binary.LittleEndian.Uint64(msg[62+8*n+8*i:])
	}
	s.metrics.Messages += time.Since(start)
	start = time.Now()
	t := s.triples.Slice(s.usedTriples, s.usedTriples+n)
	next := make([]uint64, n)
	parallel(n, s.workers, func(lo, hi int) {
		for i := lo; i < hi; i++ {
			next[i] = t.FinishAt(s.party, i, d[i], e[i])
		}
	})
	s.cur = next
	s.usedTriples += n
	s.round++
	s.pending = false
	s.d = nil
	s.e = nil
	s.metrics.Compute += time.Since(start)
	return nil
}
func (s *Session) Output() (TargetGroupMatches, error) {
	s.Lock()
	defer s.Unlock()
	if s.done || s.pending || s.round != 8 {
		return TargetGroupMatches{}, ErrBinding
	}
	start := time.Now()
	s.out.MatchShares = make([]share.BitShare, s.g)
	if s.w > 0 && s.g%64 != 0 {
		s.cur[s.w-1] &= (uint64(1) << uint(s.g%64)) - 1
	}
	for i := range s.out.MatchShares {
		s.out.MatchShares[i] = share.NewBitShare(domain.Bit((s.cur[i/64]>>uint(i%64))&1 == 1))
	}
	s.done = true
	s.cur = nil
	s.triples = f2beaver.PackedBatch{}
	s.metrics.Output += time.Since(start)
	return s.out, nil
}
func (s *Session) Metrics() Metrics { s.Lock(); defer s.Unlock(); return s.metrics }
