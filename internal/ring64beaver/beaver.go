// Package ring64beaver applies the existing additive Beaver and XOR-to-
// arithmetic equations in Z/(2^64). It never reconstructs input values.
package ring64beaver

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"

	"pmeq/internal/domain"
	"pmeq/internal/share"
)

var ErrState = errors.New("ring64beaver: invalid shape, party or consumed material")

type state struct {
	sync.Mutex
	used    bool
	next    int
	a, b, c []uint64
}

// Take reserves a disjoint batch in a packet owned by an enclosing one-use
// query. Copies share the same cursor; already reserved entries cannot recur.
func (p Packet) Take(n int) (Packet, error) {
	if p.state == nil {
		return Packet{}, ErrState
	}
	s := p.state
	s.Lock()
	defer s.Unlock()
	if s.used || n < 0 || n > len(s.a)-s.next {
		return Packet{}, ErrState
	}
	lo, hi := s.next, s.next+n
	s.next = hi
	return Packet{party: p.party, state: &state{a: s.a[lo:hi], b: s.b[lo:hi], c: s.c[lo:hi]}}, nil
}

// Packet handles share a one-use guard even when copied.
type Packet struct {
	party uint8
	state *state
}

// Limit reserves a public prefix before Begin, burning unused capacity in the
// enclosing one-use query packet. It cannot follow a Begin or streamed Take.
func (p Packet) Limit(n int) error {
	if p.state == nil {
		return ErrState
	}
	s := p.state
	s.Lock()
	defer s.Unlock()
	if s.used || s.next != 0 || n < 0 || n > len(s.a) {
		return ErrState
	}
	s.a = s.a[:n:n]
	s.b = s.b[:n:n]
	s.c = s.c[:n:n]
	return nil
}

type Message struct{ D, E []uint64 }
type Pending struct {
	sync.Mutex
	party uint8
	state *state
	own   Message
	bits  []uint64
	done  bool
}

// Preprocess is trusted OFFLINE code. Storage is 24*n bytes per party,
// excluding Go objects. Online methods never invoke this function.
func Preprocess(n int) (Packet, Packet, error) {
	if n < 0 || n > int(^uint(0)>>1)/24 {
		return Packet{}, Packet{}, ErrState
	}
	p := [2]Packet{{party: 0, state: &state{}}, {party: 1, state: &state{}}}
	for _, q := range p {
		q.state.a = make([]uint64, n)
		q.state.b = make([]uint64, n)
		q.state.c = make([]uint64, n)
	}
	var buf [40]byte
	for i := 0; i < n; i++ {
		if _, err := rand.Read(buf[:]); err != nil {
			return Packet{}, Packet{}, err
		}
		a, b := binary.LittleEndian.Uint64(buf[:8]), binary.LittleEndian.Uint64(buf[8:16])
		x, y, z := binary.LittleEndian.Uint64(buf[16:24]), binary.LittleEndian.Uint64(buf[24:32]), binary.LittleEndian.Uint64(buf[32:])
		p[0].state.a[i], p[1].state.a[i] = x, a-x
		p[0].state.b[i], p[1].state.b[i] = y, b-y
		p[0].state.c[i], p[1].state.c[i] = z, a*b-z
	}
	return p[0], p[1], nil
}

func Begin(p Packet, x, y []share.Ring64Share) (*Pending, Message, error) {
	if p.state == nil || p.party > 1 || len(x) != len(y) {
		return nil, Message{}, ErrState
	}
	p.state.Lock()
	defer p.state.Unlock()
	if p.state.used || p.state.next != 0 || len(x) != len(p.state.a) {
		return nil, Message{}, ErrState
	}
	p.state.used = true
	m := Message{make([]uint64, len(x)), make([]uint64, len(x))}
	for i := range x {
		m.D[i] = uint64(x[i].Value()) - p.state.a[i]
		m.E[i] = uint64(y[i].Value()) - p.state.b[i]
	}
	// Keep a distinct copy so callers cannot mutate the local opening afterward.
	own := Message{append([]uint64(nil), m.D...), append([]uint64(nil), m.E...)}
	return &Pending{party: p.party, state: p.state, own: own}, m, nil
}

// BeginB2A embeds the local XOR bit on its owner's arithmetic input wire.
// b0 XOR b1 = b0+b1-2*b0*b1, including ring wraparound.
func BeginB2A(p Packet, bits []share.BitShare) (*Pending, Message, error) {
	if p.party > 1 {
		return nil, Message{}, ErrState
	}
	x, y := make([]share.Ring64Share, len(bits)), make([]share.Ring64Share, len(bits))
	v := make([]uint64, len(bits))
	for i, b := range bits {
		if b.Value() {
			v[i] = 1
		}
		if p.party == 0 {
			x[i] = share.NewRing64Share(domain.Ring64(v[i]))
		} else {
			y[i] = share.NewRing64Share(domain.Ring64(v[i]))
		}
	}
	s, m, e := Begin(p, x, y)
	if e != nil {
		return nil, Message{}, e
	}
	s.bits = v
	return s, m, nil
}

// Finish accepts only the peer's masked message, never its input/triple shares.
// Binding the message to query/stage/order belongs to the enclosing protocol.
func (s *Pending) Finish(peer Message) ([]share.Ring64Share, error) {
	s.Lock()
	defer s.Unlock()
	if s.done || len(peer.D) != len(s.own.D) || len(peer.E) != len(s.own.E) {
		return nil, ErrState
	}
	s.done = true
	out := make([]share.Ring64Share, len(peer.D))
	for i := range out {
		d, e := s.own.D[i]+peer.D[i], s.own.E[i]+peer.E[i]
		v := s.state.c[i] + d*s.state.b[i] + e*s.state.a[i]
		if s.party == 0 {
			v += d * e
		}
		if s.bits != nil {
			v = s.bits[i] - 2*v
		}
		out[i] = share.NewRing64Share(domain.Ring64(v))
	}
	s.state.a = nil
	s.state.b = nil
	s.state.c = nil
	s.state = nil
	s.bits = nil
	s.own = Message{}
	return out, nil
}
