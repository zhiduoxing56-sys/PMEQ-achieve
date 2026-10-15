package zeroagg

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"pmeq/internal/f2beaver"
)

// DO-only. Existing shares are retained across queries, never re-randomized
// under the same identity. Comparisons below happen only inside trusted DO.
func EnsureStaticOwn(root string, s Spec, party int, labels []F) (Spec, int64, error) {
	if e := s.Validate(); e != nil {
		return s, 0, e
	}
	if party < 0 || party > 1 || len(labels) != s.T {
		return s, 0, fmt.Errorf("static shape")
	}
	for _, d := range []string{root, filepath.Join(root, "packets"), filepath.Join(root, "burn")} {
		if e := os.MkdirAll(d, 0700); e != nil {
			return s, 0, e
		}
	}
	path := filepath.Join(root, "static.json")
	raw, e := os.ReadFile(path)
	if e == nil {
		var v Static
		if e = json.Unmarshal(raw, &v); e != nil {
			return s, 0, e
		}
		old, expected := v.Spec, s
		old.StaticID = ""
		expected.StaticID = ""
		if old != expected || v.Party != party || len(v.Labels) != len(labels) {
			return s, 0, fmt.Errorf("static identity mismatch")
		}
		for i := range labels {
			if labels[i] != v.Labels[i] {
				return s, 0, fmt.Errorf("static shares changed")
			}
		}
		return v.Spec, 0, nil
	}
	if !os.IsNotExist(e) {
		return s, 0, e
	}
	if e = writeExclusive(path, Static{s, party, labels}); e != nil {
		return s, 0, e
	}
	st, e := os.Stat(path)
	if e != nil {
		return s, 0, e
	}
	return s, st.Size(), nil
}

// DO-only serialization of already-generated fresh material, no online dealer.
func SealOwn(root string, s Spec, id, ticket string, occ int, p *Party, and [2]f2beaver.PartyBatch) (int64, error) {
	if e := s.Validate(); e != nil {
		return 0, e
	}
	tp, n, g := Gates(s.T, s.D)
	if !validID(ticket) || occ < 0 || occ >= 14 || !validID(id) || p == nil || p.inputT != s.T || p.t != tp || p.d != s.D || p.n != n || p.used != 0 || p.started.Load() || len(p.triples) != g {
		return 0, fmt.Errorf("invalid material to seal")
	}
	if !p.sealed.CompareAndSwap(false, true) {
		return 0, fmt.Errorf("material already sealed; generate fresh budget")
	}
	gf := make([]byte, 6*g)
	defer clear(gf)
	for i, q := range p.triples {
		binary.LittleEndian.PutUint16(gf[6*i:], uint16(q.a))
		binary.LittleEndian.PutUint16(gf[6*i+2:], uint16(q.b))
		binary.LittleEndian.PutUint16(gf[6*i+4:], uint16(q.c))
	}
	bb := append(and[0].EncodeOwn(), and[1].EncodeOwn()...)
	defer clear(bb)
	if len(bb) != 6*s.T {
		return 0, fmt.Errorf("boolean gate range mismatch")
	}
	path := filepath.Join(root, "packets", id+".json")
	if e := writeExclusive(path, Packet{Spec: s, ID: id, Party: p.id, Digest: digest(gf, bb), GF: gf, Boolean: bb, WholeTicket: ticket, Occurrence: occ}); e != nil {
		return 0, e
	}
	st, e := os.Stat(path)
	if e != nil {
		return 0, e
	}
	return st.Size(), nil
}
func (p *Party) Discard() { p.started.Store(true); clear(p.triples); p.triples = nil }
