// Bounded DO-offline material bank. Each cloud is given ONE root.
// Persistent burn records are anchored to that root, not to packet file paths.
// Filesystem durability and honest storage configuration are model assumptions;
// copying/rolling back a whole cloud state is outside semi-honest operation.
package zeroagg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"pmeq/internal/f2beaver"
	"pmeq/internal/material"
)

const Purpose = "anchor-zero-agg-v1"

type Spec struct {
	Version                                      int
	Purpose, IndexID, LayoutID, StaticID, Bucket string
	T, D                                         int
}
type Packet struct {
	Spec        Spec
	ID          string
	Party       int
	Digest      string
	GF, Boolean []byte
	WholeTicket string `json:",omitempty"`
	Occurrence  int    `json:",omitempty"`
}
type Static struct {
	Spec   Spec
	Party  int
	Labels []F
}
type Bank struct {
	root  string
	party int
	spec  Spec
}

func RandomID() string {
	var v [16]byte
	if _, e := rand.Read(v[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(v[:])
}
func validID(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 16 && v == hex.EncodeToString(b) && v != "00000000000000000000000000000000"
}
func (s Spec) Validate() error {
	if s.Version != 1 || s.Purpose != Purpose || !validID(s.IndexID) || !validID(s.LayoutID) || !validID(s.StaticID) || s.Bucket == "" || len(s.Bucket) > 128 || s.T < 0 || s.T > 65536 || s.D < 0 || s.D > 32768 || (s.D > 0 && s.D&(s.D-1) != 0) || (s.D == 0 && s.T != 0) || (s.T == 0 && s.D != 0) {
		return fmt.Errorf("invalid public bank spec")
	}
	return nil
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func writeExclusive(path string, v any) error {
	raw, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return syncDir(filepath.Dir(path))
}
func digest(g, b []byte) string {
	h := sha256.New()
	h.Write(g)
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func OpenBank(root string, party int, s Spec) (*Bank, error) {
	if party < 0 || party > 1 {
		return nil, fmt.Errorf("invalid party")
	}
	if e := s.Validate(); e != nil {
		return nil, e
	}
	abs, e := filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	return &Bank{abs, party, s}, nil
}
func (b *Bank) StaticLabels() ([]F, error) {
	raw, e := os.ReadFile(filepath.Join(b.root, "static.json"))
	if e != nil {
		return nil, e
	}
	var v Static
	if e = json.Unmarshal(raw, &v); e != nil {
		return nil, e
	}
	if v.Spec != b.spec || v.Party != b.party || len(v.Labels) != b.spec.T {
		return nil, fmt.Errorf("static role/layout binding mismatch")
	}
	return v.Labels, nil
}

// Claim burns the WHOLE package durably BEFORE decoding, constructing Party,
// emitting any input-dependent message, or handing out boolean material.
// Any subsequent error, panic, process interruption or peer mismatch loses it.
func (b *Bank) ClaimOccurrence(id, query string, occ int) (*Party, *f2beaver.PartyBatch, error) {
	if !validID(id) || !validID(query) || occ < 0 || occ >= 14 {
		return nil, nil, fmt.Errorf("invalid consumption identity")
	}
	var key [16]byte
	v, _ := hex.DecodeString(id)
	copy(key[:], v)
	if e := material.ClaimPersistent(filepath.Join(b.root, "burn"), key); e != nil {
		return nil, nil, e
	}
	if e := writeExclusive(filepath.Join(b.root, "burn", id+".context"), struct {
		Spec  Spec
		Party int
		Query string
	}{b.spec, b.party, query}); e != nil {
		return nil, nil, e
	}
	raw, e := os.ReadFile(filepath.Join(b.root, "packets", id+".json"))
	if e != nil {
		return nil, nil, e
	}
	var pkt Packet
	if e = json.Unmarshal(raw, &pkt); e != nil {
		return nil, nil, e
	}
	if pkt.WholeTicket != query || pkt.Occurrence != occ {
		return nil, nil, fmt.Errorf("query/occurrence binding mismatch (burned)")
	}
	tp, n, g := Gates(b.spec.T, b.spec.D)
	if pkt.Spec != b.spec || pkt.Party != b.party || pkt.ID != id || len(pkt.GF) != 6*g || len(pkt.Boolean) != 6*b.spec.T || digest(pkt.GF, pkt.Boolean) != pkt.Digest {
		return nil, nil, fmt.Errorf("packet identity/role/shape/digest mismatch (burned)")
	}
	p := &Party{inputT: b.spec.T, t: tp, d: b.spec.D, n: n, id: b.party, triples: make([]LocalTriple, g)}
	for i := range p.triples {
		p.triples[i] = LocalTriple{F(binary.LittleEndian.Uint16(pkt.GF[6*i:])), F(binary.LittleEndian.Uint16(pkt.GF[6*i+2:])), F(binary.LittleEndian.Uint16(pkt.GF[6*i+4:]))}
	}
	bb, e := f2beaver.DecodeOwn(pkt.Boolean, 2*b.spec.T)
	clear(pkt.GF)
	clear(pkt.Boolean)
	return p, bb, e
}
func IsConsumed(e error) bool { return errors.Is(e, material.ErrConsumed) }
