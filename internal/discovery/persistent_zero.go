// Persistent integration of the audited material bank with whole PMEQ tickets.
package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"pmeq/internal/f2beaver"
	"pmeq/internal/material"
	"pmeq/internal/zeroagg"
	"time"
)

type ZeroBinding struct {
	Spec            zeroagg.Spec
	ID, WholeTicket string
	Occurrence      int
}
type zeroReference struct {
	Binding      ZeroBinding
	Root         string
	OwnStaticSHA [32]byte
}
type PersistenceCost struct {
	Ticket                     string
	MaterialBytes, StaticBytes int64
	SerializeNS                int64
	Bindings                   []ZeroBinding
}
type PersistentLoad struct {
	WallNS        int64
	MaterialBytes int64
	Packages      int
}

func (g *guard) reserve() error {
	if g == nil {
		return ErrBinding
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.used || g.reserved || g.ledger == "" {
		return ErrBinding
	}
	if e := material.ClaimPersistent(g.ledger, g.id); e != nil {
		return e
	}
	g.reserved = true
	return nil
}
func (g *guard) invalidate() { g.mu.Lock(); g.used = true; g.mu.Unlock() }

// All original materials remain party-local, fresh and protected by the same
// durable whole-query ticket. New GF/F2 states additionally load from own files.
func PersistReservation(root, banks string, u *UserPacket, a, b *PartyPacket, sa, sb *Static) (cost PersistenceCost, err error) {
	start := time.Now()
	defer func() { cost.SerializeNS = time.Since(start).Nanoseconds() }()
	if sa == nil || sb == nil || sa.payload.LayoutID != sb.payload.LayoutID || len(a.anchor) != len(b.anchor) {
		return cost, ErrBinding
	}
	if e := persistBaseReservation(root, u, a, b); e != nil {
		return cost, e
	}
	cost.Ticket = hex.EncodeToString(u.id[:])
	for h := range a.anchor {
		x, y := &a.anchor[h], &b.anchor[h]
		if x.empty || y.empty {
			if !x.empty || !y.empty || x.bucket != y.bucket {
				return cost, ErrBinding
			}
			continue
		}
		if x.bucket != y.bucket || x.zero == nil || y.zero == nil {
			return cost, ErrBinding
		}
		own0, e := sa.anchorFor(x.bucket)
		if e != nil {
			return cost, e
		}
		own1, e := sb.anchorFor(x.bucket)
		if e != nil {
			return cost, e
		}
		if own0.D != own1.D || own0.T != own1.T || own0.LabelID != own1.LabelID {
			return cost, ErrBinding
		}
		d, t := own0.D, own0.T
		index := sa.target.Manifest().IndexID
		spec := zeroagg.Spec{Version: 1, Purpose: zeroagg.Purpose, IndexID: hex.EncodeToString(index[:]), LayoutID: hex.EncodeToString(sa.payload.LayoutID[:]), StaticID: own0.LabelID, Bucket: fmt.Sprint(x.bucket), T: t, D: d}
		roots := [2]string{filepath.Join(banks, spec.LayoutID, spec.Bucket, "cs0"), filepath.Join(banks, spec.LayoutID, spec.Bucket, "cs1")}
		s, n, e := zeroagg.EnsureStaticOwn(roots[0], spec, 0, own0.Labels)
		if e != nil {
			return cost, e
		}
		cost.StaticBytes += n
		s1, n, e := zeroagg.EnsureStaticOwn(roots[1], s, 1, own1.Labels)
		if e != nil || s1 != s {
			return cost, ErrBinding
		}
		cost.StaticBytes += n
		_, _, g := zeroagg.Gates(t, d)
		if cost.MaterialBytes+int64(4*(12*g+12*t)/3+4096) > 256<<20 {
			return cost, fmt.Errorf("per-query persistent material cap exceeded")
		}
		id := zeroagg.RandomID()
		binding := ZeroBinding{s, id, cost.Ticket, h}
		for j, ap := range []*anchorPacket{x, y} {
			n, e = zeroagg.SealOwn(roots[j], s, id, cost.Ticket, h, ap.zero, ap.and)
			if e != nil {
				return cost, e
			}
			cost.MaterialBytes += n
			ap.zero.Discard()
			for _, bb := range ap.and {
				bb.DiscardOwn()
			}
			ap.zero = nil
			ap.and = [2]f2beaver.PartyBatch{}
			staticRaw, se := os.ReadFile(filepath.Join(roots[j], "static.json"))
			if se != nil {
				return cost, se
			}
			ap.zeroRef = &zeroReference{Binding: binding, Root: roots[j], OwnStaticSHA: sha256.Sum256(staticRaw)}
			if j == 0 {
				a.persistentRefs = append(a.persistentRefs, *ap.zeroRef)
			} else {
				b.persistentRefs = append(b.persistentRefs, *ap.zeroRef)
			}
			raw, e := json.Marshal(ap.zeroRef.Binding)
			if e != nil {
				return cost, e
			}
			path := filepath.Join(root, cost.Ticket, fmt.Sprintf("cs%d", j), fmt.Sprintf("zero-%02d.json", h))
			if e = writeReservation(path, raw); e != nil {
				return cost, e
			}
		}
		cost.Bindings = append(cost.Bindings, binding)
		if sb.anchorStore != nil && own1.Stage1 != nil {
			own1.Stage1.Discard()
		}
	}
	for _, p := range []*PartyPacket{a, b} {
		d := p.g.ledger
		f, e := os.Open(d)
		if e != nil {
			return cost, e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return cost, e
		}
	}
	return cost, nil
}

// Called once BEFORE tokens/online. Whole-query burn is first; then every
// occurrence's material ID is burned and loaded, never just the visited prefix.
func loadPersistentQuery(u *UserPacket, packets [2]*PartyPacket, statics [2]*Static) (cost PersistentLoad, err error) {
	if len(packets[0].anchor) == 0 {
		return cost, ErrBinding
	}
	if u.movieBinding != statics[0].movieBinding || u.movieBinding != statics[1].movieBinding || u.movieBinding != packets[0].movieBinding || u.movieBinding != packets[1].movieBinding {
		return cost, ErrBinding
	}
	start := time.Now()
	defer func() {
		cost.WallNS = time.Since(start).Nanoseconds()
		if err != nil {
			u.g.invalidate()
			for _, p := range packets {
				p.g.invalidate()
			}
		}
	}()
	for _, g := range []*guard{u.g, packets[0].g, packets[1].g} {
		if err = g.reserve(); err != nil {
			return cost, err
		}
	}
	for j, p := range packets {
		for h := range p.anchor {
			ap := &p.anchor[h]
			if ap.empty {
				if ap.zeroRef != nil || ap.zero != nil {
					return cost, ErrBinding
				}
				continue
			}
			ref := ap.zeroRef
			index := statics[j].target.Manifest().IndexID
			own, e := statics[j].anchorFor(ap.bucket)
			if e != nil {
				return cost, e
			}
			if ref == nil || ref.Binding.Spec.LayoutID != hex.EncodeToString(statics[j].payload.LayoutID[:]) || ref.Binding.Spec.IndexID != hex.EncodeToString(index[:]) || ref.Binding.Spec.T != own.T || ref.Binding.Spec.D != own.D || ref.Binding.Spec.StaticID != own.LabelID || ref.Binding.WholeTicket != hex.EncodeToString(p.id[:]) || ref.Binding.Occurrence != h || ref.Binding.Spec.Bucket != fmt.Sprint(ap.bucket) {
				return cost, ErrBinding
			}
			b, e := zeroagg.OpenBank(ref.Root, j, ref.Binding.Spec)
			if e != nil {
				return cost, e
			}
			party, bb, e := b.ClaimOccurrence(ref.Binding.ID, ref.Binding.WholeTicket, h)
			if e != nil {
				return cost, e
			}
			staticRaw, e := os.ReadFile(filepath.Join(ref.Root, "static.json"))
			if e != nil {
				return cost, e
			}
			if sha256.Sum256(staticRaw) != ref.OwnStaticSHA {
				return cost, ErrBinding
			}
			labels, e := b.StaticLabels()
			if e != nil {
				return cost, e
			}
			expected := own.Labels
			if len(labels) != len(expected) {
				return cost, ErrBinding
			} /* Do not branch on secret label values online: layout equality was checked offline. */
			if statics[j].anchorStore == nil {
				own.Labels = labels
				statics[j].anchor[ap.bucket] = own
			}
			ap.zero = party
			ap.and = [2]f2beaver.PartyBatch{bb.Slice(0, ref.Binding.Spec.T), bb.Slice(ref.Binding.Spec.T, 2*ref.Binding.Spec.T)}
			st, e := os.Stat(filepath.Join(ref.Root, "packets", ref.Binding.ID+".json"))
			if e != nil {
				return cost, e
			}
			cost.MaterialBytes += st.Size()
			cost.Packages++
			if statics[j].anchorStore != nil && own.Stage1 != nil {
				own.Stage1.Discard()
			}
		}
	}
	return cost, nil
}
func EnableZeroInterruption(p *PartyPacket) { p.interruptZero = true }

// Read-only failure audit: neither query nor old packets can become available
// again after process restart; an unclaimed suffix is quarantined on an error.
func CheckTicketBurned(u *UserPacket, a, b *PartyPacket) error {
	for _, g := range []*guard{u.g, a.g, b.g} {
		if g.ledger == "" {
			return ErrBinding
		}
		if _, e := os.Stat(filepath.Join(g.ledger, hex.EncodeToString(g.id[:])+".consumed")); e != nil {
			return e
		}
	}
	for _, p := range []*PartyPacket{a, b} {
		for _, ownRef := range p.persistentRefs {
			ref := ownRef.Binding
			bank, e := zeroagg.OpenBank(ownRef.Root, int(p.party), ref.Spec)
			if e != nil {
				return e
			}
			_, _, e = bank.ClaimOccurrence(ref.ID, ref.WholeTicket, ref.Occurrence)
			if !zeroagg.IsConsumed(e) {
				return fmt.Errorf("old package not refused: %v", e)
			}
		}
	}
	return nil
}
