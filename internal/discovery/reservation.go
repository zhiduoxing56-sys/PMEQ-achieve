package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"pmeq/internal/aggregation"
)

// PersistReservation is offline-only and must finish before tokens are made.
// Existing comparison/triple handles remain resident and are all protected by
// this durable, party-local reservation burn. Restart never refills a ticket.
// The new permutation factors/masks are independently sealed per party.
func persistBaseReservation(root string, u *UserPacket, a, b *PartyPacket) error {
	if u == nil || a == nil || b == nil || u.g == nil || a.g == nil || b.g == nil || a.id != u.id || b.id != u.id || a.movieBinding != u.movieBinding || b.movieBinding != u.movieBinding || (a.output == nil) != (b.output == nil) || a.g.used || b.g.used {
		return ErrBinding
	}
	dir := filepath.Join(root, hex.EncodeToString(u.id[:]))
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	for _, x := range []struct {
		name string
		p    *PartyPacket
	}{{"cs0", a}, {"cs1", b}} {
		d := filepath.Join(dir, x.name)
		if e := os.Mkdir(d, 0700); e != nil {
			return e
		}
		permutationDigest := ""
		outputCapacity := 26 // original generic target interface; no selected output permutation.
		if x.p.output != nil {
			outputCapacity = 16
			raw, e := x.p.output.Seal()
			if e != nil {
				return e
			}
			f, e := os.OpenFile(filepath.Join(d, "output-permutation.bin"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
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
			h := sha256.Sum256(raw)
			permutationDigest = hex.EncodeToString(h[:])
			// Exercise the same authenticated party-local loader that a later
			// process would use. It cannot load the peer's factor.
			sealed, e := os.ReadFile(filepath.Join(d, "output-permutation.bin"))
			if e != nil {
				return e
			}
			x.p.output, e = aggregation.LoadPairPermutation(sealed, h, x.p.party, u.layout, 16*x.p.capacity)
			if e != nil {
				return e
			}
			if e = x.p.output.BindLedger(d); e != nil {
				return e
			}

		}
		meta, e := json.Marshal(struct {
			Packet, Layout                   [16]byte
			MovieBinding                     [32]byte
			C, D                             int
			SharingDomain, PermutationSHA256 string
		}{u.id, u.layout, u.movieBinding, x.p.capacity, outputCapacity, "F2xRing64xRing64-v1", permutationDigest})
		if e != nil {
			return e
		}
		if e = writeReservation(filepath.Join(d, "reservation.json"), meta); e != nil {
			return e
		}
		x.p.g.ledger = d
		x.p.g.id = u.id
	}
	if e := os.Mkdir(filepath.Join(dir, "user"), 0700); e != nil {
		return e
	}
	u.g.ledger = filepath.Join(dir, "user")
	u.g.id = u.id
	for _, path := range []string{filepath.Join(dir, "cs0"), filepath.Join(dir, "cs1"), u.g.ledger, dir, root} {
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return e
		}
	}
	return nil
}

func writeReservation(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
