package discovery

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"pmeq/internal/imdbprod"
	"pmeq/internal/material"
	"strings"
	"time"
)

const ticketStoreVersion = "IMDB-OFFLINE-TICKET-v1"

type TicketRoleManifest struct {
	Version, Role, Ticket, BindingSHA256, IndexSealSHA256            string
	LayoutID, KeyFingerprint, TargetManifestSHA256                   string
	Buckets                                                          []uint32
	CandidateCapacity, TargetRoutes, TargetSlots, TargetGroups, Uses int
	MaterialSHA256                                                   string
	MaterialBytes                                                    int64
}

type TicketSeal struct {
	Version, Ticket, BindingSHA256, IndexSealSHA256 string
	RoleManifestSHA256                              [3]string // user, cs0, cs1
}

type FullTicketCost struct {
	Ticket                string
	RoleBytes             [3]int64
	Zero                  PersistenceCost
	WallNS                int64
	MaxTemporaryFileBytes int64
}

func roleName(i int) string {
	if i == 0 {
		return "user"
	}
	return fmt.Sprintf("cs%d", i-1)
}

func ticketManifest(role string, u *UserPacket, s *Static, indexSeal, binding [32]byte) TicketRoleManifest {
	target := s.target.ManifestDigest()
	return TicketRoleManifest{Version: ticketStoreVersion, Role: role, Ticket: hex.EncodeToString(u.id[:]), BindingSHA256: hex.EncodeToString(binding[:]), IndexSealSHA256: hex.EncodeToString(indexSeal[:]),
		LayoutID: hex.EncodeToString(u.layout[:]), KeyFingerprint: u.keyFingerprint, TargetManifestSHA256: hex.EncodeToString(target[:]), Buckets: append([]uint32(nil), u.buckets...),
		CandidateCapacity: imdbprod.CandidateCapacity, TargetRoutes: imdbprod.CandidateCapacity * imdbprod.TargetSignatures,
		TargetSlots: imdbprod.CandidateCapacity * imdbprod.TargetSignatures * imdbprod.TargetBucketSlots, TargetGroups: imdbprod.TargetGroupCapacity, Uses: 1}
}

// PersistFullTicket seals one fixed public-capacity query ticket. No cloud
// file contains the peer share or either master key. The seal is published
// last; an interrupted write has no loadable ticket.
func PersistFullTicket(root string, indexSeal [32]byte, u *UserPacket, a, b *PartyPacket, sa, sb *Static) (seal TicketSeal, digest [32]byte, cost FullTicketCost, err error) {
	start := time.Now()
	defer func() { cost.WallNS = time.Since(start).Nanoseconds() }()
	if u == nil || a == nil || b == nil || sa == nil || sb == nil || indexSeal == [32]byte{} || sa.productionSeal != indexSeal || sb.productionSeal != indexSeal || u.movieBinding == [32]byte{} || u.movieBinding != sa.movieBinding || sa.movieBinding != sb.movieBinding || u.keyFingerprint != sa.keyFingerprint || u.keyFingerprint != sb.keyFingerprint || a.id != u.id || b.id != u.id || len(u.buckets) != imdbprod.AnchorSignatures {
		return seal, digest, cost, ErrBinding
	}
	if sa.target.ManifestDigest() != sb.target.ManifestDigest() || sa.payload.LayoutID != sb.payload.LayoutID || u.layout != sa.payload.LayoutID {
		return seal, digest, cost, ErrBinding
	}
	ticket := hex.EncodeToString(u.id[:])
	ticketDir := filepath.Join(root, ticket)
	if err = os.MkdirAll(root, 0700); err != nil {
		return
	}
	if info, e := os.Lstat(root); e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		err = ErrBinding
		return
	}
	// PersistReservation lays out the zero banks below each party directory.
	cost.Zero, err = PersistReservation(root, ticketDir, u, a, b, sa, sb)
	if err != nil {
		return
	}
	cost.Ticket = ticket
	seal = TicketSeal{Version: ticketStoreVersion, Ticket: ticket, BindingSHA256: hex.EncodeToString(u.movieBinding[:]), IndexSealSHA256: hex.EncodeToString(indexSeal[:])}
	for i := 0; i < 3; i++ {
		role := roleName(i)
		roleDir := filepath.Join(ticketDir, role)
		var m TicketRoleManifest
		m = ticketManifest(role, u, sa, indexSeal, u.movieBinding)
		var save func(*material.StreamEncoder)
		if i == 0 {
			save = u.writeOwn
		} else if i == 1 {
			save = func(e *material.StreamEncoder) { a.writeOwn(e, sa) }
		} else {
			save = func(e *material.StreamEncoder) { b.writeOwn(e, sb) }
		}
		m.MaterialBytes, m.MaterialSHA256, err = writeMaterialFile(roleDir, save)
		if err != nil {
			return
		}
		cost.RoleBytes[i] = m.MaterialBytes
		if m.MaterialBytes > cost.MaxTemporaryFileBytes {
			cost.MaxTemporaryFileBytes = m.MaterialBytes
		}
		raw, e := json.Marshal(m)
		if e != nil {
			err = e
			return
		}
		if err = writeReservation(filepath.Join(roleDir, "manifest.json"), raw); err != nil {
			return
		}
		sha := sha256.Sum256(raw)
		seal.RoleManifestSHA256[i] = hex.EncodeToString(sha[:])
		if err = syncDirectory(roleDir); err != nil {
			return
		}
	}
	raw, e := json.Marshal(seal)
	if e != nil {
		err = e
		return
	}
	if err = writeReservation(filepath.Join(ticketDir, "ticket-seal.json"), raw); err != nil {
		return
	}
	if err = syncDirectory(ticketDir); err != nil {
		return
	}
	digest = sha256.Sum256(raw)
	return
}

func syncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

func writeMaterialFile(dir string, save func(*material.StreamEncoder)) (int64, string, error) {
	path := filepath.Join(dir, "material.bin")
	if _, e := os.Lstat(path); e == nil {
		return 0, "", ErrBinding
	} else if !os.IsNotExist(e) {
		return 0, "", e
	}
	f, e := os.CreateTemp(dir, ".material-*")
	if e != nil {
		return 0, "", e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return 0, "", e
	}
	h := sha256.New()
	w := bufio.NewWriterSize(io.MultiWriter(f, h), 1<<20)
	enc := &material.StreamEncoder{W: w}
	save(enc)
	if enc.Err == nil {
		enc.Err = w.Flush()
	}
	if enc.Err == nil {
		enc.Err = f.Sync()
	}
	closeErr := f.Close()
	if enc.Err != nil {
		return 0, "", enc.Err
	}
	if closeErr != nil {
		return 0, "", closeErr
	}
	info, e := os.Lstat(f.Name())
	if e != nil {
		return 0, "", e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return 0, "", e
	}
	if e = syncDirectory(dir); e != nil {
		return 0, "", e
	}
	return info.Size(), hex.EncodeToString(h.Sum(nil)), nil
}

func ReadTicketSeal(ticketDir string, expected [32]byte) (TicketSeal, error) {
	var seal TicketSeal
	if expected == [32]byte{} {
		return seal, ErrBinding
	}
	raw, e := os.ReadFile(filepath.Join(ticketDir, "ticket-seal.json"))
	if e != nil {
		return seal, e
	}
	if sha256.Sum256(raw) != expected || json.Unmarshal(raw, &seal) != nil || seal.Version != ticketStoreVersion || seal.Ticket != filepath.Base(ticketDir) || len(seal.Ticket) != 32 {
		return TicketSeal{}, ErrBinding
	}
	for _, v := range seal.RoleManifestSHA256 {
		if len(v) != 64 {
			return TicketSeal{}, ErrBinding
		}
	}
	return seal, nil
}

func readRoleManifest(dir string, expected [32]byte, role string, binding imdbprod.Binding, indexSeal [32]byte, ticket [16]byte, targetDigest [32]byte) (TicketRoleManifest, error) {
	var m TicketRoleManifest
	bind, e := binding.Digest()
	if e != nil || expected == [32]byte{} || indexSeal == [32]byte{} || targetDigest == [32]byte{} {
		return m, ErrBinding
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 || filepath.Base(dir) != role {
		return m, ErrBinding
	}
	path := filepath.Join(dir, "manifest.json")
	info, e = os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return m, ErrBinding
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return m, e
	}
	if sha256.Sum256(raw) != expected || json.Unmarshal(raw, &m) != nil || m.Version != ticketStoreVersion || m.Role != role || m.Ticket != hex.EncodeToString(ticket[:]) || m.BindingSHA256 != hex.EncodeToString(bind[:]) || m.IndexSealSHA256 != hex.EncodeToString(indexSeal[:]) || m.LayoutID != hex.EncodeToString(binding.LayoutID[:]) || m.KeyFingerprint != binding.KeyFingerprint || m.TargetManifestSHA256 != hex.EncodeToString(targetDigest[:]) || len(m.Buckets) != imdbprod.AnchorSignatures || m.CandidateCapacity != imdbprod.CandidateCapacity || m.TargetRoutes != imdbprod.CandidateCapacity*imdbprod.TargetSignatures || m.TargetSlots != imdbprod.CandidateCapacity*imdbprod.TargetSignatures*imdbprod.TargetBucketSlots || m.TargetGroups != imdbprod.TargetGroupCapacity || m.Uses != 1 || m.MaterialBytes < 64 || len(m.MaterialSHA256) != 64 {
		return TicketRoleManifest{}, ErrBinding
	}
	for _, bucket := range m.Buckets {
		if bucket >= 1<<imdbprod.BucketBits {
			return TicketRoleManifest{}, ErrBinding
		}
	}
	return m, nil
}

func readMaterialFile(dir string, m TicketRoleManifest, load func(*material.StreamDecoder) error) error {
	path := filepath.Join(dir, "material.bin")
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != m.MaterialBytes {
		return ErrBinding
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	h := sha256.New()
	r := io.TeeReader(bufio.NewReaderSize(f, 1<<20), h)
	d := &material.StreamDecoder{R: r}
	if e = load(d); e != nil {
		return e
	}
	if d.Err != nil {
		return d.Err
	}
	var extra [1]byte
	n, e := r.Read(extra[:])
	if n != 0 || e != io.EOF || hex.EncodeToString(h.Sum(nil)) != m.MaterialSHA256 {
		return ErrBinding
	}
	return nil
}

func OpenUserTicket(dir string, manifestSHA [32]byte, binding imdbprod.Binding, indexSeal [32]byte, ticket [16]byte, targetDigest [32]byte) (*UserPacket, error) {
	m, e := readRoleManifest(dir, manifestSHA, "user", binding, indexSeal, ticket, targetDigest)
	if e != nil {
		return nil, e
	}
	bind, _ := binding.Digest()
	var u *UserPacket
	e = readMaterialFile(dir, m, func(d *material.StreamDecoder) error {
		var err error
		u, err = readUserOwn(d, ticket, bind, binding.LayoutID, binding.KeyFingerprint, dir, m.Buckets)
		return err
	})
	if e != nil {
		return nil, e
	}
	return u, nil
}

func OpenPartyTicket(dir string, manifestSHA [32]byte, binding imdbprod.Binding, indexSeal [32]byte, ticket [16]byte, s *Static) (*PartyPacket, error) {
	if s == nil || s.party > 1 || s.target == nil || s.movieBinding == [32]byte{} || s.productionSeal != indexSeal {
		return nil, ErrBinding
	}
	role := fmt.Sprintf("cs%d", s.party)
	m, e := readRoleManifest(dir, manifestSHA, role, binding, indexSeal, ticket, s.target.ManifestDigest())
	if e != nil {
		return nil, e
	}
	bind, _ := binding.Digest()
	if s.movieBinding != bind || s.payload.LayoutID != binding.LayoutID {
		return nil, ErrBinding
	}
	var p *PartyPacket
	e = readMaterialFile(dir, m, func(d *material.StreamDecoder) error {
		var err error
		p, err = readPartyOwn(d, ticket, bind, dir, m.Buckets, s)
		return err
	})
	if e != nil {
		return nil, e
	}
	return p, nil
}

func TicketRoleDigest(seal TicketSeal, role string) ([32]byte, error) {
	var out [32]byte
	i := -1
	for j := 0; j < 3; j++ {
		if roleName(j) == role {
			i = j
			break
		}
	}
	if i < 0 || seal.Version != ticketStoreVersion {
		return out, ErrBinding
	}
	b, e := hex.DecodeString(seal.RoleManifestSHA256[i])
	if e != nil || len(b) != 32 {
		return out, ErrBinding
	}
	copy(out[:], b)
	return out, nil
}

func TicketID(seal TicketSeal) ([16]byte, error) {
	var out [16]byte
	b, e := hex.DecodeString(seal.Ticket)
	if e != nil || len(b) != 16 || strings.ToLower(seal.Ticket) != seal.Ticket {
		return out, ErrBinding
	}
	copy(out[:], b)
	return out, nil
}
