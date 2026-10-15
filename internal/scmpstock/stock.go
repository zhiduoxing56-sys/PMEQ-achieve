// Package scmpstock is the separate, persistent, query-independent target
// position SCMP inventory. A dealer writes both roles; each cloud opens only
// its own role file. The small ledger is serialized with an OS file lock.
package scmpstock

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/share"
	"syscall"
)

const Version = "PMEQ-SCMP-STOCK-v3"
const ReserveCBytes uint64 = 15 << 30
const TemporaryBudget uint64 = 1 << 30

var ErrBinding = errors.New("scmpstock: version, role, index, plan or state mismatch")
var ErrShortage = errors.New("scmpstock: insufficient unbound inventory for admission or claim")

type Manifest struct {
	Version               string
	BankID                [16]byte
	IndexID, LayoutID     [16]byte
	IndexSeal             [32]byte
	Bin                   uint8
	MaxPosition           uint32
	Capacity, RecordBytes int
	RoleSHA256            [2][32]byte
}

type Admission struct {
	Guarantee             int
	Closed                bool
	QueryID               [16]byte
	Plan                  [32]byte
	Start, Count          int
	RoleClaim, RoleFinish [2]bool
	Burned                bool
}
type Ledger struct {
	Version    string
	BankID     [16]byte
	NextFree   int
	Admissions map[string]Admission
}

type Unit struct {
	ID         [16]byte
	Theta, Rho [2]uint32
	Key        [2]anchorfilter.SCMPKeyShare
}

type Pool struct {
	Root     string
	Role     uint8
	Manifest Manifest
	file     *os.File
}

func keyBytes(bin uint8) int    { return 88 + 28*int(bin) }
func recordBytes(bin uint8) int { return 16 + 8 + 8 + 2*(keyBytes(bin)+1) }
func randomRing(bin uint8) (uint32, error) {
	var b [4]byte
	_, e := io.ReadFull(rand.Reader, b[:])
	return binary.LittleEndian.Uint32(b[:]) & ((uint32(1) << bin) - 1), e
}
func split(v uint32, bin uint8) ([2]uint32, error) {
	a, e := randomRing(bin)
	return [2]uint32{a, (v - a) & ((uint32(1) << bin) - 1)}, e
}
func rolePath(root string, role uint8) string {
	return filepath.Join(root, fmt.Sprintf("cs%d.stock", role))
}

// CheckBudget uses the backing WSL filesystem and the actual Windows C mount.
// It rejects writes if either cannot cover expected output, temporary space,
// and the C-system reserve. It never substitutes WSL free bytes for C free.
func CheckBudget(path string, expected uint64) error {
	if expected > ^uint64(0)-TemporaryBudget-ReserveCBytes {
		return ErrShortage
	}
	var local, windows syscall.Statfs_t
	if e := syscall.Statfs(path, &local); e != nil {
		return e
	}
	if e := syscall.Statfs("/mnt/c", &windows); e != nil {
		return fmt.Errorf("Windows C free space unavailable: %w", e)
	}
	localFree := uint64(local.Bavail) * uint64(local.Bsize)
	cFree := uint64(windows.Bavail) * uint64(windows.Bsize)
	if localFree < expected+TemporaryBudget || cFree < expected+TemporaryBudget+ReserveCBytes {
		return fmt.Errorf("%w: expected=%d temporary=%d WSL_free=%d C_free=%d C_reserve=%d", ErrShortage, expected, TemporaryBudget, localFree, cFree, ReserveCBytes)
	}
	return nil
}

// Generate writes a new bank exactly once. No query input is accepted. The
// role files are streamed; no second full-sized copy is created.
func Generate(root string, index, layout [16]byte, seal [32]byte, bin uint8, maxPosition uint32, count int, backend anchorfilter.SCMPBackend) (Manifest, error) {
	var m Manifest
	if root == "" || index == [16]byte{} || layout == [16]byte{} || seal == [32]byte{} || (bin != 7 && bin != 10) || maxPosition >= (uint32(1)<<(bin-1))-1 || count < 1 || backend == nil {
		return m, ErrBinding
	}
	parent := filepath.Dir(root)
	if e := os.MkdirAll(parent, 0700); e != nil {
		return m, e
	}
	expected := uint64(count)*uint64(recordBytes(bin))*2 + (1 << 20)
	if e := CheckBudget(parent, expected); e != nil {
		return m, e
	}
	if e := os.Mkdir(root, 0700); e != nil {
		return m, e
	}
	m = Manifest{Version: Version, IndexID: index, LayoutID: layout, IndexSeal: seal, Bin: bin, MaxPosition: maxPosition, Capacity: count, RecordBytes: recordBytes(bin)}
	if _, e := io.ReadFull(rand.Reader, m.BankID[:]); e != nil {
		return m, e
	}
	var f [2]*os.File
	var h [2]io.Writer
	var hashes [2]hashWriter
	for p := 0; p < 2; p++ {
		var e error
		f[p], e = os.OpenFile(rolePath(root, uint8(p)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return m, e
		}
		hashes[p] = hashWriter{h: sha256.New()}
		h[p] = io.MultiWriter(f[p], hashes[p].h)
	}
	for j := 0; j < count; j++ {
		if j%8192 == 0 {
			remaining := uint64(count-j) * uint64(m.RecordBytes) * 2
			if e := CheckBudget(root, remaining); e != nil {
				return m, e
			}
		}
		var id [16]byte
		if _, e := io.ReadFull(rand.Reader, id[:]); e != nil {
			return m, e
		}
		var theta, rho [2]uint32
		var ts, rs [2][2]uint32
		var keys [2][2]anchorfilter.SCMPKeyShare
		for side := 0; side < 2; side++ {
			var e error
			if theta[side], e = randomRing(bin); e != nil {
				return m, e
			}
			if rho[side], e = randomRing(bin); e != nil {
				return m, e
			}
			if ts[side], e = split(theta[side], bin); e != nil {
				return m, e
			}
			if rs[side], e = split(rho[side], bin); e != nil {
				return m, e
			}
			omega, e := randomRing(1)
			if e != nil {
				return m, e
			}
			keys[0][side], keys[1][side], e = backend.KeyGen(bin, rho[side], theta[side], domain.Bit(omega != 0))
			if e != nil {
				return m, e
			}
		}
		for p := 0; p < 2; p++ {
			buf := make([]byte, m.RecordBytes)
			copy(buf[:16], id[:])
			for side := 0; side < 2; side++ {
				binary.LittleEndian.PutUint32(buf[16+4*side:], ts[side][p])
				binary.LittleEndian.PutUint32(buf[24+4*side:], rs[side][p])
				key := keys[p][side].Opaque()
				if len(key) != keyBytes(bin) {
					return m, ErrBinding
				}
				start := 32 + side*(len(key)+1)
				copy(buf[start:], key)
				if keys[p][side].OutputMaskShare().Value() {
					buf[start+len(key)] = 1
				}
			}
			if _, e := h[p].Write(buf); e != nil {
				return m, e
			}
		}
	}
	for p := 0; p < 2; p++ {
		if e := f[p].Sync(); e != nil {
			return m, e
		}
		if e := f[p].Close(); e != nil {
			return m, e
		}
		copy(m.RoleSHA256[p][:], hashes[p].h.Sum(nil))
	}
	ledger := Ledger{Version: Version, BankID: m.BankID, Admissions: map[string]Admission{}}
	if e := writeExclusiveJSON(filepath.Join(root, "ledger.json"), ledger); e != nil {
		return m, e
	}
	if e := writeExclusiveJSON(filepath.Join(root, "manifest.json"), m); e != nil {
		return m, e
	}
	if e := syncDir(root); e != nil {
		return m, e
	}
	return m, nil
}

type hashWriter struct {
	h interface {
		io.Writer
		Sum([]byte) []byte
	}
}

func writeExclusiveJSON(path string, v any) error {
	raw, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(append(raw, '\n'))
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

func Open(root string, role uint8, index, layout [16]byte, seal [32]byte, bin uint8) (*Pool, error) {
	if role > 1 {
		return nil, ErrBinding
	}
	raw, e := os.ReadFile(filepath.Join(root, "manifest.json"))
	if e != nil {
		return nil, e
	}
	var m Manifest
	if json.Unmarshal(raw, &m) != nil || m.Version != Version || m.IndexID != index || m.LayoutID != layout || m.IndexSeal != seal || m.Bin != bin || m.Capacity < 1 || m.RecordBytes != recordBytes(bin) {
		return nil, ErrBinding
	}
	f, e := os.Open(rolePath(root, role))
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil || st.Size() != int64(m.Capacity)*int64(m.RecordBytes) {
		f.Close()
		return nil, ErrBinding
	}
	// The authenticated index seal and manifest bind each role's exact file.
	// Verification is streaming and keeps no peer material in this process.
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		f.Close()
		return nil, e
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	if digest != m.RoleSHA256[role] {
		f.Close()
		return nil, ErrBinding
	}
	return &Pool{Root: root, Role: role, Manifest: m, file: f}, nil
}
func (p *Pool) Close() error {
	if p == nil || p.file == nil {
		return nil
	}
	return p.file.Close()
}
func (p *Pool) ReadUnit(index int) (Unit, error) {
	var u Unit
	if p == nil || index < 0 || index >= p.Manifest.Capacity {
		return u, ErrBinding
	}
	b := make([]byte, p.Manifest.RecordBytes)
	if _, e := p.file.ReadAt(b, int64(index)*int64(len(b))); e != nil {
		return u, e
	}
	copy(u.ID[:], b[:16])
	m := (uint32(1) << p.Manifest.Bin) - 1
	for side := 0; side < 2; side++ {
		u.Theta[side] = binary.LittleEndian.Uint32(b[16+4*side:])
		u.Rho[side] = binary.LittleEndian.Uint32(b[24+4*side:])
		start := 32 + side*(keyBytes(p.Manifest.Bin)+1)
		rb := b[start+keyBytes(p.Manifest.Bin)]
		if u.Theta[side] > m || u.Rho[side] > m || rb > 1 {
			return Unit{}, ErrBinding
		}
		u.Key[side] = anchorfilter.NewSCMPKeyShare(b[start:start+keyBytes(p.Manifest.Bin)], share.NewBitShare(domain.Bit(rb == 1)))
	}
	return u, nil
}

// withLedger owns an advisory lock across the complete read/modify/fsync/rename
// transaction. A crash after Claim returns cannot recover its units as FREE.
func withLedger(root string, fn func(*Ledger) error) error {
	lock, e := os.OpenFile(filepath.Join(root, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); e != nil {
		return e
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	raw, e := os.ReadFile(filepath.Join(root, "ledger.json"))
	if e != nil {
		return e
	}
	var l Ledger
	if json.Unmarshal(raw, &l) != nil || l.Version != Version || l.Admissions == nil {
		return ErrBinding
	}
	if e = fn(&l); e != nil {
		return e
	}
	f, e := os.CreateTemp(root, "ledger.next.*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	enc, e := json.Marshal(l)
	if e == nil {
		_, e = f.Write(append(enc, '\n'))
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, filepath.Join(root, "ledger.json")); e != nil {
		return e
	}
	return syncDir(root)
}
func idKey(id [16]byte) string { return hex.EncodeToString(id[:]) }

func (p *Pool) Admit(ticket [16]byte, guarantee int) error {
	if p == nil || ticket == [16]byte{} || guarantee < 0 || guarantee > p.Manifest.Capacity {
		return ErrBinding
	}
	return withLedger(p.Root, func(l *Ledger) error {
		if l.BankID != p.Manifest.BankID {
			return ErrBinding
		}
		if _, ok := l.Admissions[idKey(ticket)]; ok {
			return ErrBinding
		}
		reserved := 0
		for _, a := range l.Admissions {
			if !a.Closed {
				reserved += a.Guarantee
			}
		}
		if p.Manifest.Capacity-l.NextFree-reserved < guarantee {
			return ErrShortage
		}
		l.Admissions[idKey(ticket)] = Admission{Guarantee: guarantee}
		return nil
	})
}
func (p *Pool) Claim(ticket, query [16]byte, plan [32]byte, count int) (start int, err error) {
	if p == nil || ticket == [16]byte{} || query == [16]byte{} || plan == [32]byte{} || count < 0 || p.Role > 1 {
		return 0, ErrBinding
	}
	err = withLedger(p.Root, func(l *Ledger) error {
		if l.BankID != p.Manifest.BankID {
			return ErrBinding
		}
		a, ok := l.Admissions[idKey(ticket)]
		if !ok || a.Closed || a.Burned || a.RoleClaim[p.Role] {
			return ErrBinding
		}
		if a.QueryID == [16]byte{} {
			if count > a.Guarantee || count > p.Manifest.Capacity-l.NextFree {
				return ErrShortage
			}
			a.QueryID, a.Plan, a.Start, a.Count = query, plan, l.NextFree, count
			l.NextFree += count
		} else if a.QueryID != query || a.Plan != plan || a.Count != count {
			return ErrBinding
		}
		a.RoleClaim[p.Role] = true
		start = a.Start
		l.Admissions[idKey(ticket)] = a
		return nil
	})
	return
}
func (p *Pool) Finish(ticket [16]byte, success bool) error {
	if p == nil || ticket == [16]byte{} || p.Role > 1 {
		return ErrBinding
	}
	return withLedger(p.Root, func(l *Ledger) error {
		if l.BankID != p.Manifest.BankID {
			return ErrBinding
		}
		a, ok := l.Admissions[idKey(ticket)]
		if !ok || a.Closed || !a.RoleClaim[p.Role] || a.RoleFinish[p.Role] || (a.Burned && success) {
			return ErrBinding
		}
		a.RoleFinish[p.Role] = true
		if !success {
			a.Burned = true
			a.Closed = true
		}
		if a.RoleFinish[0] && a.RoleFinish[1] {
			a.Closed = true
		}
		l.Admissions[idKey(ticket)] = a
		return nil
	})
}
func (p *Pool) Abort(ticket [16]byte) error {
	if p == nil || ticket == [16]byte{} {
		return ErrBinding
	}
	return withLedger(p.Root, func(l *Ledger) error {
		if l.BankID != p.Manifest.BankID {
			return ErrBinding
		}
		a, ok := l.Admissions[idKey(ticket)]
		if !ok || a.Closed {
			return ErrBinding
		}
		a.Burned = true
		a.Closed = true
		l.Admissions[idKey(ticket)] = a
		return nil
	})
}
func (p *Pool) Status() (Ledger, error) {
	var l Ledger
	raw, e := os.ReadFile(filepath.Join(p.Root, "ledger.json"))
	if e != nil {
		return l, e
	}
	if json.Unmarshal(raw, &l) != nil || l.Version != Version || l.BankID != p.Manifest.BankID {
		return Ledger{}, ErrBinding
	}
	return l, nil
}
