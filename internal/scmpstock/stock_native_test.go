//go:build phase6native

package scmpstock

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"pmeq/internal/scmpnative"
	"sync"
	"testing"
)

func TestPersistentPairingAdmissionAndCrash(t *testing.T) {
	root := filepath.Join(t.TempDir(), "bank")
	index, layout, seal := [16]byte{1}, [16]byte{2}, [32]byte{3}
	m, e := Generate(root, index, layout, seal, 7, 62, 8, scmpnative.Backend{})
	if e != nil {
		t.Fatal(e)
	}
	open := func(role uint8) *Pool {
		p, e := Open(root, role, index, layout, seal, 7)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	a, b := open(0), open(1)
	if a.Manifest != b.Manifest || a.Manifest != m {
		t.Fatal("role mismatch")
	}
	for i := 0; i < m.Capacity; i++ {
		x, e := a.ReadUnit(i)
		if e != nil {
			t.Fatal(e)
		}
		y, e := b.ReadUnit(i)
		if e != nil {
			t.Fatal(e)
		}
		if x.ID != y.ID {
			t.Fatal("unpaired keys")
		}
	}
	if _, e = Open(root, 1, index, layout, [32]byte{4}, 7); !errors.Is(e, ErrBinding) {
		t.Fatal("wrong seal")
	}
	if _, e = Open(root, 1, [16]byte{4}, layout, seal, 7); !errors.Is(e, ErrBinding) {
		t.Fatal("wrong index")
	}
	if _, e = Open(root, 1, index, [16]byte{4}, seal, 7); !errors.Is(e, ErrBinding) {
		t.Fatal("wrong layout")
	}
	if _, e = Open(root, 2, index, layout, seal, 7); !errors.Is(e, ErrBinding) {
		t.Fatal("invalid cloud role")
	}
	if _, e = Open(root, 1, index, layout, seal, 10); !errors.Is(e, ErrBinding) {
		t.Fatal("wrong width")
	}
	ticket, query := [16]byte{5}, [16]byte{6}
	plan := [32]byte{7}
	if e = a.Admit(ticket, 8); e != nil {
		t.Fatal(e)
	}
	if _, e = a.Claim([16]byte{99}, query, plan, 1); !errors.Is(e, ErrBinding) {
		t.Fatal("unknown ticket claimed")
	}
	if e = a.Admit([16]byte{8}, 1); !errors.Is(e, ErrShortage) {
		t.Fatal("guarantee oversubscribed")
	}
	if _, e = a.Claim(ticket, query, plan, 9); !errors.Is(e, ErrShortage) {
		t.Fatal("over-guarantee claim not rejected")
	}
	before, e := a.Status()
	if e != nil || before.NextFree != 0 {
		t.Fatal("shortage consumed partial stock", e, before.NextFree)
	}
	start, e := a.Claim(ticket, query, plan, 3)
	if e != nil || start != 0 {
		t.Fatal(e, start)
	}
	if _, e = a.Claim(ticket, query, plan, 3); !errors.Is(e, ErrBinding) {
		t.Fatal("role replay")
	}
	if _, e = b.Claim(ticket, query, [32]byte{9}, 3); !errors.Is(e, ErrBinding) {
		t.Fatal("plan mismatch")
	}
	if _, e = b.Claim(ticket, query, plan, 4); !errors.Is(e, ErrBinding) {
		t.Fatal("count mismatch")
	}
	start, e = b.Claim(ticket, query, plan, 3)
	if e != nil || start != 0 {
		t.Fatal("clouds claimed distinct ranges", e, start)
	}
	if _, e = b.Claim(ticket, [16]byte{10}, plan, 3); !errors.Is(e, ErrBinding) {
		t.Fatal("rebound query accepted")
	}
	// Simulate both processes dying after claim, before result completion.
	a.Close()
	b.Close()
	a, b = open(0), open(1)
	defer a.Close()
	defer b.Close()
	l, e := a.Status()
	if e != nil || l.NextFree != 3 {
		t.Fatal("claim rolled back after restart", e, l)
	}
	if _, e = a.Claim(ticket, query, plan, 3); !errors.Is(e, ErrBinding) {
		t.Fatal("restart replay")
	}
	if e = a.Finish(ticket, false); e != nil {
		t.Fatal(e)
	}
	if e = b.Finish(ticket, true); !errors.Is(e, ErrBinding) {
		t.Fatal("burned claim accepted")
	}
	if e = b.Finish(ticket, false); !errors.Is(e, ErrBinding) {
		t.Fatal("burned claim reopened", e)
	}
	if e = a.Admit([16]byte{10}, 6); !errors.Is(e, ErrShortage) {
		t.Fatal("burned units restored")
	}
	if e = a.Admit([16]byte{10}, 5); e != nil {
		t.Fatal("unbound stock unavailable", e)
	}
	// Tampering with a unit ID must fail the own-role file hash before any key
	// can be attached to a query plan.
	f, e := os.OpenFile(rolePath(root, 1), os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	var first [1]byte
	if _, e = f.ReadAt(first[:], 0); e != nil {
		t.Fatal(e)
	}
	first[0] ^= 1
	if _, e = f.WriteAt(first[:], 0); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(root, 1, index, layout, seal, 7); !errors.Is(e, ErrBinding) {
		t.Fatal("tampered unit ID accepted", e)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	raw, e := os.ReadFile(manifestPath)
	if e != nil {
		t.Fatal(e)
	}
	raw = bytes.Replace(raw, []byte(Version), []byte("PMEQ-SCMP-STOCK-v2"), 1)
	if e = os.WriteFile(manifestPath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Open(root, 0, index, layout, seal, 7); !errors.Is(e, ErrBinding) {
		t.Fatal("wrong stock protocol version accepted", e)
	}
}

func TestConcurrentClaimsNeverOverlap(t *testing.T) {
	root := filepath.Join(t.TempDir(), "bank")
	index, layout, seal := [16]byte{11}, [16]byte{12}, [32]byte{13}
	_, e := Generate(root, index, layout, seal, 7, 62, 8, scmpnative.Backend{})
	if e != nil {
		t.Fatal(e)
	}
	a, e := Open(root, 0, index, layout, seal, 7)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := Open(root, 0, index, layout, seal, 7)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	tickets := [2][16]byte{{1}, {2}}
	for _, ticket := range tickets {
		if e := a.Admit(ticket, 4); e != nil {
			t.Fatal(e)
		}
	}
	var starts [2]int
	var errs [2]error
	var wg sync.WaitGroup
	for i, pool := range [2]*Pool{a, b} {
		wg.Add(1)
		go func(i int, pool *Pool) {
			defer wg.Done()
			starts[i], errs[i] = pool.Claim(tickets[i], [16]byte{byte(i + 3)}, [32]byte{byte(i + 5)}, 4)
		}(i, pool)
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || (starts[0] != 0 && starts[0] != 4) || starts[0]+starts[1] != 4 {
		t.Fatal("concurrent claims overlap or failed", starts, errs)
	}
	status, e := a.Status()
	if e != nil || status.NextFree != 8 {
		t.Fatal(e, status.NextFree)
	}
}
