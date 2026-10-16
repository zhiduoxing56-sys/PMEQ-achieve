//go:build phase6native

package discovery

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"pmeq/internal/candidatequery"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpnative"
	"pmeq/internal/scmpstock"
	"pmeq/internal/targetaggregation"
	"testing"
	"time"
)

func TestInventoryFullCryptographicChain(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "K0", true: "K1"}[present], func(t *testing.T) {
			f := newDomainFixture(t, 7, present)
			upper, e := f.st[0].PublicAnchorSlotUpperBound(f.buckets, 7)
			if e != nil || upper < f.shape.K {
				t.Fatal("public admission bound", upper, f.shape.K, e)
			}
			lineage := f.st[0].target.Lineage()
			root := filepath.Join(t.TempDir(), "stock")
			seal := [32]byte{1}
			capacity := max(4, f.shape.S+3)
			manifest, e := scmpstock.Generate(root, lineage.IndexID, lineage.LayoutID, seal, 7, 62, capacity, scmpnative.Backend{})
			domainMust(t, e)
			var pools [2]*scmpstock.Pool
			for role := 0; role < 2; role++ {
				pools[role], e = scmpstock.Open(root, uint8(role), lineage.IndexID, lineage.LayoutID, seal, 7)
				domainMust(t, e)
				defer pools[role].Close()
			}
			if pools[0].Manifest != pools[1].Manifest {
				t.Fatal("role manifest mismatch")
			}
			u, p0, p1, _, e := ProvisionInventory(f.st[0], f.st[1], f.buckets, f.cap, f.shape, scmpnative.Backend{}, false, manifest.BankID)
			domainMust(t, e)
			_, e = PersistReservation(t.TempDir(), t.TempDir(), u, p0, p1, f.st[0], f.st[1])
			domainMust(t, e)
			if !errors.Is(BindInventoryParty(p0, f.st[0], pools[1]), ErrBinding) {
				t.Fatal("wrong cloud role accepted")
			}
			domainMust(t, BindInventoryParty(p0, f.st[0], pools[0]))
			domainMust(t, BindInventoryParty(p1, f.st[1], pools[1]))
			domainMust(t, pools[0].Admit(u.id, capacity))
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			out, metrics, e := RunLocal(ctx, f.q, f.keys, u, f.st, [2]*PartyPacket{p0, p1}, scmpnative.Backend{})
			domainMust(t, e)
			if metrics.K != f.shape.K || metrics.Slots != f.shape.S || len(out.Pairs) != f.shape.K {
				t.Fatal("wrong full-chain workload", metrics.K, metrics.Slots, out)
			}
			if present && out.Pairs[0] != (candidatequery.Pair{AnchorRecordID: 1001, TargetRecordID: 901}) {
				t.Fatal("wrong pair", out)
			}
			ledger, e := pools[0].Status()
			domainMust(t, e)
			if ledger.NextFree != metrics.Slots || !ledger.Admissions[hex.EncodeToString(u.id[:])].Closed {
				t.Fatal("stock accounting", ledger, metrics.Slots)
			}
			if _, _, e = RunLocal(ctx, f.q, f.keys, u, f.st, [2]*PartyPacket{p0, p1}, scmpnative.Backend{}); e == nil {
				t.Fatal("reused v3 ticket")
			}
			// Unbound stock is still available to a second independent session.
			u2, a2, b2, _, e := ProvisionInventory(f.st[0], f.st[1], f.buckets, f.cap, f.shape, scmpnative.Backend{}, false, manifest.BankID)
			domainMust(t, e)
			_, e = PersistReservation(t.TempDir(), t.TempDir(), u2, a2, b2, f.st[0], f.st[1])
			domainMust(t, e)
			domainMust(t, BindInventoryParty(a2, f.st[0], pools[0]))
			domainMust(t, BindInventoryParty(b2, f.st[1], pools[1]))
			remaining := capacity - ledger.NextFree
			if remaining >= f.shape.S {
				domainMust(t, pools[0].Admit(u2.id, f.shape.S))
			} else if !errors.Is(pools[0].Admit(u2.id, f.shape.S), scmpstock.ErrShortage) {
				t.Fatal("shortage not rejected")
			}
			if remaining >= f.shape.S {
				out2, metrics2, e := RunLocal(ctx, f.q, f.keys, u2, f.st, [2]*PartyPacket{a2, b2}, scmpnative.Backend{})
				domainMust(t, e)
				if len(out2.Pairs) != len(out.Pairs) || metrics2.Slots != metrics.Slots {
					t.Fatal("second query changed output")
				}
			}
		})
	}
}

func TestInventoryD1FullCryptographicChain(t *testing.T) {
	f := newDomainFixtureWithBitsAndD(t, 7, true, 16, 1)
	lineage := f.st[0].target.Lineage()
	seal := [32]byte{31}
	root := filepath.Join(t.TempDir(), "d1-stock")
	m, err := scmpstock.Generate(root, lineage.IndexID, lineage.LayoutID, seal, 7, 62, f.shape.S+2, scmpnative.Backend{})
	domainMust(t, err)
	var pools [2]*scmpstock.Pool
	for role := range pools {
		pools[role], err = scmpstock.Open(root, uint8(role), lineage.IndexID, lineage.LayoutID, seal, 7)
		domainMust(t, err)
		defer pools[role].Close()
	}
	u, a, b, _, err := ProvisionInventory(f.st[0], f.st[1], f.buckets, f.cap, f.shape, scmpnative.Backend{}, false, m.BankID)
	domainMust(t, err)
	_, err = PersistReservation(t.TempDir(), t.TempDir(), u, a, b, f.st[0], f.st[1])
	domainMust(t, err)
	domainMust(t, BindInventoryParty(a, f.st[0], pools[0]))
	domainMust(t, BindInventoryParty(b, f.st[1], pools[1]))
	domainMust(t, pools[0].Admit(u.id, f.shape.S))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, metrics, err := RunLocal(ctx, f.q, f.keys, u, f.st, [2]*PartyPacket{a, b}, scmpnative.Backend{})
	if err != nil {
		t.Fatalf("D1 full-chain failed: %v; metrics=%+v", err, metrics)
	}
	if len(out.Pairs) != 1 || out.Pairs[0] != (candidatequery.Pair{AnchorRecordID: 1001, TargetRecordID: 901}) || metrics.K != 1 || metrics.Slots != f.shape.S {
		t.Fatal("D1 full-chain mismatch", out, metrics)
	}
}

func TestInventoryZeroPolynomialFullChain(t *testing.T) {
	f := newDomainFixture(t, 7, true)
	labels := filepath.Join(t.TempDir(), "labels")
	domainMust(t, targetaggregation.MigrateZeroLabels(labels, f.st[0].sidecar, f.st[1].sidecar))
	domainMust(t, f.st[0].sidecar.LoadZeroLabels(labels))
	domainMust(t, f.st[1].sidecar.LoadZeroLabels(labels))
	lineage := f.st[0].target.Lineage()
	root := filepath.Join(t.TempDir(), "stock")
	seal := [32]byte{8}
	m, e := scmpstock.Generate(root, lineage.IndexID, lineage.LayoutID, seal, 7, 62, f.shape.S, scmpnative.Backend{})
	domainMust(t, e)
	var pools [2]*scmpstock.Pool
	for role := 0; role < 2; role++ {
		pools[role], e = scmpstock.Open(root, uint8(role), lineage.IndexID, lineage.LayoutID, seal, 7)
		domainMust(t, e)
		defer pools[role].Close()
	}
	u, a, b, _, e := ProvisionInventory(f.st[0], f.st[1], f.buckets, f.cap, f.shape, scmpnative.Backend{}, true, m.BankID)
	domainMust(t, e)
	_, e = PersistReservation(t.TempDir(), t.TempDir(), u, a, b, f.st[0], f.st[1])
	domainMust(t, e)
	domainMust(t, BindInventoryParty(a, f.st[0], pools[0]))
	domainMust(t, BindInventoryParty(b, f.st[1], pools[1]))
	domainMust(t, pools[0].Admit(u.id, f.shape.S))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, metrics, e := RunLocal(ctx, f.q, f.keys, u, f.st, [2]*PartyPacket{a, b}, scmpnative.Backend{})
	domainMust(t, e)
	if metrics.K != 1 || metrics.Slots != f.shape.S || len(out.Pairs) != 1 || out.Pairs[0] != (candidatequery.Pair{AnchorRecordID: 1001, TargetRecordID: 901}) {
		t.Fatal("zero-polynomial full-chain mismatch", metrics, out)
	}
}

// One routed bucket is visited by both target occurrences. The second alias
// contributes two postings for one object, while another object has the same
// join value. Final pair selection must preserve both object IDs once each.
func TestInventoryRepeatedRouteAndObjectCoordinates(t *testing.T) {
	for _, tc := range []struct {
		name string
		zero bool
	}{{"matrix", false}, {"zero_poly", true}} {
		t.Run(tc.name, func(t *testing.T) { runInventoryRepeatedRouteAndObjectCoordinates(t, tc.zero) })
	}
}

func runInventoryRepeatedRouteAndObjectCoordinates(t *testing.T, zeroMode bool) {
	f := newDomainFixtureWithBits(t, 7, true, 16,
		indexbuild.AreaAliasRecord{ID: 902, Name: "efghefgh", Area: 1001})
	if zeroMode {
		labels := filepath.Join(t.TempDir(), "labels")
		domainMust(t, targetaggregation.MigrateZeroLabels(labels, f.st[0].sidecar, f.st[1].sidecar))
		domainMust(t, f.st[0].sidecar.LoadZeroLabels(labels))
		domainMust(t, f.st[1].sidecar.LoadZeroLabels(labels))
	}
	f.q.Target = "efghefgh"
	f.q.TauTarget = 1
	one := f.shape.S
	f.shape.R = 2
	f.shape.S = 2 * one
	f.shape.G *= 2
	f.cap = []int{one, one}
	lineage := f.st[0].target.Lineage()
	root := filepath.Join(t.TempDir(), "stock")
	seal := [32]byte{7}
	m, e := scmpstock.Generate(root, lineage.IndexID, lineage.LayoutID, seal, 7, 62, 2*one+3, scmpnative.Backend{})
	domainMust(t, e)
	var pools [2]*scmpstock.Pool
	for role := 0; role < 2; role++ {
		pools[role], e = scmpstock.Open(root, uint8(role), lineage.IndexID, lineage.LayoutID, seal, 7)
		domainMust(t, e)
		defer pools[role].Close()
	}
	u, a, b, _, e := ProvisionInventory(f.st[0], f.st[1], f.buckets, f.cap, f.shape, scmpnative.Backend{}, zeroMode, m.BankID)
	domainMust(t, e)
	_, e = PersistReservation(t.TempDir(), t.TempDir(), u, a, b, f.st[0], f.st[1])
	domainMust(t, e)
	domainMust(t, BindInventoryParty(a, f.st[0], pools[0]))
	domainMust(t, BindInventoryParty(b, f.st[1], pools[1]))
	domainMust(t, pools[0].Admit(u.id, 2*one))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, metrics, e := RunLocal(ctx, f.q, f.keys, u, f.st, [2]*PartyPacket{a, b}, scmpnative.Backend{})
	domainMust(t, e)
	if metrics.K != 1 || metrics.Routes != 2 || metrics.Slots != 2*one || len(out.Pairs) != 2 {
		t.Fatal("unexpected repeated-route workload", metrics, out)
	}
	want := map[candidatequery.Pair]bool{
		{AnchorRecordID: 1001, TargetRecordID: 901}: true,
		{AnchorRecordID: 1001, TargetRecordID: 902}: true,
	}
	for _, pair := range out.Pairs {
		if !want[pair] {
			t.Fatal("wrong or duplicate object pair", pair, out)
		}
		delete(want, pair)
	}
	if len(want) != 0 {
		t.Fatal("missing object pair", want)
	}
}
