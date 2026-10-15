//go:build phase6native

// Command imdb_ticket is the local trusted offline/user coordinator. It uses
// the sealed production index and existing two-cloud cryptographic protocol.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/anchorindex"
	"pmeq/internal/discovery"
	"pmeq/internal/imdbowner"
	"pmeq/internal/imdbprod"
	"pmeq/internal/imdbrecovery"
	"pmeq/internal/indexbuild"
	"pmeq/internal/scmpnative"
	"pmeq/internal/scmpstock"
	"pmeq/internal/targetaggregation"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func buckets(text string) ([]uint32, error) {
	parts := strings.Split(text, ",")
	if len(parts) != imdbprod.AnchorSignatures {
		return nil, fmt.Errorf("expected exactly four public anchor bucket IDs")
	}
	out := make([]uint32, len(parts))
	for i, p := range parts {
		v, e := strconv.ParseUint(strings.TrimSpace(p), 10, imdbprod.BucketBits)
		if e != nil {
			return nil, e
		}
		out[i] = uint32(v)
	}
	return out, nil
}
func queryFile(path string) (discovery.Query, error) {
	var q discovery.Query
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return q, fmt.Errorf("query file must be a 0600 regular local file")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return q, e
	}
	if json.Unmarshal(raw, &q) != nil {
		return q, fmt.Errorf("invalid query JSON")
	}
	if e = imdbprod.Production().CheckQuery(q.Anchor, q.Target, q.TauAnchor, q.TauTarget); e != nil {
		return q, e
	}
	return q, nil
}
func enoughOfflineResources(path string) error {
	var disk syscall.Statfs_t
	if e := syscall.Statfs(path, &disk); e != nil {
		return e
	}
	if uint64(disk.Bavail)*uint64(disk.Bsize) < 16<<30 {
		return fmt.Errorf("offline ticket requires at least 16 GiB free disk")
	}
	raw, e := os.ReadFile("/proc/meminfo")
	if e != nil {
		return e
	}
	var available uint64
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			fmt.Sscanf(line, "MemAvailable: %d kB", &available)
			break
		}
	}
	if available*1024 < 32<<30 {
		return fmt.Errorf("offline ticket requires at least 32 GiB available memory before generation")
	}
	return nil
}
func privateRunDirectory(privateRoot, resultRoot, ticket string) (string, error) {
	root, e := filepath.Abs(resultRoot)
	if e != nil || filepath.Dir(root) != privateRoot {
		return "", fmt.Errorf("result root must be a direct child of .private")
	}
	if e = os.MkdirAll(root, 0700); e != nil {
		return "", e
	}
	info, e := os.Lstat(root)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", fmt.Errorf("result root permissions are unsafe")
	}
	dir := filepath.Join(root, ticket)
	if e = os.Mkdir(dir, 0700); e != nil {
		return "", e // A second attempt must not overwrite the first one's evidence.
	}
	return dir, nil
}
func writeRunJSON(dir, name string, value any) (string, error) {
	raw, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return "", e
	}
	raw = append(raw, '\n')
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", e
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return "", e
	}
	d, e := os.Open(dir)
	if e != nil {
		return "", e
	}
	e = d.Sync()
	d.Close()
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}
func requireUnconsumedTicket(ticketDir, ticket string) error {
	for _, role := range []string{"user", "cs0", "cs1"} {
		marker := filepath.Join(ticketDir, role, ticket+".consumed")
		if _, e := os.Lstat(marker); e == nil {
			return fmt.Errorf("one-use ticket has already been consumed")
		} else if !os.IsNotExist(e) {
			return e
		}
	}
	return nil
}
func run() error {
	processStart := time.Now()
	phase := flag.String("phase", "inspect", "inspect, buckets, labels, stock, status, issue, verify, or run")
	aggregationMode := flag.String("target-aggregation", "matrix", "matrix or zero-poly")
	labelRoot := flag.String("zero-label-root", ".private/imdb-v3-target-zero-labels", "v3 target label root")
	start := flag.Bool("generate-full-ticket", false, "explicitly start expensive fixed-capacity preprocessing")
	startStock := flag.Bool("generate-stock", false, "explicitly create a new independent SCMP bank")
	stockSlots := flag.Int("stock-slots", imdbprod.CandidateCapacity*imdbprod.TargetSignatures*imdbprod.TargetBucketSlots, "offline inventory slots")
	stockRoot := flag.String("stock-root", ".private/imdb-v3-scmp-stock", "isolated stock root")
	ownerRoot := flag.String("owner-root", ".private/imdb-v2-production", "sealed production root")
	ticketRoot := flag.String("ticket-root", ".private/imdb-v3-tickets", "private v3 ticket root")
	sample := flag.String("sample", "imdb_production_20261015", "frozen sample")
	keysPath := flag.String("keys", ".private/imdb-production-keypair.json", "local user key file")
	receipt := flag.String("receipt", ".private/imdb-key-backup-receipt.json", "backup receipt")
	bucketText := flag.String("buckets", "", "four public bucket IDs in query occurrence order")
	ticketText := flag.String("ticket", "", "ticket ID for read/run")
	queryPath := flag.String("query-file", "", "local 0600 JSON query file")
	resultRoot := flag.String("result-root", ".private/imdb-v3-query-results", "private v3 output root")
	flag.Parse()
	if *phase != "inspect" && *phase != "buckets" && *phase != "labels" && *phase != "stock" && *phase != "status" && *phase != "issue" && *phase != "verify" && *phase != "run" {
		return fmt.Errorf("unsupported phase")
	}
	if *aggregationMode != "matrix" && *aggregationMode != "zero-poly" {
		return fmt.Errorf("unsupported target aggregation")
	}
	if *start != (*phase == "issue") {
		return fmt.Errorf("ticket generation requires --phase issue --generate-full-ticket; switch is invalid in other phases")
	}
	if *startStock != (*phase == "stock") {
		return fmt.Errorf("stock generation requires --phase stock --generate-stock")
	}
	if *phase == "buckets" {
		q, e := queryFile(*queryPath)
		if e != nil {
			return e
		}
		keys, _, e := discovery.LoadMovieUserKeys(*keysPath)
		if e != nil {
			return e
		}
		chunks, e := anchorfilter.QueryChunksWithQ(q.Anchor, imdbprod.Q, imdbprod.AnchorSignatures)
		if e != nil {
			return e
		}
		out := make([]uint32, len(chunks))
		for i, chunk := range chunks {
			z, e := anchorindex.EncodeMovie(keys.Anchor, chunk.QGram)
			if e != nil {
				return e
			}
			out[i], e = indexbuild.AnchorBucket(z, imdbprod.BucketBits)
			if e != nil {
				return e
			}
		}
		fmt.Printf("public_anchor_buckets=%d,%d,%d,%d\n", out[0], out[1], out[2], out[3])
		return nil
	}
	gate, e := imdbowner.CheckProduction(*sample, *keysPath, *receipt)
	if e != nil {
		return e
	}
	if *phase == "inspect" {
		fmt.Printf("key=%s anchor_buckets=%d target_max=12/48 complete_ticket_floor=%d bytes\n", gate.Keys.Fingerprint, len(gate.Layout.Metadata.AnchorBuckets), uint64(4793760000))
		return nil
	}
	owner, e := filepath.Abs(*ownerRoot)
	if e != nil {
		return e
	}
	verifyStart := time.Now()
	seal, e := imdbowner.VerifyProduction(owner, gate)
	if e != nil {
		return fmt.Errorf("complete anchor and target production seal required: %w", e)
	}
	indexVerifyNS := time.Since(verifyStart).Nanoseconds()
	sealRaw, e := os.ReadFile(filepath.Join(owner, "production-seal.json"))
	if e != nil {
		return e
	}
	sealHash := sha256.Sum256(sealRaw)
	partyOpenStart := time.Now()
	st0, e := imdbowner.OpenParty(owner, 0, sealHash)
	if e != nil {
		return e
	}
	defer st0.Close()
	st1, e := imdbowner.OpenParty(owner, 1, sealHash)
	if e != nil {
		return e
	}
	defer st1.Close()
	partyOpenNS := time.Since(partyOpenStart).Nanoseconds()
	stockPath, e := filepath.Abs(*stockRoot)
	privateStockRoot, pe := filepath.Abs(".private")
	if e != nil || pe != nil || filepath.Dir(stockPath) != privateStockRoot {
		return fmt.Errorf("stock root must be an isolated direct child of .private")
	}
	if *phase == "stock" {
		if *stockSlots < 1 {
			return fmt.Errorf("invalid stock capacity")
		}
		m, e := scmpstock.Generate(stockPath, seal.Binding.IndexID, seal.Binding.LayoutID, sealHash, imdbprod.PositionBin, imdbprod.PositionMax, *stockSlots, scmpnative.Backend{})
		if e != nil {
			return e
		}
		fmt.Printf("bank=%x capacity=%d record_bytes_per_role=%d stock_root=%s\n", m.BankID, m.Capacity, m.RecordBytes, stockPath)
		return nil
	}
	if *phase == "labels" {
		if *aggregationMode != "zero-poly" {
			return fmt.Errorf("labels phase requires zero-poly")
		}
		if e = discovery.BuildTargetZeroLabels(st0, st1, *labelRoot); e != nil {
			return e
		}
		fmt.Printf("target_zero_labels=%s\n", *labelRoot)
		return nil
	}
	if *aggregationMode == "zero-poly" {
		if e = st0.LoadTargetZeroLabels(*labelRoot); e != nil {
			return e
		}
		if e = st1.LoadTargetZeroLabels(*labelRoot); e != nil {
			return e
		}
	}
	pool0, e := scmpstock.Open(stockPath, 0, seal.Binding.IndexID, seal.Binding.LayoutID, sealHash, imdbprod.PositionBin)
	if e != nil {
		return e
	}
	defer pool0.Close()
	pool1, e := scmpstock.Open(stockPath, 1, seal.Binding.IndexID, seal.Binding.LayoutID, sealHash, imdbprod.PositionBin)
	if e != nil {
		return e
	}
	defer pool1.Close()
	if pool0.Manifest != pool1.Manifest {
		return fmt.Errorf("stock role manifests disagree")
	}
	ledger, e := pool0.Status()
	if e != nil {
		return e
	}
	if *phase == "status" {
		outstanding := 0
		for _, a := range ledger.Admissions {
			if !a.Closed {
				outstanding += a.Guarantee
			}
		}
		fmt.Printf("bank=%x capacity=%d claimed_or_burned=%d unbound=%d reserved_guarantee=%d available_for_admission=%d worst_case_replenishment=%d admissions=%d\n", pool0.Manifest.BankID, pool0.Manifest.Capacity, ledger.NextFree, pool0.Manifest.Capacity-ledger.NextFree, outstanding, pool0.Manifest.Capacity-ledger.NextFree-outstanding, max(0, imdbprod.CandidateCapacity*imdbprod.TargetSignatures*imdbprod.TargetBucketSlots-(pool0.Manifest.Capacity-ledger.NextFree-outstanding)), len(ledger.Admissions))
		return nil
	}
	root, e := filepath.Abs(*ticketRoot)
	if e != nil {
		return e
	}
	privateRoot, e := filepath.Abs(".private")
	if e != nil || filepath.Dir(root) != privateRoot {
		return fmt.Errorf("ticket root must be a direct child of .private")
	}
	privateInfo, e := os.Lstat(privateRoot)
	if e != nil || !privateInfo.IsDir() || privateInfo.Mode().Perm() != 0700 {
		return fmt.Errorf(".private directory permissions are unsafe")
	}
	if ticketInfo, e := os.Lstat(root); e == nil {
		if !ticketInfo.IsDir() || ticketInfo.Mode().Perm() != 0700 {
			return fmt.Errorf("ticket root permissions are unsafe")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if *phase == "issue" {
		bs, e := buckets(*bucketText)
		if e != nil {
			return e
		}
		if e = os.MkdirAll(root, 0700); e != nil {
			return e
		}
		// The production query contract allows tau_anchor <= 3 for four
		// signatures, so every surviving candidate must occupy at least one
		// of these public anchor slots. This tightens admission without changing
		// C or consulting any secret hit, threshold, or target object.
		upper0, e := st0.PublicAnchorSlotUpperBound(bs, imdbprod.CandidateCapacity)
		if e != nil {
			return e
		}
		upper1, e := st1.PublicAnchorSlotUpperBound(bs, imdbprod.CandidateCapacity)
		if e != nil || upper0 != upper1 {
			return fmt.Errorf("public anchor capacity mismatch: %w", discovery.ErrBinding)
		}
		guarantee := upper0 * imdbprod.TargetSignatures * imdbprod.TargetBucketSlots
		outstanding := 0
		for _, a := range ledger.Admissions {
			if !a.Closed {
				outstanding += a.Guarantee
			}
		}
		if pool0.Manifest.Capacity-ledger.NextFree-outstanding < guarantee {
			return scmpstock.ErrShortage
		}
		if e = enoughOfflineResources(root); e != nil {
			return e
		}
		if e = scmpstock.CheckBudget(root, 3<<30); e != nil {
			return e
		}
		shape := targetaggregation.Shape{K: imdbprod.CandidateCapacity, R: imdbprod.TargetSignatures, S: imdbprod.TargetSignatures * imdbprod.TargetGroupCapacity, G: imdbprod.TargetGroupCapacity, D: imdbprod.TargetDimension}
		caps := []int{imdbprod.TargetGroupCapacity, imdbprod.TargetGroupCapacity, imdbprod.TargetGroupCapacity, imdbprod.TargetGroupCapacity}
		started := time.Now()
		var u *discovery.UserPacket
		var a, b *discovery.PartyPacket
		var estimated discovery.OfflineBytes
		u, a, b, estimated, e = discovery.ProvisionInventory(st0, st1, bs, caps, shape, scmpnative.Backend{}, *aggregationMode == "zero-poly", pool0.Manifest.BankID)
		if e != nil {
			return e
		}
		provisionNS := time.Since(started).Nanoseconds()
		sealed, digest, cost, e := discovery.PersistFullTicket(root, sealHash, u, a, b, st0, st1)
		if e != nil {
			return e
		}
		id, e := discovery.TicketID(sealed)
		if e != nil {
			return e
		}
		if e = pool0.Admit(id, guarantee); e != nil {
			return e
		}
		receiptPath := filepath.Join(root, sealed.Ticket, "trusted-seal.sha256")
		f, e := os.OpenFile(receiptPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = fmt.Fprintf(f, "%x\n", digest)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		fmt.Printf("ticket=%s seal_sha256=%x public_candidate_upper=%d guaranteed_stock_slots=%d roles_bytes=%v zero_bytes=%d elapsed=%s provision_ns=%d persist_ns=%d zero_serialize_ns=%d max_temporary_file_bytes=%d field_accounting=%+v index=%x\n", sealed.Ticket, digest, upper0, guarantee, cost.RoleBytes, cost.Zero.MaterialBytes, time.Since(started).Round(time.Millisecond), provisionNS, cost.WallNS, cost.Zero.SerializeNS, cost.MaxTemporaryFileBytes, estimated, seal.Binding.IndexID)
		return nil
	}
	var ticketID [16]byte
	idBytes, e := hex.DecodeString(*ticketText)
	if e != nil || len(idBytes) != 16 || *ticketText != hex.EncodeToString(idBytes) {
		return fmt.Errorf("invalid ticket ID")
	}
	copy(ticketID[:], idBytes)
	ticketDir := filepath.Join(root, *ticketText)
	receiptPath := filepath.Join(ticketDir, "trusted-seal.sha256")
	receiptInfo, e := os.Lstat(receiptPath)
	if e != nil || !receiptInfo.Mode().IsRegular() || receiptInfo.Mode().Perm() != 0600 {
		return fmt.Errorf("trusted ticket seal receipt must be a 0600 regular file")
	}
	receiptRaw, e := os.ReadFile(receiptPath)
	if e != nil {
		return fmt.Errorf("trusted ticket seal receipt missing: %w", e)
	}
	trusted, e := hex.DecodeString(strings.TrimSpace(string(receiptRaw)))
	if e != nil || len(trusted) != 32 {
		return fmt.Errorf("bad trusted ticket receipt")
	}
	var expected [32]byte
	copy(expected[:], trusted)
	ticketSeal, e := discovery.ReadTicketSeal(ticketDir, expected)
	if e != nil {
		return e
	}
	if ticketSeal.IndexSealSHA256 != hex.EncodeToString(sealHash[:]) {
		return fmt.Errorf("ticket bound to another production seal")
	}
	if ticketSeal.Version != "PMEQ-INVENTORY-SESSION-v3" || ticketSeal.BankID != hex.EncodeToString(pool0.Manifest.BankID[:]) {
		return fmt.Errorf("v3 ticket/stock version mismatch")
	}
	if e = requireUnconsumedTicket(ticketDir, *ticketText); e != nil {
		return e
	}
	manifestDigest := st0.TargetManifestDigestForTicket()
	ud, e := discovery.TicketRoleDigest(ticketSeal, "user")
	if e != nil {
		return e
	}
	aD, e := discovery.TicketRoleDigest(ticketSeal, "cs0")
	if e != nil {
		return e
	}
	bD, e := discovery.TicketRoleDigest(ticketSeal, "cs1")
	if e != nil {
		return e
	}
	loadStart := time.Now()
	u, e := discovery.OpenInventoryUserTicket(filepath.Join(ticketDir, "user"), ud, seal.Binding, sealHash, ticketID, manifestDigest, pool0.Manifest.BankID)
	if e != nil {
		return e
	}
	a, e := discovery.OpenInventoryPartyTicket(filepath.Join(ticketDir, "cs0"), aD, seal.Binding, sealHash, ticketID, st0, pool0.Manifest.BankID)
	if e != nil {
		return e
	}
	b, e := discovery.OpenInventoryPartyTicket(filepath.Join(ticketDir, "cs1"), bD, seal.Binding, sealHash, ticketID, st1, pool0.Manifest.BankID)
	if e != nil {
		return e
	}
	if e = discovery.BindInventoryParty(a, st0, pool0); e != nil {
		return e
	}
	if e = discovery.BindInventoryParty(b, st1, pool1); e != nil {
		return e
	}
	ticketLoadNS := time.Since(loadStart).Nanoseconds()
	if *phase == "verify" {
		fmt.Printf("ticket_roles_verified=%s load=%s unconsumed=true\n", *ticketText, time.Duration(ticketLoadNS).Round(time.Millisecond))
		return nil
	}
	if *phase == "run" {
		q, e := queryFile(*queryPath)
		if e != nil {
			return e
		}
		privateRoot, e := filepath.Abs(".private")
		if e != nil {
			return e
		}
		resultDir, e := privateRunDirectory(privateRoot, *resultRoot, *ticketText)
		if e != nil {
			return e
		}
		queryRaw, e := os.ReadFile(*queryPath)
		if e != nil {
			return e
		}
		querySHA := sha256.Sum256(queryRaw)
		if _, e = writeRunJSON(resultDir, "attempt.json", map[string]any{
			"ticket": *ticketText, "query_sha256": hex.EncodeToString(querySHA[:]),
			"production_seal_sha256": hex.EncodeToString(sealHash[:]),
			"started_utc":            time.Now().UTC().Format(time.RFC3339Nano),
		}); e != nil {
			return e
		}
		keys := discovery.UserKeys{Anchor: gate.Keys.Anchor, Target: gate.Keys.Target}
		onlineStart := time.Now()
		wires, binding, metrics, e := discovery.RunCloudLocal(context.Background(), q, keys, u, [2]*discovery.Static{st0, st1}, [2]*discovery.PartyPacket{a, b}, scmpnative.Backend{})
		if e != nil {
			_, _ = writeRunJSON(resultDir, "failure.json", map[string]any{
				"error": e.Error(), "metrics": metrics,
				"online_elapsed_ns": time.Since(onlineStart).Nanoseconds(),
				"failed_utc":        time.Now().UTC().Format(time.RFC3339Nano),
			})
			return e
		}
		recoveryStart := time.Now()
		out, e := imdbrecovery.Recover(gate.Mapping, gate.Freeze, seal.Binding, binding, wires[0], wires[1])
		if e != nil {
			return e
		}
		metrics.Recovery = time.Since(recoveryStart)
		metrics.LocalE2E += metrics.Recovery
		onlineNS := time.Since(onlineStart).Nanoseconds()
		pairSHA, e := writeRunJSON(resultDir, "pairs.json", out)
		if e != nil {
			return e
		}
		metricSHA, e := writeRunJSON(resultDir, "metrics.json", map[string]any{
			"metrics": metrics, "index_verify_ns": indexVerifyNS,
			"party_open_ns": partyOpenNS, "ticket_load_ns": ticketLoadNS,
			"online_and_recovery_ns": onlineNS, "process_until_result_ns": time.Since(processStart).Nanoseconds(),
		})
		if e != nil {
			return e
		}
		if _, e = writeRunJSON(resultDir, "complete.json", map[string]any{
			"ticket": *ticketText, "query_id": hex.EncodeToString(out.QueryID[:]),
			"pair_count": len(out.Pairs), "pairs_sha256": pairSHA, "metrics_sha256": metricSHA,
			"completed_utc": time.Now().UTC().Format(time.RFC3339Nano),
		}); e != nil {
			return e
		}
		fmt.Printf("query_id=%x candidate_pairs=%d cloud=%s peak_heap=%d server_bytes=%d\n", out.QueryID, len(out.Pairs), metrics.Cloud, metrics.PeakHeap, metrics.ServerBytes)
	}
	return nil
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "imdb_ticket:", e)
		os.Exit(1)
	}
}
