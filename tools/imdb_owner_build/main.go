// Command imdb_owner_build is the trusted owner entry for the fixed IMDb
// production sample. The full anchor build is a separate, explicitly gated
// operation; this command currently publishes and verifies the target stage.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"pmeq/internal/imdbowner"
	"pmeq/internal/imdbprod"
)

func enoughResources(path string) error {
	var disk syscall.Statfs_t
	if err := syscall.Statfs(path, &disk); err != nil {
		return err
	}
	if uint64(disk.Bavail)*uint64(disk.Bsize) < 2<<30 {
		return fmt.Errorf("less than 2 GiB disk available for target stage")
	}
	meminfo, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return err
	}
	var available uint64
	for _, line := range strings.Split(string(meminfo), "\n") {
		if strings.HasPrefix(line, "MemAvailable:") {
			if _, err := fmt.Sscanf(line, "MemAvailable: %d kB", &available); err != nil {
				return err
			}
			break
		}
	}
	if available < 2<<20 {
		return fmt.Errorf("less than 2 GiB memory available for target stage")
	}
	return nil
}

func run() error {
	phase := flag.String("phase", "preflight", "preflight or target")
	sample := flag.String("sample", "imdb_production_20261015", "immutable sample directory")
	keyPath := flag.String("keys", ".private/imdb-production-keypair.json", "local trusted key file")
	receipt := flag.String("receipt", ".private/imdb-key-backup-receipt.json", "verified backup receipt")
	root := flag.String("root", ".private/imdb-v2-production", "private output root")
	flag.Parse()
	if *phase != "preflight" && *phase != "target" {
		return fmt.Errorf("unsupported phase")
	}
	privateRoot, err := filepath.Abs(".private")
	if err != nil {
		return err
	}
	outputRoot, err := filepath.Abs(*root)
	if err != nil || !strings.HasPrefix(outputRoot, privateRoot+string(os.PathSeparator)) {
		return fmt.Errorf("output root must be below this worktree's .private directory")
	}
	start := time.Now()
	gate, err := imdbowner.CheckProduction(*sample, *keyPath, *receipt)
	if err != nil {
		return err
	}
	maxGroups, maxSlots := 0, 0
	for _, b := range gate.Layout.Metadata.TargetBuckets {
		if int(b.GroupCount) > maxGroups {
			maxGroups = int(b.GroupCount)
		}
		if int(b.TotalSlots) > maxSlots {
			maxSlots = int(b.TotalSlots)
		}
	}
	fmt.Printf("preflight passed: contract=%s key=%s anchor_buckets=%d target_buckets=%d target_max=%d/%d limit=%d/%d elapsed=%s\n",
		imdbprod.Version, gate.Keys.Fingerprint, len(gate.Layout.Metadata.AnchorBuckets),
		len(gate.Layout.Metadata.TargetBuckets), maxGroups, maxSlots,
		imdbprod.TargetBucketGroups, imdbprod.TargetBucketSlots, time.Since(start).Round(time.Millisecond))
	budget, err := imdbowner.Estimate(gate.Layout)
	if err != nil {
		return err
	}
	fmt.Printf("resource floor: anchor_cs0=%d anchor_cs1=%d max_bucket=%d offline_fields_both=%d bytes\n",
		budget.AnchorCS0Bytes, budget.AnchorCS1Bytes, budget.MaxAnchorBucketBytes, budget.OfflineFieldBytes)
	if *phase == "preflight" {
		return nil
	}
	if err := os.MkdirAll(outputRoot, 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(outputRoot); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("output root permissions are unsafe")
	}
	if err := enoughResources(outputRoot); err != nil {
		return err
	}
	targetRoot := filepath.Join(outputRoot, "target")
	var seal imdbowner.TargetSeal
	if _, err := os.Lstat(targetRoot); os.IsNotExist(err) {
		seal, err = imdbowner.BuildTargetStage(targetRoot, gate.Mapping, gate.Freeze, gate.Keys)
	} else if err == nil {
		seal, err = imdbowner.VerifyTargetStage(targetRoot, gate.Freeze, gate.Keys)
	}
	if err != nil {
		return err
	}
	if int(seal.Target.NonemptyBuckets) != len(gate.Layout.Metadata.TargetBuckets) ||
		int(seal.Target.LogicalGroups) != gate.Layout.Target.LogicalGroups ||
		int(seal.Target.PaddedSlots) != gate.Layout.Target.PaddedSlots ||
		int(seal.Target.RealPostings) != gate.Layout.Target.RealSlots {
		return fmt.Errorf("target stage disagrees with keyed layout")
	}
	fmt.Printf("target stage verified: index=%x layout=%x groups=%d padded_slots=%d elapsed=%s\n",
		seal.Binding.IndexID, seal.Binding.LayoutID, seal.Target.LogicalGroups,
		seal.Target.PaddedSlots, time.Since(start).Round(time.Millisecond))
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "imdb_owner_build:", err)
		os.Exit(1)
	}
}
