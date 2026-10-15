// Command imdb_owner_build is the trusted owner entry for the fixed IMDb
// production sample. The full anchor build is a separate, explicitly gated
// operation; the anchor phase requires an explicit launch switch.
package main

import (
	"bytes"
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

func monitorAnchorBuild(root string, done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			raw, err := os.ReadFile(filepath.Join(root, "anchor", "catalog.json"))
			if err != nil {
				continue
			}
			var disk syscall.Statfs_t
			if syscall.Statfs(root, &disk) != nil {
				continue
			}
			fmt.Printf("anchor progress: catalog_buckets=%d disk_available=%d bytes\n", bytes.Count(raw, []byte(`"Bucket":`)), uint64(disk.Bavail)*uint64(disk.Bsize))
		}
	}
}

func enoughResources(path string, diskFloor, memoryFloor, inodeFloor uint64) error {
	var disk syscall.Statfs_t
	if err := syscall.Statfs(path, &disk); err != nil {
		return err
	}
	if uint64(disk.Bavail)*uint64(disk.Bsize) < diskFloor {
		return fmt.Errorf("disk available %d bytes is below required %d bytes", uint64(disk.Bavail)*uint64(disk.Bsize), diskFloor)
	}
	if disk.Ffree < inodeFloor {
		return fmt.Errorf("free inodes %d is below required %d", disk.Ffree, inodeFloor)
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
	if available*1024 < memoryFloor {
		return fmt.Errorf("memory available %d bytes is below required %d bytes", available*1024, memoryFloor)
	}
	return nil
}

func run() error {
	phase := flag.String("phase", "preflight", "preflight, target, anchor-preflight, or anchor")
	startAnchor := flag.Bool("start-full-anchor-build", false, "explicitly authorize all remaining anchor buckets")
	sample := flag.String("sample", "imdb_production_20261015", "immutable sample directory")
	keyPath := flag.String("keys", ".private/imdb-production-keypair.json", "local trusted key file")
	receipt := flag.String("receipt", ".private/imdb-key-backup-receipt.json", "verified backup receipt")
	root := flag.String("root", ".private/imdb-v2-production", "private output root")
	flag.Parse()
	if *phase != "preflight" && *phase != "target" && *phase != "anchor-preflight" && *phase != "anchor" {
		return fmt.Errorf("unsupported phase")
	}
	if *phase == "anchor" && !*startAnchor {
		return fmt.Errorf("full anchor build is disabled; --start-full-anchor-build is required")
	}
	if *phase != "anchor" && *startAnchor {
		return fmt.Errorf("launch switch is valid only for --phase anchor")
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
	inodeFloor := uint64(2*len(gate.Layout.Metadata.AnchorBuckets) + 4096)
	if *phase == "target" {
		if err := enoughResources(outputRoot, 2<<30, 2<<30, 100); err != nil {
			return err
		}
	} else {
		// Reserve the complete projected anchor stage even on resume. This
		// conservative floor leaves 8 GiB for temporary files and the OS.
		floor := budget.AnchorCS0Bytes + budget.AnchorCS1Bytes + 8<<30
		if err := enoughResources(outputRoot, floor, 8<<30, inodeFloor); err != nil {
			return err
		}
		fmt.Printf("anchor resource gate: disk_floor=%d memory_floor=%d bytes inode_floor=%d (includes 8 GiB disk reserve)\n", floor, uint64(8<<30), inodeFloor)
	}
	if *phase == "anchor-preflight" || *phase == "anchor" {
		if _, err := imdbowner.VerifyTargetStage(filepath.Join(outputRoot, "target"), gate.Freeze, gate.Keys); err != nil {
			return err
		}
		fmt.Printf("anchor prerequisite verified: sealed target stage; offline ticket is not a build input\n")
		if *phase == "anchor-preflight" {
			fmt.Printf("full build remains disabled; use --phase anchor --start-full-anchor-build only after authorization\n")
			return nil
		}
		monitorDone := make(chan struct{})
		go monitorAnchorBuild(outputRoot, monitorDone)
		defer close(monitorDone)
		seal, err := imdbowner.BuildAnchorStageGuarded(outputRoot, gate, func() error {
			return enoughResources(outputRoot, budget.AnchorCS0Bytes+budget.AnchorCS1Bytes+8<<30, 8<<30, inodeFloor)
		})
		if err != nil {
			return err
		}
		fmt.Printf("anchor stage sealed: buckets=%d catalog=%s elapsed=%s\n", seal.AnchorBuckets, seal.AnchorCatalogSHA256, time.Since(start).Round(time.Millisecond))
		return nil
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
