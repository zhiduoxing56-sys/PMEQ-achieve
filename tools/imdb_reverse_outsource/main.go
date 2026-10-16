// Command imdb_reverse_outsource constructs the missing offline-only IMDb
// direction in a separate namespace. It never creates a query ticket.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"pmeq/internal/aggregation"
	"pmeq/internal/discovery"
	"pmeq/internal/imdbkeys"
	"pmeq/internal/imdbprod"
	"pmeq/internal/incidence"
	"pmeq/internal/indexbuild"
	"pmeq/internal/targetaggregation/gen"
	"pmeq/internal/targetartifact"
	"pmeq/internal/zeroagg"
)

const version = "IMDB-REVERSE-OUTSOURCE-v1"
const minWindowsFree = uint64(15 << 30)
const tempReserve = uint64(2 << 30)

type fileRecord struct {
	Path   string `json:"path"`
	Bytes  uint64 `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type runReport struct {
	Version               string                     `json:"version"`
	SampleVersion         string                     `json:"sample_version"`
	KeyFingerprint        string                     `json:"key_fingerprint"`
	IndexID               string                     `json:"index_id"`
	LayoutID              string                     `json:"layout_id"`
	AnchorTable           string                     `json:"anchor_table"`
	TargetTable           string                     `json:"target_table"`
	AnchorObjects         int                        `json:"anchor_objects"`
	TargetObjects         int                        `json:"target_objects"`
	D                     int                        `json:"d"`
	MaxMultiplicity       int                        `json:"max_multiplicity"`
	AnchorGroups          int                        `json:"anchor_groups"`
	AnchorBuckets         int                        `json:"anchor_buckets"`
	AnchorPaddedSlots     int                        `json:"anchor_padded_slots"`
	TargetGroups          int                        `json:"target_groups"`
	TargetBuckets         int                        `json:"target_buckets"`
	TargetPaddedSlots     int                        `json:"target_padded_slots"`
	TargetMaxBucketGroups uint32                     `json:"target_max_bucket_groups"`
	TargetMaxBucketSlots  uint64                     `json:"target_max_bucket_slots"`
	ProjectedMaxBytes     uint64                     `json:"projected_max_bytes"`
	WindowsFreeBefore     uint64                     `json:"windows_free_before"`
	WindowsFreeAfter      uint64                     `json:"windows_free_after"`
	WSLFreeBefore         uint64                     `json:"wsl_free_before"`
	PeakRSSBytes          uint64                     `json:"peak_rss_bytes"`
	TargetBuildNS         int64                      `json:"target_build_ns"`
	MatrixBuildNS         int64                      `json:"matrix_build_ns"`
	PayloadBuildNS        int64                      `json:"payload_build_ns"`
	AnchorBuildNS         int64                      `json:"anchor_build_ns"`
	TotalBuildNS          int64                      `json:"total_build_ns"`
	Anchor                []discovery.AnchorArtifact `json:"anchor_catalog"`
	TargetManifest        indexbuild.TargetManifest  `json:"target_manifest"`
	MatrixManifest        any                        `json:"matrix_manifest"`
	MatrixAudit           gen.Audit                  `json:"matrix_audit"`
	Files                 []fileRecord               `json:"files"`
}

func freeBytes(path string) (uint64, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return 0, err
	}
	return uint64(s.Bavail) * uint64(s.Bsize), nil
}
func peakRSS() uint64 {
	var r syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &r) != nil {
		return 0
	}
	return uint64(r.Maxrss) * 1024
}
func writeJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	c := f.Close()
	if e == nil {
		e = c
	}
	return e
}

type countedHash struct {
	w           io.Writer
	h           hash.Hash
	n           uint64
	windowsPath string
	sinceGate   uint64
}

func (c *countedHash) Write(p []byte) (int, error) {
	if c.windowsPath != "" && c.sinceGate >= 64<<20 {
		free, e := freeBytes(c.windowsPath)
		if e != nil {
			return 0, e
		}
		if free < minWindowsFree+tempReserve {
			return 0, fmt.Errorf("Windows C free %d below write gate", free)
		}
		c.sinceGate = 0
	}
	n, e := c.w.Write(p)
	if n > 0 {
		c.h.Write(p[:n])
		c.n += uint64(n)
		c.sinceGate += uint64(n)
	}
	return n, e
}
func writeFile(path string, windowsPath string, visit func(io.Writer) error) (fileRecord, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return fileRecord{}, e
	}
	c := &countedHash{w: f, h: sha256.New(), windowsPath: windowsPath}
	e = visit(c)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return fileRecord{}, e
	}
	return fileRecord{Path: path, Bytes: c.n, SHA256: hex.EncodeToString(c.h.Sum(nil))}, nil
}

func shape(casts []indexbuild.AreaAliasRecord) (int, int, error) {
	joins := make(map[uint64]int)
	maxMultiplicity := 0
	for _, a := range casts {
		joins[a.Area]++
		qgrams := map[string]int{}
		indexbuild.VisitQGrams(a.Name, func(q string, _ uint32) { qgrams[q]++ })
		for _, n := range qgrams {
			if n > maxMultiplicity {
				maxMultiplicity = n
			}
		}
	}
	d := 0
	for _, n := range joins {
		if n > d {
			d = n
		}
	}
	if d < 1 || maxMultiplicity < 1 || maxMultiplicity > 16 {
		return 0, 0, fmt.Errorf("unsupported reverse shape d=%d multiplicity=%d", d, maxMultiplicity)
	}
	return d, maxMultiplicity, nil
}
func projection(m *imdbprod.Mapping) ([]indexbuild.AreaRecord, []uint64, []indexbuild.AreaAliasRecord) {
	movies := make([]indexbuild.AreaRecord, len(m.Targets))
	joins := make([]uint64, len(m.Targets))
	for i, t := range m.Targets {
		movies[i] = indexbuild.AreaRecord{ID: t.ID, Name: t.PrimaryTitle}
		joins[i] = t.JoinID
	}
	casts := make([]indexbuild.AreaAliasRecord, len(m.Anchors))
	for i, a := range m.Anchors {
		casts[i] = indexbuild.AreaAliasRecord{ID: a.ID, Name: a.AliasTitle, Area: a.JoinID}
	}
	return movies, joins, casts
}
func estimate(a indexbuild.LayoutAnalysis, d int, n int) uint64 {
	b := uint64(len(a.Metadata.AnchorBuckets))
	g := uint64(a.Anchor.LogicalGroups)
	t := uint64(a.Anchor.PaddedSlots)
	// BS02 stores one N-word sigma on CS1, a 32-byte seed on CS0,
	// and both parties' 47-byte posting slots plus labels.
	anchor := b*(4*uint64(n)+256) + 2*(20*g+64*t)
	bg := uint64(len(a.Metadata.TargetBuckets))
	tg := uint64(a.Target.LogicalGroups)
	ts := uint64(a.Target.PaddedSlots)
	psmj := 2 * indexbuild.TargetEncodedBytes(bg, tg, ts)
	matrix := 2 * (uint64(d)*(ts+8*tg) + 4*(1<<16) + 4*tg + 128)
	payload := 2 * (uint64(n)*42 + 64)
	return anchor + psmj + matrix + payload + 1<<30 // catalog, filesystem and estimation margin
}
func verifyOutputPath(privateRoot, output string) error {
	root, e := filepath.Abs(privateRoot)
	if e != nil {
		return e
	}
	out, e := filepath.Abs(output)
	if e != nil {
		return e
	}
	if filepath.Dir(out) != root || filepath.Base(out) != "imdb-reverse-outsource-v1" {
		return fmt.Errorf("output must be the isolated reverse namespace directly under %s", root)
	}
	if s, e := os.Lstat(root); e != nil || !s.IsDir() || s.Mode().Perm() != 0700 {
		return errors.New("unsafe private root")
	}
	if _, e := os.Lstat(out); e == nil {
		return errors.New("reverse output already exists; refusing overwrite")
	} else if !os.IsNotExist(e) {
		return e
	}
	return nil
}
func run() error {
	phase := flag.String("phase", "preflight", "preflight or build")
	sample := flag.String("sample", "", "absolute frozen IMDb sample directory")
	keyPath := flag.String("keys", "", "absolute trusted keypair path")
	privateRoot := flag.String("private-root", "", "absolute existing .private directory")
	output := flag.String("output", "", "absolute isolated output directory")
	windowsPath := flag.String("windows-path", "/mnt/c", "Windows system drive mount")
	flag.Parse()
	if *phase != "preflight" && *phase != "build" {
		return errors.New("phase must be preflight or build")
	}
	if *sample == "" || *keyPath == "" || *privateRoot == "" || *output == "" {
		return errors.New("sample, keys, private-root and output are required")
	}
	if e := verifyOutputPath(*privateRoot, *output); e != nil {
		return e
	}
	start := time.Now()
	m, _, e := imdbprod.LoadFrozen(*sample)
	if e != nil {
		return e
	}
	keys, e := imdbkeys.Load(*keyPath)
	if e != nil {
		return e
	}
	movies, joins, casts := projection(m)
	d, multiplicity, e := shape(casts)
	if e != nil {
		return e
	}
	layout, e := indexbuild.AnalyzeReverseIMDbTierLayout(movies, joins, casts, keys.Anchor, keys.Target)
	if e != nil {
		return e
	}
	var maxGroups uint32
	var maxSlots uint64
	for _, b := range layout.Metadata.TargetBuckets {
		if b.GroupCount > maxGroups {
			maxGroups = b.GroupCount
		}
		if b.TotalSlots > maxSlots {
			maxSlots = b.TotalSlots
		}
	}
	est := estimate(layout, d, len(movies))
	cFree, e := freeBytes(*windowsPath)
	if e != nil {
		return e
	}
	wFree, e := freeBytes(*privateRoot)
	if e != nil {
		return e
	}
	fmt.Printf("reverse preflight: MOVIE.BSMJ N=%d groups=%d buckets=%d; MOVIECAST.PSMJ objects=%d groups=%d padded=%d max_bucket=%d/%d D=%d multiplicity=%d estimate_max=%d C_free=%d WSL_free=%d elapsed=%s\n", len(movies), layout.Anchor.LogicalGroups, len(layout.Metadata.AnchorBuckets), len(casts), layout.Target.LogicalGroups, layout.Target.PaddedSlots, maxGroups, maxSlots, d, multiplicity, est, cFree, wFree, time.Since(start))
	if *phase == "preflight" {
		return nil
	}
	if cFree < minWindowsFree+tempReserve+est || wFree < tempReserve+est {
		return fmt.Errorf("resource gate: need C free >= %d and WSL free >= %d", minWindowsFree+tempReserve+est, tempReserve+est)
	}
	if peakRSS() == 0 {
		return errors.New("cannot measure process RSS")
	}
	outputDir, e := os.MkdirTemp(*privateRoot, ".imdb-reverse-outsource-incomplete-")
	if e != nil {
		return e
	}
	for _, p := range []string{"cs0", "cs1"} {
		if e = os.Mkdir(filepath.Join(outputDir, p), 0700); e != nil {
			return e
		}
	}
	var indexID [16]byte
	if _, e = rand.Read(indexID[:]); e != nil {
		return e
	}
	report := runReport{Version: version, SampleVersion: imdbprod.SampleVersion, KeyFingerprint: keys.Fingerprint, IndexID: hex.EncodeToString(indexID[:]), AnchorTable: "MOVIE.primaryTitle", TargetTable: "MOVIECAST.aliasTitle", AnchorObjects: len(movies), TargetObjects: len(casts), D: d, MaxMultiplicity: multiplicity, AnchorGroups: layout.Anchor.LogicalGroups, AnchorBuckets: len(layout.Metadata.AnchorBuckets), AnchorPaddedSlots: layout.Anchor.PaddedSlots, TargetGroups: layout.Target.LogicalGroups, TargetBuckets: len(layout.Metadata.TargetBuckets), TargetPaddedSlots: layout.Target.PaddedSlots, TargetMaxBucketGroups: maxGroups, TargetMaxBucketSlots: maxSlots, ProjectedMaxBytes: est, WindowsFreeBefore: cFree, WSLFreeBefore: wFree}
	stage := time.Now()
	meta, p0, p1, stats, e := indexbuild.BuildMoviecastTarget(casts, keys.Target)
	if e != nil {
		return e
	}
	if !sameBuckets(meta.TargetBuckets, layout.Metadata.TargetBuckets) || stats.Target.PaddedSlots != layout.Target.PaddedSlots {
		return errors.New("target PSMJ disagrees with preflight")
	}
	manifest, e := indexbuild.NewTargetManifest(indexID, meta, stats.Target)
	if e != nil {
		return e
	}
	var partyBytes [2][]byte
	for u, p := range []indexbuild.PartyIndex{p0, p1} {
		var buf bytes.Buffer
		if e = indexbuild.WriteTargetParty(&buf, manifest, uint8(u), p); e != nil {
			return e
		}
		partyBytes[u] = buf.Bytes()
		name := filepath.Join(outputDir, fmt.Sprintf("cs%d/target.psmj.bin", u))
		file, e := writeFile(name, *windowsPath, func(w io.Writer) error { _, e := w.Write(partyBytes[u]); return e })
		if e != nil {
			return e
		}
		report.Files = append(report.Files, file)
		manifest.PartyBytes[u] = file.Bytes
		manifest.PartySHA256[u] = file.SHA256
	}
	report.TargetBuildNS = time.Since(stage).Nanoseconds()
	if e = writeJSON(filepath.Join(outputDir, "target-manifest.json"), manifest); e != nil {
		return e
	}
	report.TargetManifest = manifest
	stage = time.Now()
	manifestRaw, e := os.ReadFile(filepath.Join(outputDir, "target-manifest.json"))
	if e != nil {
		return e
	}
	var f [2]*os.File
	var c [2]*countedHash
	for u := 0; u < 2; u++ {
		f[u], e = os.OpenFile(filepath.Join(outputDir, fmt.Sprintf("cs%d/target.matrix.bin", u)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		c[u] = &countedHash{w: f[u], h: sha256.New(), windowsPath: *windowsPath}
	}
	sm, audit, e := gen.BuildReverseOffline(manifestRaw, partyBytes, casts, [2]io.Writer{c[0], c[1]}, d, multiplicity)
	for u := 0; u < 2; u++ {
		if e == nil {
			e = f[u].Sync()
		}
		closeErr := f[u].Close()
		if e == nil {
			e = closeErr
		}
	}
	if e != nil {
		return e
	}
	if audit.Errors != 0 || audit.MaxAliases != d || audit.MaxMultiplicity != multiplicity || audit.RealSlots != uint64(layout.Target.RealSlots) {
		return fmt.Errorf("matrix audit disagrees with preflight: %+v", audit)
	}
	for u := 0; u < 2; u++ {
		rec := fileRecord{Path: f[u].Name(), Bytes: c[u].n, SHA256: hex.EncodeToString(c[u].h.Sum(nil))}
		if rec.Bytes != sm.PartyBytes[u] || rec.SHA256 != sm.PartySHA256[u] {
			return errors.New("matrix hash mismatch")
		}
		report.Files = append(report.Files, rec)
	}
	report.MatrixBuildNS = time.Since(stage).Nanoseconds()
	report.MatrixManifest = sm
	report.MatrixAudit = audit
	if e = writeJSON(filepath.Join(outputDir, "matrix-manifest.json"), sm); e != nil {
		return e
	}
	partyBytes = [2][]byte{}
	p0 = indexbuild.PartyIndex{}
	p1 = indexbuild.PartyIndex{}
	runtime.GC()
	stage = time.Now()
	ids := make([]uint64, len(movies))
	for i, v := range movies {
		ids[i] = v.ID
	}
	dealer, payload0, payload1, e := aggregation.GeneratePayloadWithJoins(ids, joins, keys.Target, 16)
	if e != nil {
		return e
	}
	report.LayoutID = hex.EncodeToString(dealer.LayoutID[:])
	for u, p := range []aggregation.PartyPayload{payload0, payload1} {
		rec, e := writeFile(filepath.Join(outputDir, fmt.Sprintf("cs%d/payload.bin", u)), *windowsPath, func(w io.Writer) error { return targetartifact.WritePayload(w, manifest, uint8(u), p) })
		if e != nil {
			return e
		}
		report.Files = append(report.Files, rec)
	}
	report.PayloadBuildNS = time.Since(stage).Nanoseconds()
	stage = time.Now()
	e = indexbuild.VisitMovieTitleAnchorBuckets(movies, joins, keys.Anchor, keys.Target, nil, func(meta indexbuild.BucketMetadata, b0, b1 indexbuild.AnchorPartyBucket, posts []incidence.Posting) error {
		local, e := incidence.PrepareLayout(posts)
		if e != nil {
			return e
		}
		labels0, labels1, e := zeroagg.ShareCoordinates(local.Coordinates, local.D)
		if e != nil {
			return e
		}
		s0, s1, e := dealer.Alignment(meta.BucketID, local, posts)
		if e != nil {
			return e
		}
		defer s1.Discard()
		defer clear(s0.RhoSeed[:])
		var label [16]byte
		if _, e = rand.Read(label[:]); e != nil {
			return e
		}
		labelID := hex.EncodeToString(label[:])
		a0 := discovery.AnchorStatic{Bucket: b0, D: local.D, T: len(posts), Labels: labels0, LabelID: labelID, Stage0: s0}
		a1 := discovery.AnchorStatic{Bucket: b1, D: local.D, T: len(posts), Labels: labels1, LabelID: labelID, Stage1: s1}
		entry := discovery.AnchorArtifact{Bucket: meta.BucketID, D: local.D, T: len(posts), Groups: int(meta.GroupCount)}
		for u, a := range []discovery.AnchorStatic{a0, a1} {
			path := filepath.Join(outputDir, fmt.Sprintf("cs%d/anchor-%05d.bs02", u, meta.BucketID))
			var sections [3]uint64
			rec, e := writeFile(path, *windowsPath, func(w io.Writer) error {
				return discovery.WriteAnchorStatic(w, indexID, dealer.LayoutID, uint8(u), len(movies), a, &sections)
			})
			if e != nil {
				return e
			}
			entry.Bytes[u] = rec.Bytes
			entry.SHA256[u] = rec.SHA256
			entry.SectionBytes[u] = sections
			report.Files = append(report.Files, rec)
		}
		report.Anchor = append(report.Anchor, entry)
		if len(report.Anchor)%1000 == 0 {
			fmt.Printf("anchor progress: buckets=%d/%d elapsed=%s\n", len(report.Anchor), len(layout.Metadata.AnchorBuckets), time.Since(stage))
		}
		return nil
	})
	if e != nil {
		return e
	}
	if len(report.Anchor) != len(layout.Metadata.AnchorBuckets) {
		return errors.New("anchor bucket count mismatch")
	}
	sort.Slice(report.Anchor, func(i, j int) bool { return report.Anchor[i].Bucket < report.Anchor[j].Bucket })
	for i, b := range report.Anchor {
		want := layout.Metadata.AnchorBuckets[i]
		if b.Bucket != want.BucketID || b.Groups != int(want.GroupCount) || b.T != int(want.TotalSlots) {
			return errors.New("anchor layout mismatch")
		}
	}
	report.AnchorBuildNS = time.Since(stage).Nanoseconds()
	report.TotalBuildNS = time.Since(start).Nanoseconds()
	report.PeakRSSBytes = peakRSS()
	report.WindowsFreeAfter, e = freeBytes(*windowsPath)
	if e != nil {
		return e
	}
	var actual uint64
	for _, f := range report.Files {
		actual += f.Bytes
	}
	if actual > est {
		return fmt.Errorf("actual output %d exceeds estimate %d", actual, est)
	}
	if report.WindowsFreeAfter < minWindowsFree+tempReserve {
		return errors.New("Windows C safety floor reached")
	}
	for i := range report.Files {
		report.Files[i].Path = strings.TrimPrefix(report.Files[i].Path, outputDir+string(os.PathSeparator))
	}
	if e = writeJSON(filepath.Join(outputDir, "build-report.json"), report); e != nil {
		return e
	}
	if e = os.Rename(outputDir, *output); e != nil {
		return e
	}
	fmt.Printf("reverse build complete: files=%d bytes=%d target=%s matrix=%s payload=%s anchor=%s total=%s peak_rss=%d C_free_after=%d output=%s\n", len(report.Files), actual, time.Duration(report.TargetBuildNS), time.Duration(report.MatrixBuildNS), time.Duration(report.PayloadBuildNS), time.Duration(report.AnchorBuildNS), time.Duration(report.TotalBuildNS), report.PeakRSSBytes, report.WindowsFreeAfter, *output)
	return nil
}
func sameBuckets(a, b []indexbuild.BucketMetadata) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "imdb_reverse_outsource:", e)
		os.Exit(1)
	}
}
