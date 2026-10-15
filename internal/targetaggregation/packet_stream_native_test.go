//go:build phase6native

package targetaggregation

import (
	"bufio"
	"os"
	"path/filepath"
	"pmeq/internal/material"
	"pmeq/internal/scmpnative"
	"pmeq/internal/targetpe"
	"runtime"
	"testing"
	"time"
)

// Opt-in fixed-envelope operator measurement. It never creates a query
// result or changes the target index or the production key.
func TestProductionAggregationMaterialStream(t *testing.T) {
	if os.Getenv("PMEQ_FULL_AGGREGATION_PROBE") != "1" {
		t.Skip("opt-in fixed 10k x 4 x 26 native operator probe")
	}
	lineage := targetpe.AlignmentLineage{IndexID: [16]byte{1}, LayoutID: [16]byte{2}, N: 100000}
	shape := Shape{K: 10000, R: 4, S: 1920000, G: 480000, D: 26}
	started := time.Now()
	_, a, b, body, err := Preprocess(lineage, shape, scmpnative.Backend{})
	if err != nil {
		t.Fatal(err)
	}
	genWall := time.Since(started)
	wantID := a.id
	root := t.TempDir()
	var sizes [2]int64
	started = time.Now()
	for party, p := range []Packet{a, b} {
		path := filepath.Join(root, "cs"+string(rune('0'+party))+".bin")
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		buffered := bufio.NewWriterSize(f, 1<<20)
		enc := &material.StreamEncoder{W: buffered}
		p.WriteOwn(enc)
		if enc.Err == nil {
			enc.Err = buffered.Flush()
		}
		if enc.Err == nil {
			enc.Err = f.Sync()
		}
		closeErr := f.Close()
		if enc.Err != nil {
			t.Fatal(enc.Err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		info, e := os.Stat(path)
		if e != nil {
			t.Fatal(e)
		}
		sizes[party] = info.Size()
	}
	writeWall := time.Since(started)
	a, b = Packet{}, Packet{}
	runtime.GC()
	started = time.Now()
	for party := 0; party < 2; party++ {
		path := filepath.Join(root, "cs"+string(rune('0'+party))+".bin")
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		p, e := ReadPacketOwn(&material.StreamDecoder{R: bufio.NewReaderSize(f, 1<<20)}, uint8(party), lineage, shape)
		f.Close()
		if e != nil || p.id != wantID {
			t.Fatalf("readback party=%d err=%v", party, e)
		}
		p = Packet{}
		runtime.GC()
	}
	readWall := time.Since(started)
	t.Logf("fixed-aggregation native generation=%s write=%s read=%s role_bytes=%v total_bytes=%d body_accounting=%+v", genWall, writeWall, readWall, sizes, sizes[0]+sizes[1], body)
}
