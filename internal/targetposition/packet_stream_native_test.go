//go:build phase6native

package targetposition

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	matcodec "pmeq/internal/material"
	"pmeq/internal/scmpnative"
	"pmeq/internal/targetpe"
	"runtime"
	"testing"
	"time"
)

func TestNativePositionOwnStreamPreservesOpaqueKeys(t *testing.T) {
	lineage := targetpe.AlignmentLineage{IndexID: [16]byte{1}, LayoutID: [16]byte{2}, N: 10}
	capacity := []int{0, 2, 3, 1}
	_, a, b, _, err := PreprocessWithDomain(lineage, capacity, 10, 270, scmpnative.Backend{})
	if err != nil {
		t.Fatal(err)
	}
	for party, original := range []Packet{a, b} {
		var raw bytes.Buffer
		e := &matcodec.StreamEncoder{W: &raw}
		original.WriteOwn(e)
		if e.Err != nil {
			t.Fatal(e.Err)
		}
		loaded, err := ReadPacketOwn(&matcodec.StreamDecoder{R: bytes.NewReader(raw.Bytes())}, uint8(party), lineage, capacity, 10, 270)
		if err != nil {
			t.Fatal(err)
		}
		before := original.state.materials[1].prep.Lower[0]
		after := loaded.state.materials[1].prep.Lower[0]
		if !bytes.Equal(before.Opaque(), after.Opaque()) || before.OutputMaskShare() != after.OutputMaskShare() {
			t.Fatal("native key changed")
		}
		for _, xy := range [][2]uint32{{0, 0}, {17, 23}, {270, 271}, {1023, 1023}} {
			v0, e0 := (scmpnative.Backend{}).Eval(uint8(party), before, xy[0], xy[1])
			v1, e1 := (scmpnative.Backend{}).Eval(uint8(party), after, xy[0], xy[1])
			if e0 != nil || e1 != nil || v0 != v1 {
				t.Fatal("native evaluation changed")
			}
		}
	}
}

// Opt-in fixed-envelope operator measurement. This uses all 1,920,000 public
// target slots and real native SCMP keys, but is not a complete query ticket.
func TestProductionPositionMaterialStream(t *testing.T) {
	if os.Getenv("PMEQ_FULL_POSITION_PROBE") != "1" {
		t.Skip("opt-in 1.92m-slot native operator probe")
	}
	lineage := targetpe.AlignmentLineage{IndexID: [16]byte{1}, LayoutID: [16]byte{2}, N: 100000}
	capacities := []int{480000, 480000, 480000, 480000}
	started := time.Now()
	_, a, b, _, err := PreprocessWithDomain(lineage, capacities, 10, 270, scmpnative.Backend{})
	if err != nil {
		t.Fatal(err)
	}
	genWall := time.Since(started)
	wantPID := a.state.materials[0].prep.PID
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
		enc := &matcodec.StreamEncoder{W: buffered}
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
		p, e := ReadPacketOwn(&matcodec.StreamDecoder{R: bufio.NewReaderSize(f, 1<<20)}, uint8(party), lineage, capacities, 10, 270)
		f.Close()
		if e != nil || p.state.materials[0].prep.PID != wantPID {
			t.Fatalf("readback party=%d err=%v", party, e)
		}
		p = Packet{}
		runtime.GC()
	}
	readWall := time.Since(started)
	t.Logf("fixed-position native generation=%s write=%s read=%s role_bytes=%v total_bytes=%d", genWall, writeWall, readWall, sizes, sizes[0]+sizes[1])
}
