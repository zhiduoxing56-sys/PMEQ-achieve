package targetpe

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestOldStandaloneDifferential(t *testing.T) {
	dir := os.Getenv("PMEQ_PE_REFERENCE")
	if dir == "" {
		t.Skip("external old reference vectors")
	}
	read := func(name string) []byte { v, e := os.ReadFile(filepath.Join(dir, name+".bin")); must(t, e); return v }
	x0, x1, truth, o0, o1 := read("x0"), read("x1"), read("truth"), read("out0"), read("out1")
	n := len(truth)
	w := Words(n)
	if n != 100000 || len(x0) != 256*w*8 || len(x1) != len(x0) || len(o0) != w*8 || len(o1) != len(o0) {
		t.Fatal("reference shape")
	}
	a, b := make([][32]byte, n), make([][32]byte, n)
	for i := 0; i < n; i++ {
		for bit := 0; bit < 256; bit++ {
			at := 8 * (bit*w + i/64)
			u := (binary.LittleEndian.Uint64(x0[at:]) >> uint(i%64)) & 1
			v := (binary.LittleEndian.Uint64(x1[at:]) >> uint(i%64)) & 1
			a[i][bit/8] |= byte(u^1) << uint(bit%8)
			b[i][bit/8] |= byte(v) << uint(bit%8)
		}
	}
	p, q, e := Preprocess(AlignmentLineage{IndexID: [16]byte{1}, LayoutID: [16]byte{2}}, n)
	must(t, e)
	s0, s1 := encodedSession(t, 0, a, p, 1), encodedSession(t, 1, b, q, 1)
	packing := s0.Metrics().Compute + s1.Metrics().Compute
	l, r := run(t, s0, s1)
	t.Logf("CURRENT_REFERENCE G=%d packing=%s boolean_compute=%s message_processing=%s payload_bytes=%d", n, packing, s0.Metrics().Compute+s1.Metrics().Compute-packing, s0.Metrics().Messages+s1.Metrics().Messages, s0.Metrics().PayloadBytes+s1.Metrics().PayloadBytes)
	for i := 0; i < n; i++ {
		old := ((binary.LittleEndian.Uint64(o0[8*(i/64):]) ^ binary.LittleEndian.Uint64(o1[8*(i/64):])) >> uint(i%64)) & 1
		now := bool(l.MatchShares[i].Value().Add(r.MatchShares[i].Value()))
		if now != (old == 1) || now != (truth[i] == 1) {
			t.Fatal("old/new differential", i)
		}
	}
	t.Log("old standalone vs current: 100000 identical shared inputs/results, errors=0")
}
