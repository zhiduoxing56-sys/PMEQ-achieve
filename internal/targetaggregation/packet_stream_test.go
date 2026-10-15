package targetaggregation

import (
	"bytes"
	"pmeq/internal/material"
	"pmeq/internal/targetpe"
	"testing"
)

func TestOwnPacketStreamRoundTripAndRole(t *testing.T) {
	lineage := targetpe.AlignmentLineage{IndexID: [16]byte{1}, LayoutID: [16]byte{2}, N: 10}
	shape := Shape{K: 1, R: 1, S: 4, G: 1, D: 26}
	u, p0, p1, _, err := Preprocess(lineage, shape, oracleBackend{})
	must(t, err)
	var ub, a, b bytes.Buffer
	ue := &material.StreamEncoder{W: &ub}
	u.WriteOwn(ue)
	ae := &material.StreamEncoder{W: &a}
	p0.WriteOwn(ae)
	be := &material.StreamEncoder{W: &b}
	p1.WriteOwn(be)
	must(t, ue.Err)
	must(t, ae.Err)
	must(t, be.Err)
	loadedU, err := ReadUserOwn(&material.StreamDecoder{R: bytes.NewReader(ub.Bytes())}, shape)
	must(t, err)
	loaded0, err := ReadPacketOwn(&material.StreamDecoder{R: bytes.NewReader(a.Bytes())}, 0, lineage, shape)
	must(t, err)
	loaded1, err := ReadPacketOwn(&material.StreamDecoder{R: bytes.NewReader(b.Bytes())}, 1, lineage, shape)
	must(t, err)
	var again bytes.Buffer
	e := &material.StreamEncoder{W: &again}
	loaded0.WriteOwn(e)
	must(t, e.Err)
	if !bytes.Equal(a.Bytes(), again.Bytes()) {
		t.Fatal("party material changed across stream")
	}
	again.Reset()
	e = &material.StreamEncoder{W: &again}
	loaded1.WriteOwn(e)
	must(t, e.Err)
	if !bytes.Equal(b.Bytes(), again.Bytes()) {
		t.Fatal("peer material changed across stream")
	}
	again.Reset()
	e = &material.StreamEncoder{W: &again}
	loadedU.WriteOwn(e)
	must(t, e.Err)
	if !bytes.Equal(ub.Bytes(), again.Bytes()) {
		t.Fatal("user material changed across stream")
	}
	if _, err = ReadPacketOwn(&material.StreamDecoder{R: bytes.NewReader(a.Bytes())}, 1, lineage, shape); err == nil {
		t.Fatal("cross-role load")
	}
	if _, err = ReadPacketOwn(&material.StreamDecoder{R: bytes.NewReader(a.Bytes()[:a.Len()-1])}, 0, lineage, shape); err == nil {
		t.Fatal("truncated material")
	}
	if _, err = loadedU.Token([16]byte{5}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = loadedU.Token([16]byte{5}, 0); err == nil {
		t.Fatal("user bound reused")
	}
}
