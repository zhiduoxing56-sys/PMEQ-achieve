package targetposition

import (
	"bytes"
	matcodec "pmeq/internal/material"
	"pmeq/internal/targetpe"
	"testing"
)

func TestPositionOwnStreamRoundTrip(t *testing.T) {
	lineage := targetpe.AlignmentLineage{IndexID: [16]byte{1}, LayoutID: [16]byte{2}, N: 10}
	capacities := []int{0, 3, 5, 1}
	_, a, b, _, err := PreprocessWithDomain(lineage, capacities, 10, 270, oracleBackend{})
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
		loaded, err := ReadPacketOwn(&matcodec.StreamDecoder{R: bytes.NewReader(raw.Bytes())}, uint8(party), lineage, capacities, 10, 270)
		if err != nil {
			t.Fatal(err)
		}
		var again bytes.Buffer
		e = &matcodec.StreamEncoder{W: &again}
		loaded.WriteOwn(e)
		if e.Err != nil || !bytes.Equal(raw.Bytes(), again.Bytes()) {
			t.Fatal("position material changed")
		}
		if _, err := ReadPacketOwn(&matcodec.StreamDecoder{R: bytes.NewReader(raw.Bytes())}, uint8(1-party), lineage, capacities, 10, 270); err == nil {
			t.Fatal("cross-role load")
		}
		if _, err := ReadPacketOwn(&matcodec.StreamDecoder{R: bytes.NewReader(raw.Bytes())}, uint8(party), lineage, []int{0, 3, 4, 1}, 10, 270); err == nil {
			t.Fatal("wrong public capacity accepted")
		}
	}
}
