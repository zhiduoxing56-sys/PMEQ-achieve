package aggregation

import (
	"bytes"
	"pmeq/internal/incidence"
	"pmeq/internal/material"
	"testing"
)

func TestOwnStreamPermutationAndCompaction(t *testing.T) {
	pi, err := permutation(17)
	must(t, err)
	s0, s1, err := SplitPermutation([16]byte{7}, 19, pi)
	must(t, err)
	a, b, err := PreprocessPermutation(s0, s1)
	must(t, err)
	var raw0, raw1 bytes.Buffer
	e0 := &material.StreamEncoder{W: &raw0}
	a.WriteOwn(e0)
	e1 := &material.StreamEncoder{W: &raw1}
	b.WriteOwn(e1)
	must(t, e0.Err)
	must(t, e1.Err)
	a, err = ReadPermPrep0Own(&material.StreamDecoder{R: bytes.NewReader(raw0.Bytes())}, s0, 17)
	must(t, err)
	b, err = ReadPermPrep1Own(&material.StreamDecoder{R: bytes.NewReader(raw1.Bytes())}, s1, 17)
	must(t, err)
	x, y := make([]incidence.Share, 17), make([]incidence.Share, 17)
	for i := range x {
		x[i], y[i], err = incidence.Split(incidence.Z128(i))
		must(t, err)
	}
	d1, err := b.Message1(y)
	must(t, err)
	d2, z0, err := s0.Message2(a, x, d1)
	must(t, err)
	z1, err := s1.Finish(b, d2)
	must(t, err)
	for i, j := range pi {
		if z0[int(j)].Value().Add(z1[int(j)].Value()) != incidence.Z128(i) {
			t.Fatal("recovered permutation changed")
		}
	}
	if _, err = ReadPermPrep1Own(&material.StreamDecoder{R: bytes.NewReader(raw0.Bytes())}, s1, 17); err == nil {
		t.Fatal("role swap accepted")
	}

	c0, c1, err := PreprocessCompactionWithBucketBits([16]byte{6}, 19, 16)
	must(t, err)
	raw0.Reset()
	raw1.Reset()
	e0 = &material.StreamEncoder{W: &raw0}
	c0.WriteOwn(e0)
	e1 = &material.StreamEncoder{W: &raw1}
	c1.WriteOwn(e1)
	must(t, e0.Err)
	must(t, e1.Err)
	c0, err = ReadCompaction0Own(&material.StreamDecoder{R: bytes.NewReader(raw0.Bytes())}, [16]byte{6}, 19, 16)
	must(t, err)
	c1, err = ReadCompaction1Own(&material.StreamDecoder{R: bytes.NewReader(raw1.Bytes())}, [16]byte{6}, 19, 16)
	must(t, err)
	in0, in1 := testCompactInput(t, 19, 7)
	o0, o1, _, _ := compactPrepared(t, c0, c1, in0, in1)
	verifyCompaction(t, in0, in1, o0, o1)
	if _, err = ReadCompaction1Own(&material.StreamDecoder{R: bytes.NewReader(raw0.Bytes())}, [16]byte{6}, 19, 16); err == nil {
		t.Fatal("compaction role swap accepted")
	}
}
