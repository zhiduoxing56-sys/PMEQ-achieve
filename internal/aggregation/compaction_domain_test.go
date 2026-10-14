package aggregation

import (
	"encoding/binary"
	"testing"
)

func TestCompactionExplicitDomainDecode(t *testing.T) {
	for _, n := range []int{0, 7, CandidateCount, CandidateCount + 1, 1000000} {
		shuffle := make([]byte, 37+43*n)
		shuffle[32] = 1
		binary.LittleEndian.PutUint32(shuffle[33:], uint32(n))
		keep := make([]byte, 37+n)
		binary.LittleEndian.PutUint32(keep[33:], uint32(n))
		if _, e := DecodeShuffleForDomain(shuffle, n); e != nil {
			t.Fatal(n, e)
		}
		if _, e := DecodeKeepOpeningForDomain(keep, n); e != nil {
			t.Fatal(n, e)
		}
		if _, e := DecodeShuffleForDomain(shuffle, n+1); e == nil {
			t.Fatal("wrong N accepted")
		}
		if _, e := DecodeKeepOpeningForDomain(keep, n+1); e == nil {
			t.Fatal("wrong N accepted")
		}
		if n > CandidateCount {
			if _, e := DecodeShuffle(shuffle); e == nil {
				t.Fatal("default cap changed")
			}
			if _, e := DecodeKeepOpening(keep); e == nil {
				t.Fatal("default cap changed")
			}
		}
		if _, e := DecodeShuffleForDomain(shuffle[:len(shuffle)-1], n); e == nil {
			t.Fatal("truncation accepted")
		}
		if _, e := DecodeKeepOpeningForDomain(keep[:len(keep)-1], n); e == nil {
			t.Fatal("truncation accepted")
		}
	}
	if _, e := DecodeShuffleForDomain(nil, -1); e == nil {
		t.Fatal("negative N")
	}
	if _, e := DecodeKeepOpeningForDomain(nil, -1); e == nil {
		t.Fatal("negative N")
	}
}
