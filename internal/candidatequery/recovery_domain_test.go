package candidatequery

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestRecoveryActualDomain(t *testing.T) {
	for _, n := range []int{0, 1, 7, 120071, 1000000} {
		k := min(n, 3)
		w, s := fixture(t, k)
		if k > 0 {
			setSlot(t, &s, 0, true, 1<<40|7, 1<<41|9)
		}
		var wire [2][]byte
		for u := range wire {
			var e error
			wire[u], e = EncodeSharesForDomain(uint8(u), s[u], n)
			if e != nil {
				t.Fatal(e)
			}
			legacy, e := EncodeShares(uint8(u), s[u])
			if e != nil || !bytes.Equal(legacy, wire[u]) {
				t.Fatal("wire changed", n)
			}
		}
		out, e := RecoverForDomain(w, wire[0], wire[1], n)
		old, oldErr := Recover(w, wire[0], wire[1])
		if e != nil || oldErr != nil || !reflect.DeepEqual(out, old) {
			t.Fatal("recovery changed", n, e)
		}
		if k > 0 {
			if _, e := RecoverForDomain(w, wire[0], wire[1], k-1); e == nil {
				t.Fatal("K>N")
			}
			if _, e := EncodeSharesForDomain(0, s[0], k-1); e == nil {
				t.Fatal("encode K>N")
			}
		}
		if _, e := RecoverForDomain(w, wire[0], wire[1], -1); e == nil {
			t.Fatal("negative N")
		}
	}
}

func TestRecoveryDomainRejectsMalformed(t *testing.T) {
	w, s := fixture(t, 2)
	for _, duplicate := range []bool{false, true} {
		setSlot(t, &s, 0, duplicate, 7, 8)
		setSlot(t, &s, 1, duplicate, 7, 8)
		b := encode(t, s)
		if _, e := RecoverForDomain(w, b[0], b[1], 2); e == nil {
			t.Fatal("masked zero/duplicate")
		}
	}
	w, s = fixture(t, 1)
	b := encode(t, s)
	for _, field := range []int{9, 30, 46, 62} {
		bad := append([]byte(nil), b[0]...)
		bad[field] ^= 1
		if _, e := RecoverForDomain(w, bad, b[1], 1); e == nil {
			t.Fatal("binding", field)
		}
	}
	if _, e := RecoverForDomain(w, b[1], b[0], 1); e == nil {
		t.Fatal("party")
	}
	if _, e := RecoverForDomain(w, b[0][:len(b[0])-1], b[1], 1); e == nil {
		t.Fatal("truncation")
	}
	bad := append([]byte(nil), b[0]...)
	binary.LittleEndian.PutUint32(bad[78:], ^uint32(0))
	if _, e := DecodeSharesForDomain(0, w, bad, 1); e == nil {
		t.Fatal("untrusted count")
	}
}
