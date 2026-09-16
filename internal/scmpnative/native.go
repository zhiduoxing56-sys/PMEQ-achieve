//go:build phase6native

// Package scmpnative is an opt-in experiment adapter to the already validated
// external LLAMA backend. It is excluded from ordinary production builds.
package scmpnative

/*
#cgo LDFLAGS: -lstdc++
#include <stdint.h>
#include <stddef.h>
int phase6_keygen(unsigned,unsigned,unsigned,unsigned,uint8_t*,uint8_t*,size_t*,size_t*,uint8_t*,uint8_t*);
int scmp128_key_eval(const uint8_t*,size_t,int,int,uint8_t,uint8_t,uint8_t*);
void scmp128_init(void);
*/
import "C"
import (
	"errors"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/share"
	"sync"
)

type Backend struct{}

var once sync.Once
var errNative = errors.New("external LLAMA adapter failed")

func (Backend) KeyGen(bin uint8, x, y uint32, o domain.Bit) (anchorfilter.SCMPKeyShare, anchorfilter.SCMPKeyShare, error) {
	once.Do(func() { C.scmp128_init() })
	var a, b [4096]byte
	var na, nb C.size_t
	var ra, rb C.uint8_t
	var ob C.uint
	if o {
		ob = 1
	}
	if C.phase6_keygen(C.uint(bin), C.uint(x), C.uint(y), ob, (*C.uint8_t)(&a[0]), (*C.uint8_t)(&b[0]), &na, &nb, &ra, &rb) != 1 {
		return anchorfilter.SCMPKeyShare{}, anchorfilter.SCMPKeyShare{}, errNative
	}
	return anchorfilter.NewSCMPKeyShare(a[:int(na)], share.NewBitShare(domain.Bit(ra != 0))), anchorfilter.NewSCMPKeyShare(b[:int(nb)], share.NewBitShare(domain.Bit(rb != 0))), nil
}
func (Backend) Eval(p uint8, k anchorfilter.SCMPKeyShare, x, y uint32) (share.BitShare, error) {
	b := k.Opaque()
	if len(b) == 0 {
		return share.BitShare{}, errNative
	}
	var v C.uint8_t
	if C.scmp128_key_eval((*C.uint8_t)(&b[0]), C.size_t(len(b)), C.int(p), 1, C.uint8_t(x), C.uint8_t(y), &v) != 1 {
		return share.BitShare{}, errNative
	}
	// Existing PHASE4/5 Finish methods remove k.OutputMaskShare() once.
	return share.NewBitShare(domain.Bit(v != 0)), nil
}
