//go:build phase6native

// Package scmpnative binds the repaired in-project native LLAMA comparison.
package scmpnative

/*
#cgo LDFLAGS: -lstdc++ -lcrypto
#include <stdint.h>
#include <stddef.h>
int phase6_keygen(unsigned,unsigned,unsigned,unsigned,uint8_t*,uint8_t*,size_t*,size_t*,uint8_t*,uint8_t*);
int scmp128_key_eval(const uint8_t*,size_t,int,int,uint32_t,uint32_t,uint8_t*);
void scmp128_init(void);
*/
import "C"
import (
	"encoding/binary"
	"errors"
	"pmeq/internal/anchorfilter"
	"pmeq/internal/domain"
	"pmeq/internal/share"
	"sync"
)

type Backend struct{}

var once sync.Once
var errNative = errors.New("native SCMP: invalid input or backend failure (supports Bin=7 or 10, Bout=1)")

func inputMask(bin uint8) (uint32, bool) {
	if bin != 7 && bin != 10 {
		return 0, false
	}
	return (uint32(1) << bin) - 1, true
}

func (Backend) KeyGen(bin uint8, x, y uint32, o domain.Bit) (anchorfilter.SCMPKeyShare, anchorfilter.SCMPKeyShare, error) {
	m, ok := inputMask(bin)
	if !ok || x > m || y > m {
		return anchorfilter.SCMPKeyShare{}, anchorfilter.SCMPKeyShare{}, errNative
	}
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
	if len(b) < 4 {
		return share.BitShare{}, errNative
	}
	width := binary.LittleEndian.Uint32(b[:4])
	if width != 7 && width != 10 {
		return share.BitShare{}, errNative
	}
	m, _ := inputMask(uint8(width))
	if p > 1 || len(b) != 88+28*int(width) || x > m || y > m {
		return share.BitShare{}, errNative
	}
	var v C.uint8_t
	if C.scmp128_key_eval((*C.uint8_t)(&b[0]), C.size_t(len(b)), C.int(p), 1, C.uint32_t(x), C.uint32_t(y), &v) != 1 {
		return share.BitShare{}, errNative
	}
	// Existing PHASE4/5 Finish methods remove k.OutputMaskShare() once.
	return share.NewBitShare(domain.Bit(v != 0)), nil
}
