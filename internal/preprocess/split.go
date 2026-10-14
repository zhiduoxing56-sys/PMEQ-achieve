// Package preprocess provides trusted-DO splitting of values into two
// independent party-local shares.
package preprocess

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"pmeq/internal/domain"
	"pmeq/internal/share"
)

func SplitBit(secret domain.Bit) (share.BitShare, share.BitShare, error) {
	return splitBitWithReader(rand.Reader, secret)
}

func SplitRing32(secret domain.Ring32) (share.Ring32Share, share.Ring32Share, error) {
	return splitRing32WithReader(rand.Reader, secret)
}

func SplitRing64(secret domain.Ring64) (share.Ring64Share, share.Ring64Share, error) {
	return splitRing64WithReader(rand.Reader, secret)
}

func splitBitWithReader(random io.Reader, secret domain.Bit) (share.BitShare, share.BitShare, error) {
	var raw [1]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return share.BitShare{}, share.BitShare{}, err
	}
	left := domain.Bit(raw[0]&1 == 1)
	return share.NewBitShare(left), share.NewBitShare(secret.Sub(left)), nil
}

func splitRing32WithReader(random io.Reader, secret domain.Ring32) (share.Ring32Share, share.Ring32Share, error) {
	var raw [4]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return share.Ring32Share{}, share.Ring32Share{}, err
	}
	left := domain.Ring32(binary.LittleEndian.Uint32(raw[:]))
	return share.NewRing32Share(left), share.NewRing32Share(secret.Sub(left)), nil
}

func splitRing64WithReader(random io.Reader, secret domain.Ring64) (share.Ring64Share, share.Ring64Share, error) {
	var raw [8]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return share.Ring64Share{}, share.Ring64Share{}, err
	}
	left := domain.Ring64(binary.LittleEndian.Uint64(raw[:]))
	return share.NewRing64Share(left), share.NewRing64Share(secret.Sub(left)), nil
}
