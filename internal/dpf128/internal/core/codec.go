package core

import (
	"errors"
	"pmeq/internal/domain"
)

const KeyBytes = 16 + 1 + 128*18 + 1

func Encode(k Key) []byte {
	b := make([]byte, KeyBytes)
	copy(b, k.rootSeed[:])
	bit := func(x domain.Bit) byte {
		if x {
			return 1
		}
		return 0
	}
	b[16] = bit(k.rootControl)
	for i, c := range k.corrections {
		at := 17 + 18*i
		copy(b[at:], c.seedCW[:])
		b[at+16] = bit(c.tcwLeft)
		b[at+17] = bit(c.tcwRight)
	}
	b[len(b)-1] = bit(k.finalCW)
	return b
}
func Decode(b []byte) (Key, error) {
	var k Key
	if len(b) != KeyBytes {
		return k, errors.New("dpf128: key size")
	}
	copy(k.rootSeed[:], b)
	if b[16] > 1 || b[len(b)-1] > 1 {
		return k, errors.New("dpf128: bit")
	}
	k.rootControl = domain.Bit(b[16] == 1)
	k.finalCW = domain.Bit(b[len(b)-1] == 1)
	for i := range k.corrections {
		at := 17 + 18*i
		if b[at+16] > 1 || b[at+17] > 1 {
			return k, errors.New("dpf128: bit")
		}
		copy(k.corrections[i].seedCW[:], b[at:at+16])
		k.corrections[i].tcwLeft = domain.Bit(b[at+16] == 1)
		k.corrections[i].tcwRight = domain.Bit(b[at+17] == 1)
	}
	return k, nil
}
