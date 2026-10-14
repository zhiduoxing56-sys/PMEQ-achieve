package core

import (
	"crypto/aes"

	"pmeq/internal/domain"
)

var (
	domainLeft    = [16]byte{}
	domainRight   = [16]byte{15: 1}
	domainControl = [16]byte{15: 2}
	domainValue   = [16]byte{15: 3}
)

func encrypt(seed Seed, input [16]byte) (output Seed) {
	block, err := aes.NewCipher(seed[:])
	if err != nil {
		panic("dpf128: impossible AES-128 key length")
	}
	block.Encrypt(output[:], input[:])
	return output
}

func Expand(seed Seed) (left Seed, leftControl domain.Bit, right Seed, rightControl domain.Bit) {
	block, err := aes.NewCipher(seed[:])
	if err != nil {
		panic("dpf128: impossible AES-128 key length")
	}
	var control Seed
	block.Encrypt(left[:], domainLeft[:])
	block.Encrypt(right[:], domainRight[:])
	block.Encrypt(control[:], domainControl[:])
	leftControl = domain.Bit((control[0]>>7)&1 == 1)
	rightControl = domain.Bit((control[0]>>6)&1 == 1)
	return left, leftControl, right, rightControl
}

func Convert(seed Seed) domain.Bit {
	value := encrypt(seed, domainValue)
	return domain.Bit((value[0]>>7)&1 == 1)
}
