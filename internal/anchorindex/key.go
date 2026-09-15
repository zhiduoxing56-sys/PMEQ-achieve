package anchorindex

import (
	"crypto/rand"
	"errors"
	"io"
)

var errZeroKey = errors.New("anchorindex: all-zero key is invalid")

// Key is the 256-bit secret held only by the DO and an authorized Query User.
// Key provisioning and serialization are outside the AnchorIndexEncode
// primitive and are intentionally not implemented here.
type Key [32]byte

// Value is the opaque 128-bit Anchor production index representation.
type Value [16]byte

// GenerateKey creates a fresh production Key from the operating system's
// cryptographic random source.
func GenerateKey() (Key, error) {
	return generateKeyWithReader(rand.Reader)
}

// NewKey validates trusted 256-bit key material supplied by a future
// provisioning boundary. It does not serialize, persist, or log the material.
func NewKey(material [32]byte) (Key, error) {
	if material == ([32]byte{}) {
		return Key{}, errZeroKey
	}
	return Key(material), nil
}

func generateKeyWithReader(random io.Reader) (Key, error) {
	var material [32]byte
	if _, err := io.ReadFull(random, material[:]); err != nil {
		return Key{}, err
	}
	return NewKey(material)
}

func (key Key) valid() bool {
	return key != (Key{})
}
