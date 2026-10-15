// Package targetcrypto implements the PHASE 3B Target routing foundation: the
// canonical target encoder, the keyed scalar mapping, the fixed KHPRF base
// point, Ristretto255 additive point sharing, and the domain-separated bucket
// component mapping.
//
// Every share type in this package holds at most one party's local value. No
// exported type carries a peer share, a full secret, a join value, a q-gram, a
// record identifier, a position, or a party index, and the package exposes no
// point or scalar recovery entry point.
package targetcrypto

import (
	"crypto/rand"
	"errors"
	"io"
)

var errZeroMasterKey = errors.New("targetcrypto: all-zero master key is invalid")

// MasterKey is the 256-bit Target routing secret shared only by the data owner
// and an authorized query user. Provisioning, persistence, and logging are
// outside this package: it deliberately offers no serialization and no
// formatting method.
type MasterKey [32]byte

// GenerateMasterKey creates a fresh production MasterKey from the operating
// system's cryptographic random source.
func GenerateMasterKey() (MasterKey, error) {
	return generateMasterKeyWithReader(rand.Reader)
}

// NewMasterKey validates trusted 256-bit key material supplied by a future
// provisioning boundary. An all-zero value is rejected so that an unset key
// cannot silently reach production.
func NewMasterKey(material [32]byte) (MasterKey, error) {
	if material == ([32]byte{}) {
		return MasterKey{}, errZeroMasterKey
	}
	return MasterKey(material), nil
}

func generateMasterKeyWithReader(random io.Reader) (MasterKey, error) {
	var material [32]byte
	if _, err := io.ReadFull(random, material[:]); err != nil {
		return MasterKey{}, err
	}
	return NewMasterKey(material)
}
