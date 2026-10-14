package material

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

var ErrConsumed = errors.New("material: reservation already consumed or durable claim failed")

// ClaimPersistent burns a reservation BEFORE any token/masked opening. O_EXCL
// prevents two processes from claiming it; fsync of file and directory makes
// the burn survive restart. A crash burns the whole reservation, fail closed.
func ClaimPersistent(dir string, id [16]byte) error {
	if dir == "" || id == [16]byte{} {
		return ErrConsumed
	}
	f, e := os.OpenFile(filepath.Join(dir, hex.EncodeToString(id[:])+".consumed"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ErrConsumed
	}
	_, e = f.Write([]byte("consumed-before-online\n"))
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
