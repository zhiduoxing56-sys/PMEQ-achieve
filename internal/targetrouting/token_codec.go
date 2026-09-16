package targetrouting

import (
	"encoding/binary"
	"pmeq/internal/targetcrypto"
)

// EncodeToken is the exact QueryUser -> one cloud representation.
func EncodeToken(t QueryToken) ([]byte, error) {
	if e := t.Manifest.Validate(); e != nil {
		return nil, e
	}
	if t.Party > 1 || uint64(len(t.Words)) > uint64(^uint32(0))/4 {
		return nil, ErrBinding
	}
	b := make([]byte, TokenBytes(len(t.Words)))
	copy(b[:16], t.Manifest.IndexID[:])
	b[16] = t.Manifest.TargetBucketBits
	binary.LittleEndian.PutUint32(b[17:21], t.Manifest.Q)
	copy(b[21:37], t.QueryID[:])
	b[37] = t.Party
	binary.LittleEndian.PutUint32(b[38:42], uint32(len(t.Words)))
	d, _ := targetcrypto.NewBucketDomain(int(t.Manifest.TargetBucketBits))
	for h, w := range t.Words {
		if w.OccurrenceID != uint32(h) || w.Position != uint32(4*h) {
			return nil, ErrBinding
		}
		if e := d.Validate(w.BucketWordShare); e != nil {
			return nil, e
		}
		if _, e := targetcrypto.NewPointShare(w.WordPointShare); e != nil {
			return nil, e
		}
		at := 42 + 42*h
		binary.LittleEndian.PutUint32(b[at:], w.OccurrenceID)
		binary.LittleEndian.PutUint32(b[at+4:], w.Position)
		copy(b[at+8:at+40], w.WordPointShare[:])
		binary.LittleEndian.PutUint16(b[at+40:], uint16(w.BucketWordShare))
	}
	return b, nil
}
func DecodeToken(m Manifest, party uint8, b []byte) (QueryToken, error) {
	if len(b) < 42 || party > 1 {
		return QueryToken{}, ErrBinding
	}
	n := uint64(binary.LittleEndian.Uint32(b[38:42]))
	if n > uint64(^uint32(0))/4 || uint64(len(b)) != 42+42*n {
		return QueryToken{}, ErrBinding
	}
	var t QueryToken
	copy(t.Manifest.IndexID[:], b[:16])
	t.Manifest.TargetBucketBits = b[16]
	t.Manifest.Q = binary.LittleEndian.Uint32(b[17:21])
	copy(t.QueryID[:], b[21:37])
	t.Party = b[37]
	if t.Manifest != m || t.Party != party {
		return t, ErrBinding
	}
	t.Words = make([]WordToken, int(n))
	for h := range t.Words {
		at := 42 + 42*h
		w := &t.Words[h]
		w.OccurrenceID = binary.LittleEndian.Uint32(b[at:])
		w.Position = binary.LittleEndian.Uint32(b[at+4:])
		copy(w.WordPointShare[:], b[at+8:at+40])
		w.BucketWordShare = targetcrypto.BucketShare(binary.LittleEndian.Uint16(b[at+40:]))
	}
	_, e := EncodeToken(t)
	return t, e
}
