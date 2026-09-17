package aggregation

import (
	"encoding/binary"
	"pmeq/internal/domain"
)

func (m ShuffleMessage) Encode() []byte {
	b := make([]byte, 37+43*len(m.values))
	copy(b, m.layout[:])
	copy(b[16:], m.query[:])
	b[32] = byte(m.stage)
	binary.LittleEndian.PutUint32(b[33:], uint32(len(m.values)))
	for i, v := range m.values {
		at := 37 + 43*i
		if v.keep {
			b[at] = 1
		}
		binary.LittleEndian.PutUint64(b[at+1:], v.id)
		copy(b[at+9:], v.scalar.Bytes())
		binary.LittleEndian.PutUint16(b[at+41:], v.bucket)
	}
	return b
}
func DecodeShuffle(b []byte) (ShuffleMessage, error) {
	var m ShuffleMessage
	if len(b) < 37 {
		return m, ErrCompaction
	}
	n := int(binary.LittleEndian.Uint32(b[33:]))
	if n > CandidateCount || len(b) != 37+43*n || (b[32] != 1 && b[32] != 2) {
		return m, ErrCompaction
	}
	copy(m.layout[:], b)
	copy(m.query[:], b[16:])
	m.stage = int(b[32])
	m.values = make([]compactTuple, n)
	for i := range m.values {
		at := 37 + 43*i
		if b[at] > 1 {
			return m, ErrCompaction
		}
		v := &m.values[i]
		v.keep = domain.Bit(b[at] == 1)
		v.id = binary.LittleEndian.Uint64(b[at+1:])
		if _, e := v.scalar.SetCanonicalBytes(b[at+9 : at+41]); e != nil {
			return m, e
		}
		v.bucket = binary.LittleEndian.Uint16(b[at+41:])
	}
	return m, nil
}
func (m KeepOpening) Encode() []byte {
	b := make([]byte, 37+len(m.bits))
	copy(b, m.layout[:])
	copy(b[16:], m.query[:])
	b[32] = m.party
	binary.LittleEndian.PutUint32(b[33:], uint32(len(m.bits)))
	for i, v := range m.bits {
		if v {
			b[37+i] = 1
		}
	}
	return b
}
func DecodeKeepOpening(b []byte) (KeepOpening, error) {
	var m KeepOpening
	if len(b) < 37 {
		return m, ErrCompaction
	}
	n := int(binary.LittleEndian.Uint32(b[33:]))
	if n > CandidateCount || len(b) != 37+n || b[32] > 1 {
		return m, ErrCompaction
	}
	copy(m.layout[:], b)
	copy(m.query[:], b[16:])
	m.party = b[32]
	m.bits = make([]domain.Bit, n)
	for i := range m.bits {
		if b[37+i] > 1 {
			return m, ErrCompaction
		}
		m.bits[i] = domain.Bit(b[37+i] == 1)
	}
	return m, nil
}
