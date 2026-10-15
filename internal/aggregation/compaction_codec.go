package aggregation

import (
	"encoding/binary"
	"pmeq/internal/domain"
)

func (m ShuffleMessage) Encode() []byte {
	stride := 43
	if m.bucketBits > 16 {
		stride = 45
	}
	b := make([]byte, 37+stride*len(m.values))
	copy(b, m.layout[:])
	copy(b[16:], m.query[:])
	b[32] = byte(m.stage)
	if stride == 45 {
		b[32] |= 0x80
	}
	binary.LittleEndian.PutUint32(b[33:], uint32(len(m.values)))
	for i, v := range m.values {
		at := 37 + stride*i
		if v.keep {
			b[at] = 1
		}
		binary.LittleEndian.PutUint64(b[at+1:], v.id)
		copy(b[at+9:], v.scalar.Bytes())
		if stride == 45 {
			binary.LittleEndian.PutUint32(b[at+41:], v.bucket)
		} else {
			binary.LittleEndian.PutUint16(b[at+41:], uint16(v.bucket))
		}
	}
	return b
}
func DecodeShuffle(b []byte) (ShuffleMessage, error) {
	return decodeShuffle(b, CandidateCount)
}

// DecodeShuffleForDomain binds decoding to the caller's public global domain.
// The wire format and tuple decoding are identical to DecodeShuffle.
func DecodeShuffleForDomain(b []byte, n int) (ShuffleMessage, error) {
	if n < 0 || uint64(n) > uint64(^uint32(0)) || len(b) < 37 || uint64(binary.LittleEndian.Uint32(b[33:])) != uint64(n) {
		return ShuffleMessage{}, ErrCompaction
	}
	return decodeShuffle(b, n)
}

func decodeShuffle(b []byte, limit int) (ShuffleMessage, error) {
	var m ShuffleMessage
	if len(b) < 37 {
		return m, ErrCompaction
	}
	n := int(binary.LittleEndian.Uint32(b[33:]))
	stage := b[32] & 0x7f
	stride := 43
	if b[32]&0x80 != 0 {
		stride = 45
	}
	if n > limit || uint64(len(b)) != 37+uint64(stride)*uint64(n) || (stage != 1 && stage != 2) {
		return m, ErrCompaction
	}
	copy(m.layout[:], b)
	copy(m.query[:], b[16:])
	m.stage = int(stage)
	if stride == 45 {
		m.bucketBits = 17
	}
	m.values = make([]compactTuple, n)
	for i := range m.values {
		at := 37 + stride*i
		if b[at] > 1 {
			return m, ErrCompaction
		}
		v := &m.values[i]
		v.keep = domain.Bit(b[at] == 1)
		v.id = binary.LittleEndian.Uint64(b[at+1:])
		if _, e := v.scalar.SetCanonicalBytes(b[at+9 : at+41]); e != nil {
			return m, e
		}
		if stride == 45 {
			v.bucket = binary.LittleEndian.Uint32(b[at+41:])
		} else {
			v.bucket = uint32(binary.LittleEndian.Uint16(b[at+41:]))
		}
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
	return decodeKeepOpening(b, CandidateCount)
}

// DecodeKeepOpeningForDomain requires the explicitly selected public domain.
func DecodeKeepOpeningForDomain(b []byte, n int) (KeepOpening, error) {
	if n < 0 || uint64(n) > uint64(^uint32(0)) || len(b) < 37 || uint64(binary.LittleEndian.Uint32(b[33:])) != uint64(n) {
		return KeepOpening{}, ErrCompaction
	}
	return decodeKeepOpening(b, n)
}

func decodeKeepOpening(b []byte, limit int) (KeepOpening, error) {
	var m KeepOpening
	if len(b) < 37 {
		return m, ErrCompaction
	}
	n := int(binary.LittleEndian.Uint32(b[33:]))
	if n > limit || uint64(len(b)) != 37+uint64(n) || b[32] > 1 {
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
