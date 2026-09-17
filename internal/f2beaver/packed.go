package f2beaver

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// PackedBatch is this party's triples for independent F2 lanes, not Ring64.
// One-time ownership belongs to the enclosing query packet.
type PackedBatch struct{ a, b, c []uint64 }

func PreprocessPacked(n int) (PackedBatch, PackedBatch, error) {
	if n < 0 || n > int(^uint(0)>>1)/40 {
		return PackedBatch{}, PackedBatch{}, errors.New("f2beaver: packed size")
	}
	p, q := PackedBatch{make([]uint64, n), make([]uint64, n), make([]uint64, n)}, PackedBatch{make([]uint64, n), make([]uint64, n), make([]uint64, n)}
	var raw [40 * 1024]byte
	for start := 0; start < n; {
		count := min(1024, n-start)
		if _, e := rand.Read(raw[:40*count]); e != nil {
			return PackedBatch{}, PackedBatch{}, e
		}
		for j := 0; j < count; j++ {
			v := raw[40*j:]
			a, b := binary.LittleEndian.Uint64(v), binary.LittleEndian.Uint64(v[8:])
			i := start + j
			p.a[i] = binary.LittleEndian.Uint64(v[16:])
			p.b[i] = binary.LittleEndian.Uint64(v[24:])
			p.c[i] = binary.LittleEndian.Uint64(v[32:])
			q.a[i] = a ^ p.a[i]
			q.b[i] = b ^ p.b[i]
			q.c[i] = (a & b) ^ p.c[i]
		}
		start += count
	}
	return p, q, nil
}
func (p PackedBatch) Len() int { return len(p.a) }
func (p PackedBatch) Slice(start, end int) PackedBatch {
	return PackedBatch{p.a[start:end], p.b[start:end], p.c[start:end]}
}
func (p PackedBatch) MaskAt(i int, x, y uint64) (uint64, uint64) { return x ^ p.a[i], y ^ p.b[i] }

// finishWord is the single Beaver Finish formula used by scalar and packed F2.
func finishWord(party uint8, a, b, c, d, e uint64) uint64 {
	z := c ^ (d & b) ^ (e & a)
	if party == 0 {
		z ^= d & e
	}
	return z
}
func (p PackedBatch) FinishAt(party uint8, i int, d, e uint64) uint64 {
	return finishWord(party, p.a[i], p.b[i], p.c[i], d, e)
}
