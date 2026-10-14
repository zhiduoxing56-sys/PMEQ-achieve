package aggregation

import (
	"encoding/binary"
	"io"
)

// WriteSigma preserves the original explicit uint32 permutation representation.
func (s *Stage1) WriteSigma(w io.Writer) error {
	if s == nil {
		return ErrShape
	}
	var b [65536]byte
	for at := 0; at < len(s.sigma); {
		n := min(len(b)/4, len(s.sigma)-at)
		for i := 0; i < n; i++ {
			binary.LittleEndian.PutUint32(b[4*i:], s.sigma[at+i])
		}
		m, e := w.Write(b[:4*n])
		if e != nil {
			return e
		}
		if m != 4*n {
			return io.ErrShortWrite
		}
		at += n
	}
	return nil
}

// ReadSigma restores one authenticated party's original Stage1 state.
func ReadSigma(r io.Reader, layout [16]byte, bucket uint32, n int) (*Stage1, error) {
	if layout == [16]byte{} || n < 0 || uint64(n) > uint64(^uint32(0)) {
		return nil, ErrShape
	}
	s := &Stage1{LayoutID: layout, BucketID: bucket, sigma: make([]uint32, n)}
	if e := binary.Read(r, binary.LittleEndian, s.sigma); e != nil {
		return nil, e
	}
	if !validPermutation(s.sigma) {
		return nil, ErrShape
	}
	return s, nil
}
