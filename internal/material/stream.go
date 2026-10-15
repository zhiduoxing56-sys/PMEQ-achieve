package material

import (
	"encoding/binary"
	"errors"
	"io"
)

var ErrEncoding = errors.New("material: invalid or truncated own-share encoding")

// StreamEncoder and StreamDecoder use fixed-width little-endian fields. They
// never collect a complete material file in memory. Callers fix every public
// array length and authenticate the enclosing file before accepting a packet.
type StreamEncoder struct {
	W   io.Writer
	Err error
	b   [8]byte
}

func (e *StreamEncoder) Bytes(v []byte) {
	if e.Err != nil {
		return
	}
	n, err := e.W.Write(v)
	if err == nil && n != len(v) {
		err = io.ErrShortWrite
	}
	e.Err = err
}
func (e *StreamEncoder) U8(v uint8) { e.b[0] = v; e.Bytes(e.b[:1]) }
func (e *StreamEncoder) U32(v uint32) {
	binary.LittleEndian.PutUint32(e.b[:4], v)
	e.Bytes(e.b[:4])
}
func (e *StreamEncoder) U64(v uint64) {
	binary.LittleEndian.PutUint64(e.b[:8], v)
	e.Bytes(e.b[:8])
}
func (e *StreamEncoder) Blob(v []byte) {
	if uint64(len(v)) > uint64(^uint32(0)) {
		e.Err = ErrEncoding
		return
	}
	e.U32(uint32(len(v)))
	e.Bytes(v)
}

type StreamDecoder struct {
	R   io.Reader
	Err error
	b   [8]byte
}

func (d *StreamDecoder) Bytes(v []byte) {
	if d.Err == nil {
		_, d.Err = io.ReadFull(d.R, v)
	}
}
func (d *StreamDecoder) U8() uint8 { d.Bytes(d.b[:1]); return d.b[0] }
func (d *StreamDecoder) U32() uint32 {
	d.Bytes(d.b[:4])
	return binary.LittleEndian.Uint32(d.b[:4])
}
func (d *StreamDecoder) U64() uint64 {
	d.Bytes(d.b[:8])
	return binary.LittleEndian.Uint64(d.b[:8])
}
func (d *StreamDecoder) Blob(max uint32) []byte {
	n := d.U32()
	if d.Err != nil || n > max {
		d.Err = ErrEncoding
		return nil
	}
	v := make([]byte, n)
	d.Bytes(v)
	return v
}
