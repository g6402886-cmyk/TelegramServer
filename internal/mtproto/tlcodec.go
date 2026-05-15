package mtproto

import (
	"encoding/binary"
	"errors"
)

var ErrDecode = errors.New("mtproto: decode error")

type Reader struct {
	data []byte
	pos  int
	err  error
}

func NewReader(data []byte) *Reader {
	return &Reader{data: data}
}

func (r *Reader) Err() error {
	return r.err
}

func (r *Reader) Pos() int {
	return r.pos
}

func (r *Reader) Bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.pos+n > len(r.data) {
		r.err = ErrDecode
		return nil
	}
	value := r.data[r.pos : r.pos+n]
	r.pos += n
	return value
}

func (r *Reader) UInt32() uint32 {
	value := r.Bytes(4)
	if value == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(value)
}

func (r *Reader) Int32() int32 {
	return int32(r.UInt32())
}

func (r *Reader) UInt64() uint64 {
	value := r.Bytes(8)
	if value == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(value)
}

func (r *Reader) Int64() int64 {
	return int64(r.UInt64())
}

func (r *Reader) String() []byte {
	if r.err != nil {
		return nil
	}
	first := r.Bytes(1)
	if first == nil {
		return nil
	}

	length := int(first[0])
	if first[0] == 254 {
		wide := r.Bytes(3)
		if wide == nil {
			return nil
		}
		length = int(wide[0]) | int(wide[1])<<8 | int(wide[2])<<16
	}

	value := append([]byte(nil), r.Bytes(length)...)
	for r.err == nil && r.pos%4 != 0 {
		r.Bytes(1)
	}
	return value
}

type Writer struct {
	buf []byte
}

func NewWriter() *Writer {
	return &Writer{buf: make([]byte, 0, 256)}
}

func (w *Writer) Bytes() []byte {
	return append([]byte(nil), w.buf...)
}

func (w *Writer) UInt32(v uint32) {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	w.buf = append(w.buf, tmp[:]...)
}

func (w *Writer) Int32(v int32) {
	w.UInt32(uint32(v))
}

func (w *Writer) UInt64(v uint64) {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	w.buf = append(w.buf, tmp[:]...)
}

func (w *Writer) Int64(v int64) {
	w.UInt64(uint64(v))
}

func (w *Writer) Raw(v []byte) {
	w.buf = append(w.buf, v...)
}

func (w *Writer) String(v []byte) {
	if len(v) < 254 {
		w.buf = append(w.buf, byte(len(v)))
		w.buf = append(w.buf, v...)
		for len(w.buf)%4 != 0 {
			w.buf = append(w.buf, 0)
		}
		return
	}

	w.buf = append(w.buf, 254, byte(len(v)), byte(len(v)>>8), byte(len(v)>>16))
	w.buf = append(w.buf, v...)
	for len(w.buf)%4 != 0 {
		w.buf = append(w.buf, 0)
	}
}

func (w *Writer) VectorLong(values []uint64) {
	w.UInt32(0x1cb5c415)
	w.UInt32(uint32(len(values)))
	for _, value := range values {
		w.UInt64(value)
	}
}
