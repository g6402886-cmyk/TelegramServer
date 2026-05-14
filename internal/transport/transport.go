package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	ProtocolAbridged           = uint32(0xefefefef)
	ProtocolIntermediate       = uint32(0xeeeeeeee)
	ProtocolPaddedIntermediate = uint32(0xdddddddd)

	MaxFrameSize = 16 * 1024 * 1024
)

var (
	ErrUnsupportedTransport = errors.New("transport: unsupported mtproto transport")
	ErrInvalidFrame         = errors.New("transport: invalid frame")
)

type Codec interface {
	ReadFrame() ([]byte, error)
	WriteFrame([]byte) error
	DCID() int16
	Protocol() uint32
}

type codec struct {
	conn     io.ReadWriter
	protocol uint32
	dcID     int16
	encrypt  cipher.Stream
	decrypt  cipher.Stream
}

func NewCodec(conn io.ReadWriter) (Codec, error) {
	return NewObfuscatedCodec(conn)
}

func NewObfuscatedCodec(conn io.ReadWriter) (Codec, error) {
	var header [64]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}

	decrypt, err := aesCTR(header[8:40], header[40:56])
	if err != nil {
		return nil, err
	}

	var reversed [48]byte
	for i := 0; i < 48; i++ {
		reversed[i] = header[55-i]
	}
	encrypt, err := aesCTR(reversed[:32], reversed[32:48])
	if err != nil {
		return nil, err
	}

	probe := append([]byte(nil), header[:]...)
	decrypt.XORKeyStream(probe, probe)
	protocol := binary.BigEndian.Uint32(probe[56:60])
	if protocol != ProtocolAbridged && protocol != ProtocolIntermediate && protocol != ProtocolPaddedIntermediate {
		return nil, fmt.Errorf("%w: protocol 0x%08x", ErrUnsupportedTransport, protocol)
	}

	dcID := int16(binary.LittleEndian.Uint16(probe[60:62]))
	if dcID == 0 {
		return nil, fmt.Errorf("%w: empty dc id", ErrUnsupportedTransport)
	}

	return &codec{
		conn:     conn,
		protocol: protocol,
		dcID:     dcID,
		encrypt:  encrypt,
		decrypt:  decrypt,
	}, nil
}

func NewPlainCodec(conn io.ReadWriter, protocol uint32, dcID int16) (Codec, error) {
	switch protocol {
	case ProtocolAbridged, ProtocolIntermediate, ProtocolPaddedIntermediate:
	default:
		return nil, fmt.Errorf("%w: protocol 0x%08x", ErrUnsupportedTransport, protocol)
	}

	return &codec{
		conn:     conn,
		protocol: protocol,
		dcID:     dcID,
	}, nil
}

func (c *codec) DCID() int16 {
	return c.dcID
}

func (c *codec) Protocol() uint32 {
	return c.protocol
}

func (c *codec) ReadFrame() ([]byte, error) {
	switch c.protocol {
	case ProtocolAbridged:
		return c.readAbridged()
	case ProtocolIntermediate, ProtocolPaddedIntermediate:
		return c.readIntermediate()
	default:
		return nil, ErrUnsupportedTransport
	}
}

func (c *codec) WriteFrame(payload []byte) error {
	switch c.protocol {
	case ProtocolAbridged:
		return c.writeAbridged(payload)
	case ProtocolIntermediate, ProtocolPaddedIntermediate:
		return c.writeIntermediate(payload)
	default:
		return ErrUnsupportedTransport
	}
}

func (c *codec) readAbridged() ([]byte, error) {
	lengthHeader := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, lengthHeader); err != nil {
		return nil, err
	}
	decrypt(c.decrypt, lengthHeader)

	var length int
	if lengthHeader[0] == 0x7f {
		wide := make([]byte, 3)
		if _, err := io.ReadFull(c.conn, wide); err != nil {
			return nil, err
		}
		decrypt(c.decrypt, wide)
		length = int(uint32(wide[0]) | uint32(wide[1])<<8 | uint32(wide[2])<<16)
	} else {
		length = int(lengthHeader[0] & 0x7f)
	}

	size := length * 4
	if size <= 0 || size > MaxFrameSize {
		return nil, fmt.Errorf("%w: abridged size %d", ErrInvalidFrame, size)
	}

	return c.readEncryptedPayload(size)
}

func (c *codec) readIntermediate() ([]byte, error) {
	lengthHeader := make([]byte, 4)
	if _, err := io.ReadFull(c.conn, lengthHeader); err != nil {
		return nil, err
	}
	decrypt(c.decrypt, lengthHeader)

	size := int(binary.LittleEndian.Uint32(lengthHeader) & 0x7fffffff)
	if size <= 0 || size%4 != 0 || size > MaxFrameSize {
		return nil, fmt.Errorf("%w: intermediate size %d", ErrInvalidFrame, size)
	}

	return c.readEncryptedPayload(size)
}

func (c *codec) readEncryptedPayload(size int) ([]byte, error) {
	payload := make([]byte, size)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, err
	}
	decrypt(c.decrypt, payload)
	return payload, nil
}

func (c *codec) writeAbridged(payload []byte) error {
	if len(payload)%4 != 0 {
		return fmt.Errorf("%w: payload is not divisible by 4", ErrInvalidFrame)
	}

	length := len(payload) / 4
	var frame []byte
	if length < 0x7f {
		frame = append(frame, byte(length))
	} else {
		frame = append(frame, 0x7f, byte(length), byte(length>>8), byte(length>>16))
	}
	frame = append(frame, payload...)
	encrypt(c.encrypt, frame)
	_, err := c.conn.Write(frame)
	return err
}

func (c *codec) writeIntermediate(payload []byte) error {
	frame := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	encrypt(c.encrypt, frame)
	_, err := c.conn.Write(frame)
	return err
}

func encrypt(stream cipher.Stream, payload []byte) {
	if stream != nil {
		stream.XORKeyStream(payload, payload)
	}
}

func decrypt(stream cipher.Stream, payload []byte) {
	if stream != nil {
		stream.XORKeyStream(payload, payload)
	}
}

func aesCTR(key []byte, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}
