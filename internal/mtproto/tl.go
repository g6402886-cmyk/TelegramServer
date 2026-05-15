package mtproto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ConstructorReqPQMulti = uint32(0xbe7e8ef1)
	ConstructorReqPQ      = uint32(0x60469778)
	ConstructorResPQ      = uint32(0x05162463)
)

var (
	ErrPacketTooShort     = errors.New("mtproto: packet too short")
	ErrUnsupportedMessage = errors.New("mtproto: unsupported message")

	DefaultPQ = []byte{0x17, 0xed, 0x48, 0x94, 0x1a, 0x08, 0xf9, 0x81}
)

type UnencryptedMessage struct {
	AuthKeyID int64
	MessageID int64
	Body      []byte
}

func ParseUnencryptedMessage(payload []byte) (UnencryptedMessage, error) {
	if len(payload) < 20 {
		return UnencryptedMessage{}, ErrPacketTooShort
	}

	bodyLen := int(binary.LittleEndian.Uint32(payload[16:20]))
	if bodyLen < 4 || len(payload) < 20+bodyLen {
		return UnencryptedMessage{}, fmt.Errorf("%w: invalid body length %d", ErrPacketTooShort, bodyLen)
	}

	return UnencryptedMessage{
		AuthKeyID: int64(binary.LittleEndian.Uint64(payload[0:8])),
		MessageID: int64(binary.LittleEndian.Uint64(payload[8:16])),
		Body:      payload[20 : 20+bodyLen],
	}, nil
}

func EncodeUnencryptedMessage(messageID int64, body []byte) []byte {
	payload := make([]byte, 20+len(body))
	binary.LittleEndian.PutUint64(payload[8:16], uint64(messageID))
	binary.LittleEndian.PutUint32(payload[16:20], uint32(len(body)))
	copy(payload[20:], body)
	return payload
}

func Constructor(body []byte) (uint32, error) {
	if len(body) < 4 {
		return 0, ErrPacketTooShort
	}
	return binary.LittleEndian.Uint32(body[:4]), nil
}

func ParseReqPQNonce(body []byte) ([16]byte, error) {
	constructor, err := Constructor(body)
	if err != nil {
		return [16]byte{}, err
	}
	if constructor != ConstructorReqPQMulti && constructor != ConstructorReqPQ {
		return [16]byte{}, fmt.Errorf("%w: constructor 0x%08x", ErrUnsupportedMessage, constructor)
	}
	if len(body) < 20 {
		return [16]byte{}, ErrPacketTooShort
	}

	var nonce [16]byte
	copy(nonce[:], body[4:20])
	return nonce, nil
}

func EncodeResPQ(nonce [16]byte, serverNonce [16]byte, pq []byte, fingerprints []uint64) []byte {
	writer := NewWriter()
	writer.UInt32(ConstructorResPQ)
	writer.Raw(nonce[:])
	writer.Raw(serverNonce[:])
	writer.String(pq)
	writer.VectorLong(fingerprints)
	return writer.Bytes()
}

func RandomNonce() ([16]byte, error) {
	var nonce [16]byte
	_, err := rand.Read(nonce[:])
	return nonce, err
}
