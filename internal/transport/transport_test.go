package transport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func TestPlainAbridgedRoundTrip(t *testing.T) {
	conn := bytes.NewBuffer(nil)
	codec, err := NewPlainCodec(conn, ProtocolAbridged, 1)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := codec.WriteFrame(payload); err != nil {
		t.Fatal(err)
	}

	got, err := codec.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %x", got)
	}
}

func TestPlainIntermediateRoundTrip(t *testing.T) {
	conn := bytes.NewBuffer(nil)
	codec, err := NewPlainCodec(conn, ProtocolIntermediate, 1)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte{1, 2, 3, 4}
	if err := codec.WriteFrame(payload); err != nil {
		t.Fatal(err)
	}

	got, err := codec.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %x", got)
	}
}

func TestObfuscatedAbridgedRead(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	input := buildObfuscatedInput(t, ProtocolAbridged, payload)

	codec, err := NewObfuscatedCodec(bytes.NewBuffer(input))
	if err != nil {
		t.Fatal(err)
	}
	if codec.DCID() != 1 {
		t.Fatalf("dc = %d", codec.DCID())
	}
	if codec.Protocol() != ProtocolAbridged {
		t.Fatalf("protocol = 0x%08x", codec.Protocol())
	}

	got, err := codec.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %x", got)
	}
}

func buildObfuscatedInput(t *testing.T, protocol uint32, payload []byte) []byte {
	t.Helper()

	var header [64]byte
	if _, err := rand.Read(header[:]); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(header[56:60], protocol)
	binary.LittleEndian.PutUint16(header[60:62], 1)

	stream := newStream(t, header[8:40], header[40:56])
	encryptedHeader := append([]byte(nil), header[:]...)
	stream.XORKeyStream(encryptedHeader, encryptedHeader)
	copy(header[56:64], encryptedHeader[56:64])

	frame := []byte{byte(len(payload) / 4)}
	frame = append(frame, payload...)
	stream.XORKeyStream(frame, frame)

	return append(header[:], frame...)
}

func newStream(t *testing.T, key []byte, iv []byte) cipher.Stream {
	t.Helper()

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return cipher.NewCTR(block, iv)
}
