package mtproto

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestReqPQRoundTrip(t *testing.T) {
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[:4], ConstructorReqPQMulti)
	for i := range 16 {
		body[4+i] = byte(i)
	}

	payload := EncodeUnencryptedMessage(123, body)
	message, err := ParseUnencryptedMessage(payload)
	if err != nil {
		t.Fatal(err)
	}
	if message.MessageID != 123 {
		t.Fatalf("message id = %d", message.MessageID)
	}

	nonce, err := ParseReqPQNonce(message.Body)
	if err != nil {
		t.Fatal(err)
	}
	for i, value := range nonce {
		if value != byte(i) {
			t.Fatalf("nonce[%d] = %d", i, value)
		}
	}
}

func TestUnsupportedConstructor(t *testing.T) {
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[:4], 0xffffffff)

	_, err := ParseReqPQNonce(body)
	if !errors.Is(err, ErrUnsupportedMessage) {
		t.Fatalf("expected unsupported message, got %v", err)
	}
}

func TestEncodeResPQ(t *testing.T) {
	var nonce [16]byte
	var serverNonce [16]byte
	body := EncodeResPQ(nonce, serverNonce, DefaultPQ, []uint64{DefaultKeyFingerprint})

	if got := binary.LittleEndian.Uint32(body[:4]); got != ConstructorResPQ {
		t.Fatalf("constructor = 0x%08x", got)
	}
}
