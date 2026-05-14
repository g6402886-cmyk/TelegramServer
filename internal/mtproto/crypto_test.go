package mtproto

import "testing"

func TestAESIGERoundtrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("abcdef0123456789abcdef0123456789")
	plain := []byte("0123456789abcdef0123456789abcdef")

	encrypted, err := AESIGEEncrypt(plain, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := AESIGEDecrypt(encrypted, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(plain) {
		t.Fatalf("decrypted mismatch: %x", decrypted)
	}
}

func TestHandshakeAESKeyIV(t *testing.T) {
	newNonce := make([]byte, 32)
	serverNonce := [16]byte{1, 2, 3}
	key, iv := HandshakeAESKeyIV(newNonce, serverNonce)
	if key == [32]byte{} {
		t.Fatal("empty key")
	}
	if iv == [32]byte{} {
		t.Fatal("empty iv")
	}
}
