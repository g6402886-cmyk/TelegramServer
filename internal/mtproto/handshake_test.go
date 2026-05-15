package mtproto

import (
	"bytes"
	"math/big"
	"testing"
)

func TestServerDHInnerDataEncoding(t *testing.T) {
	var nonce [16]byte
	var serverNonce [16]byte
	body := EncodeServerDHInnerData(nonce, serverNonce, DHGenerator, DHPrime(), []byte{1, 2, 3}, 123)

	r := NewReader(body)
	if constructor := r.UInt32(); constructor != ConstructorServerDHInnerData {
		t.Fatalf("constructor = 0x%x", constructor)
	}
	r.Bytes(16)
	r.Bytes(16)
	if g := r.Int32(); g != DHGenerator {
		t.Fatalf("g = %d", g)
	}
	if prime := r.String(); !bytes.Equal(prime, DHPrime()) {
		t.Fatal("dh prime mismatch")
	}
	if gA := r.String(); !bytes.Equal(gA, []byte{1, 2, 3}) {
		t.Fatal("g_a mismatch")
	}
	if serverTime := r.Int32(); serverTime != 123 {
		t.Fatalf("server time = %d", serverTime)
	}
	if r.Err() != nil {
		t.Fatal(r.Err())
	}
}

func TestCompleteClientDH(t *testing.T) {
	var nonce [16]byte
	var serverNonce [16]byte
	for i := range nonce {
		nonce[i] = byte(i)
		serverNonce[i] = byte(16 - i)
	}
	newNonce := make([]byte, 32)
	for i := range newNonce {
		newNonce[i] = byte(i + 1)
	}

	serverA := []byte{5}
	clientB := []byte{7}
	p := DHPrimeInt()
	g := big.NewInt(DHGenerator)
	gB := new(big.Int).Exp(g, new(big.Int).SetBytes(clientB), p)

	inner := EncodeClientDHInnerData(nonce, serverNonce, 0, gB.Bytes())
	padded, err := PadWithHash(inner)
	if err != nil {
		t.Fatal(err)
	}
	key, iv := HandshakeAESKeyIV(newNonce, serverNonce)
	encrypted, err := AESIGEEncrypt(padded, key[:], iv[:])
	if err != nil {
		t.Fatal(err)
	}

	state := DHState{Nonce: nonce, ServerNonce: serverNonce, NewNonce: newNonce, A: serverA}
	_, response, err := CompleteClientDH(state, SetClientDHParams{
		Nonce:         nonce,
		ServerNonce:   serverNonce,
		EncryptedData: encrypted,
	})
	if err != nil {
		t.Fatal(err)
	}

	r := NewReader(response)
	if constructor := r.UInt32(); constructor != ConstructorDHGenOK {
		t.Fatalf("constructor = 0x%x", constructor)
	}
	if !bytes.Equal(r.Bytes(16), nonce[:]) {
		t.Fatal("nonce mismatch")
	}
	if !bytes.Equal(r.Bytes(16), serverNonce[:]) {
		t.Fatal("server nonce mismatch")
	}
	if hash := r.Bytes(16); len(hash) != 16 {
		t.Fatal("missing new nonce hash")
	}
}
