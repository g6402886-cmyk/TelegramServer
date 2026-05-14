package mtproto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math/big"
	"time"
)

const (
	ConstructorReqDHParams       = uint32(0xd712e4be)
	ConstructorServerDHParamsOK  = uint32(0xd0e8075c)
	ConstructorSetClientDHParams = uint32(0xf5045f1f)
	ConstructorDHGenOK           = uint32(0x3bcbf734)

	ConstructorPQInnerData       = uint32(0x83c95aec)
	ConstructorPQInnerDataDC     = uint32(0xa9f55f95)
	ConstructorPQInnerDataTemp   = uint32(0x3c6a84d4)
	ConstructorPQInnerDataTempDC = uint32(0x56fddf88)
	ConstructorServerDHInnerData = uint32(0xb5890dba)
	ConstructorClientDHInnerData = uint32(0x6643b654)
)

var (
	DefaultP = []byte{0x49, 0x4c, 0x55, 0x3b}
	DefaultQ = []byte{0x53, 0x91, 0x10, 0x73}

	ErrBadNonce       = errors.New("mtproto: bad nonce")
	ErrBadFingerprint = errors.New("mtproto: bad rsa fingerprint")
)

type ReqDHParams struct {
	Nonce                [16]byte
	ServerNonce          [16]byte
	P                    []byte
	Q                    []byte
	PublicKeyFingerprint uint64
	EncryptedData        []byte
}

type PQInnerData struct {
	PQ          []byte
	P           []byte
	Q           []byte
	Nonce       [16]byte
	ServerNonce [16]byte
	NewNonce    []byte
}

type SetClientDHParams struct {
	Nonce         [16]byte
	ServerNonce   [16]byte
	EncryptedData []byte
}

type ClientDHInnerData struct {
	Nonce       [16]byte
	ServerNonce [16]byte
	RetryID     int64
	GB          []byte
}

type DHState struct {
	Nonce       [16]byte
	ServerNonce [16]byte
	NewNonce    []byte
	A           []byte
}

func ParseReqDHParams(body []byte) (ReqDHParams, error) {
	r := NewReader(body)
	if r.UInt32() != ConstructorReqDHParams {
		return ReqDHParams{}, ErrUnsupportedMessage
	}
	var out ReqDHParams
	copy(out.Nonce[:], r.Bytes(16))
	copy(out.ServerNonce[:], r.Bytes(16))
	out.P = r.String()
	out.Q = r.String()
	out.PublicKeyFingerprint = r.UInt64()
	out.EncryptedData = r.String()
	if r.Err() != nil {
		return ReqDHParams{}, r.Err()
	}
	return out, nil
}

func ParseSetClientDHParams(body []byte) (SetClientDHParams, error) {
	r := NewReader(body)
	if r.UInt32() != ConstructorSetClientDHParams {
		return SetClientDHParams{}, ErrUnsupportedMessage
	}
	var out SetClientDHParams
	copy(out.Nonce[:], r.Bytes(16))
	copy(out.ServerNonce[:], r.Bytes(16))
	out.EncryptedData = r.String()
	if r.Err() != nil {
		return SetClientDHParams{}, r.Err()
	}
	return out, nil
}

func DecryptPQInnerData(privateKey *rsa.PrivateKey, fingerprint uint64, req ReqDHParams) (PQInnerData, error) {
	if req.PublicKeyFingerprint != fingerprint {
		return PQInnerData{}, ErrBadFingerprint
	}
	data, err := RSAModExpDecrypt(privateKey, req.EncryptedData)
	if err != nil {
		return PQInnerData{}, err
	}

	key := append([]byte(nil), data[:32]...)
	hash := SHA256(data[32:])
	for i := range key {
		key[i] ^= hash[i]
	}
	zeroIV := make([]byte, 32)
	decrypted, err := AESIGEDecrypt(data[32:], key, zeroIV)
	if err != nil {
		return PQInnerData{}, err
	}
	if len(decrypted) != 224 {
		return PQInnerData{}, ErrDecode
	}

	padded := decrypted[:192]
	for i, j := 0, len(padded)-1; i < j; i, j = i+1, j-1 {
		padded[i], padded[j] = padded[j], padded[i]
	}
	return parsePQInnerData(padded)
}

func parsePQInnerData(data []byte) (PQInnerData, error) {
	for size := len(data); size >= 4; size-- {
		out, err := tryParsePQInnerData(data[:size])
		if err == nil {
			return out, nil
		}
	}
	return PQInnerData{}, ErrDecode
}

func tryParsePQInnerData(data []byte) (PQInnerData, error) {
	r := NewReader(data)
	constructor := r.UInt32()
	if constructor != ConstructorPQInnerData &&
		constructor != ConstructorPQInnerDataDC &&
		constructor != ConstructorPQInnerDataTemp &&
		constructor != ConstructorPQInnerDataTempDC {
		return PQInnerData{}, ErrUnsupportedMessage
	}

	var out PQInnerData
	out.PQ = r.String()
	out.P = r.String()
	out.Q = r.String()
	copy(out.Nonce[:], r.Bytes(16))
	copy(out.ServerNonce[:], r.Bytes(16))
	out.NewNonce = r.Bytes(32)
	if constructor == ConstructorPQInnerDataDC || constructor == ConstructorPQInnerDataTempDC {
		r.Int32()
	}
	if constructor == ConstructorPQInnerDataTemp || constructor == ConstructorPQInnerDataTempDC {
		r.Int32()
	}
	if r.Err() != nil || r.Pos() != len(data) {
		return PQInnerData{}, ErrDecode
	}
	return out, nil
}

func BuildServerDHParams(req ReqDHParams, inner PQInnerData) (DHState, []byte, error) {
	if req.Nonce != inner.Nonce || req.ServerNonce != inner.ServerNonce {
		return DHState{}, nil, ErrBadNonce
	}
	if !bytes.Equal(inner.PQ, DefaultPQ) || !bytes.Equal(inner.P, DefaultP) || !bytes.Equal(inner.Q, DefaultQ) {
		return DHState{}, nil, ErrDecode
	}

	a := make([]byte, 256)
	if _, err := rand.Read(a); err != nil {
		return DHState{}, nil, err
	}

	p := DHPrimeInt()
	g := big.NewInt(DHGenerator)
	gA := new(big.Int).Exp(g, new(big.Int).SetBytes(a), p)
	serverDHInner := EncodeServerDHInnerData(req.Nonce, req.ServerNonce, DHGenerator, DHPrime(), gA.Bytes(), int32(time.Now().Unix()))
	padded, err := PadWithHash(serverDHInner)
	if err != nil {
		return DHState{}, nil, err
	}

	key, iv := HandshakeAESKeyIV(inner.NewNonce, req.ServerNonce)
	encrypted, err := AESIGEEncrypt(padded, key[:], iv[:])
	if err != nil {
		return DHState{}, nil, err
	}

	state := DHState{
		Nonce:       req.Nonce,
		ServerNonce: req.ServerNonce,
		NewNonce:    inner.NewNonce,
		A:           a,
	}
	body := EncodeServerDHParamsOK(req.Nonce, req.ServerNonce, encrypted)
	return state, body, nil
}

func EncodeServerDHInnerData(nonce, serverNonce [16]byte, g int, dhPrime, gA []byte, serverTime int32) []byte {
	w := NewWriter()
	w.UInt32(ConstructorServerDHInnerData)
	w.Raw(nonce[:])
	w.Raw(serverNonce[:])
	w.Int32(int32(g))
	w.String(dhPrime)
	w.String(gA)
	w.Int32(serverTime)
	return w.Bytes()
}

func EncodeServerDHParamsOK(nonce, serverNonce [16]byte, encryptedAnswer []byte) []byte {
	w := NewWriter()
	w.UInt32(ConstructorServerDHParamsOK)
	w.Raw(nonce[:])
	w.Raw(serverNonce[:])
	w.String(encryptedAnswer)
	return w.Bytes()
}

func CompleteClientDH(state DHState, req SetClientDHParams) ([]byte, []byte, error) {
	if state.Nonce != req.Nonce || state.ServerNonce != req.ServerNonce {
		return nil, nil, ErrBadNonce
	}
	key, iv := HandshakeAESKeyIV(state.NewNonce, state.ServerNonce)
	decrypted, err := AESIGEDecrypt(req.EncryptedData, key[:], iv[:])
	if err != nil {
		return nil, nil, err
	}
	body, err := VerifyPaddedHash(decrypted)
	if err != nil {
		return nil, nil, err
	}
	clientInner, err := ParseClientDHInnerData(body)
	if err != nil {
		return nil, nil, err
	}
	if clientInner.Nonce != state.Nonce || clientInner.ServerNonce != state.ServerNonce {
		return nil, nil, ErrBadNonce
	}

	authKeyNum := new(big.Int).Exp(new(big.Int).SetBytes(clientInner.GB), new(big.Int).SetBytes(state.A), DHPrimeInt())
	authKey := PadTo256(authKeyNum)
	return authKey, EncodeDHGenOK(state.Nonce, state.ServerNonce, NewNonceHash(state.NewNonce, authKey, 1)), nil
}

func ParseClientDHInnerData(body []byte) (ClientDHInnerData, error) {
	r := NewReader(body)
	if r.UInt32() != ConstructorClientDHInnerData {
		return ClientDHInnerData{}, ErrUnsupportedMessage
	}
	var out ClientDHInnerData
	copy(out.Nonce[:], r.Bytes(16))
	copy(out.ServerNonce[:], r.Bytes(16))
	out.RetryID = r.Int64()
	out.GB = r.String()
	if r.Err() != nil {
		return ClientDHInnerData{}, r.Err()
	}
	return out, nil
}

func EncodeDHGenOK(nonce, serverNonce [16]byte, newNonceHash1 [16]byte) []byte {
	w := NewWriter()
	w.UInt32(ConstructorDHGenOK)
	w.Raw(nonce[:])
	w.Raw(serverNonce[:])
	w.Raw(newNonceHash1[:])
	return w.Bytes()
}

func EncodeClientDHInnerData(nonce, serverNonce [16]byte, retryID int64, gB []byte) []byte {
	w := NewWriter()
	w.UInt32(ConstructorClientDHInnerData)
	w.Raw(nonce[:])
	w.Raw(serverNonce[:])
	w.Int64(retryID)
	w.String(gB)
	return w.Bytes()
}

func LittleEndianUint64(v []byte) uint64 {
	return binary.LittleEndian.Uint64(v)
}
