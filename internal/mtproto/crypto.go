package mtproto

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
)

var (
	ErrInvalidAESBlockSize = errors.New("mtproto: invalid AES-IGE block size")
	ErrInvalidAESParams    = errors.New("mtproto: invalid AES-IGE key or iv")
)

func AESIGEEncrypt(data, key, iv []byte) ([]byte, error) {
	return aesIGE(data, key, iv, true)
}

func AESIGEDecrypt(data, key, iv []byte) ([]byte, error) {
	return aesIGE(data, key, iv, false)
}

func aesIGE(data, key, iv []byte, encrypt bool) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, ErrInvalidAESBlockSize
	}
	if len(key) != 32 || len(iv) != 32 {
		return nil, ErrInvalidAESParams
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(data))
	xPrev := append([]byte(nil), iv[:aes.BlockSize]...)
	yPrev := append([]byte(nil), iv[aes.BlockSize:]...)
	tmp := make([]byte, aes.BlockSize)
	for offset := 0; offset < len(data); offset += aes.BlockSize {
		src := data[offset : offset+aes.BlockSize]
		dst := out[offset : offset+aes.BlockSize]
		if encrypt {
			xorBlock(tmp, src, yPrev)
			block.Encrypt(dst, tmp)
			xorBlock(dst, dst, xPrev)
			copy(xPrev, src)
			copy(yPrev, dst)
			continue
		}
		xorBlock(tmp, src, xPrev)
		block.Decrypt(dst, tmp)
		xorBlock(dst, dst, yPrev)
		copy(xPrev, dst)
		copy(yPrev, src)
	}

	return out, nil
}

func xorBlock(dst, a, b []byte) {
	for i := 0; i < aes.BlockSize; i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func HandshakeAESKeyIV(newNonce []byte, serverNonce [16]byte) ([32]byte, [32]byte) {
	var material [64]byte
	buf := make([]byte, 0, 64)
	buf = append(buf, newNonce...)
	buf = append(buf, serverNonce[:]...)
	sumA := sha1.Sum(buf)

	buf = buf[:0]
	buf = append(buf, serverNonce[:]...)
	buf = append(buf, newNonce...)
	sumB := sha1.Sum(buf)

	buf = buf[:0]
	buf = append(buf, newNonce...)
	buf = append(buf, newNonce...)
	sumC := sha1.Sum(buf)

	copy(material[0:], sumA[:])
	copy(material[20:], sumB[:])
	copy(material[40:], sumC[:])
	copy(material[60:], newNonce[:4])

	var key [32]byte
	var iv [32]byte
	copy(key[:], material[:32])
	copy(iv[:], material[32:])
	return key, iv
}

func PadWithHash(data []byte) ([]byte, error) {
	total := 20 + len(data)
	if rem := total % aes.BlockSize; rem != 0 {
		total += aes.BlockSize - rem
	}

	out := make([]byte, total)
	hash := sha1.Sum(data)
	copy(out, hash[:])
	copy(out[20:], data)
	if _, err := rand.Read(out[20+len(data):]); err != nil {
		return nil, err
	}
	return out, nil
}

func VerifyPaddedHash(data []byte) ([]byte, error) {
	if len(data) < 24 || len(data)%aes.BlockSize != 0 {
		return nil, ErrInvalidAESBlockSize
	}
	hash := data[:20]
	body := data[20:]
	for size := len(body); size >= 4; size-- {
		sum := sha1.Sum(body[:size])
		if string(hash) == string(sum[:]) {
			return body[:size], nil
		}
	}
	return nil, ErrDecode
}

func NewNonceHash(newNonce, authKey []byte, number byte) [16]byte {
	authKeyHash := sha1.Sum(authKey)
	buf := make([]byte, 0, len(newNonce)+1+20)
	buf = append(buf, newNonce...)
	buf = append(buf, number)
	buf = append(buf, authKeyHash[:]...)
	sum := sha1.Sum(buf[:len(buf)-12])

	var out [16]byte
	copy(out[:], sum[4:])
	return out
}

func AuthKeyID(authKey []byte) int64 {
	hash := sha1.Sum(authKey)
	return int64(readLittleUint64(hash[12:20]))
}

func readLittleUint64(v []byte) uint64 {
	return uint64(v[0]) | uint64(v[1])<<8 | uint64(v[2])<<16 | uint64(v[3])<<24 |
		uint64(v[4])<<32 | uint64(v[5])<<40 | uint64(v[6])<<48 | uint64(v[7])<<56
}

func SHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}
