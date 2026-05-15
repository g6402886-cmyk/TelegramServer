package mtproto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
)

func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRSAPrivateKey(data)
}

func LoadOrCreateRSAKey(privatePath string, publicPath string) (*rsa.PrivateKey, error) {
	key, err := LoadRSAPrivateKey(privatePath)
	if err == nil {
		return key, WriteRSAPublicKey(publicPath, &key.PublicKey)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := writeFile(privatePath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0o600); err != nil {
		return nil, err
	}
	if err := WriteRSAPublicKey(publicPath, &key.PublicKey); err != nil {
		return nil, err
	}
	return key, nil
}

func WriteRSAPublicKey(path string, key *rsa.PublicKey) error {
	return writeFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(key),
	}), 0o644)
}

func ParseRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("mtproto: invalid rsa private key pem")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("mtproto: pem is not an rsa private key")
	}
	return key, nil
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, perm)
}

func RSAFingerprint(key *rsa.PrivateKey) (uint64, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return 0, err
	}
	hash := SHA1(der)
	return binary.LittleEndian.Uint64(hash[12:20]), nil
}

func RSAModExpDecrypt(key *rsa.PrivateKey, encrypted []byte) ([]byte, error) {
	if len(encrypted) != key.Size() {
		return nil, ErrDecode
	}
	c := new(big.Int).SetBytes(encrypted)
	if c.Cmp(key.N) >= 0 {
		return nil, ErrDecode
	}
	m := new(big.Int).Exp(c, key.D, key.N)
	out := make([]byte, key.Size())
	return m.FillBytes(out), nil
}

func SHA1(data []byte) [20]byte {
	return sha1.Sum(data)
}
