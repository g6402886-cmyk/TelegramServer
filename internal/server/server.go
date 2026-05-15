package server

import (
	"crypto/rsa"
	"errors"
	"io"
	"log"
	"net"
	"time"

	"github.com/g6402886-cmyk/TelegramServer/internal/mtproto"
	"github.com/g6402886-cmyk/TelegramServer/internal/transport"
)

func ListenAndServe(addr string, rsaKeyPath string, rsaPublicKeyPath string) error {
	privateKey, err := mtproto.LoadOrCreateRSAKey(rsaKeyPath, rsaPublicKeyPath)
	if err != nil {
		return err
	}
	fingerprint, err := mtproto.RSAFingerprint(privateKey)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("telegram server listening on %s rsa_fingerprint=0x%016x", listener.Addr(), fingerprint)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleConnection(conn, privateKey, fingerprint)
	}
}

func handleConnection(conn net.Conn, privateKey *rsa.PrivateKey, fingerprint uint64) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))

	codec, err := transport.NewCodec(conn)
	if err != nil {
		log.Printf("transport handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("accepted mtproto transport from %s dc=%d protocol=0x%08x", conn.RemoteAddr(), codec.DCID(), codec.Protocol())

	session := newHandshakeSession(privateKey, fingerprint)
	for {
		payload, err := codec.ReadFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("read frame failed from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}

		response, err := session.handlePayload(payload)
		if err != nil {
			log.Printf("payload ignored from %s: %v", conn.RemoteAddr(), err)
			continue
		}
		if err := codec.WriteFrame(response); err != nil {
			log.Printf("write frame failed to %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}

type handshakeSession struct {
	privateKey  *rsa.PrivateKey
	fingerprint uint64
	serverNonce [16]byte
	dh          *mtproto.DHState
	authKey     []byte
}

func newHandshakeSession(privateKey *rsa.PrivateKey, fingerprint uint64) *handshakeSession {
	return &handshakeSession{privateKey: privateKey, fingerprint: fingerprint}
}

func (s *handshakeSession) handlePayload(payload []byte) ([]byte, error) {
	message, err := mtproto.ParseUnencryptedMessage(payload)
	if err != nil {
		return nil, err
	}

	constructor, err := mtproto.Constructor(message.Body)
	if err != nil {
		return nil, err
	}

	var body []byte
	switch constructor {
	case mtproto.ConstructorReqPQ, mtproto.ConstructorReqPQMulti:
		body, err = s.handleReqPQ(message.Body)
	case mtproto.ConstructorReqDHParams:
		body, err = s.handleReqDHParams(message.Body)
	case mtproto.ConstructorSetClientDHParams:
		body, err = s.handleSetClientDHParams(message.Body)
	default:
		err = mtproto.ErrUnsupportedMessage
	}
	if err != nil {
		return nil, err
	}
	return mtproto.EncodeUnencryptedMessage(nextMessageID(), body), nil
}

func (s *handshakeSession) handleReqPQ(body []byte) ([]byte, error) {
	nonce, err := mtproto.ParseReqPQNonce(body)
	if err != nil {
		return nil, err
	}

	serverNonce, err := mtproto.RandomNonce()
	if err != nil {
		return nil, err
	}
	s.serverNonce = serverNonce

	return mtproto.EncodeResPQ(nonce, serverNonce, mtproto.DefaultPQ, []uint64{s.fingerprint}), nil
}

func (s *handshakeSession) handleReqDHParams(body []byte) ([]byte, error) {
	req, err := mtproto.ParseReqDHParams(body)
	if err != nil {
		return nil, err
	}
	inner, err := mtproto.DecryptPQInnerData(s.privateKey, s.fingerprint, req)
	if err != nil {
		return nil, err
	}
	state, response, err := mtproto.BuildServerDHParams(req, inner)
	if err != nil {
		return nil, err
	}
	s.dh = &state
	return response, nil
}

func (s *handshakeSession) handleSetClientDHParams(body []byte) ([]byte, error) {
	if s.dh == nil {
		return nil, mtproto.ErrUnsupportedMessage
	}
	req, err := mtproto.ParseSetClientDHParams(body)
	if err != nil {
		return nil, err
	}
	authKey, response, err := mtproto.CompleteClientDH(*s.dh, req)
	if err != nil {
		return nil, err
	}
	s.authKey = authKey
	log.Printf("mtproto auth key established id=%d", mtproto.AuthKeyID(authKey))
	return response, nil
}

func nextMessageID() int64 {
	now := time.Now()
	return (now.Unix() << 32) | int64((now.Nanosecond()/1_000_000)<<22)
}
