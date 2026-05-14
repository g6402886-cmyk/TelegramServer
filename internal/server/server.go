package server

import (
	"errors"
	"io"
	"log"
	"net"
	"time"

	"github.com/g6402886-cmyk/TelegramServer/internal/mtproto"
	"github.com/g6402886-cmyk/TelegramServer/internal/transport"
)

func ListenAndServe(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("telegram server listening on %s", listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))

	codec, err := transport.NewCodec(conn)
	if err != nil {
		log.Printf("transport handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}
	log.Printf("accepted mtproto transport from %s dc=%d protocol=0x%08x", conn.RemoteAddr(), codec.DCID(), codec.Protocol())

	for {
		payload, err := codec.ReadFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("read frame failed from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}

		response, err := handlePayload(payload)
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

func handlePayload(payload []byte) ([]byte, error) {
	message, err := mtproto.ParseUnencryptedMessage(payload)
	if err != nil {
		return nil, err
	}

	nonce, err := mtproto.ParseReqPQNonce(message.Body)
	if err != nil {
		return nil, err
	}

	serverNonce, err := mtproto.RandomNonce()
	if err != nil {
		return nil, err
	}

	body := mtproto.EncodeResPQ(nonce, serverNonce, mtproto.DefaultPQ, []uint64{mtproto.DefaultKeyFingerprint})
	return mtproto.EncodeUnencryptedMessage(nextMessageID(), body), nil
}

func nextMessageID() int64 {
	now := time.Now()
	return (now.Unix() << 32) | int64((now.Nanosecond()/1_000_000)<<22)
}
