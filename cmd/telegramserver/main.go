package main

import (
	"flag"
	"log"

	"github.com/g6402886-cmyk/TelegramServer/internal/server"
)

func main() {
	addr := flag.String("addr", ":10443", "TCP listen address")
	rsaKey := flag.String("rsa-key", "server_rsa_private.pem", "RSA private key PEM path")
	rsaPubKey := flag.String("rsa-public-key", "server_rsa_public.pem", "RSA public key PEM path")
	flag.Parse()

	if err := server.ListenAndServe(*addr, *rsaKey, *rsaPubKey); err != nil {
		log.Fatal(err)
	}
}
