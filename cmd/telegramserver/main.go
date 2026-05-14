package main

import (
	"flag"
	"log"

	"github.com/g6402886-cmyk/TelegramServer/internal/server"
)

func main() {
	addr := flag.String("addr", ":10443", "TCP listen address")
	flag.Parse()

	if err := server.ListenAndServe(*addr); err != nil {
		log.Fatal(err)
	}
}
