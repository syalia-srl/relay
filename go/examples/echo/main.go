// An echo host and a guest that pair through a relay and exchange one message.
//
//	RELAY_URL=ws://10.255.0.1:8010 RELAY_KEY=<project key> \
//	    go run ./examples/echo
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	relay "github.com/syalia-srl/relay/go"
)

func must[T any](value T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return value
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := must(os.MkdirTemp("", "relay-example-"))
	defer os.RemoveAll(dir)
	url := os.Getenv("RELAY_URL")
	if url == "" {
		url = "ws://10.255.0.1:8010"
	}
	host := must(relay.OpenHost(ctx, relay.FileStore(filepath.Join(dir, "host")),
		[]relay.Relay{{URL: url, Key: os.Getenv("RELAY_KEY")}}))
	defer host.Close()
	guest := must(relay.OpenGuest(ctx, relay.FileStore(filepath.Join(dir, "guest")), nil))
	defer guest.Close()

	pairing := must(host.Pair(ctx, "echo"))
	link := must(guest.Pair(ctx, pairing.Payload()))
	// A person reads link.Code() on the guest and types it into the host.
	_ = must(pairing.Confirm(ctx, link.Code()))
	check(link.Bound(ctx))

	go func() {
		for {
			device, message, err := host.Recv(ctx)
			if err != nil {
				return
			}
			if device.Send(ctx, message) != nil {
				return
			}
		}
	}()

	check(link.Send(ctx, []byte("hello from the guest")))
	reply := must(link.Recv(ctx))
	fmt.Printf("guest received: %q\n", reply)
	check(link.Unpair(ctx))
}
