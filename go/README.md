# relay (Go)

The host and guest of the relay channel protocol (`PROTOCOL.md`, sections 3 to 9),
in the shape a Go programmer expects. The module is
`github.com/syalia-srl/relay/go`, the package is `relay`, and the only dependency
is `github.com/coder/websocket`. Cryptography uses the standard library only.

    go get github.com/syalia-srl/relay/go

## Usage

`go/API.md` is the complete public API.

### Host

```go
host, err := relay.OpenHost(ctx, relay.FileStore("state/host"), []relay.Relay{
	{URL: "wss://relay.syalia.dev", Key: projectKey},
})
if err != nil { ... }
defer host.Close()

pairing, err := host.Pair(ctx, "pixel-7")
showQR(pairing.Payload())                        // string, the JSON of section 4

pairing, err = host.Pairing(pairing.Device())   // in a later request
device, err := pairing.Confirm(ctx, code)       // *relay.WrongCodeError, relay.ErrPairingFailed

for {
	device, message, err := host.Recv(ctx)      // messages from every bound device
	if err != nil { break }                      // relay.ErrClosed after Close
	err = device.Send(ctx, []byte("pong"))
}

err = host.Revoke(ctx, device)
```

### Guest

```go
guest, err := relay.OpenGuest(ctx, relay.FileStore("state/guest"), nil)   // or a StaticKey
defer guest.Close()

host, err := guest.Pair(ctx, payload)            // first contact
fmt.Println(host.Code())                         // the 6 digits the person types
err = host.Bound(ctx)

err = host.Send(ctx, message)
message, err := host.Recv(ctx)                   // errors.Is(err, relay.ErrRevoked) when revoked

err = host.Unpair(ctx)                           // close / closed
```

A `relay.StaticKey` has `PublicKey() []byte` and `DH(peerPublic []byte) ([]byte, error)`,
so a guest can keep its private key in an HSM or another process. With `nil`,
`OpenGuest` draws and stores one key per pairing.

## Test

    cd go
    go vet ./...
    go test -race ./...

The end-to-end and hostile-relay tests start the relay binary named by
`RELAY_BIN` (default `../server/relay`) on a private address given by
`RELAY_TEST_ADDR` or found on a local interface. Build it first:

    cd server && CGO_ENABLED=0 go build -o relay ./cmd/relay

The cross-language matrix also needs `uv` for the Python partner and `node` for
the JavaScript partner; without both it is skipped.
