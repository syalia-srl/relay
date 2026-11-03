# Public API of the Go library

The same four things as the Python and JavaScript libraries (`py/API.md`,
`js/API.md`): a host, a guest, a pairing, and a peer to send to and receive from, in
the shape a Go programmer expects: a `context.Context` on every call that waits, an
`error` on every call that can fail, no goroutines or channels in the API. Everything
else in PROTOCOL.md stays internal. Messages are `[]byte`; one `Send` arrives as one
`Recv`. Module `github.com/syalia-srl/relay/go`, package `relay`. The only dependency
is `github.com/coder/websocket`, which the relay server already uses; the cryptography
is the standard library's (`crypto/ecdh`, `crypto/aes`, `crypto/cipher`,
`crypto/hkdf`, `crypto/hmac`, `crypto/sha256`).

## Host

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

- `host.Devices()` lists bound devices; a `*Device` has `ID()`, `Name()` and
  `Connected()`.
- `device.Send` waits until the device is connected or `ctx` ends.
- `Confirm` is the only way to bind a key. A wrong code returns a
  `*relay.WrongCodeError` with `TriesLeft`; the third wrong code, a collision, `exp` or
  the 10-minute limit return an error that `errors.Is(err, relay.ErrPairingFailed)`.
  The host never exposes pending codes.
- Every method is safe to call from several goroutines.

## Guest

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

- The third argument of `OpenGuest` is nil or a `relay.StaticKey`:

  ```go
  type StaticKey interface {
  	PublicKey() []byte
  	DH(peerPublic []byte) ([]byte, error)
  }
  ```

  so the private key can live in an HSM or another process. With nil the guest draws
  one per pairing and keeps it in the store. A given key serves one pairing, as in
  Python and JavaScript.
- `guest.Hosts()` lists paired hosts after a restart.

## Stores

A `relay.Store` is `Load() ([]byte, error)` (nil, nil on the first run) and
`Save([]byte) error`. `relay.FileStore(path)` writes atomically at mode 0600.

## Errors

`relay.ErrPairingFailed`, `relay.ErrRevoked`, `relay.ErrPayloadInvalid`,
`relay.ErrClosed` and `*relay.WrongCodeError`, all matched with `errors.Is` and
`errors.As`. Transient network errors are retried inside and never returned.

## Not in the API

No callbacks, no exported channels, no functional options, nothing beyond the above.
