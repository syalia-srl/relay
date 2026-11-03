# Go

The Go module `github.com/syalia-srl/relay/go`, package `relay`, implements both
ends of the channel protocol: the host of a server install and the guest of a client.
It pairs two static keys through a relay, then carries messages with Noise IKpsk1 and
KK ([PROTOCOL.md](protocol.html) sections 3 to 9). A message is a `[]byte`; one `Send`
arrives as one `Recv`, up to the 16 MiB limit of the protocol. Every call that
waits takes a `context.Context`; every call that can fail returns an `error`. The API has no goroutines or channels of its own.

The public surface is four things: a host, a guest, a pairing, and a peer to send to
and receive from. The only dependency is `github.com/coder/websocket`; the
cryptography is in the standard library (`crypto/ecdh`, `crypto/aes`, `crypto/cipher`,
`crypto/hkdf`, `crypto/hmac`, `crypto/sha256`).

## Install

```bash
go get github.com/syalia-srl/relay/go
```

The module requires Go 1.27 or later.

## A host

`relay.OpenHost` reads or creates the state through a store, draws the host's static
key on the first run, and opens a socket on every channel of every bound device:

```go
host, err := relay.OpenHost(ctx, relay.FileStore("state/host"), []relay.Relay{
	{URL: "wss://relay.syalia.dev", Key: projectKey},
})
if err != nil { ... }
defer host.Close()
```

The relay list is ordered. The host creates a pairing channel, and later one device
channel, on each relay, and keeps a socket on each. A `relay.Relay` checks its URL
against the policy of section 8.1: `wss`, or `ws` to a literal private address. A host
may reach a relay by a different URL than the one it gives guests, which is how an
install uses `ws://relay:8010` on a container network while its guests use
`wss://relay.example.com`.

`host.Pair(ctx, name)` draws a device id, a pairing secret and the channels:

```go
pairing, err := host.Pair(ctx, "pixel-7")
showQR(pairing.Payload())                        // string, the JSON of section 4
```

`Payload()` is the pairing payload. The application renders it as a QR code or as
copied text with any library it likes; the relay library does not draw it. The payload
carries the pairing secret and live guest tokens, so it travels only over the
application's authenticated admin connection and is never logged.

The host confirms in a later request, after a person reads the six digits on the
guest. The device id is what the admin session stores between the two requests:

```go
pairing, err := host.Pairing(deviceID)           // the id from pairing.Device()
device, err := pairing.Confirm(ctx, code)        // *relay.WrongCodeError, relay.ErrPairingFailed
```

`host.Pairing(id)` returns the open pairing or an error when it has ended. `Confirm`
is the only way to bind a key. A wrong code returns a `*relay.WrongCodeError` with
`TriesLeft`; the third wrong code, two pending keys with the same code, the expiry or
the 10-minute limit return an error that `errors.Is(err, relay.ErrPairingFailed)`. The
host never exposes the codes of pending keys.

Messages from every bound device arrive through `host.Recv`:

```go
for {
	device, message, err := host.Recv(ctx)
	if err != nil { break }                      // relay.ErrClosed after Close
	err = device.Send(ctx, message)              // echo it back
}
```

`device.Send` waits until the device is connected or `ctx` ends. `host.Devices()`
lists the bound devices, each with `ID()`, `Name()` and `Connected()`. Revocation
sends `revoked`, deletes the channels on every relay and unbinds the key:

```go
err = host.Revoke(ctx, device)
```

Every method is safe to call from several goroutines. `host.Close()` stops the
sockets; the bound devices and their channels stay in the store.

## A guest

`relay.OpenGuest` reads or creates the guest state. Its third argument is `nil`, which
makes the library draw a fresh static key for each pairing and keep it in the store:

```go
guest, err := relay.OpenGuest(ctx, relay.FileStore("state/guest"), nil)
defer guest.Close()
```

A native key store implements `relay.StaticKey`:

```go
type StaticKey interface {
	PublicKey() []byte
	DH(peerPublic []byte) ([]byte, error)
}
```

The library asks that object for Diffie-Hellman results and never sees the private
key, so the key can live in an HSM or another process. A native key serves one
pairing: a second host needs a second `Guest` with its own store and key.

First contact takes the payload string and returns the paired host:

```go
link, err := guest.Pair(ctx, pairing.Payload())  // relay.ErrPayloadInvalid on a bad payload
fmt.Println(link.Code())                         // the 6 digits the person types
if err := link.Bound(ctx); err != nil { ... }    // device channels carry a session
```

`guest.Pair` returns once the host holds the guest's key candidate and the pairing
code exists, which is before the person has typed it. `link.Bound(ctx)` returns when
the host has confirmed and the device channels work.

```go
err = link.Send(ctx, message)
message, err := link.Recv(ctx)                   // relay.ErrRevoked when revoked
```

`Recv` returns `relay.ErrRevoked` when the host revokes the device. Unpairing sends
`close`, waits for `closed` and forgets the host; `guest.Close()` only stops the
connections and keeps the pairings in the store:

```go
err = link.Unpair(ctx)
err = guest.Close()
```

After a restart, `guest.Hosts()` lists the paired hosts. A pairing that a restart
interrupts is not kept: the person scans a new payload.

## Store

```go
type Store interface {
	Load() ([]byte, error)   // nil, nil on the first run
	Save([]byte) error
}
```

`relay.FileStore(path)` writes atomically at mode `0600`. An application can keep the
same bytes in a database or in a secret manager behind its own `Store`. The state
holds keys: the host's static key, or the guest's per-pairing keys.

## Errors

| Error | Returned when |
|---|---|
| `relay.ErrPayloadInvalid` | The payload is not the JSON of section 4, or every relay in it fails the URL policy. |
| `*relay.WrongCodeError` | The typed code matches no pending key; `TriesLeft` says how many remain. |
| `relay.ErrPairingFailed` | The pairing expired, collided, ran out of tries, or has ended. |
| `relay.ErrRevoked` | The host revoked this device. |
| `relay.ErrClosed` | The host or guest has been closed. |

`errors.Is` and `errors.As` match all of them. Transient network errors are retried
inside the library and never returned.

## What the application still owns

`PROTOCOL.md` section 10 lists five duties outside the encrypted stream. The library's
shape leaves them where they belong:

| Duty | In a Go application |
|---|---|
| The code that holds the guest key | The application ships and updates the guest binary; a `relay.StaticKey` can keep the private key in an HSM or another process. |
| The host key at rest | The state belongs to the `Store`; `relay.FileStore` writes `0600` and the directory is the application's choice. |
| The confirmation | `Confirm(ctx, code)` takes the code; the application decides who may call it and over which connection. |
| What a session may do | The application reads the `*relay.Device` and the message and decides what to run; the library has no command set. |
| Revocation | `host.Revoke(ctx, device)` sends `revoked`, deletes the channels and unbinds the key. |

The application also owns the QR display, the admin login that carries the payload
and the code, and the choice of relays.

## Worked example

The example is one program with an echo host and a guest in the same process. It
starts both from temporary stores, pairs them through a relay, sends one message from
the guest, echoes it from the host and prints the reply. The person's step is played
by the program: `pairing.Confirm(ctx, link.Code())` uses the code the guest shows,
where a real application would read it from a person.

<!-- include: go/examples/echo/main.go go -->

It runs against a relay on a private address, because a guest accepts `ws://` only to
one (section 8.1):

```bash
RELAY_URL=ws://10.255.0.1:8010 RELAY_KEY=<project key> \
    go run ./examples/echo
```

The command runs from the `go/` directory and prints one line, `guest received:
"hello from the guest"`. The [relay page](run-a-relay.html) covers the relay, its keys
file and its checks.
