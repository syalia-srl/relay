# JavaScript

The JavaScript library `@syalia/relay` implements both ends of the channel protocol:
the host of a server install and the guest of a browser page or an Android WebView.
It pairs two static keys through a relay, then carries messages with Noise IKpsk1 and
KK ([PROTOCOL.md](protocol.html) sections 3 to 9). A message is a `Uint8Array`; one
`send` arrives as one message, up to the 16 MiB limit of the protocol.

The public surface is four things: `Host`, `Guest`, a pairing, and a peer to send to
and receive from. The library has no runtime dependencies. It uses `crypto.subtle`
for X25519, HKDF, HMAC, SHA-256 and AES-GCM, and the global `WebSocket` and `fetch`,
as browsers, Android WebView and Node 22 provide them. Node-only modules are
imported lazily, so a browser bundle never loads `node:fs`.

## Install

```bash
npm install ./js
```

The package requires Node 22 or later when it runs on Node. In a browser it is a
source module that the page's bundler or its own module loader serves.

## A host

`Host.open` reads or creates the state through a store. The file store writes a JSON
file atomically at mode `0600`; it is the store a host uses, because the host's static
key lives in it:

```js
import { Host, Relay, fileStore } from "@syalia/relay";

const host = await Host.open(fileStore("state/host"), {
  relays: [new Relay("wss://relay.syalia.dev", { key: projectKey })],
});
```

The relay list is ordered. The host creates a pairing channel, and later one device
channel, on each relay, and keeps a socket on each. `Relay` checks its URL against
the policy of section 8.1: `wss`, or `ws` to a literal private address. A host may
reach a relay by a different URL than the one it gives guests, which is how an
install uses `ws://relay:8010` on a container network while its guests use
`wss://relay.example.com`.

`host.pair(name)` draws a device id, a pairing secret and the channels:

```js
const pairing = await host.pair("pixel-7");
showQr(pairing.payload);   // a string: the JSON of PROTOCOL.md section 4
```

`pairing.payload` is the pairing payload. The application renders it as a QR code or
as copied text with any library it likes; the relay library does not draw it. The
payload carries the pairing secret and live guest tokens, so it travels only over the
application's authenticated admin connection and is never logged.

The host confirms in a later request, after a person reads the six digits on the
guest:

```js
const pairing = host.pairing(deviceId);          // the dev drawn by host.pair
const device = await pairing.confirm(code);      // WrongCode, PairingFailed
```

`pairing.device` is the id to store with the pending pairing, for example in the
admin session that rendered the QR. `host.pairing(id)` returns that open pairing or
throws `PairingFailed` when it has ended. `confirm` is the only way to bind a key. A
wrong code throws `WrongCode` with `triesLeft`; the third wrong code, two pending keys
with the same code, the expiry or the 10-minute limit throw `PairingFailed`. The host
never exposes the codes of pending keys.

Messages from every bound device arrive through one async iterator:

```js
for await (const [device, message] of host) {
  await device.send(message);                   // echo it back
}
```

`device.send` waits until the device is connected; pass `{ signal }` to give up:
`device.send(bytes, { signal: AbortSignal.timeout(5000) })`. `host.devices` lists the
bound devices, each with `id`, `name` and `connected`. Revocation sends `revoked`,
deletes the channels on every relay and unbinds the key:

```js
await host.revoke(device);
await host.close();
```

`host.close()` stops the sockets; the bound devices and their channels stay in the
store. The iterator has one consumer; the library keeps a bounded inbox, so a slow
consumer pushes back on the relay through the socket.

## A guest

`Guest.open` reads or creates the guest state through a store. Without a `key` option
the library draws a fresh static key for each pairing with `crypto.subtle` and keeps
it in the store. A browser page uses `webStore`, which is `localStorage`:

```js
import { Guest, webStore } from "@syalia/relay";

const guest = await Guest.open(webStore("relay-guest"));
```

A native key store is passed as any object with a `publicKey` byte array and an
asynchronous `dh(peerPublic)` method:

```js
const guest = await Guest.open(webStore("relay-guest"), { key: keystoreKey });
```

The library asks that object for Diffie-Hellman results and never sees the private
key. This is the shape a WebView app uses to keep the X25519 key in the Android
Keystore behind a native bridge. A native key serves one pairing: a second host needs
a second `Guest` with its own store name and key.

First contact takes the payload string and returns the paired host:

```js
const link = await guest.pair(pairing.payload);  // PayloadInvalid on a bad payload
showCode(link.code);                             // the 6 digits the person types
await link.bound();                              // device channels carry a session
```

`guest.pair` returns once the host holds the guest's key candidate and the pairing
code exists, which is before the person has typed it. `link.bound()` returns when the
host has confirmed and the device channels work.

```js
await link.send(bytes);
for await (const message of link) {
  ...
}
```

The iterator throws `Revoked` when the host revokes the device. Unpairing sends
`close`, waits for `closed` and forgets the host; `guest.close()` only stops the
connections and keeps the pairings in the store:

```js
await link.unpair();
await guest.close();
```

After a restart, `guest.hosts` lists the paired hosts; each is the same `PairedHost`
object `pair` returned, and the library reconnects them. A pairing that a restart
interrupts is not kept: the person scans a new payload.

## Stores

A store is any object with `load()` and `save(state)`, both returning promises.
`load()` answers the state or `null` on the first run. The library ships two:

| Store | Where | Shape |
|---|---|---|
| `fileStore(path)` | Node | A JSON file, replaced atomically, mode `0600`. |
| `webStore(name)` | Browsers | One `localStorage` entry, readable by any script on the page's origin. |

The state holds keys: the host's static key, or the guest's per-pairing keys. With
`webStore` those keys sit in `localStorage` in clear, so the security of the guest key
is the security of the page origin. `Guest.open(store, { key })` with a native key
object keeps the private key out of JavaScript; the page can use it while it is open
but cannot copy it.

The state format is the library's. An application may back a store with a database or
a key-value service, as long as `load` and `save` carry the whole object.

## Errors

| Error | Thrown when |
|---|---|
| `PayloadInvalid` | The payload is not the JSON of section 4, or every relay in it fails the URL policy. |
| `WrongCode` | The typed code matches no pending key; `triesLeft` says how many remain. |
| `PairingFailed` | The pairing expired, collided, ran out of tries, or has ended. |
| `Revoked` | The host revoked this device. |
| `RelayError` | Any other failure, including a damaged store. |

All four specific errors extend `RelayError`. Transient network errors are retried
inside the library and never thrown.

## What the application still owns

`PROTOCOL.md` section 10 lists five duties outside the encrypted stream. The library's
shape leaves them where they belong:

| Duty | In a JavaScript application |
|---|---|
| The code that holds the guest key | The application ships and updates the guest code and its pages; a native `key` object can hold the private key where JavaScript reads only its public half and its `dh` results. |
| The host key at rest | The state belongs to the store; `fileStore` writes `0600`, and a host runs where the file is not public. |
| The confirmation | `pairing.confirm(code)` takes the code; the application decides who may call it and over which connection. |
| What a session may do | The application reads `device` and `message` and decides what to run; the library has no command set. |
| Revocation | `await host.revoke(device)` sends `revoked`, deletes the channels and unbinds the key. |

The application also owns the QR display, the admin login that carries the payload
and the code, and the choice of relays.

## Worked example

The example is one program with an echo host and a guest in the same process. It
starts both from temporary stores, pairs them through a relay, sends one message from
the guest, echoes it from the host and prints the reply. The person's step is played
by the program: `pairing.confirm(link.code)` uses the code the guest shows, where a
real application would read it from a person.

<!-- include: js/examples/echo.mjs javascript -->

It runs against a relay on a private address, because a guest accepts `ws://` only to
one (section 8.1):

```bash
RELAY_URL=ws://10.255.0.1:8010 RELAY_KEY=<project key> \
    node js/examples/echo.mjs
```

The output is one line, `guest received: hello from the guest`. The
[relay page](run-a-relay.html) covers the relay, its keys file and its checks.
