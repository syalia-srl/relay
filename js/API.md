# Public API of the JavaScript library

The same four things as the Python library (`py/API.md`): `Host`, `Guest`, a pairing,
and a peer to send to and receive from, in the shape a JavaScript programmer expects.
Everything else in PROTOCOL.md stays internal. Messages are `Uint8Array`; one `send`
arrives as one message. The library has no runtime dependencies: `crypto.subtle`
(X25519, HKDF, HMAC, SHA-256, AES-GCM), `WebSocket` and `fetch`, as browsers, Android
WebView and Node 22 provide them.

## Host

```js
import { Host, Relay, fileStore } from "@syalia/relay";

const host = await Host.open(fileStore("state/host"), {   // Node: JSON file, mode 0600
  relays: [new Relay("wss://relay.syalia.dev", { key: projectKey })],
});

const pairing = await host.pair("pixel-7");
showQr(pairing.payload);                          // string, the JSON of section 4
const device = await host.pairing(pairing.device).confirm(code);   // WrongCode, PairingFailed

for await (const [device, message] of host) {     // messages from every bound device
  await device.send(new TextEncoder().encode("pong"));
}

await host.revoke(device);
await host.close();
```

- `new Relay(url, { key, hostUrl })` takes an optional `hostUrl` for the host's own
  use; it defaults to `url`. `url` is the guests' URL and keeps the section 8.1
  policy. `hostUrl` follows section 2.3: `wss://` anywhere, or `ws://` only to
  loopback, a private literal address, or a plain name without dots (a container or
  compose service name). A `ws://` host URL across a shared LAN sends the project key
  and host token in cleartext, so use one only on loopback or on a network whose only
  members are the host and the relay (a container network); the library cannot check
  that. Pairing payloads and `relays` messages carry `url` only.
- `host.devices` lists bound devices; a device has `id`, `name` and `connected`.
- `device.send` waits until the device is connected; pass `{ signal }` to give up:
  `device.send(bytes, { signal: AbortSignal.timeout(5000) })`.
- `confirm(code)` is the only way to bind a key. A wrong code throws `WrongCode` with
  `triesLeft`; the third wrong code, a collision, `exp` or the 10-minute limit throw
  `PairingFailed`. The host never exposes pending codes.

## Guest

```js
import { Guest, webStore } from "@syalia/relay";

const guest = await Guest.open(webStore("relay-guest"), { key: keystoreKey });
const host = await guest.pair(payload);           // first contact
showCode(host.code);                              // the 6 digits the person types
await host.bound();

await host.send(bytes);
for await (const message of host) { ... }         // throws Revoked when revoked

await host.unpair();                              // close / closed
await guest.close();                              // stops connections, keeps pairings
```

- `key` is any object with `publicKey: Uint8Array` and
  `dh(peerPublic: Uint8Array): Promise<Uint8Array>`, so a WebView app keeps the private
  key in the Android Keystore behind a native bridge. Without `key` the guest draws one
  per pairing with `crypto.subtle` and keeps it in the store. A native `key` serves one
  pairing, as in Python.
- `guest.hosts` lists paired hosts after a restart.

## Stores

A store is any object with `load(): Promise<object | null>` and
`save(state: object): Promise<void>`. The library ships two: `fileStore(path)` for
Node (atomic replace, mode 0600) and `webStore(name)` for browsers (`localStorage`).
A host keeps its static key in its store, so a host runs on Node with `fileStore`.

## Errors

`RelayError`, with `PairingFailed`, `WrongCode`, `Revoked` and `PayloadInvalid`
extending it. Transient network errors are retried inside and never thrown.

## Not in the API

No callbacks, no event emitters, no options beyond the ones above.
