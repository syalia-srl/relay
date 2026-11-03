# relay (JavaScript)

The JavaScript library of the relay channel protocol: both the host and the guest
of `PROTOCOL.md` sections 3 to 9. It pairs two static keys through a relay it
never trusts, then carries messages between them end to end encrypted with its
own Noise IKpsk1 and KK.

`API.md` is the public API. Everything else — handshakes, candidates, fragments,
rekey, ping, relay failover and backoff, the relays list, abort and reconnect — is
internal.

The library has no runtime dependencies: `crypto.subtle` (X25519, HKDF or HMAC,
SHA-256, AES-GCM), the global `WebSocket` and `fetch`, as browsers, Android
WebView and Node 22 provide them. Node-only code is imported lazily, so a browser
bundle never loads `node:fs`.

## Install

    npm install ./js

or, to work on it:

    cd js
    npm install

## Use

A host:

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

A guest:

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

The store named in `open` keeps the host's static key and the paired channels, or
the guest's keys and paired hosts. `fileStore` replaces it atomically with mode
0600; `webStore` uses `localStorage`.

## Test

    cd server && CGO_ENABLED=0 go build -o relay ./cmd/relay
    cd ../js && RELAY_BIN=../server/relay node --test

The suite checks every file in `vectors/` and `vectors/tools/cacophony_subset.json`
against the library, runs a host and a guest through the real Go relay (pair,
confirm, send both ways, a 200 kB message, restart both sides from their stores,
revoke, unpair, fail over to a second relay), puts a hostile relay that drops,
duplicates, reorders, delays, relabels and flips frames between them, and pairs a
Python host with a JavaScript guest and a JavaScript host with a Python guest
through the same relay.
