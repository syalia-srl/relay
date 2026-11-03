# Security

## Reporting

Report a vulnerability privately through GitHub's "Report a vulnerability" button
on this repository's Security tab. Please do not open a public issue for it.

## What this code promises

The relay passes bytes and is never trusted. The channel protocol (`PROTOCOL.md`)
gives two static keys an ordered, authenticated, confidential message stream across
any relay. The guarantees below hold for an implementation that follows
`PROTOCOL.md` and passes every vector in `vectors/`.

## Threat model

| Adversary | Can | Cannot, and why |
|---|---|---|
| A hostile relay (any operator, or one faking a relay's address) | Drop or delay frames. See when each side is connected, how much it sends, and both sides' IP addresses. Forge an `abort`. | Read, inject, replay or reorder messages: Noise KK authenticates both static keys and the transport nonces are counters. Move a session to another channel or relay: the channel id is in the prologue. Learn who holds a relay token: it carries an opaque `sub`. |
| The local network, with a `ws://` relay | See that relay's guest token and the ciphertext. Take the guest's slot on that relay, which pushes the guest onto the next relay. | Use the token on another relay: each relay has its own channel and tokens. Read or forge anything, as for a hostile relay. |
| A network that fakes the address of a `ws://` relay | Accept the guest's socket and token for the 1.5 seconds it waits. | Complete the handshake without the host's static key, so the guest moves on. |
| Someone who saw a pairing payload (a photographed QR) | Within its expiry, race the real guest to the first pairing message. | Bind: nothing binds before a person confirms, in the host application, a 6-digit code that matches the one on their own guest. Keep a relay slot: the payload's channels are deleted when the pairing ends. Decrypt traffic, recorded or live: every handshake uses ephemeral keys. |
| Someone who knows the host's public key (any past pairer) | Send a first pairing message. | Have it accepted: IKpsk1 authenticates it with the pairing secret, which only the payload carries. Connect as a device: KK needs a bound guest key. |
| A relay replaying a recorded handshake message | Make the host compute and send an answer. | Get the host to record anything: the host commits a connection only when the first transport frame decrypts, which needs the guest's ephemeral key. |
| Theft of the host's static key | Impersonate the host to its guests from then on. | Decrypt earlier sessions (forward secrecy). Recovery: rotate the host key, which ends every pairing. |
| Theft of a guest's static key | Connect as that device until it is revoked. | Decrypt earlier sessions. Keep access after the device is revoked. |

## What this code does not do

- **Hide metadata.** A relay sees timing, volume and IP addresses. There is no
  padding or cover traffic.
- **Store and forward.** A frame for an absent side is dropped; the application
  retries.
- **Protect the code that holds a key.** If the code running the guest side can be
  replaced, the replacement can use the guest's key. This, the storage of both
  static keys, the confirmation step and what a session may reach belong to the
  host application (`PROTOCOL.md` section 10).

## How AInBox meets the host application's part

AInBox is the first application built on this protocol. The host is the install's
bridge service; the guest is the AInBox Android app.

| Responsibility | How AInBox meets it |
|---|---|
| Authentic guest code | The app's JavaScript bundle is signed with a release key whose public half is built into the APK. The app refuses a bundle whose signature or hash does not verify or whose version is older than the one it runs, always loads pages from the verified local copy, and checks the same signature on app updates. |
| The guest key at rest | The private key lives in the Android Keystore (an X25519 key from Android 13; before that, a key file encrypted under a Keystore key). The page asks native code for Diffie-Hellman results and never holds the private key, so a script in the page can use the key while the page is open but cannot copy it. A rooted phone before Android 13 can read the wrapped file. |
| The host key at rest | One key per install, in the bridge's data volume, readable only by the bridge. |
| The confirmation | The code appears beside the new device in the user's own settings on the install, behind their login; only a confirmation there binds the key. |
| What a session may reach | The bridge maps messages to HTTP and WebSocket calls through an allow-list of paths and with a session for the device's user only. |
| Revocation | Revoking a device in the install's settings sends `revoked`, deletes the device's channel on every relay and unbinds its key. |
| `ws://` relays | The install's relay list form and the app both apply the URL policy of `PROTOCOL.md` 8.1. The app's network configuration allows cleartext only to private addresses. |

## Cryptographic choices

- Noise Protocol Framework revision 34, patterns IKpsk1 (pairing) and KK (each
  connection), suite 25519, AES-GCM, SHA-256. AES-GCM because WebCrypto has no
  ChaCha20-Poly1305.
- Relay tokens: Ed25519 (RFC 8032) signatures by an issuer the relay operator trusts.
- The reference used for the vectors (`vectors/tools/noise_ref.py`) passes the
  published cacophony vectors for both patterns, and every transcript is replayed
  through the independent `noiseprotocol` package.
