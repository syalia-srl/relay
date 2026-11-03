# Relay API v1 and channel protocol v3

This document is normative. The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY
are to be read as in RFC 2119. The JSON test vectors in `vectors/` are part of the
specification: an implementation that disagrees with a vector is wrong, and where a
vector and this text disagree, report it as a bug.

## 1. Layers

| Layer | What it does | Defined here |
|---|---|---|
| L0 relay | Channels with two sides, `host` and `guest`. Binary frames passed through untouched, presence events. | Section 2 |
| L1 channel | Pairing, a Noise handshake on every connection, transport frames, control messages. Its output is an ordered, authenticated, confidential stream of messages between two static keys. | Sections 3 to 9 |
| L2 application | What the messages mean (for AInBox, HTTP and WebSocket operations, an allow-list and a session). | No. See section 10. |

A relay is never trusted with confidentiality or integrity. Everything L1 promises
holds against a relay that drops, delays, replays, reorders, duplicates or alters
frames. What a relay can still do is listed in `SECURITY.md`.

The **host** is the long-lived side (a server install). The **guest** is the side
that pairs with it (a phone). One guest and one host share one channel per relay.

## 2. Relay API v1 (L0)

### 2.1 Identifiers and tokens

A channel id is 16 random bytes and a side token 32 random bytes, both encoded as
base64url without padding (22 and 43 characters). A relay MUST draw them from a
cryptographically secure generator. A relay MUST NOT store tokens in clear: it
stores their SHA-256 digests and compares digests in constant time. A relay MUST
NOT log request lines, URLs or `Authorization` headers.

### 2.2 Project keys

Creating a channel takes a project key, sent as `Authorization: Bearer <key>`. A
key carries a quota with three limits:

| Limit | Counts |
|---|---|
| `channels` | Channels created with the key that are still alive. |
| `creates_per_minute` | Channel creations with the key in any 60-second window. |
| `bytes_per_day` | Data frame bytes (section 2.4) the relay forwarded on the key's channels since 00:00 UTC. |

A key is one of two kinds:

- **An operator key**: any bearer string that does not start with `rt1.`. The relay
  operator lists the SHA-256 digests of the keys it accepts with their quotas. How
  that list is stored is the operator's business.
- **A relay token**: a statement signed by an issuer the operator trusts, so that one
  issuer (a vendor) can hand out keys to many installs without the operator listing
  each one. Its form is

      rt1.<payload>.<signature>

  where `<payload>` is the base64url (no padding) of a UTF-8 JSON object and
  `<signature>` is the base64url (no padding) of the 64-byte Ed25519 signature
  (RFC 8032) over the ASCII bytes `rt1.<payload>`. The payload holds:

  | Field | Type | Meaning |
  |---|---|---|
  | `iss` | string | Issuer id. The relay looks up the issuer's Ed25519 public key by it. |
  | `sub` | string | An opaque id for the holder. It MUST NOT name the holder. |
  | `exp` | integer | Expiry, Unix seconds. |
  | `channels`, `creates_per_minute`, `bytes_per_day` | integers | The quota. |

  The relay MUST refuse a token whose issuer it does not know, whose signature does
  not verify, whose payload is not a JSON object with every field above at its type,
  or whose `exp` has passed. Unknown fields are ignored. The quota is accounted per
  `(iss, sub)`, so two tokens for the same holder share it. Revocation is expiry:
  an issuer that needs to cut a holder issues tokens with short lives.

A relay operator MAY give its own channels (a relay run inside one install for its
local network) a key with no limits.

### 2.3 HTTP

`POST /v1/channels` creates a channel. Request body: empty. Answers:

| Status | When | Body |
|---|---|---|
| 201 | Created. | `{"channel": <id>, "host_token": <token>, "guest_token": <token>}` |
| 401 | No key, an unknown key, or a refused relay token. | any |
| 429 | Over `channels` or `creates_per_minute`. SHOULD carry `Retry-After`. | any |
| 503 | The relay holds as many channels as it can. | any |

`DELETE /v1/channels/{id}` with `Authorization: Bearer <host_token>` closes both
sockets of the channel with code 4410 and forgets it. Answers 204 when deleted, 404
for an unknown channel or a wrong token alike. Only the host can delete a channel.

### 2.4 WebSocket

`GET /v1/ws/{id}` opens a WebSocket for one side of a channel. The URL carries no
token. The client's first frame MUST be a text frame holding the UTF-8 JSON object
`{"auth": <token>}`, sent within 5 seconds of the socket opening. The token decides
the side. If the channel is unknown, the token is not one of its two, the frame is
malformed, or 5 seconds pass, the relay closes with 4401. It uses 4401 for all
these cases so that a client learns nothing about which channels exist.

After a valid `auth` the relay answers with a `ready` system frame and, if the other
side holds a socket, a `peer_connected` system frame. From then on every frame in
both directions is binary and its first byte says what it is:

| First byte | Name | Body |
|---|---|---|
| `0x00` | system | UTF-8 JSON `{"type": "system", "event": <event>}`. Only the relay sends it. |
| `0x01` | data | Opaque bytes, at most 1 MiB (1,048,576 bytes) after the first byte. |

A client MUST send only data frames. The relay MUST forward a data frame from one
side to the other byte for byte, first byte included, in the order received. If the
other side holds no socket, the relay drops the frame: there is no store and
forward.

System events:

| Event | Sent to a side when |
|---|---|
| `ready` | Its `auth` was accepted. |
| `peer_connected` | The other side's `auth` was accepted, or, right after `ready`, the other side is already present. |
| `peer_disconnected` | The other side's socket closed and no newer one holds its place. |
| `replaced` | A newer socket authenticated as the same side. The relay then closes this socket with 4409. |

Presence events are hints for user interfaces. L1 never takes them as evidence of
anything (section 6.3).

A second socket that authenticates as a side already held replaces the first: the
relay sends `replaced` to the old socket and closes it with 4409. Only the socket
that holds a side frees it; a replaced socket that closes late MUST NOT produce a
`peer_disconnected`.

Close codes:

| Code | Meaning |
|---|---|
| 4400 | Protocol violation: a text frame after `auth`, a client frame whose first byte is not `0x01`. |
| 4401 | Authentication failed (unknown channel, wrong token, malformed or late `auth`). |
| 4409 | Replaced by a newer socket for the same side. |
| 4410 | The channel was deleted. |
| 4413 | A frame larger than allowed. |
| 4429 | The channel's key is over its `bytes_per_day`. The relay also refuses `auth` on the key's channels with 4429 until 00:00 UTC. |

### 2.5 Lifetime

A relay MUST keep channel ids, token digests and the key each channel was created
with across restarts, in storage only the relay can read. It SHOULD forget a
channel whose guest never authenticated within 1 hour of creation, and MUST forget
any channel that had no authenticated socket for 30 days.

### 2.6 v0

A relay MAY also serve the earlier API (`POST /channels`, `/ws/{id}?token=`, sides
`mobile` and `bridge`) during a migration. v0 is not specified here and new clients
MUST NOT use it.

## 3. Channel protocol v3 (L1): keys and primitives

L1 uses the Noise Protocol Framework, revision 34, with two handshake patterns and
one suite:

- `Noise_IKpsk1_25519_AESGCM_SHA256` for pairing (section 5),
- `Noise_KK_25519_AESGCM_SHA256` for every later connection (section 6).

AES-GCM rather than ChaCha20-Poly1305, because WebCrypto has AES-GCM and no ChaCha.
An implementation MUST pass the published Noise test vectors for both protocol
names (the cacophony set has one of each) and every vector in `vectors/`.

Keys:

| Key | Owner | Lifetime |
|---|---|---|
| `hs` | The host's static X25519 key pair. Its public half is in every pairing payload, so it authenticates the host and nothing else. | Created once per host. Rotating it ends every pairing. |
| `gs` | The guest's static X25519 key pair. | Created fresh for each pairing; a guest MUST NOT use one `gs` with two hosts or for two pairings. |
| `psk` | 32 random bytes the host draws for one pairing. | Until the pairing ends (section 5.4). |

Every handshake has no payload: each handshake message ends with the encryption of
an empty payload, which is still a 16-byte tag once a key is set.

### 3.1 Prologue

Both handshakes use the same prologue, which binds the session to one device on one
channel of one relay:

    prologue = "relay-channel/3" || u16(len(dev)) || dev || u16(len(channel)) || channel

where `dev` is the device id from the pairing payload and `channel` the relay channel
id the handshake runs on, both as UTF-8 bytes, and `u16` is a 2-byte big-endian
length. A session therefore cannot be moved to another channel or relay.

### 3.2 L1 frames

Each L0 data frame carries exactly one L1 frame after its `0x01` byte. The L1 frame's
first byte is its type:

| Type | Name | Sender | Body | Body length |
|---|---|---|---|---|
| `0x01` | pair | guest | IKpsk1 message 1 | exactly 96 |
| `0x02` | connect | guest | KK message 1 | exactly 48 |
| `0x03` | accept | host | Message 2 of either pattern | exactly 48 |
| `0x04` | transport | either | One Noise transport message | 18 to 65,535 |
| `0x05` | abort | either | empty | 0 |

A receiver MUST abort (section 9) on an unknown type, a body of the wrong length, or
a type its role does not receive.

## 4. Pairing payload

The host gives the guest everything it needs for the first contact in a pairing
payload, a UTF-8 JSON object. It travels only out of band (a QR on a screen, copied
text, an explicit intent), never through a relay.

| Field | Type | Meaning |
|---|---|---|
| `v` | integer | `3`. |
| `hs` | string | The host's static public key, 64 lowercase hex characters. |
| `psk` | string | The pairing secret, 64 lowercase hex characters. |
| `dev` | string | The device id the host assigned, 1 to 64 characters from `A-Z a-z 0-9 _ -`. |
| `exp` | integer | Unix seconds after which the host refuses the pairing. A host SHOULD set it 5 minutes after it draws the payload. |
| `relays` | array | 1 to 16 objects `{"url", "channel", "token"}`: a relay base URL, a pairing channel id on it and the guest token for that channel, in the host's order of preference. |
| `name` | string, optional | A display name for the host, at most 100 characters. |
| `url` | string, optional | A host-defined URL, for the host application's own use. |

Unknown fields are ignored. A guest MUST refuse a payload whose `v` is not 3, that
misses a required field or has one of the wrong type or form, or in which no relay
passes the URL policy (section 8.1). It drops relays that fail the policy and keeps
the rest in order. A guest SHOULD refuse a payload more than 60 seconds past its
`exp` by its own clock. The host MUST enforce `exp` itself, whatever the guest does.

A payload carries `psk` and live guest tokens. A guest that took it from the
clipboard SHOULD clear the clipboard.

## 5. Pairing

### 5.1 The host prepares

For one device, the host draws `dev` and `psk`, creates one pairing channel on each
relay it uses, and builds the payload. The pairing is **open**.

### 5.2 First contact

The guest creates `gs` and connects to the relays of the payload in order (section
8.2). On the first one that answers `ready`, it runs `Noise_IKpsk1` as initiator with
its `gs`, the host's `hs` as the known remote static, the `psk`, and the prologue of
section 3.1, and sends message 1 in a `pair` frame. In IKpsk1
(`-> e, es, s, ss, psk`) the guest's static key travels encrypted under `es`; the
`psk` is mixed in last, so the tag on the message's empty payload is what proves
knowledge of the `psk`.

The host, on a `pair` frame on an open pairing's channel before `exp`, reads the
message as responder with `hs` and the `psk`. If decryption fails it aborts and the
pairing stays open: a sender who knows `hs` but not the `psk` changes nothing. If it
succeeds, the host holds the result as a **candidate** for that socket (the guest
key, the session, the handshake hash `h`), answers with an `accept` frame, and
commits nothing else. A later valid `pair` replaces the candidate.

The guest, on `accept`, finishes the handshake, derives the pairing code (section
5.3) and shows it, then sends a `ping` (section 7) as its first transport frame.

The host promotes a candidate when the first transport frame on that socket decrypts
under it. The candidate's guest key becomes the pairing's **pending** key, the code
derived from its `h` is the pairing's code, and the pairing is **pending**. A relay
that replays a recorded `pair` gets an `accept` it cannot use, because it cannot
produce the transport frame that follows.

### 5.3 The pairing code

    code = (u32(SHA-256("relay-channel/3 pairing code" || h)[0..4]) mod 1000000)

written as 6 decimal digits with leading zeros, where `u32` reads 4 bytes as a
big-endian unsigned integer and `h` is the IKpsk1 handshake hash after message 2.
(The modulo bias is below 2^-12 and does not matter here.)

### 5.4 Confirmation

While a pairing is pending:

- The host refuses every `pair` frame with an abort, whatever its key.
- The host accepts `connect` frames on the pairing channels from the pending key only
  (a guest that lost its socket reconnects with KK, section 6), and the pairing code
  stays the same.
- The host answers `ping` and refuses every application message with an abort. It
  sends no `relays` and gives the guest no access of any kind.
- The host application shows the code. A person compares it with the code on the
  guest and confirms in the host application. A host MUST NOT bind a key without
  that confirmation.

Unconfirmed after 2 minutes, the pairing ends: the host deletes its pairing channels
and forgets the pending key. An open pairing that reaches `exp` ends the same way.
A guest `close` (section 7) also ends it.

On confirmation, the host binds the pending key to `dev`, erases the `psk`, creates
one fresh device channel per relay, and sends `relays` with them inside the
pairing session (now, or when the guest next connects on a pairing channel). The
guest replaces its list and connects to a device channel. The host deletes the
pairing channels when the guest's first transport frame decrypts on a device
channel, or 10 minutes after confirmation, whichever comes first. The tokens in the
payload die with those channels.

## 6. Connections

### 6.1 Handshake

Each time the guest opens a socket on a device channel, it runs `Noise_KK` as
initiator with its `gs` and the host's `hs`, and the prologue of section 3.1, and
sends message 1 in a `connect` frame. The host reads it as responder with `hs` and
the guest key bound to that channel's device (on a pairing channel: the pending
key), answers with `accept`, and holds the result as the channel's candidate. If
the device is not bound, the key does not match, or decryption fails, it aborts.

Both sides contribute ephemeral keys, so every connection has fresh transport keys,
and a later theft of either static key does not open earlier sessions.

The guest's first transport frame after `accept` MUST be a `ping`.

### 6.2 Split

After message 2, both sides call Noise's `Split()`. The first cipher state carries
guest-to-host frames, the second host-to-guest frames.

### 6.3 What the host commits, and when

A relay can replay a KK message 1. So:

- A host keeps per channel at most one **current** session and one **candidate**. A
  `connect` or `pair` frame replaces the candidate, never the current session.
- While a candidate exists, the host decrypts a transport frame from the guest under
  the candidate. If that succeeds the candidate becomes current and the old current
  session is discarded. If it fails, the host aborts and discards both.
- With no candidate, it decrypts under the current session.
- A host MUST NOT send a transport frame under a candidate, and MUST NOT record
  anything about a connection (that it is connected, a queued answer) before the
  candidate is promoted.
- Presence events never change session state. A new guest socket always means a new
  handshake, whatever the relay said.

The guest keeps one session per socket and discards it when the socket closes.

## 7. Transport

### 7.1 Frames

After the handshake every L1 frame is `transport`, carrying one Noise transport
message: the AES-GCM encryption, with empty associated data and Noise's implicit
64-bit counter nonce, of the plaintext

| Byte | Meaning |
|---|---|
| 0 | kind: `0x00` application data, `0x01` control |
| 1 | flags: bit 0 set means more fragments of this message follow; other bits MUST be 0 |
| 2.. | payload, at most 65,517 bytes |

A frame replayed, dropped or reordered by the relay fails to decrypt, and the
receiver aborts.

### 7.2 Fragments

A message longer than 65,517 bytes is split into fragments sent in order, each in
its own frame with the same kind, with bit 0 set on every fragment but the last.
Fragments of two messages in one direction MUST NOT interleave. A receiver MUST
abort on a fragment of a different kind than the one before it, or when a message
grows past 16 MiB (16,777,216 bytes). An empty message is one frame with an empty
payload.

### 7.3 Rekey

Each cipher state calls Noise's `Rekey()` right after it encrypts or decrypts the
transport message whose nonce `n` satisfies `(n + 1) mod 2^20 = 0`. Both ends of a
direction do it at the same message, so no signal is needed; the nonce keeps
counting. A session whose nonce would reach 2^64 - 1 MUST be closed.

## 8. Relays

### 8.1 URL policy

A relay is named by a base URL; the socket URL is the base with any trailing `/`
removed, then `/v1/ws/` and the channel id. A guest and a host MUST accept a relay
URL only if it has no user info, query or fragment, and either

- its scheme is `wss`, or
- its scheme is `ws` and its host is a literal IPv4 address in 10.0.0.0/8,
  172.16.0.0/12 or 192.168.0.0/16, or a literal IPv6 address in fc00::/7.

Everything else is refused, including `ws` to a name (`.local` names too, since any
machine on the network can answer them), to loopback (127.0.0.0/8, ::1) and to
link-local addresses (169.254.0.0/16, fe80::/10). Over `ws`, the network sees the
token and the ciphertext; the token gives it the guest's slot on that one relay and
nothing more, which is why each relay has its own channel and tokens.

### 8.2 Choosing a relay

A guest holds an ordered list of relays per host. It:

1. Tries them in list order, giving each 1.5 seconds to open the socket, get `ready`
   and complete the handshake, and keeps the first that completes.
2. While on a relay other than the first, retries the ones before it every 60
   seconds and moves up when one completes. A move is a new socket and a new
   handshake.
3. On an abort, a socket that closes, or a frame that fails to decrypt, goes back to
   step 1.

The host keeps a socket on its side of every channel it holds, on every relay.

### 8.3 The list

The list changes only through a `relays` control message inside an established
session. A guest MUST ignore relay lists from anywhere else: a relay, a presence
event, another pairing payload.

## 9. Control messages and abort

A control message is a UTF-8 JSON object with an `op` field.

| `op` | Sender | Fields | Effect |
|---|---|---|---|
| `relays` | host | `relays`: 1 to 16 objects `{"url", "channel", "token"}` | Replaces the guest's relay list for this host. The guest drops entries that fail the URL policy, and ignores the message if none remain. |
| `close` | guest | | The guest unpairs. The host unbinds the device (or ends a pending pairing) and deletes its channels on every relay. |
| `revoked` | host | | Sent before the host deletes a revoked device's channels, so the guest can forget its key and say why. |
| `ping` | either | | Answered with `pong`. |
| `pong` | either | | |

A receiver ignores an `op` it does not know, and aborts on a known `op` from the
wrong side or with fields of the wrong type.

**Abort.** On any decryption failure, malformed frame or protocol violation, a side
sends an `abort` frame and discards its session state for that socket (for the host,
the channel's candidate and current session). A guest that receives `abort`
discards its session and goes back to step 1 of section 8.2. `abort` is not
authenticated, so a relay can forge it; that gives it nothing it does not have by
dropping frames.

## 10. What the host application must do

L1 secures the stream between two keys. The parts below are outside it and decide
whether the whole system is safe; each application states in its own documents how
it meets them. `SECURITY.md` says how AInBox does.

1. **The code that holds the guest key.** A guest's private key is only as safe as
   the code that can use it. The application MUST ensure that the code running the
   guest side is authentic, and SHOULD keep the private key where that code can use
   it without reading it (a hardware-backed key store).
2. **The host key at rest.** `hs` MUST be stored where only the host process can read
   it.
3. **The confirmation.** The application MUST show the pairing code only to the
   person entitled to pair, and bind only on their confirmation.
4. **What a session may do.** L1 says who is on the other end, not what they may
   ask. The application's L2 decides what a bound guest can reach.
5. **Revocation.** Revoking a device MUST delete its channels on every relay and
   unbind its key.

## 11. Versions

The L1 version is fixed for a device when it pairs (`v` in the payload, and the
prologue). Hosts and guests never negotiate it, so there is nothing to downgrade.
The L0 version is in the path (`/v1`).

## 12. Test vectors

`vectors/` holds one JSON file per topic. Each file has a `description` and a list of
cases; hex strings are lowercase. `vectors/tools/generate.py` regenerates them from
a small reference implementation (`vectors/tools/noise_ref.py`), which passes the
cacophony vectors for both protocol names and agrees with the `noiseprotocol`
package on every transcript. Fixed ephemeral keys appear in the handshake vectors
only so the transcripts are reproducible; an implementation MUST draw fresh ones.
