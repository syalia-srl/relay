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

JSON in this document is UTF-8 (RFC 8259). A receiver MUST refuse a JSON object with
a duplicate key, and MUST treat an integer field as valid only when it is a JSON
number with no fraction or exponent in the range 0 to 2^53 - 1, unless a field says
otherwise. Lengths of strings are counted in Unicode code points.

## 2. Relay API v1 (L0)

### 2.1 Identifiers and tokens

A channel id is 16 random bytes and a side token 32 random bytes, both encoded as
base64url without padding (22 and 43 characters from `A-Z a-z 0-9 - _`). Wherever
this document uses a channel id or a token, it means that text, not the decoded
bytes. A relay MUST draw them from a cryptographically secure generator. A relay
MUST NOT store tokens in clear: it stores their SHA-256 digests and compares digests
in constant time. A relay MUST NOT log request lines, URLs or `Authorization`
headers.

### 2.2 Project keys

Creating a channel takes a project key, sent as `Authorization: Bearer <key>`. A
key carries a quota with three limits:

| Limit | Counts |
|---|---|
| `channels` | Channels created with the key that are still alive. |
| `creates_per_minute` | Channel creations with the key in any 60-second window. |
| `bytes_per_day` | Data frame bytes (section 2.4, first byte included) the relay forwarded on the key's channels since 00:00 UTC. |

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
  (RFC 8032) over the ASCII bytes `rt1.<payload>`. The whole token is at most 4096
  bytes. The payload holds:

  | Field | Type | Meaning |
  |---|---|---|
  | `iss` | string, 1 to 64 | Issuer id. The relay looks up the issuer's Ed25519 public key by it. |
  | `aud` | string, 1 to 64 | The relay this token is for. Each relay has its own id, unique among the relays that trust the issuer; the operator assigns it and tells the issuer. Two relays MUST NOT share an id. |
  | `sub` | string, 1 to 128 | An opaque id for the holder. It MUST NOT name the holder. |
  | `exp` | integer | Expiry, Unix seconds. The token is valid while `now < exp`. |
  | `channels`, `creates_per_minute`, `bytes_per_day` | integers | The quota. |

  The relay MUST refuse a token that is longer than 4096 bytes, not of the form
  above, signed by an issuer it does not know or not by that issuer's key, whose
  payload is not a JSON object with every field above at its type, whose `aud` is
  not the relay's own id, or whose `exp` has passed. Unknown fields are ignored.
  The quota is accounted per `(iss, sub)`; when two valid tokens for the same
  holder carry different quotas, the relay applies the one in the token presented
  with each request. Revocation is expiry: an issuer that needs to cut a holder
  issues tokens with short lives, and SHOULD NOT issue tokens that live longer than
  the holder's entitlement.

A relay operator MAY give its own channels (a relay run inside one install for its
local network) a key with no limits.

### 2.3 HTTP

A relay's base URL (section 8.1) may carry a path; every route below is relative to
it.

`POST /v1/channels` creates a channel. Request body: empty. Answers:

| Status | When | Body |
|---|---|---|
| 201 | Created. | `{"channel": <id>, "host_token": <token>, "guest_token": <token>}` |
| 401 | No key, an unknown key, or a refused relay token. | any |
| 429 | Over `channels` or `creates_per_minute`. SHOULD carry `Retry-After`. | any |
| 503 | The relay holds as many channels as it can. | any |

The relay checks in that order: the key first, then its quota, then its capacity.

`DELETE /v1/channels/{id}` with `Authorization: Bearer <host_token>` closes both
sockets of the channel with code 4410 and forgets it. Answers 204 when deleted, 404
for an unknown channel or a wrong token alike. Only the host can delete a channel.

The host token authenticates the host's socket and also deletes the channel, and the
project key creates channels. A host MUST NOT send either over a `ws://` or `http://`
connection that crosses a network other machines share; over plain text it may only
reach a relay on its own machine (loopback) or on a network that only it and the
relay are members of (a container network). A host MAY reach a relay by a different
URL than the one it gives guests, for this reason: the URL in a relay entry is the
guests' URL.

### 2.4 WebSocket

`GET /v1/ws/{id}` opens a WebSocket for one side of a channel. The URL carries no
token. The client's first frame MUST be a text frame holding a JSON object with a
string field `auth`, the token, sent within 5 seconds of the socket opening; other
fields are ignored. The token decides the side. If the channel is unknown, the token
is not one of its two, the frame is not such a text frame, or 5 seconds pass, the
relay closes with 4401. It uses 4401 for all these cases so that a client learns
nothing about which channels exist, and checks authentication before quota.

After a valid `auth` the relay sends a `ready` system frame and then, if the other
side holds a socket, a `peer_connected` system frame. From then on every frame in
both directions is binary and its first byte says what it is:

| First byte | Name | Body |
|---|---|---|
| `0x00` | system | JSON `{"type": "system", "event": <event>}`. Only the relay sends it. Receivers ignore other fields. |
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

Clients ignore an event they do not know. Presence events are hints for user
interfaces; L1 never takes them as evidence of anything (section 6.3).

A second socket that authenticates as a side already held replaces the first: the
relay sends `replaced` to the old socket and closes it with 4409. Only the socket
that holds a side frees it; a replaced socket that closes late MUST NOT produce a
`peer_disconnected`.

Close codes:

| Code | Meaning | What a client does |
|---|---|---|
| 4400 | Protocol violation: a text frame after `auth`, a client frame whose first byte is not `0x01`. | Fix itself; treat as a failed relay. |
| 4401 | Authentication failed (unknown channel, wrong token, malformed or late `auth`). | The channel is gone for it (section 8.4). |
| 4409 | Replaced by a newer socket for the same side. | Reconnect only if it did not open the newer socket itself, after the backoff of section 8.2. |
| 4410 | The channel was deleted. | The channel is gone for it (section 8.4). |
| 4413 | A data frame whose body is longer than 1 MiB. | Treat as a failed relay. |
| 4429 | The channel's key is over its `bytes_per_day`. The relay also refuses `auth` on the key's channels with 4429 until 00:00 UTC. | Treat as a failed relay. |

### 2.5 Lifetime

A relay MUST keep channel ids, token digests and the identifier of the key each
channel was created with (for an operator key its digest, for a relay token its
`(iss, sub)`) across restarts, in storage only the relay can read. It SHOULD forget
a channel whose guest never authenticated within 1 hour of creation, and MUST forget
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
Its 96-bit nonce is, as Noise defines for AES-GCM, 32 zero bits followed by the
64-bit big-endian counter. An implementation MUST pass the published Noise test
vectors for both protocol names (the cacophony set has one of each) and every vector
in `vectors/`.

Keys:

| Key | Owner | Lifetime |
|---|---|---|
| `hs` | The host's static X25519 key pair. Its public half is in every pairing payload, so it authenticates the host and nothing else. | Created once per host. Rotating it ends every pairing. |
| `gs` | The guest's static X25519 key pair. | Created fresh for each pairing; a guest MUST NOT use one `gs` with two hosts or for two pairings. |
| `psk` | 32 random bytes the host draws for one pairing. | Until the pairing ends (section 5.5). |

Every handshake draws a fresh ephemeral key pair, also when a guest retries the same
handshake on another relay. Every handshake has no payload: each handshake message
ends with the encryption of an empty payload, which is still a 16-byte tag once a
key is set.

### 3.1 Prologue

Both handshakes use the same prologue:

    prologue = "relay-channel/3" || u16(len(dev)) || dev || u16(len(channel)) || channel

where `dev` is the device id from the pairing payload and `channel` the channel id
the handshake runs on, both as the ASCII text of section 2.1 and 4, and `u16` is a
2-byte big-endian length. A session is bound to that channel id: a relay cannot move
it to another channel. Channel ids are chosen by relays, so the prologue does not by
itself tell two relays apart; a host MUST treat a channel id equal to any channel id
it already holds, on any relay, as a failed creation.

### 3.2 L1 frames

Each L0 data frame carries exactly one L1 frame after its `0x01` byte. The L1 frame's
first byte is its type:

| Type | Name | Sender | Valid on | Body | Body length |
|---|---|---|---|---|---|
| `0x01` | pair | guest | a pairing channel | IKpsk1 message 1 | exactly 96 |
| `0x02` | connect | guest | a device channel, or a pairing channel (section 5.4) | KK message 1 | exactly 48 |
| `0x03` | accept | host | either | Message 2 of the handshake the guest started | exactly 48 |
| `0x04` | transport | either | either, after a handshake | One Noise transport message | 18 to 65,535 |
| `0x05` | abort | either | either | empty | 0 |

A receiver MUST abort (section 9.2) on an unknown type, a body of the wrong length, a
type its role does not receive, or a type the channel does not take. The type byte
is not authenticated. A relay that changes it gets the same result as dropping the
frame: the frame fails as what it now claims to be, and the stream behind it fails
to decrypt.

## 4. Pairing payload

The host gives the guest everything it needs for the first contact in a pairing
payload, a JSON object. It travels only out of band (a QR on a screen, copied text,
an explicit intent), never through a relay.

| Field | Type | Meaning |
|---|---|---|
| `v` | integer | `3`. |
| `hs` | string | The host's static public key, 64 lowercase hex characters. |
| `psk` | string | The pairing secret, 64 lowercase hex characters. |
| `dev` | string | The device id the host assigned, 1 to 64 characters from `A-Z a-z 0-9 _ -`. |
| `exp` | integer | Unix seconds after which the host refuses the pairing. A host SHOULD set it 5 minutes after it draws the payload. |
| `relays` | array | 1 to 16 relay entries, in the host's order of preference. |
| `name` | string, optional | A display name for the host, at most 100 characters. |
| `url` | string, optional | A host-defined URL, at most 2048 characters, for the host application's own use. |

A **relay entry**, here and in the `relays` control message, is an object with
`url` (a relay base URL), `channel` (a channel id, section 2.1) and `token` (the
guest token for that channel, section 2.1). Unknown fields are ignored.

A guest MUST refuse a payload that is not a JSON object, whose `v` is not 3, that
misses a required field, or that has a field of the wrong type or form, a relay
entry included. It then drops relay entries whose URL fails the policy of section
8.1 and keeps the rest in order; if none remain, it refuses the payload. A guest
SHOULD refuse a payload more than 60 seconds past its `exp` by its own clock
(`now > exp + 60`). The host MUST enforce `exp` itself, whatever the guest does.

A payload carries `psk` and live guest tokens. A guest that took it from the
clipboard SHOULD clear the clipboard.

## 5. Pairing

### 5.1 State

The host keeps one pairing state per device (`dev`), shared by all its pairing
channels:

- the `psk`, `exp` and the pairing channels;
- at most one **candidate** per pairing channel: a guest key, a session and a
  handshake hash `h` from a `pair` or `connect` that has been answered but not yet
  proved (section 6.3);
- up to 4 **pending** keys, each with the code derived from its `h`;
- the time the first key became pending.

### 5.2 The host prepares

For one device, the host draws `dev` and `psk`, creates one pairing channel on each
relay it uses, and builds the payload. The pairing is **open**.

### 5.3 First contact

The guest creates `gs` and connects to the relays of the payload in order (section
8.2). On the first one that answers `ready`, it runs `Noise_IKpsk1` as initiator with
its `gs`, the host's `hs` as the known remote static, the `psk`, and the prologue of
section 3.1, and sends message 1 in a `pair` frame. In IKpsk1
(`-> e, es, s, ss, psk`) the guest's static key travels encrypted under `es`; the
`psk` is mixed in last, so the tag on the message's empty payload is what proves
knowledge of the `psk`.

The host, on a `pair` frame on a pairing channel of an open pairing before `exp`,
reads the message as responder with `hs` and the `psk`. It aborts, and changes
nothing in the pairing state, if decryption fails (the sender knows `hs` but not
the `psk`), if the guest key is already pending (it reconnects with `connect`,
section 5.4), or if 4 keys are already pending. Otherwise it holds the result as the
channel's candidate and answers with `accept`.

The guest, on `accept`, finishes the handshake, derives the pairing code (section
5.6), and sends a `ping` (section 9.1) as its first transport frame. It shows the
code only when the `pong` arrives, since the host sends that only after it promoted
the key, so a code the person types is never one the host does not yet hold.

The host promotes the candidate when a transport frame decrypts under it (section
6.3): its guest key becomes pending with its code. A key has at most one pending
entry and one code, the one from its first promoted `pair`; a later `pair` candidate
for a key already pending is aborted when it would be promoted. A guest sends `pair`
once per pairing and uses `connect` for every later socket, on any of the pairing
channels. A relay that replays a recorded `pair` gets an `accept` it cannot use,
because it cannot produce the transport frame that follows.

### 5.4 While keys are pending

- The host accepts `connect` frames on its pairing channels from a pending key only
  (after confirmation, from the bound key only), so a guest that lost its socket or
  moved to another relay reconnects with KK (section 6). Promoting such a candidate
  adds no pending entry and leaves the key's code as it was.
- The host answers `ping` and aborts on any application message or any control
  message other than `ping`, `pong` and `close`. It sends no `relays` and gives a
  pending guest no access of any kind.

### 5.5 Confirmation and the end of a pairing

The person who pairs reads the code on their own guest and types it into the host
application. The host binds the pending key whose code equals the typed code. A host
MUST NOT bind a key any other way, and MUST NOT show the codes of pending keys: a
person who sees a code on the host could confirm a stranger's. If two pending keys
have the typed code, the host binds neither and ends the pairing. After 3 typed codes
that match no pending key, the host ends the pairing.

Someone who photographed the payload can race the real guest and hold pending keys
of their own, but their codes are unknown to the person, so the typed code binds the
real guest. With at most 3 stranger keys pending, the chance that a stranger's code
equals the real one is below 3 in a million, and then the host binds neither and
the person starts over.

A pairing ends:

- **bound**, on confirmation. The host binds the key to `dev`, erases the `psk`,
  forgets the other pending keys and candidates (aborting their sessions), and creates
  one fresh device channel per relay. It sends `relays` with them on the bound key's
  current pairing session if there is one, and otherwise right after promoting the
  bound key's next `connect` on a pairing channel. The host deletes the pairing
  channels when a candidate of the bound key is promoted on a device channel. If that
  has not happened 10 minutes after confirmation, the guest never received its
  channels: the host unbinds the key, deletes the device channels and the pairing
  channels, and the pairing has failed. Until the pairing channels are deleted, the
  payload's guest tokens still open a socket on them, which gives a stranger nothing
  but the chance to displace the real guest there (4409).
- **ended**, at `exp` with no confirmation, on a `close` from a pending key, or as
  said above. The host deletes the pairing channels and forgets the pairing.

### 5.6 The pairing code

    code = (u32(SHA-256("relay-channel/3 pairing code" || h)[0..4]) mod 1000000)

written as 6 decimal digits with leading zeros, where `u32` reads 4 bytes as a
big-endian unsigned integer and `h` is the IKpsk1 handshake hash after message 2.
(The modulo bias is below 2^-12 and does not matter here.)

## 6. Connections

### 6.1 Handshake

Each time the guest opens a socket on a device channel, it runs `Noise_KK` as
initiator with its `gs` and the host's `hs`, and the prologue of section 3.1, and
sends message 1 in a `connect` frame. The host reads it as responder with `hs` and
the guest key bound to that channel's device (on a pairing channel: each pending
key in turn), answers with `accept`, and holds the result as the channel's
candidate. If the device is not bound, no key matches, or decryption fails, it
aborts.

Both sides contribute ephemeral keys, so every connection has fresh transport keys,
and a later theft of either static key does not open earlier sessions.

The guest's first transport frame after `accept` MUST be a `ping`. A host that
promotes a candidate on a frame that is not a `ping` MUST abort.

### 6.2 Split

After message 2, both sides call Noise's `Split()`, which returns `c1` and `c2`. On
both sides `c1` carries guest-to-host frames and `c2` host-to-guest frames: the guest
encrypts with `c1` and decrypts with `c2`, the host the other way round.

### 6.3 Candidates and the current session

A relay can replay a handshake message 1. So:

- A host keeps per channel at most one **current** session and one **candidate**. A
  `connect` or `pair` replaces the candidate, never the current session, and a
  failed one discards only the candidate.
- A transport frame from the guest is decrypted first under the candidate, if there
  is one, then under the current session. Noise does not advance a nonce on a failed
  decryption, so the second try sees the same state the first did. If the candidate
  succeeds, it is promoted: it becomes current and the old current session is
  discarded. If the current session succeeds, the candidate is discarded. If both
  fail, the host aborts and discards both.
- A host MUST NOT send a transport frame under a candidate, and MUST NOT record
  anything about a connection (that it is connected, a queued answer) before the
  candidate is promoted.
- Presence events never change session state. A new guest socket always means a new
  handshake, whatever the relay said.

The guest keeps one session per socket and discards it when the socket closes or on
an abort.

## 7. Transport

### 7.1 Frames

After the handshake every L1 frame is `transport` or `abort`. A `transport` frame
carries one Noise transport message: the AES-GCM encryption, with empty associated
data and the cipher state's counter nonce, of the plaintext

| Byte | Meaning |
|---|---|
| 0 | kind: `0x00` application data, `0x01` control |
| 1 | flags: bit 0 set means more fragments of this message follow; other bits MUST be 0 |
| 2.. | payload, at most 65,517 bytes |

A frame replayed, dropped or reordered by the relay fails to decrypt, and the
receiver aborts. A receiver aborts on an unknown kind or a flag bit other than bit 0.

### 7.2 Fragments

A message of either kind longer than 65,517 bytes is split into fragments sent in
order, each in its own frame with the same kind, with bit 0 set on every fragment
but the last. Fragments of two messages in one direction MUST NOT interleave: the
frame after a fragment with bit 0 set belongs to the same message. A receiver MUST
abort on a fragment whose kind differs from the previous fragment of the same
message, and when the payloads of one message add up to more than 16 MiB
(16,777,216 bytes). An empty message is one frame with an empty payload.

### 7.3 Rekey

The unit is the transport frame, each fragment counting as one. Each cipher state
calls Noise's `Rekey()` right after it encrypts or decrypts the frame whose nonce `n`
satisfies `(n + 1) mod 2^20 = 0`. Both ends of a direction do it at the same frame,
so no signal is needed; the nonce keeps counting. A session whose nonce would reach
2^64 - 1 MUST be closed.

## 8. Relays

### 8.1 URL policy

A relay is named by a base URL. A guest and a host MUST accept a relay URL only if it
is at most 2048 characters, is absolute, has no user info, query or fragment, has a
port (when present) from 1 to 65535, and either

- its scheme is `wss`, or
- its scheme is `ws` and its host is a literal IPv4 address in 10.0.0.0/8,
  172.16.0.0/12 or 192.168.0.0/16, or a literal IPv6 address, without a zone id, in
  fc00::/7.

Everything else is refused, including `ws` to a name (`.local` names too, since any
machine on the network can answer them), to loopback (127.0.0.0/8, ::1), to
link-local addresses (169.254.0.0/16, fe80::/10) and to IPv4-mapped IPv6 addresses.
Over `ws`, the network sees the guest token and the ciphertext; the guest token gives
it the guest's slot on that one relay and nothing more, which is why each relay has
its own channel and tokens. (The host token must not cross such a network at all,
section 2.3.)

The socket URL is the base with one trailing `/` removed, then `/v1/ws/` and the
channel id; the HTTP routes are built the same way.

### 8.2 Choosing a relay

A guest holds an ordered list of relays per host. It:

1. Tries them in list order. Each gets 1.5 seconds, counted from starting the
   connection to receiving `accept`, and the guest keeps the first that gets there.
2. While on a relay other than the first, retries the ones before it every 60
   seconds and moves up when one gets to `accept`. A move opens the new socket and
   completes its handshake first, then closes the old socket.
3. On an abort, a socket that closes, or a frame that fails to decrypt, goes back to
   step 1. After a round in which every relay failed, it waits before the next round:
   1 second, doubling each round, at most 60 seconds, and back to 1 second after a
   success.

The host keeps a socket on its side of every channel it holds, on every relay. When
one closes without a code in the 4400 to 4499 range, or with 4429, it reconnects with
the same backoff. On 4401 or 4410 it stops using the channel (section 8.4); on 4409
another socket of its own holds the side, and it keeps that one; on 4400 or 4413 it
stops using the relay and reports a fault.

### 8.3 The list

The list changes only through a `relays` control message inside an established
session with a bound key. A guest MUST ignore relay lists from anywhere else: a
relay, a presence event, another pairing payload.

The guest applies a `relays` message as a whole: it filters the entries through the
URL policy and, if any remain, replaces its list with them and starts over at step 1
of section 8.2. The host keeps the channels it took out of the list until it promotes a candidate
from the guest on a channel of the new list, then deletes them.

### 8.4 A channel that is gone

A relay answers 4401 or 4410 for a channel it no longer has. A guest whose every relay
for a host answered 4401 or 4410, in three rounds in a row, SHOULD treat the pairing
as ended: for a pairing in progress, it stops and says the pairing failed; for a
bound key, it says the host revoked or forgot the device. A host that gets 4401 or
4410 on a channel stops using it.

## 9. Control messages and abort

### 9.1 Control messages

A control message is a JSON object with a string field `op`. Unknown fields are
ignored.

| `op` | Sender | Fields | Effect |
|---|---|---|---|
| `relays` | host | `relays`: 1 to 16 relay entries (section 4), the guest's tokens | Replaces the guest's relay list for this host (section 8.3). |
| `close` | guest | | The guest unpairs. The host unbinds the device (or forgets a pending key), sends `closed`, then deletes the device's channels on every relay. |
| `closed` | host | | Answers `close`. |
| `revoked` | host | | Sent before the host deletes a revoked device's channels, so the guest can forget its key and say why. |
| `ping` | either | | Answered with `pong`. |
| `pong` | either | | |

A guest that sends `close` keeps its key and its list until it receives `closed`,
sends `close` again as the first message after `ping` on every connection until then,
and treats a pairing that is gone (section 8.4) as closed.

A receiver ignores an `op` it does not know, and aborts on a message that is not a
JSON object, has no string `op`, or carries a known `op` from the wrong side, with a
field of the wrong type, or with a relay list out of range.

### 9.2 Abort

On any decryption failure, malformed frame or protocol violation, a side sends an
`abort` frame and discards its session state for that socket: for the host, the
channel's candidate, and its current session unless the failure was in a handshake
message (section 6.3). A guest that receives `abort` discards its session and goes
back to step 1 of section 8.2; a host that receives one discards the channel's
candidate and current session, and the guest reconnects. `abort` is not
authenticated, so a relay can forge it. That ends a connection, which a relay can
already do by closing the socket or dropping one frame. A relay can thereby make a
pairing fail, by keeping the guest from getting through, but it cannot make the host
bind any key other than the one whose code the person typed.

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
3. **The confirmation.** The application MUST take the typed code only from the
   person entitled to pair, over a connection as confidential as the rest of its
   administration, and MUST NOT show pending codes (section 5.5).
4. **What a session may do.** L1 says who is on the other end, not what they may
   ask. The application's L2 decides what a bound guest can reach.
5. **Revocation.** Revoking a device MUST send `revoked`, delete its channels on every
   relay and unbind its key.

## 11. Versions

The L1 version is fixed for a device when it pairs (`v` in the payload, and the
prologue). Hosts and guests never negotiate it, so there is nothing to downgrade.
The L0 version is in the path (`/v1`).

## 12. Test vectors

`vectors/` holds one JSON file per topic. Each file has a `description` and a list of
cases; hex strings are lowercase, and list indexes are 0-based. Where a vector gives
a frame by its SHA-256 and length instead of its bytes, the digest is normative.
`vectors/tools/generate.py` regenerates them from a small reference implementation
(`vectors/tools/noise_ref.py`), which passes the cacophony vectors for both protocol
names; every handshake and transport transcript and the rekey function are also
replayed through the `noiseprotocol` package. Fixed ephemeral keys appear in the
handshake vectors only so the transcripts are reproducible; an implementation MUST
draw fresh ones.

The vectors pin bytes and pure functions. The state machines (sections 5, 6.3, 8 and
9) are tested by the libraries' own suites, including a hostile relay that drops,
duplicates, reorders, delays, relabels and alters frames.
