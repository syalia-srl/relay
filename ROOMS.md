# Rooms: relay mailbox v1 and room protocol v1

This document is normative. The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY
are to be read as in RFC 2119. It extends `PROTOCOL.md`, whose sections 1 (JSON rules),
2.1 (identifiers and tokens) and 2.2 (credentials) apply here unchanged. The JSON test
vectors in `vectors/rooms_*.json` are part of the specification: an implementation that
disagrees with a vector is wrong, and where a vector and this text disagree, report it
as a bug.

## 1. Layers

A room is a group of devices that exchange end-to-end encrypted messages and files
through a relay, with no server of their own and no need to be online together.

| Layer | What it does | Defined here |
|---|---|---|
| L0 mailbox | Rooms, devices, tokens, invites, roster records, epochs, ciphertext messages and blobs, retention, quotas, a notification socket. Never reads content. | Section 3 |
| L1 room protocol | Device keys, the signed roster, epochs, sealed messages and blobs, invite links. Everything the relay must not be trusted with. | Sections 2, 4 and 5 |
| L2 application | What a message means (text, a file, a reply), what names devices show, who in the application may ask for a room. | No. See section 6. |

A relay is never trusted with confidentiality or with membership. Everything L1
promises holds against a relay that drops, delays, replays, reorders or alters what it
stores. What a relay can still do is listed in section 6.

Roles:

- A **credential** is a project key of `PROTOCOL.md` 2.2 (an operator key or an `rt1`
  relay token) that carries a room quota. It creates rooms and is never given to a
  device.
- A **device** holds two P-256 key pairs, one to sign and one to receive, and a device
  token for each room it is in.
- An **owner** is a device that may change the room's membership. A **member** is a
  device that may read and post.
- The **custodian** is a signing key of the party that holds the credential (for
  example a server install that created the room for one of its users). It is an
  owner with no receiving key: it can manage the room and can never read it.

Rooms are a separate use of the relay. Channels (`PROTOCOL.md` section 2) and their
store are unaffected, and a relay MAY serve one without the other.

## 2. Encodings

- **Public keys** on the wire and in roster entries are P-256 JWKs reduced to the four
  members `kty` (`"EC"`), `crv` (`"P-256"`), `x` and `y`, each coordinate 32 bytes in
  base64url (43 characters). A receiver reduces a JWK it is given to these four members
  before it uses or compares it, and refuses one with another curve or a coordinate of
  another length.
- **Bytes in JSON** (`iv`, `ct`, `sig`, the members of a wrap) are base64url without
  padding, with canonical trailing bits. A receiver MUST refuse padding and characters
  outside `A-Z a-z 0-9 - _`.
- **Canonical JSON** of an object is its serialisation with the keys of every object
  sorted, no whitespace, strings escaped as ECMAScript's `JSON.stringify` escapes them
  (non-ASCII characters as themselves, control characters as `\b \f \n \r \t` or
  `\u00XX` in lowercase hex), encoded in UTF-8. Every object this document signs has
  ASCII keys and only strings, integers in the range of `PROTOCOL.md` section 1,
  booleans, `null`, arrays and objects, so sorting by UTF-16 code unit and by code
  point agree.
- **Signatures** are ECDSA on P-256 with SHA-256, encoded as the 64 raw bytes `r‖s`
  (what WebCrypto produces), over the canonical JSON of the signed object. A verifier
  MUST refuse a signature that does not decode to exactly 64 bytes (a DER signature
  included) and MUST accept either of the two valid values of `s`. Nothing in the
  protocol depends on the bytes of a signature: hashes cover signed bodies, never
  signatures.
- **Ids made by clients** (a message's `cid`, a blob id, an invite key id) are 16
  random bytes in base64url (22 characters).
- **Ids made by the relay** (room ids, device ids, invite ids) are 16 random bytes and
  **tokens** (device tokens, join tokens) are 32 random bytes, both in base64url
  (22 and 43 characters), drawn and stored as `PROTOCOL.md` 2.1 requires: only their
  SHA-256 digests are kept, and no token is ever logged or put in a URL.

`vectors/rooms_encoding.json` gives canonical texts, signatures to accept and refuse,
and a JWK reduction.

## 3. Relay mailbox v1 (L0)

### 3.1 Credentials and room quota

A credential may create rooms only if it carries a room quota (`PROTOCOL.md` 2.2):

| Limit | `keys.json` (`rooms` object) | `rt1` payload | Counts |
|---|---|---|---|
| Rooms | `max` | `rooms` | Rooms created with the credential that are not deleted. |
| Stored bytes | `stored_bytes` | `room_stored_bytes` | Bytes held for all its rooms: the decoded `ct` of every message and the body of every blob the relay still keeps. |
| Retention | `retention_days` | `room_retention_days` | The longest a room may keep a message or blob. |
| Blob size | `blob_bytes` | `room_blob_bytes` | The largest blob body a room takes. |

A credential has a room quota when all four values are present and integers, the
number of rooms is at least 1 and the retention at least 1 day. Otherwise it has none
and the credential routes answer 403; the credential still works for channels.
`"unlimited": true` lifts channel limits only: an operator key creates rooms only with
a `rooms` object. The quota is accounted per credential as for channels: per key
digest for an operator key, per `(iss, sub)` for a relay token, so a renewed token with
the same `sub` keeps its rooms.

A room has its own limits, fixed when it is created:

| Limit | Default | Bounded by |
|---|---|---|
| `max_bytes` | 2,000,000,000 | The credential's stored bytes. |
| `retention_days` | 30 | The credential's retention. |
| `blob_bytes` | The credential's blob size. | |

A request that asks for more gets the bound. A request that names `max_bytes` or
`retention_days` with a value that is not an integer of at least 1 is refused with 400.
`vectors/rooms_quota.json` gives credentials with and without a room quota, and the
limits for several requests.

### 3.2 Devices, tokens and roles

The relay keeps, for each room, its own view of membership, made only of what it did
itself:

- the device tokens it issued: the creator's and the custodian's at creation, one per
  join;
- which of them it revoked, on a remove call;
- which devices are owners: the creator and the custodian at creation, and changes made
  by an owner through `POST /owners`;
- each device's kind: `device`, or `custodian` for the custodian, which has no
  receiving key.

It uses that view to authorise routes and for nothing else. It stores roster records
and epochs without reading their contents, and never refuses an epoch over who it is
wrapped for. Members decide who is in the room from the signed roster (section 4.2).

| Route needs | Who |
|---|---|
| a credential | `Authorization: Bearer <operator key or rt1 token>` with a room quota. |
| a join token | `Authorization: Bearer <join token>` of an open invite of that room. |
| a device | `Authorization: Bearer <device token>` of a device of that room, not revoked. |
| an owner | A device whose role in the relay's view is owner. |

A custodian device MAY call every device route except `POST /epochs`,
`GET` and `POST /messages`, `PUT` and `GET /blobs`: it holds no epoch key, and the
relay answers these with 403.

### 3.3 Answers and errors

Request and answer bodies are JSON (section 1 of `PROTOCOL.md`), except blob bodies.
An error is `{"error": "<code>"}` with one of these statuses:

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | A body that is not the JSON this section describes, or a value out of range. |
| 401 | `unauthorized` | No token, an unknown or revoked token, a token of another room, a refused relay token. |
| 403 | `forbidden` | A credential without a room quota, or a device that may not do this (not an owner, the custodian on a route it may not call, `creator` not the caller). |
| 404 | `not_found` | No such room, invite or blob. |
| 409 | `conflict` | A roster record or epoch whose `n` is not the last plus one; an invite used up or expired; a change that would leave the room with no owner. |
| 410 | `gone` | The room was deleted. |
| 413 | `too_large` | A blob body over the room's `blob_bytes`, or a JSON body over the sizes below. |
| 423 | `read_only` | A write to a room that is read-only (section 3.6). |
| 507 | `full` | The room's `max_bytes`, the credential's stored bytes or its number of rooms would be exceeded. |

The relay checks in this order: the token, the room (404, 410), the role, the body,
then read-only, then the quota. A JSON body is at most 1 MiB, and a message's `ct`
decodes to at most 65,536 bytes; larger content goes in a blob.

Every answer to a device route, once its token is accepted, carries the header
`Relay-Room-Watermark: <seq>`, the room's watermark: every message with a sequence
below it has been deleted, and every message the relay assigned a sequence at or above
it is still held. Sequences start at 1; a room with no messages deleted has watermark
1. Clients use it to tell a deleted message from a missing one (section 4.5).

### 3.4 Routes

Under the relay's base URL, beside the channel routes:

```
POST /v1/rooms                       Authorization: Bearer <operator key | rt1 token>
  {"owner": {"sign_pub": JWK, "recv_pub": JWK},
   "custodian": {"sign_pub": JWK},
   "max_bytes": 2000000000, "retention_days": 30}          # both optional, clamped to the credential
→ 201 {"room": "<id>", "device": "<id>", "token": "<device token>",
       "custodian": {"device": "<id>", "token": "<device token>"},
       "limits": {"max_bytes": n, "retention_days": n, "blob_bytes": n}}

GET  /v1/rooms/quota                  Authorization: Bearer <operator key | rt1 token>
→ 200 {"rooms": {"max": n, "used": n}, "stored_bytes": {"max": n, "used": n},
       "retention_days": n, "blob_bytes": n, "read_only_since": null | <unix s>}   403 without a room quota

POST /v1/rooms/{id}/invites          {"uses": 1, "expires_at": <unix s>}
→ 201 {"invite": "<id>", "token": "<join token>"}
DELETE /v1/rooms/{id}/invites/{invite}

POST /v1/rooms/{id}/join             Authorization: Bearer <join token>
  {"sign_pub": JWK, "recv_pub": JWK}
→ 201 {"device": "<id>", "token": "<device token>"}

GET  /v1/rooms/{id}/roster?after=<n>  → {"entries": [{"n", "entry", "sig", "signer", "prev"}...]}
POST /v1/rooms/{id}/roster           {"n", "entry", "sig", "prev"}       409 when n is not last+1
POST /v1/rooms/{id}/epochs           {"n", "roster", "creator", "wraps": {device: wrap}, "sig"}   409 when n is not last+1
GET  /v1/rooms/{id}/epochs?after=<n>
POST /v1/rooms/{id}/owners           {"device": "<id>", "owner": true|false}
DELETE /v1/rooms/{id}/devices/{device}
GET  /v1/rooms/{id}/messages?after=<seq>&limit=<n>   → {"messages": [...], "watermark": seq}
POST /v1/rooms/{id}/messages         {"cid", "epoch", "n", "iv", "ct", "sig", "blob"?}  → {"seq": n}
PUT  /v1/rooms/{id}/blobs/{blob}     body: ciphertext bytes
GET  /v1/rooms/{id}/blobs/{blob}
POST /v1/rooms/{id}/ack              {"seq": n}
PUT  /v1/rooms/{id}/push             {"token": "<push token>" | null}
GET  /v1/rooms/{id}                  → {"room", "devices": [{"device", "kind", "role", "last_ack_at"}], "limits", "stored_bytes", "read_only_since"}
DELETE /v1/rooms/{id}
GET  /v1/rooms/ws                    first frame {"tokens": ["<device token>", ...]}; then {"room", "seq"} per arrival
```

Each route in detail. "Last" is the highest `n` the room holds, 0 when it holds none.

**`POST /v1/rooms`** (a credential). `owner.sign_pub`, `owner.recv_pub` and
`custodian.sign_pub` are JWKs (section 2); `max_bytes` and `retention_days` are
optional (section 3.1). The relay creates the room, a device of kind `device` for the
owner and one of kind `custodian`, both owners, and answers with their ids and tokens
and the room's limits. 403 without a room quota, 507 when the credential already has
`max` rooms. A room whose roster record 1 has not arrived within 1 hour is deleted
and stops counting against the quota.

**`GET /v1/rooms/quota`** (a credential). What the credential may use and uses now:
the number of its rooms that are not deleted, its stored bytes, its retention and blob
size, and `read_only_since` (section 3.6), `null` when its rooms are writable. It
counts as presenting the credential for section 3.6. 403 without a room quota.

**`POST /v1/rooms/{id}/invites`** (an owner). `uses` is an integer from 1 to 1000 and
`expires_at` a time in Unix seconds after now and at most 30 days ahead; otherwise 400.
The relay stores the join token's digest with its uses and expiry. **`DELETE
…/invites/{invite}`** (an owner) closes it at once: 204, or 404 for an unknown invite.

**`POST /v1/rooms/{id}/join`** (a join token). The relay checks only the token, its
uses and its expiry, and nothing about the keys beyond their form. It takes one use and
adds a device of kind `device`, role member, with the given public keys, in one
transaction. 409 when the invite is used up or expired; 401 when the token is unknown,
closed or of another room. Whether the device may read is the members' decision
(section 4.8).

**`GET /v1/rooms/{id}/roster?after=<n>`** (a device) returns the records with `n`
above `after` (0 when absent), in order. Each record is what was posted, plus
`signer`, the id of the device whose token posted it. `signer` is the relay's claim:
clients use the signing device named inside the entry (section 4.2), never `signer`.
**`POST …/roster`** (a device) appends one record. The relay checks only that `n` is
the last plus one (409 otherwise), that `entry` is an object and `sig` and `prev`
strings, and that the record is at most 64 KiB (413), and answers 201 `{"n": n}`.
Record 1 marks the room as set up.

**`POST /v1/rooms/{id}/epochs`** (a device, not the custodian) appends epoch `n`,
which MUST be the last plus one (409 otherwise). `roster` MUST be an integer of at
least 0 (400 otherwise); the relay stores it as given and checks nothing else about it.
`creator` MUST be the calling device's id (403 otherwise). `wraps` maps device ids to
wraps; the relay does not check them. It answers 201 `{"n": n}`. **`GET …/epochs?after=<n>`** returns
`{"epochs": [{"n", "roster", "creator", "wraps", "sig"}...]}` in order.

**`POST /v1/rooms/{id}/owners`** (an owner) sets the role of a device of the room in
the relay's view: 204, 404 for an unknown or removed device, 409 when it would leave
the room with no owner. **`DELETE /v1/rooms/{id}/devices/{device}`** (an owner for any
device, any device for itself) revokes the device's token and push token: 204, 404 for
an unknown device, 409 when it would leave no owner. The device stays out of every
count from then on. An owner's client makes these calls together with the matching
roster record (section 4.3).

**`GET /v1/rooms/{id}/messages?after=<seq>&limit=<n>`** (a device, not the custodian)
returns the messages with a sequence above `after`, oldest first, at most `limit`
(default 100, at most 500), and the watermark. Each message is
`{"seq", "device", "cid", "epoch", "n", "iv", "ct", "sig", "blob"?, "at"}`, where
`device` is the posting device and `at` the Unix second the relay took it.
**`POST …/messages`** (a device, not the custodian) takes `cid` (a client id),
`epoch` and `n` (integers), `iv` and `ct` (base64url), `sig` (base64url) and an
optional `blob` (a blob id), and answers 201 `{"seq": n}`. The sequence is the room's
next, assigned in one transaction, so no two messages share one. A repeated `cid` from
the same device returns the first message's sequence with 200 and stores nothing: a
client retries with the same `cid`, and this holds on a read-only room too, since it
stores nothing. The relay checks the form of each field and nothing else, so it takes
a message whose `blob` it does not hold; a client PUTs a message's blob before it
posts the message.

**`PUT /v1/rooms/{id}/blobs/{blob}`** (a device, not the custodian) stores the request
body as the blob, with `blob` a client id: 201 with no body, 413 above `blob_bytes`,
409 when the id is taken, even by the same bytes from the same device. **`GET …/blobs/{blob}`** returns the bytes, 404 when not held.

**`POST /v1/rooms/{id}/ack`** (a device) records `seq` as the highest sequence the
device holds, if it is higher than the one recorded, and the time as its
`last_ack_at`: 204.

**`PUT /v1/rooms/{id}/push`** (a device) sets the device's push token, a string of at
most 4096 characters, or clears it with `null`: 204 (section 3.7).

**`GET /v1/rooms/{id}`** (a device) returns the room id, its current devices with
kind, role and last ack time (Unix seconds, or `null`), its limits, its stored bytes
and its `read_only_since`. **`DELETE /v1/rooms/{id}`** (an owner) deletes the room,
its messages, blobs, roster and epochs, closes its sockets and answers 204. The room's
id then answers 410 for at least 30 days.

### 3.5 Notification socket

`GET /v1/rooms/ws` opens a WebSocket. The URL carries no token. The client's first
frame MUST be a text frame, within 5 seconds, holding `{"tokens": [...]}` with 1 to
256 device tokens, usually one per room the device is in on this relay. The relay
watches the rooms of the tokens it accepts and ignores the others; when it accepts
none, or the frame is late or malformed, it closes with 4401. A socket that a deleted
room or a revoked token leaves with nothing to watch is closed with 4410.

From then on the relay sends a text frame `{"room": "<id>", "seq": n}` each time a
watched room takes a message, with that message's sequence. It sends nothing else and
ignores what the client sends. Data still goes over HTTP: the frame is a hint to fetch,
and a client that missed one loses nothing, since it fetches from its last sequence.

### 3.6 Retention, quota and lifetime

- A message or blob is deleted once every device of kind `device` that acked within
  the last 14 days has acked past it, or once it is older than the room's
  `retention_days`, whichever comes first. A device that has not acked for 14 days
  stops holding anything back; a device that has never acked counts from the time it
  joined. A blob counts as past an ack when the message that
  names it is; a blob no message names is deleted after 1 day.
- A write that would take the room over `max_bytes`, or the credential over its stored
  bytes, is refused with 507 and stores nothing. One full room leaves the credential's
  other rooms working.
- A credential is gone when its operator key leaves the keys file, when the latest
  relay token the relay has seen for its `(iss, sub)` has expired (the latest is the one
  with the highest expiry, so presenting an older token shortens nothing), or when it no longer
  carries a room quota. Its rooms are then read-only from that moment, as
  `read_only_since`: reads, acks, removals and deletion still work, and every other
  write answers 423, closing an invite and setting a push token included. Presenting
  the credential again with a room quota, at any credential route, ends it; an operator
  key put back in the keys file stays read-only until it is presented. A room read-only for 30 days is deleted.
- A relay MUST keep rooms, devices, invites, roster records, epochs, messages and blobs
  across restarts, in storage only the relay can read, with tokens kept as digests.

### 3.7 Push

A device MAY give the relay a push token. When a room takes a message, the relay sends
each other device's push token, and nothing else, to the push gateway named in its own
configuration. It MUST NOT contact any URL a device supplies. With no gateway
configured it sends nothing. The gateway learns that a device received something, and
when; the relay's configuration MUST say so next to the setting that turns it on. The
device then fetches as after a socket hint.

## 4. Room protocol v1 (L1)

### 4.1 Device keys

A device has, per room, an ECDSA P-256 signing key and an ECDH P-256 receiving key.
A device MUST create fresh keys for each room. The protocol never needs a private key's
bytes; an implementation uses a key store that signs and derives without exporting
them. All the protocol asks of it is:

- `sign(bytes)`: an ECDSA P-256 SHA-256 signature, as 64 bytes `r‖s`;
- `derive(peer_jwk)`: the raw 32-byte ECDH shared secret (the x coordinate) with a
  peer's public key. Key derivation from that secret is part of the protocol (section
  4.4).

The custodian has only a signing key.

### 4.2 The roster

The roster is an append-only list of records, numbered from 1, that says which devices
are in the room and what they may do. Every client replays all of it and trusts only
the devices it proves.

A record is `{"n", "entry", "sig", "prev"}` (the body of `POST /roster`):

- `n`: its position, 1 for the first;
- `entry`: the entry, an object with `kind`, `by` (the id of the device whose signing
  key signs it) and the fields of its kind;
- `prev`: `""` for record 1; for every later record, the hash of the record before it;
- `sig`: the signature of `by`'s signing key over the canonical JSON of
  `{"v": "relay-roster-1", "n": n, "prev": prev, "entry": entry}`.

The hash of a record is the base64url of the SHA-256 of the canonical JSON of that same
signed object. It covers no signature.

Entries:

| `kind` | Signed by (`by`) | Fields | Effect |
|---|---|---|---|
| `genesis` | the creator | `room`; `creator`: `{device, sign_pub, recv_pub}`; `custodian`: `{device, sign_pub}` | The creator, kind `device`, and the custodian, kind `custodian`, both owners. |
| `invite` | an owner | `invite` (invite key id), `invite_pub` (JWK), `uses` (at least 1), `expires_at` (Unix s), `approval` (boolean) | An invite that admits up to `uses` devices. |
| `join` | the joining device | `device`, `sign_pub`, `recv_pub`, `invite`, `at` (Unix s), `invite_sig` | A device, role member, under that invite. It is pending when the invite asks for approval, active otherwise. |
| `approve` | an owner | `device` | A pending device becomes active. |
| `link` | a device of the person | `device`, `device_sig` | `device` becomes another device of the same person as `by`, and an owner if `by` is one. |
| `remove` | an owner, or a device of the same person | `devices` (a non-empty list of ids) | Those devices leave. |
| `promote` | an owner | `device` | An active member becomes an owner. |
| `demote` | an owner | `device` | An active owner becomes a member. |
| `close-invite` | an owner | `invite` | The invite admits no more devices. |

`invite_sig` is the invite key's signature over the canonical JSON of
`{"v": "relay-join-1", "invite", "device", "sign_pub", "recv_pub", "at"}` with the
join's own values. `device_sig` is the signature of `device`'s own key over
`{"v": "relay-link-1", "member": <the person id of by>, "device": <device>}`.

Replay keeps, for each device, its keys, kind, role (`owner` or `member`), status
(`pending`, `active` or `removed`) and person id (`member`, its own id until a `link`),
and for each invite its key, uses, uses taken, expiry, approval and whether it is
closed. A record is valid when, after every record before it:

1. it has the four fields, `n` is its position and `prev` is the hash of the record
   before it (`""` for record 1);
2. `kind` is one of the table, and it is `genesis` exactly when `n` is 1;
3. `by` is the creator's device for `genesis`, the new `device` for `join`, and an
   active device otherwise; `sig` verifies with that device's signing key (for
   `genesis` and `join`, the key in the entry);
4. for `genesis`, the creator and custodian ids differ;
5. for `invite`, `approve`, `promote`, `demote`, `close-invite` and `remove` of
   another person's device, `by` is an owner;
6. for `join`: the device id is new; the invite is in the roster; `invite_sig`
   verifies with its `invite_pub`; it is not closed; fewer than `uses` devices joined
   with it; and `at` is before its `expires_at`;
7. for `approve`, the device is pending; for `promote`, an active member; for `demote`,
   an active owner; for `close-invite`, an open invite; for `remove`, every device is
   in the roster and not removed;
8. for `link`, `by` and `device` are distinct active devices of kind `device`,
   `device` has linked to nobody and nobody has linked to it, and `device_sig`
   verifies;
9. after it, at least one active owner remains.

A client MUST stop at the first record that is not valid: the records before it stand,
that record and every later one are refused, and the client shows the room's roster as
broken. It MUST check that the `room` of record 1 is the room it asked for. A pending
or removed device signs no valid record and gets no wraps in an epoch made after it
left. An epoch it makes is refused when it names a record where the device is not
active, or a record before one that an accepted epoch with a lower `n` names (4.4). Its
messages under an epoch it held before its removal can still arrive late if
a relay delayed them (section 6).

The `at` of a join is the joiner's claim. The relay enforces the real expiry when it
takes the join token; the roster check only refuses a join that admits it came late.

A relay that withholds the newest records is not caught by replay: every prefix of a
valid roster is valid. It can delay a removal that way, and nothing more: every added
device needs a signature by a key the relay does not have. `vectors/rooms_roster.json`
gives a roster that uses every kind and rosters that fail at a given record.

### 4.3 The relay's view and the roster

An owner's client makes the relay call and the roster record of the same change
together: `DELETE /devices/{device}` with `remove`, `POST /owners` with `promote` and
`demote`, `DELETE /invites/{invite}` with `close-invite`. The relay's invite id
(`POST /invites`) and the invite key id of the roster are separate ids; the client
that makes an invite keeps both. If the two views disagree, the room keeps working:
the relay may let a removed device fetch ciphertext it cannot open, or refuse a call to
a device the roster still lists, and clients follow the roster.

### 4.4 Epochs and wraps

Room content is encrypted under epoch keys: 32 random bytes, used as an AES-256-GCM
key. Epochs are numbered from 1. The creator posts epoch 1 right after the genesis
record. A new epoch follows every join, removal and approval: the joiner creates it
for its own join, and the owner that appends a `remove` or `approve` creates it for
that record. Any device that sees such a record not yet followed by an epoch MAY
create one. No device sends with an epoch key that a device that has left holds.

An epoch is `{"n", "roster", "creator", "wraps", "sig"}`. `roster` is the `n` of the
last roster record the creator had verified when it made the epoch: a sender sets it to
the length of its verified roster. `wraps` maps the id of every active device of kind
`device` at that record, the creator included, to a wrap of the epoch key for that
device's receiving key:

1. Draw an ephemeral P-256 key pair and a 12-byte IV.
2. `secret` = the raw ECDH secret of the ephemeral private key and the device's
   `recv_pub` (what the device's `derive(eph)` returns on the other side).
3. `key` = HKDF-SHA-256 with `secret` as input key material, a salt of 32 zero bytes,
   the info `relay-wrap-1|<room>|<n>|<device>` in ASCII, and 32 bytes of output.
4. The wrap is `{"eph": <ephemeral public JWK>, "iv": <IV>, "ct": AES-256-GCM(key, IV,
   epoch key)}` with no additional data.

`sig` is the creator's signature over
`{"v": "relay-epoch-1", "room", "n", "roster", "creator", "wraps"}`. A receiver accepts
an epoch only when:

1. the roster's room is its room;
2. `roster` is an integer with 1 <= `roster` <= the length of its verified roster;
3. `creator` and every device in `wraps` are active devices of kind `device` at record
   `roster`, that is after replaying records 1 to `roster`, and `creator` is in `wraps`;
4. `sig` verifies with the creator's key;
5. `roster` is not lower than the `roster` of any epoch it accepted with a lower `n`:
   it never decreases as `n` grows.

When `roster` is beyond its verified roster or a wrap names a device it does not know,
it first fetches the roster again, then refuses the epoch and shows it. Rule 5 is what
keeps a removed device out: once a member has made an epoch after the `remove`, an
epoch signed with the removed device's key must name a record before the removal, and
is refused, even when a relay that holds that key posts it. A device opens its wrap
with `derive(eph)`, the same HKDF, and AES-256-GCM.

Two devices that create the same epoch number get one 201 and one 409. The loser
fetches epochs and roster and creates the next epoch only if the new one does not cover
what it needed. `vectors/rooms_epoch.json` gives an epoch with every intermediate value
of its wraps, and epochs a receiver accepts or refuses, among them a removed device's.

### 4.5 Messages

A message is sealed by its sender under an epoch whose key it holds:

- `n` is the sender's counter in the room: 1 for its first message, then one more for
  each message, across epochs. A sender posts its messages in order of `n`, each after
  the previous one has its sequence.
- `iv` is 12 random bytes, `ct` the AES-256-GCM encryption of the plaintext under the
  epoch key with the additional data `relay-msg-1|<room>|<epoch>|<device>|<n>` in
  ASCII, where `device` is the sender's id.
- `sig` is the sender's signature over
  `{"v": "relay-msg-1", "room", "device", "epoch", "n", "iv", "ct"}`, plus `"blob"`
  when the message names a blob.

The plaintext is the application's (section 6). A receiver opens a message as the
relay returns it only when it holds that epoch, the sender is in the epoch's `wraps`,
`sig` verifies with the sender's key from the roster, and the decryption succeeds.

Each receiver keeps, per sending device, the last `n` it accepted and that message's
sequence. A message whose `n` is not above the last is dropped: it is a replay. When
`n` skips values, the missing messages lie between the two sequences. If the watermark
of the answer that delivered the new message is at most the last sequence plus one,
the relay still holds that whole range and owes the gap (`missing`); otherwise part of
the range was deleted by retention (`expired`). The first message a receiver sees from
a device sets its baseline. `vectors/rooms_message.json` gives sealed messages,
messages a receiver refuses and counter cases with their gaps.

### 4.6 Blobs

A file is a blob, encrypted whole under the epoch key of the message that names it:
the body is a 12-byte random IV followed by the AES-256-GCM encryption of the file with
the additional data `relay-blob-1|<room>|<blob id>` in ASCII. The blob id is a client
id (section 2), and the message that refers to it carries it in `blob`, so the
message's signature binds the blob to that message. A body that is shorter than 28
bytes or fails to decrypt under its own id is refused. `vectors/rooms_blob.json` gives
sealed blobs and bodies to refuse.

### 4.7 Creating a room

1. The creating device makes its keys and has `POST /v1/rooms` called with its public
   keys and the custodian's public signing key, by whoever holds the credential.
2. It posts roster record 1, the genesis entry, naming itself and the custodian.
3. It posts epoch 1, wrapped for itself.

Until step 2 the room is not set up and the relay deletes it after an hour.

### 4.8 Joining

An owner makes an invite: it calls `POST /invites`, draws a fresh P-256 invite key pair
and an invite key id, appends an `invite` entry with the key's public half, and hands
the invite link (section 5) to the person. The joiner's device:

1. parses the link and makes its keys;
2. calls `POST /join` with the join token and gets its device id and token;
3. fetches the roster, finds the `invite` entry whose `invite_pub` is the public half of
   the link's invite key, and appends a `join` entry signed by itself, with
   `invite_sig` by the invite key;
4. unless the invite asks for approval, creates the next epoch for every active device,
   itself included, and posts under it whatever the application announces a newcomer
   with.

Every member checks the join by replaying the roster. A join that is not valid gets no
wraps. With approval, the device waits, pending, until an owner appends `approve`; that
owner then creates the next epoch. A newcomer reads nothing from before it joined.

## 5. Invite links

An invite link is any URL of the application whose fragment is:

```
v1.<relay host>.<room id>.<join token>.<invite key>
```

for example
`https://app.example/j#v1.relay.example:8443.<room id>.<join token>.<invite key>`.
Browsers do not send a fragment, so the server behind the link learns nothing from it.

- `relay host` is the host of the relay, in lowercase: a DNS name or an IPv4 address,
  optionally followed by `:` and a port from 1 to 65535 without leading zeros. The
  relay's base URL is `https://<relay host>` with no path, and its socket is at
  `wss://<relay host>/v1/rooms/ws`. IPv6 literals and relays under a path cannot be
  named in a v1 link.
- `room id` is the 22-character room id and `join token` the 43-character join token.
- `invite key` is the base64url of the invite private key in PKCS#8 DER (RFC 5208,
  with an RFC 5915 `ECPrivateKey` that includes the optional public key, as WebCrypto's
  `exportKey("pkcs8")` writes it). PKCS#8, not the raw JWK `d`: WebCrypto imports a
  PKCS#8 key directly and gives back its public half, which the joiner needs to find the
  `invite` entry, whereas from `d` alone WebCrypto cannot compute the public key. The
  public key is required inside it because not every engine computes a missing one.

A reader takes the text after the first `#`, or the whole text when it has none, and
splits it on `.`. Room ids, tokens and the invite key are base64url, whose alphabet has
no `.`, so the last three parts are the room id, the join token and the invite key,
the first is the version, and the parts between them, joined again with `.`, are the
relay host (a host contains dots, a port does not). A reader refuses a link with
another version, fewer than five parts, a host or port outside the form above, an id
or token of the wrong length or with padding, or a key that is not a P-256 PKCS#8 with
its public key. `vectors/rooms_invite_link.json` gives links to accept, with their
parts, and links to refuse.

Anyone who reads the link before the intended person can join with it, within its
uses and expiry. Such a join shows in every member's roster under that invite, and an
invite with `approval` admits nobody before an owner approves.

## 6. What the application must do

Rooms secure who can read and who is in the room. These parts are outside the protocol:

1. **What a message means.** The plaintext of messages is the application's; a JSON
   object is recommended. Names of people and devices travel inside messages, never in
   a field the relay reads.
2. **Who may create rooms.** The relay only checks the credential. An application that
   holds a credential decides which of its users may use it, and never hands the
   credential to a device.
3. **The custodian key.** It has an owner's power in every room it is in, and could
   add a device of its own (seen by every member). It MUST be stored where only the
   process that uses it can read it.
4. **Device keys.** They SHOULD live in a key store that signs and derives without
   exporting them; epoch keys at rest SHOULD be wrapped under such a key.

What a relay can still do: drop, delay or withhold messages, roster records and epochs;
refuse service; see how many devices a room has, when each one posts and fetches,
sizes, IP addresses, and the room id of every join. There is no padding and no cover
traffic. It cannot read anything, add a device that members accept, forge or replay a
message without a client noticing, or hide a dropped message for ever, since the
sender's counter shows the gap. A message a removed device sealed under an epoch from
before its removal can still appear after the removal if a relay delayed it.

## 7. Versions

The mailbox version is in the path (`/v1/rooms`). The room protocol's version is in
the labels of every signed object, key derivation and additional data (`relay-roster-1`,
`relay-join-1`, `relay-link-1`, `relay-epoch-1`, `relay-wrap-1`, `relay-msg-1`,
`relay-blob-1`) and in the link (`v1`). A room never changes version.

## 8. Test vectors

| File | Section | Covers |
|---|---|---|
| `rooms_encoding.json` | 2 | Canonical JSON, signatures to accept and refuse, JWK reduction. |
| `rooms_quota.json` | 3.1 | Room quotas from `keys.json` entries and `rt1` payloads; room limits for create requests. |
| `rooms_roster.json` | 4.2 | A roster with every entry kind and the state it yields; rosters refused at a given record (bad signature, broken chain, dropped record, forged join, used-up, expired and closed invites, signers that may not sign, no owner left). |
| `rooms_epoch.json` | 4.4 | An epoch with the ECDH secret, HKDF info, wrap key and IV of each wrap; epochs a receiver accepts or refuses at a given roster length after given earlier epochs. |
| `rooms_message.json` | 4.5 | Sealed messages with their additional data and signed JSON; refused messages; counter and gap cases. |
| `rooms_blob.json` | 4.6 | Sealed blobs; bodies to refuse. |
| `rooms_invite_link.json` | 5 | Links to accept with their parts, links to refuse. |

They follow `PROTOCOL.md` section 12: hex is lowercase, indexes are 0-based, and the
reference in `vectors/tools/rooms_ref.py` uses fixed keys, IVs and RFC 6979 signatures
only so the files are reproducible. An implementation draws fresh randomness.
