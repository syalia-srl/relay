# Public API of the Python library

The application sees four things: `Host`, `Guest`, a pairing, and a peer it sends to
and receives from. Everything else in PROTOCOL.md (handshakes, candidates, fragments,
rekey, ping, relay failover and backoff, the `relays` list, abort and reconnect) is
internal and never reaches the caller. Messages are `bytes`; one `send` arrives as
one message.

## Host

```python
from relay import Host, Relay

host = await Host.open(
    "state/host",                                  # hs, bound devices, channels; 0600
    relays=[Relay("wss://relay.syalia.dev", key=project_key)],
)

pairing = await host.pair("pixel-7")               # draws dev, psk, channels
show_qr(pairing.payload)                           # str, the JSON of section 4
device = await pairing.confirm(input("code: "))    # raises WrongCode, PairingFailed

async for device, message in host:                 # messages from every bound device
    await device.send(b"pong")

await host.revoke(device)                          # sends revoked, deletes channels
await host.close()
```

- `Relay(url, key=...)` takes an optional `host_url` for the host's own use; it
  defaults to `url`. `url` is the guests' URL and keeps the section 8.1 policy.
  `host_url` follows section 2.3: `wss://` anywhere, or `ws://` only to loopback, a
  private literal address, or a plain name without dots (a container or compose
  service name). A `ws://` host URL across a shared LAN sends the project key and
  host token in cleartext, so use one only on loopback or on a network whose only
  members are the host and the relay (a container network); the library cannot check
  that. Pairing payloads and `relays` messages carry `url` only.
- `Host` is an async context manager too: `async with await Host.open(...) as host:`.
- `pairing.confirm(code)` is the only way to bind a key (section 5.5). A wrong code
  raises `WrongCode` with the tries left; the third, a collision, `exp` or the
  10-minute limit raise `PairingFailed`. The host never exposes pending codes.
- `host.devices` lists bound devices; a `Device` has `id`, `name` and `connected`.
- `device.send` waits until the device is connected; wrap it in `asyncio.timeout`
  when the caller cannot wait.
- `pairing.device` is the drawn `dev`. A web application starts a pairing in one
  request and confirms it in another, so `host.pairing(dev)` returns the open
  pairing for that id, or raises `PairingFailed` if it has ended.
- Drawing the QR is the application's job: `pairing.payload` is a string, and the
  application renders it with any QR library. The payload holds the `psk` and live
  guest tokens, so it travels only over the application's authenticated admin
  connection and is never logged.

## Guest

```python
from relay import Guest

guest = await Guest.open("state/guest")            # creates gs in memory, or:
guest = await Guest.open("state/guest", key=keystore_key)   # any object with
                                                   # .public: bytes and dh(peer) -> bytes
host = await guest.pair(payload)                   # first contact
print(host.code)                                   # the 6 digits the person types
await host.bound()                                 # returns when the device channels work

await host.send(b"ping")
async for message in host:
    ...

await host.unpair()                                # close / closed
await guest.close()                                # stops connections, keeps pairings
```

- `guest.hosts` lists paired hosts after a restart; each is the same object `pair`
  returned. A revoked host raises `Revoked` from its iterator.
- `Guest` is an async context manager too, like `Host`.
- Section 3 gives each pairing its own `gs`. Without `key`, the guest draws one per
  pairing and keeps it in the state file. A native `key` serves one pairing, so a
  second host needs a second `Guest` with its own state path and key.
- A pairing a restart interrupts is not kept: the person scans a new payload.

## Rooms

`relay.rooms` is what a party that holds a room credential needs to manage rooms it
cannot read (`ROOMS.md` 4.2, 4.3): the custodian's signing key, signed roster records,
the roster's replay, and the owner routes. It makes no epoch and opens no message.

```python
from relay.rooms import RoomClient, new_signing_key, public_jwk, sign_entry, verify_roster

key = new_signing_key()                     # P-256; public_jwk(key) goes in POST /v1/rooms as custodian.sign_pub
record = sign_entry(key, entry, n, prev)    # the body of POST /roster
roster = verify_roster(entries)             # raises RosterInvalid(index, reason) at the first bad record
client = RoomClient(base_url, token, room=room_id, device=custodian_device, key=key)
client.roster(); client.append({"kind": "close-invite", "invite": key_id})
client.invite(uses, expires_at)             # -> invite, invite_key_id, token, invite_key, fragment
client.remove(device); client.set_owner(device, True); client.info(); client.delete()
```

`Roster` has `room`, `n`, `head`, `devices`, `invites`, `records`, `readers()` and
`state()`. `RoomError` carries a relay's `status` and `code`.

### Room members

`RoomMember` is one device in one room (`ROOMS.md` 3.5, 4.4 to 4.8, 5): it replays the
roster, accepts and opens epochs, seals and opens messages and blobs, keeps the
per-sender counters, and makes the next epoch whenever the current one does not match
the roster's readers. Plaintext is bytes; what it means is the application's.

```python
from relay.rooms import RoomMember, software_device_keys

sign_key, recv_key = software_device_keys()       # C3 shape: sign(bytes) -> 64 bytes, derive(jwk) -> 32 bytes
member = RoomMember.join(link, sign_key=sign_key, recv_key=recv_key)   # base_url= overrides the link's relay
seq = member.post(b"...", blob=b"file bytes")     # rotates first when 4.4 says so; a retry reuses the cid
for m in member.sync():                           # Message(seq, device, epoch, n, plaintext, blob, at, status)
    ...                                           # status: ok, refused, missing, expired
member.blob(m.blob); member.ack(m.seq)
async for seq in member.watch(): ...              # /v1/rooms/ws hints for this room
saved = member.state()                            # ids, token, epoch keys, counters: seal it; no private key
member = RoomMember.from_state(saved, sign_key=sign_key, recv_key=recv_key)
```

A gap entry (`missing`: the relay still owes it, `expired`: retention deleted it) comes
right before the message that revealed it: `n` is the first missing counter, `seq` that
message's. A message that fails a check is `refused` with `reason` and no plaintext;
a replay is `refused` with `replay`. `roster_error` holds a `RosterInvalid` when the
roster is broken; the records before it stand. An owner also has `RoomMember.create`
(with a credential the caller holds), `invite`, `approve`, `remove` and `info`.

Where the JavaScript `Room` differs (API shape only, the protocol is the same): its
`sync` returns gaps in a separate `gaps` list instead of inline messages; it lists
replays in `dropped` instead of returning them as `refused` with `replay`; and it makes
a due epoch only in `send`, while `RoomMember.sync` makes it too.

### Device keys

`SignKey` and `RecvKey` are the library's own key objects in the C3 shape. A caller
that keeps its device keys elsewhere (a PEM file, a key store it unwraps itself) builds
them from a `cryptography` private key:

```python
from cryptography.hazmat.primitives.asymmetric import ec
from relay.rooms import RecvKey, SignKey

sign_key = SignKey(private)          # private: ec.EllipticCurvePrivateKey on P-256
sign_key.sign_pub                    # the reduced public JWK
sign_key.sign(data)                  # -> 64 bytes r||s, ECDSA P-256 over SHA-256(data)
recv_key = RecvKey(private)          # another P-256 private key: one key per role
recv_key.recv_pub                    # the reduced public JWK
recv_key.derive(peer_jwk)            # -> the 32-byte raw ECDH secret with peer_jwk
```

Both constructors raise `ValueError` for a key on any other curve. Neither object
exports its private key; the caller keeps the `cryptography` key it passed in, and
`software_device_keys()` returns a fresh pair of them. Any object with the same
attributes and methods can stand in for either, as `RoomMember` takes the C3 shape.

## Errors

One base `RelayError`, with `PairingFailed`, `WrongCode`, `Revoked` and
`PayloadInvalid` under it. Transient network errors are retried inside and never
raised.

## Not in the API

No callbacks, no hooks, no event bus, no options beyond the ones above. Section 10
duties are met by this shape: the key at rest is the state file's mode, the
confirmation is `confirm(code)`, revocation is `revoke`, and what a session may do is
the application's own code around `send` and the iterator.
