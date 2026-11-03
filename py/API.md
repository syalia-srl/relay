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
    relays=[Relay("https://relay.syalia.dev", key=project_key)],
)

pairing = await host.pair("pixel-7")               # draws dev, psk, channels
show_qr(pairing.payload)                           # str, the JSON of section 4
device = await pairing.confirm(input("code: "))    # raises PairingFailed

async for device, message in host:                 # messages from every bound device
    await device.send(b"pong")

await host.revoke(device)                          # sends revoked, deletes channels
await host.close()
```

- `Host` is an async context manager too: `async with await Host.open(...) as host:`.
- `pairing.confirm(code)` is the only way to bind a key (section 5.5). A wrong code
  raises `WrongCode` with the tries left; the third, a collision, `exp` or the
  10-minute limit raise `PairingFailed`. The host never exposes pending codes.
- `host.devices` lists bound devices; a `Device` has `id`, `name` and `connected`.
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
```

- `guest.hosts` lists paired hosts after a restart; each is the same object `pair`
  returned. A revoked host raises `Revoked` from its iterator.

## Errors

One base `RelayError`, with `PairingFailed`, `WrongCode`, `Revoked` and
`PayloadInvalid` under it. Transient network errors are retried inside and never
raised.

## Not in the API

No callbacks, no hooks, no event bus, no options beyond the ones above. Section 10
duties are met by this shape: the key at rest is the state file's mode, the
confirmation is `confirm(code)`, revocation is `revoke`, and what a session may do is
the application's own code around `send` and the iterator.
