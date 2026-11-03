# relay (Python)

The Python library of the relay channel protocol: both the host and the guest of
`PROTOCOL.md` sections 3 to 9. It pairs two static keys through a relay it never
trusts, then carries messages between them end to end encrypted with its own
Noise IKpsk1 and KK.

`API.md` is the public API. Everything else — handshakes, candidates, fragments,
rekey, ping, relay failover and backoff, the relays list, abort and reconnect — is
internal.

## Install

    pip install ./py

or, to work on it:

    cd py
    uv sync --group test

## Use

A host:

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

A guest:

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

await guest.unpair()                               # close / closed
```

`Host` is an async context manager too: `async with await Host.open(...) as host:`.
The state file named in `open` keeps the static key and the paired channels; the
library writes it atomically with mode 0600.

## Test

    cd server && CGO_ENABLED=0 go build -o relay ./cmd/relay
    cd ../py && RELAY_BIN=../server/relay uv run --group test pytest

The suite checks every file in `vectors/` and `vectors/tools/cacophony_subset.json`
against the library, runs a host and a guest through the real Go relay (pair,
confirm, send both ways, restart both sides from their state, revoke, unpair), and
puts a hostile relay that drops, duplicates, reorders, delays, relabels and flips
frames between them.
