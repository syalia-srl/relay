# Python

The Python library `relay` implements both ends of the channel protocol: the host of
a server install and the guest of a phone or another client. It pairs two static keys
through a relay, then carries messages between them with Noise IKpsk1 and KK
([PROTOCOL.md](protocol.html) sections 3 to 9). A message is a `bytes` object; one
`send` arrives as one message, up to the 16 MiB limit of the protocol.

The public surface is four things: `Host`, `Guest`, a pairing, and a peer to send to
and receive from. Handshakes, candidates, fragments, rekey, ping, relay failover and
reconnect stay inside the library.

## Install

```bash
pip install ./py
```

or, to work on the library, `cd py && uv sync --group test`. The package requires
Python 3.12 or later and depends on `cryptography` and `websockets`.

## A host

`Host.open` reads or creates the state file at the path it is given and opens a
socket on every channel of every bound device. The file holds the host's static key,
the bound devices and their channels, and is written atomically at mode `0600`.

```python
from relay import Host, Relay

host = await Host.open(
    "state/host",
    relays=[Relay(
        "wss://relay.example.com",         # the guests' URL
        key=project_key,
        host_url="ws://127.0.0.1:8010",    # the host's own URL
    )],
)
```

The relay list is ordered. The host creates a pairing channel, and later one device
channel, on each relay, and keeps a socket on each. Each `Relay` has two URLs. `url`
is the guests' URL: it passes the policy of section 8.1 (`wss`, or `ws` to a literal
private address), it is the only relay URL in pairing payloads and `relays` messages,
and it carries the traffic between the two sides. `host_url` is optional and defaults
to `url`; the host uses it for its own HTTP calls and sockets. A `ws://` host URL
sends the project key and the host token in cleartext, so it is safe only on loopback
or on a network whose only members are the host and the relay, such as a container
network; the library cannot check that. The example runs the host on the relay's
machine, so the host dials loopback and guests use the public `wss://` URL.

`host.pair(name)` draws a device id, a pairing secret and the channels, and returns
the open pairing:

```python
pairing = await host.pair("pixel-7")
show_qr(pairing.payload)   # a string: the JSON of PROTOCOL.md section 4
```

`pairing.payload` is the pairing payload. The application renders it as a QR code or
as copied text with any library it likes; the relay library does not draw it. The
payload carries the pairing secret and live guest tokens, so it travels only over the
application's authenticated admin connection and is never logged.

The host confirms in a later request, after a person reads the six digits on the
guest:

```python
pairing = host.pairing(device_id)            # the dev drawn by host.pair
device = await pairing.confirm(code)         # WrongCode, PairingFailed
```

`pairing.device` is the id to store with the pending pairing, for example in the
admin session that renders the QR. `host.pairing(id)` returns that open pairing or
raises `PairingFailed` when it has ended. `confirm` is the only way to bind a key. A
wrong code raises `WrongCode` with the tries left; the third wrong code, two pending
keys with the same code, the expiry or the 10-minute limit raise `PairingFailed`.
The host never exposes the codes of pending keys.

After confirmation, messages from every bound device arrive through one iterator:

```python
async for device, message in host:
    await device.send(message)               # echo it back
```

`device.send` waits until the device is connected; wrap it in `asyncio.timeout` when
the caller cannot wait. `host.devices` lists the bound devices, each with `id`, `name`
and `connected`. Revocation sends `revoked`, deletes the device's channels on every
relay and unbinds its key:

```python
await host.revoke(device)
await host.close()
```

`Host` is an async context manager: `async with await Host.open(...) as host:`. The
iterator has one consumer, as `asyncio.Queue` does; the library keeps a bounded inbox
so a slow consumer pushes back on the relay through the socket.

## A guest

`Guest.open` reads or creates the guest state. Without a `key` argument the library
draws a fresh static key for each pairing and keeps it in the state file, at mode
`0600`:

```python
from relay import Guest

guest = await Guest.open("state/guest")
```

A native key store is passed as any object with a `public` byte string and a
`dh(peer_public) -> bytes` method:

```python
guest = await Guest.open("state/guest", key=keystore_key)
```

The library asks that object for Diffie-Hellman results and never sees the private
key. A native key serves one pairing: a second host needs a second `Guest` with its
own state path and key. `relay.StaticKey` and `relay.MemoryKey` describe the shape.

First contact takes the payload string and returns the paired host:

```python
link = await guest.pair(pairing.payload)     # PayloadInvalid on a bad payload
print(link.code)                             # the six digits the person types
await link.bound()                           # the device channels carry a session
```

`guest.pair` returns once the host holds the guest's key candidate and the pairing
code exists, which is before the person has typed it. `link.bound()` returns when the
host has confirmed and the device channels work; until then the link may send a
`ping` and receive its `pong`, and nothing else.

```python
await link.send(b"hello")
async for message in link:
    ...
```

The iterator raises `Revoked` when the host revokes the device. Unpairing sends
`close`, waits for `closed` and forgets the host; `guest.close()` only stops the
connections and keeps the pairings on disk:

```python
await link.unpair()
await guest.close()
```

After a restart, `guest.hosts` lists the paired hosts; each is the same `PairedHost`
object `pair` returned, and the library reconnects them. A pairing that a restart
interrupts is not kept: the person scans a new payload.

## Store and errors

The state path is the whole store. The Python library has no store interface: it
writes one JSON file atomically at mode `0600`, and the application chooses its
directory and its backup. Two processes must not open the same state path.

| Error | Raised when |
|---|---|
| `PayloadInvalid` | The payload is not the JSON of section 4, or every relay in it fails the URL policy. |
| `WrongCode` | The typed code matches no pending key; `tries_left` says how many remain. |
| `PairingFailed` | The pairing expired, collided, ran out of tries, or has ended. |
| `Revoked` | The host revoked this device. |
| `RelayError` | Any other failure, including a damaged state file. |

All four specific errors derive from `RelayError`. Transient network errors are
retried inside the library and never raised.

## What the application still owns

`PROTOCOL.md` section 10 lists five duties outside the encrypted stream. The library's
shape leaves them where they belong:

| Duty | In a Python application |
|---|---|
| The code that holds the guest key | The application ships and updates the guest code; `Guest.open(key=...)` can hand the private key to native code that exposes only `dh`. |
| The host key at rest | The state file's mode and directory belong to the application; the library writes `0600` and nothing wider. |
| The confirmation | `pairing.confirm(code)` takes the code; the application decides who may call it and over which connection. |
| What a session may do | The application reads `device` and `message` and decides what to run; the library has no command set. |
| Revocation | `await host.revoke(device)` sends `revoked`, deletes the channels and unbinds the key. |

The application also owns the QR display, the admin login that carries the payload
and the code, and the choice of relays.

## Worked example

The example is one program with an echo host and a guest in the same process. It
starts both from temporary state, pairs them through a relay, sends one message from
the guest, echoes it from the host and prints the reply. The person's step is played
by the program: `pairing.confirm(link.code)` uses the code the guest shows, where a
real application would read it from a person.

<!-- include: py/examples/echo.py python -->

It runs against a relay on a private address, because a guest accepts `ws://` only to
one (section 8.1):

```bash
RELAY_URL=ws://10.255.0.1:8010 RELAY_KEY=<project key> \
    uv run --project py python py/examples/echo.py
```

The output is one line, `guest received: b'hello from the guest'`. The
[relay page](run-a-relay.html) covers the relay, its keys file and its checks.
