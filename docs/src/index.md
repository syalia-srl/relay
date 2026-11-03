# Relay

An end-to-end encrypted channel between an app and the server it belongs to, through
relays that cannot read it. Two ends pair once with a QR code; after that the phone
reaches its server from anywhere, and at home the traffic never leaves the house.

Relay is open source under Apache-2.0. The protocol is [PROTOCOL.md](protocol.html),
the threat model is [SECURITY.md](security.html), and the relay and three libraries
are in the `syalia-srl/relay` repository.

## Why

A server that runs in an office or at home usually has no public address, and opening
a port or a VPN for every phone is work most people never do. A relay solves the
address problem: both ends dial out to it, and it joins them.

The hard part is trust. The relay is a pipe that carries only ciphertext, so it does
not matter who runs it: the same project, another operator, or a stranger. Only the
phone and its server hold keys. Every connection gets fresh keys, so a key stolen
later does not open what was recorded before.

A host keeps an ordered list of relays: one on its own network first, a public one
after. The phone uses the first that answers and moves back up when it can.

## How it works

The **host** is the end that is always on: the server. The **guest** is the end that
comes and goes: the phone. Both open a WebSocket to a relay, the relay joins the two
sockets of a channel, and passes frames from one to the other without opening them.
The host keeps a channel on every relay of its list; the guest uses one at a time.

The roles are fixed per channel, and the application picks which of its ends plays
host. Every library implements both.

| | host | guest |
|---|---|---|
| Creates channels on relays | yes, with a project key | no, joins with its token |
| Static key | one, long-lived | new for each pairing |
| Handshakes | answers | starts |
| Relay list | decides and sends it | receives it, only from the host |
| After the handshake | messages of any size, either way | messages of any size, either way |

## Pairing

1. The server draws a one-time QR. It names the server's public key and carries a
   secret that lives five minutes.
2. The phone makes its own key, proves it knows the secret, and shows a six-digit
   code.
3. A person types that code on the server's page. Only then does the phone get in.

The server never shows a code, so a stranger who photographed the QR has nothing the
person would type.

## What a relay sees

Every promise below holds for a relay that drops, delays, replays, reorders or alters
frames. The full threat model is in [SECURITY.md](security.html).

| A relay can | A relay cannot |
|---|---|
| see when each end is connected, how much it sends, and both IP addresses | read any message, now or from a recording |
| drop or delay frames, or close a connection | inject, replay or reorder a message without the ends noticing |
| make a pairing fail, so the person scans again | get a key of its choice accepted by the server |
| see an opaque id for the quota it applies | learn who the customer is |

## Running a relay

The relay is a small Go program with no runtime dependencies and one static binary.
Since confidentiality never depends on the relay, running your own is about
availability and metadata: on your own network, nobody else sees when the devices
talk.

[Running a relay](run-a-relay.html) covers the binary and the container, the systemd
unit, a Caddy reverse proxy with TLS, the `keys.json` file with project keys and their
sha256 digests, quotas, `"unlimited": true`, issuers and signed relay tokens, the
checks that prove it works, upgrades, and where the state lives.

## Libraries

Each library implements both ends: pairing, the Noise handshakes, framing, control
messages and relay failover. Each carries its own small Noise for the two patterns it
needs, with no Noise dependency, and every host is tested against every guest through
the relay. A guest can keep its private key in native code: the libraries only ask for
Diffie-Hellman results.

| Library | Install | Guide |
|---|---|---|
| Python | `pip install ./py` | [Python](python.html) |
| JavaScript | `npm install ./js` | [JavaScript](javascript.html) |
| Go | `go get github.com/syalia-srl/relay/go` | [Go](go.html) |

Each guide has a worked example: an echo host and a guest that pair through a relay
and exchange one message. The examples are real programs under `py/examples/`,
`js/examples/` and `go/examples/`, and CI runs all three against a built relay.

## The protocol and its tests

[PROTOCOL.md](protocol.html) is the normative specification of the relay API v1 and
the channel protocol v3. It defines the layers, the HTTP and WebSocket routes, the
pairing payload, both Noise handshakes, fragments, rekey, relay choice and control
messages. Section 10 lists what every host application must do outside the encrypted
stream.

Implementations that do not share this code can check themselves against the JSON test
vectors in `vectors/` and the black-box conformance suite in `conformance/`. The
vectors pin bytes and pure functions; the conformance suite starts a relay and covers
the v0 behaviour and every v1 rule. Both are in the
[repository](https://github.com/syalia-srl/relay).

## Security

[SECURITY.md](security.html) lists what the code promises, the adversaries it
considers, what it does not do, and how AInBox meets the host application's part. A
weakness is reported privately through the repository's Security tab.
