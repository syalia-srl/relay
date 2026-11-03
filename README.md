# Relay

An end-to-end encrypted channel between an app and the server it belongs to, through
relays that cannot read it. Two ends pair once with a QR code; after that the phone
reaches its server from anywhere, and the relay in between carries only ciphertext.

Documentation: <https://relay.syalia.com>

## What is here

| Path | What it holds |
|---|---|
| [`PROTOCOL.md`](PROTOCOL.md) | The protocol, precise enough to reimplement |
| [`SECURITY.md`](SECURITY.md) | The threat model, and how to report a vulnerability |
| [`server/`](server) | The relay: one static Go binary, and its Dockerfile |
| [`py/`](py), [`js/`](js), [`go/`](go) | The libraries, each with the host and the guest side |
| [`vectors/`](vectors) | Test vectors every library passes |
| [`conformance/`](conformance) | A black-box suite for any relay implementation |
| [`deploy/`](deploy) | The systemd unit for the relay |
| [`docs/`](docs) | The documentation site, built from Markdown |

Each library has an `API.md` that fixes its public API, and an `examples/` directory
with an echo host and guest that CI runs against the relay. CI also runs every pair of
host and guest across the three languages.

## Run a relay

```bash
cd server && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o relay ./cmd/relay
```

The guide at <https://relay.syalia.com/run-a-relay.html> covers keys, systemd, a TLS
proxy and Docker.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
