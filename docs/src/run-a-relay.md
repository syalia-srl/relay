# Running a relay

A relay is the Go service in `server/`: it creates channels, joins their two
WebSocket sides and forwards binary frames between them without reading them. The
channel protocol and the relay API are in [PROTOCOL.md](protocol.html). This page
covers one Linux host, one static binary, a systemd unit and a TLS reverse proxy.

The relay holds no plaintext and no keys of its own. Its configuration decides which
project keys may create channels and how much each one may use.

## What the host needs

| Item | Value |
|---|---|
| Operating system | Linux with systemd |
| Go, to build | 1.27 or later |
| Binary | `server/relay`, static (`CGO_ENABLED=0`) |
| Public name | A DNS name whose A or AAAA record points at the host, for example `relay.example.com` |
| Ports | 443 open; the relay itself listens on loopback only |
| Directories | `/srv/relay` for the binary, `/etc/relay` for keys, `/var/lib/relay` for state |

The relay needs no database and no runtime dependency beyond the kernel. It reaches
the network only through the reverse proxy.

## Build the binary

The build produces one static executable:

```bash
git clone https://github.com/syalia-srl/relay
cd relay/server
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o relay ./cmd/relay
```

`ldd relay` answers `not a dynamic executable`. The binary runs on a host without a
Go toolchain.

A local run needs no installation. The three settings below are the whole
configuration; the paths are the ones the unit uses:

```bash
RELAY_ADDR=127.0.0.1:8010 \
RELAY_STATE_PATH=/var/lib/relay/channels.json \
RELAY_KEYS_PATH=/etc/relay/keys.json \
./relay
```

`RELAY_ADDR` defaults to `127.0.0.1:8010`. `RELAY_STATE_PATH` defaults to
`/data/channels.json`, which suits the container. `RELAY_KEYS_PATH` has no default:
without it the relay refuses every v1 key.

The rest of this page uses `/srv/relay/relay` for the binary and a throwaway
directory for the first checks.

## Project keys and `keys.json`

A project key is any bearer string that does not start with `rt1.`. Its SHA-256
digest, in lowercase hex, is what the relay stores. The key itself is drawn once and
kept by the application that creates channels.

```bash
umask 077
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > project.key
DIGEST=$(printf '%s' "$(cat project.key)" | sha256sum | cut -d' ' -f1)
```

`$DIGEST` is 64 hex characters. It goes into the `sha256` field. The file holds
digests, never keys, so a copy of it does not let anyone create channels.

```bash
cat > keys.json <<EOF
{
  "relay_id": "relay.example.com",
  "issuers": {},
  "keys": [
    {"id": "ainbox", "sha256": "$DIGEST", "channels": 200,
     "creates_per_minute": 20, "bytes_per_day": 2000000000}
  ]
}
EOF
```

The complete shape, with a second key that has no limits:

```json
{
  "relay_id": "relay.example.com",
  "issuers": {},
  "keys": [
    {
      "id": "ainbox",
      "sha256": "6f0a...e21c",
      "channels": 200,
      "creates_per_minute": 20,
      "bytes_per_day": 2000000000
    },
    {
      "id": "local",
      "sha256": "a41d...78be",
      "unlimited": true
    }
  ]
}
```

- `relay_id` is this relay's name. A signed relay token is valid only on the relay
  its `aud` field names, so two relays that trust one issuer need different ids.
- `keys` lists the operator keys. `channels` caps live channels created with the
  key, `creates_per_minute` caps creations in any 60-second window, and
  `bytes_per_day` caps forwarded data bytes since 00:00 UTC. A limit of `0` allows
  nothing; only `"unlimited": true` lifts the limits, for a relay an install runs
  for itself.
- `issuers` maps an issuer id to its Ed25519 public key, 64 hex characters. A relay
  token has the form `rt1.<payload>.<signature>`; its payload carries `iss`, `aud`,
  `sub`, `exp` and the three quota numbers. The relay accepts a token signed by a
  listed issuer, addressed to its own `relay_id`, and not expired. An issuer hands
  out short-lived tokens; revocation is expiry.
- A missing or unreadable file is not fatal: the relay logs it and refuses every v1
  key, which is the safe default.

`SIGHUP` re-reads the file. A file that does not parse keeps the keys already in
memory, so a bad edit does not stop a serving relay.

## Install the service

The unit in `deploy/relay.service` runs the binary as an unprivileged user, with a
private state directory and a read-only view of the system:

```ini
[Unit]
Description=relay — E2E message relay
After=network.target

[Service]
Type=simple
User=relay
Group=relay
ExecStart=/srv/relay/relay
Environment=RELAY_ADDR=127.0.0.1:8010
StateDirectory=relay
StateDirectoryMode=0700
Environment=RELAY_STATE_PATH=/var/lib/relay/channels.json
Environment=RELAY_KEYS_PATH=/etc/relay/keys.json
Restart=on-failure
RestartSec=5

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=
LockPersonality=yes
MemoryDenyWriteExecute=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
```

The account, directories and unit are installed with:

```bash
sudo useradd --system --no-create-home --home-dir /var/lib/relay \
    --shell /usr/sbin/nologin relay
sudo install -d -m 0755 /srv/relay
sudo install -d -m 0750 -o root -g relay /etc/relay
sudo install -m 0755 relay /srv/relay/relay
sudo install -m 0640 -o root -g relay keys.json /etc/relay/keys.json
sudo install -m 0644 deploy/relay.service /etc/systemd/system/relay.service
sudo systemctl daemon-reload
sudo systemctl enable --now relay
```

`StateDirectory=relay` makes systemd create `/var/lib/relay` owned by `relay` at
mode `0700` on every start. `ProtectSystem=strict` makes the filesystem read-only for
the service apart from the state directory and its private temporary directory. The
keys file is readable by the service group and by nothing else.

`systemctl status relay` shows the last log lines. `journalctl -u relay` shows all of
them. A log line names at most the first eight characters of a channel id, and never
a token.

## TLS with Caddy

The relay speaks plain HTTP and WebSocket on loopback. A reverse proxy terminates TLS
and forwards both. With Caddy, the whole configuration is:

```caddyfile
relay.example.com {
	reverse_proxy 127.0.0.1:8010
}
```

Caddy obtains and renews a certificate for the name once the DNS record points at
the host, and proxies WebSocket upgrades without further settings. Guests use
`wss://relay.example.com` as the base URL; the relay's routes are relative to it.

Guests accept a plain `ws://` URL only when its host is a literal private address
(PROTOCOL.md 8.1). A public name is always `wss://`.

## Checks that it works

The responses below prove the key file and the routes. The relay is started from the
checkout on a local port with a state directory of its own:

```bash
umask 077
mkdir -p state
RELAY_ADDR=127.0.0.1:8010 \
RELAY_STATE_PATH="$PWD/state/channels.json" \
RELAY_KEYS_PATH="$PWD/keys.json" \
./relay &
```

The base URL and the key are held in two shell variables. The root answers 404
because the relay serves no page there:

```bash
RELAY=http://127.0.0.1:8010
KEY=$(cat project.key)
curl -sS -o /dev/null -w '%{http_code}\n' "$RELAY/"
```

`401` is the answer without a key and with an unknown key. `429` is the answer for a
known key at its channel or creation limit, including a key whose quota is `0`:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$RELAY/v1/channels"
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
    -H 'Authorization: Bearer not-a-key' "$RELAY/v1/channels"
```

`201` with the key, and the body carries one channel id and two tokens:

```bash
curl -sS -o channel.json -w '%{http_code}\n' -X POST \
    -H "Authorization: Bearer $KEY" "$RELAY/v1/channels"
CHANNEL=$(python3 -c 'import json; print(json.load(open("channel.json"))["channel"])')
HOST_TOKEN=$(python3 -c 'import json; print(json.load(open("channel.json"))["host_token"])')
```

The host token deletes the channel; the same request again answers 404:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X DELETE \
    -H "Authorization: Bearer $HOST_TOKEN" "$RELAY/v1/channels/$CHANNEL"
```

Behind the proxy the same requests use `RELAY=https://relay.example.com`. A
`201` there also proves the certificate, the proxy and the relay's routes together.

The libraries' worked examples exercise the WebSocket side end to end: a host creates
channels with the key, a guest pairs through the relay, and one message travels each
way. They run with the relay's URL and key in the environment; the
[Python](python.html), [JavaScript](javascript.html) and [Go](go.html) pages carry
them.

## State, restarts and upgrades

The relay's only state is `channels.json` in the state directory, at mode `0600`. It
holds each channel id, the creation and last-seen times, the digest of each side
token, and the identifier of the key the channel was created with. It never holds a
token. A copy of the file does not let anyone join a channel.

The store is written on creation, deletion and shutdown. A restart keeps every
channel: the tokens still authenticate because only their digests are needed. Losing
the file loses every pairing; the devices pair again. A state path the service cannot
write makes the relay log `channel store not writable`, keep channels in memory and
lose them on the next restart.

An upgrade is a new binary and a restart:

```bash
cd relay/server
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o relay ./cmd/relay
sudo install -m 0755 relay /srv/relay/relay
sudo systemctl restart relay
```

`SIGTERM` closes open sockets with code 1001 and saves the store before the process
exits; `systemctl restart` sends it. The unit's `Restart=on-failure` covers a crash.

Keys are reloaded without a restart:

```bash
sudo systemctl kill --signal=HUP relay
```

A new key, a changed quota or a new issuer applies to the next request. The unit has
no `ExecReload`, so `systemctl reload` is not the command; `systemctl kill` with
`HUP` sends the signal.

The channel store prunes itself: a channel whose guest never authenticated leaves
after one hour, and a channel with no authenticated socket leaves after 30 days.
`RELAY_MAX_CHANNELS` caps the store (default 50000). Anonymous v0 creation is rate
limited by `RELAY_CREATE_BURST` and `RELAY_CREATE_PER_MINUTE`; v0 exists for one
migration release and `RELAY_V0=off` turns it off.

## The container

`server/Dockerfile` builds the same binary into a scratch image. The image runs as
uid 65532, keeps its state in the `/data` volume and reads a keys file mounted from
the host:

```bash
docker build -t relay server/
docker run -d --name relay \
    -p 127.0.0.1:8010:8010 \
    -v relay-data:/data \
    -v /etc/relay/keys.json:/etc/relay/keys.json:ro \
    -e RELAY_KEYS_PATH=/etc/relay/keys.json \
    relay
```

The mounted keys file must be readable by uid 65532, and the proxy still points at
`127.0.0.1:8010`.
