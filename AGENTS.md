# AGENTS.md — inbox-relay

Dumb E2E-encrypted message relay for AInBox Mobile.

## What it is

FastAPI service behind `relay.syalia.dev` (port 8010 on its host). Creates channels (two-slot
WebSocket pipes), forwards encrypted binary frames between slots, emits
presence system events on connect/disconnect.

## Stack

Python 3.12 + FastAPI + uvicorn. No database: the channel store is one JSON file
(`RELAY_STATE_PATH`, default `/data/channels.json`) holding channel ids and the
SHA-256 of each slot token, never a token. `RELAY_STATE_PATH` must point at a
directory the service can write, or the relay logs "channel store not writable",
keeps channels in memory only, and every paired phone dies on the next restart.

## Rules

- A wrong slot token is refused before the WebSocket handshake (HTTP 403).
- A newer socket on a slot replaces the older one (closed 4409); only the socket
  that holds the slot frees it.
- Channel creation is anonymous, so it is rate limited (`RELAY_CREATE_BURST`,
  `RELAY_CREATE_PER_MINUTE`) and capped (`RELAY_MAX_CHANNELS`). Unscanned channels
  leave after an hour, abandoned ones after 30 days with no socket.
- No log line carries a slot token (uvicorn's request lines are redacted).

## Run

    uv run uvicorn inbox_relay.main:app --host 0.0.0.0 --port 8010 --no-access-log

## Deploy

`relay.syalia.dev` is a systemd unit, not a container: `deploy/inbox-relay.service`
is the unit as installed at `/etc/systemd/system/inbox-relay.service`. It runs a
git checkout at `/srv/inbox-relay` behind the host's caddy on 127.0.0.1:8010,
with its state in `/srv/inbox-relay-data` (0700, outside the checkout).

    git -C /srv/inbox-relay pull && (cd /srv/inbox-relay && uv sync)
    sudo systemctl daemon-reload && sudo systemctl restart inbox-relay

Check that a restart keeps channels: `channels.json` exists in the state directory
at 0600 and survives a second restart. The `Dockerfile` is the same service for a
container host, with `/data` as the volume.

Tests: `uv run pytest -q`.

## Design

`docs/2026-07-05-ainbox-mobile-relay-design.md` in `repos/ainbox`.
