# AGENTS.md — inbox-relay

Dumb E2E-encrypted message relay for AInBox Mobile.

## What it is

FastAPI service at `relay.syalia.dev:8010`. Creates channels (two-slot
WebSocket pipes), forwards encrypted binary frames between slots, emits
presence system events on connect/disconnect.

## Stack

Python 3.12 + FastAPI + uvicorn. No database: the channel store is one JSON file
(`RELAY_STATE_PATH`, default `/data/channels.json`) holding channel ids and the
SHA-256 of each slot token, never a token. Mount `/data` as a volume, or every
paired phone dies on the next restart.

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

Tests: `uv run pytest -q`.

## Design

`docs/2026-07-05-ainbox-mobile-relay-design.md` in `repos/ainbox`.
