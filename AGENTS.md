# AGENTS.md — inbox-relay

Dumb E2E-encrypted message relay for AInBox Mobile.

## What it is

FastAPI service at `relay.syalia.dev:8010`. Creates channels (two-slot
WebSocket pipes), forwards encrypted binary frames between slots, emits
presence system events on connect/disconnect.

## Stack

Python 3.12 + FastAPI + uvicorn. No database — in-memory channel store.

## Run

    uv run uvicorn inbox_relay.main:app --host 0.0.0.0 --port 8010

## Design

`docs/2026-07-05-ainbox-mobile-relay-design.md` in `repos/ainbox`.
