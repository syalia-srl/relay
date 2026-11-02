# tests/test_hardening.py — the gates from the remote-access security review (ainbox #315).
#
# Each one was red on the relay as it was (in-memory store, accept before the
# token check, the last socket out clears the slot, unlimited creation).
import asyncio
import json
import os
import socket
import threading
import time

import pytest
import uvicorn
import websockets
from fastapi.testclient import TestClient

from inbox_relay import router as relay_router
from inbox_relay.channels import IDLE_TTL, UNCLAIMED_TTL, ChannelStore
from inbox_relay.main import app


@pytest.fixture
def live_relay():
    """The real app on a real port, so clients see real handshakes."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    yield f"127.0.0.1:{port}"
    server.should_exit = True
    thread.join(5)


def test_channels_survive_a_restart(tmp_path):
    path = str(tmp_path / "channels.json")
    ch = ChannelStore(path).create()
    after = ChannelStore(path)  # a new process reading the same volume
    found = after.get_by_token(ch.token_bridge)
    assert found is not None and found[0].channel_id == ch.channel_id
    assert after.get_by_token(ch.token_mobile)[1] == "mobile"


def test_the_store_file_holds_no_token(tmp_path):
    path = str(tmp_path / "channels.json")
    ch = ChannelStore(path).create()
    raw = open(path).read()
    assert ch.token_bridge not in raw and ch.token_mobile not in raw
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"


async def test_wrong_token_is_refused_before_the_handshake(live_relay):
    ch = TestClient(app).post("/channels").json()
    with pytest.raises(websockets.InvalidStatus) as refused:
        async with websockets.connect(f"ws://{live_relay}/ws/{ch['channel_id']}?token=wrong"):
            pass
    assert refused.value.response.status_code == 403


async def test_a_replaced_socket_leaving_late_does_not_orphan_the_new_one(live_relay):
    ch = TestClient(app).post("/channels").json()
    url = lambda side: f"ws://{live_relay}/ws/{ch['channel_id']}?token={ch['token_' + side]}"
    async with websockets.connect(url("bridge")) as bridge:
        old = await websockets.connect(url("mobile"))
        new = await websockets.connect(url("mobile"))
        await asyncio.sleep(0.2)
        await old.close()
        await asyncio.sleep(0.2)
        await bridge.send(b"\x01" + b"z" * 40)
        got = None
        while got is None:
            frame = await asyncio.wait_for(new.recv(), 2.0)
            if frame[:1] == b"\x01":
                got = frame
        assert got == b"\x01" + b"z" * 40
        await new.close()


def test_gc_drops_unscanned_and_abandoned_channels_only(tmp_path):
    store = ChannelStore(str(tmp_path / "c.json"))
    now = time.time()
    unscanned, fresh, paired_idle, paired_live = (store.create() for _ in range(4))
    unscanned.created_at = now - UNCLAIMED_TTL - 1
    paired_idle.mobile_seen = True
    paired_idle.last_seen = now - IDLE_TTL - 1
    paired_live.mobile_seen = True
    paired_live.created_at = paired_live.last_seen = now - IDLE_TTL - 1
    paired_live.ws_bridge = object()  # connected: never collected
    assert store.gc(now) == 2
    assert store.get(unscanned.channel_id) is None and store.get(paired_idle.channel_id) is None
    assert store.get(fresh.channel_id) and store.get(paired_live.channel_id)


def test_anonymous_creation_is_rate_limited(monkeypatch):
    monkeypatch.setattr(relay_router, "create_bucket", relay_router.Bucket(5, 0.0))
    client = TestClient(app)
    codes = [client.post("/channels").status_code for _ in range(8)]
    assert codes.count(200) == 5 and codes.count(429) == 3, json.dumps(codes)


def test_logs_never_carry_a_slot_token(caplog):
    import logging
    import inbox_relay.main  # noqa: F401  (installs the filter)
    secret = "ab" * 32
    logger = logging.getLogger("uvicorn.error")
    with caplog.at_level(logging.INFO, logger="uvicorn.error"):
        logger.propagate, was = True, logger.propagate
        try:
            logger.info('%s - "WebSocket %s" [accepted]', "127.0.0.1:1", f"/ws/c?token={secret}")
        finally:
            logger.propagate = was
    assert caplog.records and secret not in caplog.text
