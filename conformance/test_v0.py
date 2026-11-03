"""v0, kept unchanged for one migration release: the API phones still use."""

import asyncio
import json
import os
import stat
import time

import httpx
import pytest
from websockets.exceptions import InvalidStatus

from relaytest import expect_close, recv, ws_connect


def test_creation_returns_a_two_slot_channel(relay):
    channel = relay.create_v0()
    assert len(channel["channel_id"]) == 64
    assert len(channel["token_mobile"]) == 64
    assert len(channel["token_bridge"]) == 64
    assert int(channel["channel_id"], 16) >= 0


async def test_a_restarted_relay_still_opens_the_socket(relay):
    channel = relay.create_v0()
    relay.restart()
    async with ws_connect(
        relay, f"/ws/{channel['channel_id']}?token={channel['token_bridge']}"
    ):
        pass


def test_the_store_file_holds_no_token_and_is_private(relay):
    channel = relay.create_v0()
    raw = relay.state_path.read_text()
    assert channel["token_mobile"] not in raw
    assert channel["token_bridge"] not in raw
    mode = stat.S_IMODE(os.stat(relay.state_path).st_mode)
    assert mode == 0o600


async def test_a_foreign_origin_is_allowed(relay):
    # v0 has no auth frame, but browsers still send Origin and the upgrade
    # must succeed for the same reason as v1: no ambient credential exists.
    channel = relay.create_v0()
    async with ws_connect(
        relay,
        f"/ws/{channel['channel_id']}?token={channel['token_mobile']}",
        origin="https://app.example",
    ):
        pass


async def test_a_wrong_token_is_refused_before_the_handshake(relay):
    channel = relay.create_v0()
    with pytest.raises(InvalidStatus) as refused:
        async with ws_connect(relay, f"/ws/{channel['channel_id']}?token=wrong"):
            pass
    assert refused.value.response.status_code == 403


async def test_a_missing_token_is_refused_before_the_handshake(relay):
    channel = relay.create_v0()
    with pytest.raises(InvalidStatus) as refused:
        async with ws_connect(relay, f"/ws/{channel['channel_id']}"):
            pass
    assert refused.value.response.status_code == 403


async def test_a_token_names_only_its_own_channel(relay):
    first = relay.create_v0()
    second = relay.create_v0()
    with pytest.raises(InvalidStatus):
        async with ws_connect(
            relay, f"/ws/{first['channel_id']}?token={second['token_mobile']}"
        ):
            pass


async def test_it_forwards_bytes_and_announces_the_peer(relay):
    channel = relay.create_v0()
    base = f"/ws/{channel['channel_id']}?token="
    async with ws_connect(relay, base + channel["token_bridge"]) as bridge:
        async with ws_connect(relay, base + channel["token_mobile"]) as mobile:
            event = json.loads((await recv(bridge))[1:])
            assert event["event"] == "peer_connected"
            await mobile.send(b"\x01hello encrypted")
            assert await recv(bridge) == b"\x01hello encrypted"


async def test_it_announces_a_disconnect(relay):
    channel = relay.create_v0()
    base = f"/ws/{channel['channel_id']}?token="
    async with ws_connect(relay, base + channel["token_bridge"]) as bridge:
        async with ws_connect(relay, base + channel["token_mobile"]):
            assert json.loads((await recv(bridge))[1:])["event"] == "peer_connected"
        assert json.loads((await recv(bridge))[1:])["event"] == "peer_disconnected"


async def test_a_newer_socket_replaces_the_older_one(relay):
    channel = relay.create_v0()
    base = f"/ws/{channel['channel_id']}?token="
    async with ws_connect(relay, base + channel["token_bridge"]) as bridge:
        async with ws_connect(relay, base + channel["token_mobile"]) as old:
            assert json.loads((await recv(bridge))[1:])["event"] == "peer_connected"
            async with ws_connect(relay, base + channel["token_mobile"]) as new:
                await expect_close(old, 4409)
                # The bridge hears the new socket, not the old one leaving.
                assert json.loads((await recv(bridge))[1:])["event"] == "peer_connected"
                assert json.loads((await recv(new))[1:])["event"] == "peer_connected"
                with pytest.raises(asyncio.TimeoutError):
                    await recv(bridge, 0.5)
                await bridge.send(b"\x01" + b"z" * 40)
                assert await recv(new) == b"\x01" + b"z" * 40


def test_anonymous_creation_is_rate_limited(make_relay):
    relay = make_relay(RELAY_CREATE_BURST="5", RELAY_CREATE_PER_MINUTE="0")
    codes = [httpx.post(relay.url("/channels")).status_code for _ in range(8)]
    assert codes.count(200) == 5
    assert codes.count(429) == 3


def test_creation_is_capped(make_relay):
    relay = make_relay(RELAY_MAX_CHANNELS="3")
    codes = [httpx.post(relay.url("/channels")).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 503]


async def test_the_sweep_forgets_old_channels_on_start(make_relay):
    relay = make_relay()
    unclaimed_channel = relay.create_v0()
    abandoned_channel = relay.create_v0()
    fresh_channel = relay.create_v0()
    relay.stop()

    data = json.loads(relay.state_path.read_text())
    now = time.time()
    for row in data["channels"]:
        if row["channel_id"] == unclaimed_channel["channel_id"]:
            row["created_at"] = row["last_seen"] = now - 3700
            row["mobile_seen"] = False
        elif row["channel_id"] == abandoned_channel["channel_id"]:
            row["created_at"] = row["last_seen"] = now - 31 * 24 * 3600
            row["mobile_seen"] = True
    relay.state_path.write_text(json.dumps(data))
    relay.start()

    for channel in (unclaimed_channel, abandoned_channel):
        with pytest.raises(InvalidStatus):
            async with ws_connect(
                relay, f"/ws/{channel['channel_id']}?token={channel['token_mobile']}"
            ):
                pass
    async with ws_connect(
        relay, f"/ws/{fresh_channel['channel_id']}?token={fresh_channel['token_mobile']}"
    ):
        pass


async def test_logs_never_carry_a_token(relay):
    channel = relay.create_v0()
    base = f"/ws/{channel['channel_id']}?token="
    async with ws_connect(relay, base + channel["token_mobile"]) as mobile:
        await mobile.send(b"\x01hello")
    relay.stop()
    logs = relay.logs()
    assert channel["token_mobile"] not in logs
    assert channel["token_bridge"] not in logs
    assert "token=" not in logs


def test_v0_can_be_switched_off(make_relay):
    relay = make_relay(RELAY_V0="off")
    assert httpx.post(relay.url("/channels")).status_code == 404
    assert httpx.get(relay.url("/ws/whatever"), headers={"Connection": "Upgrade"}).status_code == 404
    # v1 still works with v0 off.
    assert relay.channel_v1()["channel"]
