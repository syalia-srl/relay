"""Relay API v1: keys, quotas, the five-second auth handshake and close codes."""

import asyncio
import json
import signal
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus

from relaytest import (
    LOCAL_KEY,
    OPERATOR_KEY,
    close_code,
    expect_close,
    mint,
    read_event,
    recv,
    sha256_hex,
    v1_socket,
    ws_connect,
)


def test_no_key_is_401(relay):
    assert httpx.post(relay.url("/v1/channels")).status_code == 401
    assert httpx.post(
        relay.url("/v1/channels"), headers={"Authorization": "Basic abc"}
    ).status_code == 401


def test_an_unknown_key_is_401(relay):
    assert relay.create_v1("not-a-key").status_code == 401
    assert relay.create_v1("rt1.not.a.token").status_code == 401


def test_an_operator_key_creates_a_channel(relay):
    response = relay.create_v1(OPERATOR_KEY)
    assert response.status_code == 201
    body = response.json()
    assert len(body["channel"]) == 22
    assert len(body["host_token"]) == 43
    assert len(body["guest_token"]) == 43
    assert body["host_token"] != body["guest_token"]


def test_a_key_without_limits_is_unlimited(make_relay):
    relay = make_relay()
    for _ in range(20):
        assert relay.create_v1(LOCAL_KEY).status_code == 201


def test_a_quota_of_zero_allows_nothing(relay):
    assert relay.create_v1(mint("frozen", channels=0)).status_code == 429
    assert relay.create_v1(mint("frozen", creates_per_minute=0)).status_code == 429


async def test_a_bytes_per_day_of_zero_refuses_auth(relay):
    ch = relay.channel_v1(mint("mute", bytes_per_day=0))
    async with v1_socket(relay, ch["channel"], ch["host_token"]) as ws:
        await expect_close(ws, 4429)


def test_a_relay_token_creates_a_channel(relay):
    assert relay.create_v1(mint("holder-1")).status_code == 201


def test_an_expired_relay_token_is_401(relay):
    assert relay.create_v1(mint("holder-1", exp=int(time.time()) - 1)).status_code == 401


def test_a_relay_token_for_another_relay_is_401(relay):
    assert relay.create_v1(mint("holder-1", aud="another.relay")).status_code == 401


def test_a_relay_token_signed_by_another_key_is_401(relay):
    other = Ed25519PrivateKey.generate()
    assert relay.create_v1(mint("holder-1", key=other)).status_code == 401


def test_a_token_over_4096_bytes_is_401(relay):
    payload = json.dumps(
        {
            "iss": "test-issuer",
            "aud": "relay.test",
            "sub": "holder-1",
            "exp": int(time.time()) + 3600,
            "channels": 1,
            "creates_per_minute": 1,
            "bytes_per_day": 1,
            "pad": "p" * 5000,
        }
    ).encode()
    assert relay.create_v1(mint("holder-1", payload=payload)).status_code == 401


def test_sighup_reloads_the_keys_file(relay):
    added = "key-added-by-reload"
    assert relay.create_v1(added).status_code == 401
    keys = json.loads(relay.keys_path.read_text())
    keys["keys"].append(
        {
            "id": "added",
            "sha256": sha256_hex(added),
            "channels": 1,
            "creates_per_minute": 1,
            "bytes_per_day": 1,
        }
    )
    relay.keys_path.write_text(json.dumps(keys))
    relay.proc.send_signal(signal.SIGHUP)
    deadline = time.monotonic() + 5
    while relay.create_v1(added).status_code != 201:
        assert time.monotonic() < deadline, "the reload never happened"
        time.sleep(0.05)


def test_the_key_comes_before_quota_and_capacity(make_relay):
    relay = make_relay(RELAY_MAX_CHANNELS="2")
    assert relay.create_v1("unknown").status_code == 401
    assert relay.create_v1(OPERATOR_KEY).status_code == 201
    token = mint("holder-order", channels=1, creates_per_minute=10)
    assert relay.create_v1(token).status_code == 201
    # The relay is full, but this holder's own quota is what refuses it.
    assert relay.create_v1(token).status_code == 429
    assert relay.create_v1(OPERATOR_KEY).status_code == 503


def test_the_channels_quota_is_429(relay):
    token = mint("holder-channels", channels=1, creates_per_minute=100)
    assert relay.create_v1(token).status_code == 201
    assert relay.create_v1(token).status_code == 429


def test_the_creates_per_minute_quota_is_429(relay):
    token = mint("holder-rate", channels=100, creates_per_minute=1)
    assert relay.create_v1(token).status_code == 201
    refused = relay.create_v1(token)
    assert refused.status_code == 429
    assert 1 <= int(refused.headers["retry-after"]) <= 60


async def test_an_unknown_channel_is_4401(relay):
    async with v1_socket(relay, "a" * 22, mint("holder-1")) as websocket:
        await expect_close(websocket, 4401)


async def test_a_wrong_token_is_4401(relay):
    channel = relay.channel_v1()
    async with v1_socket(relay, channel["channel"], mint("holder-1")) as websocket:
        await expect_close(websocket, 4401)


async def test_a_token_for_another_channel_is_4401(relay):
    first = relay.channel_v1()
    second = relay.channel_v1()
    async with v1_socket(relay, first["channel"], second["host_token"]) as websocket:
        await expect_close(websocket, 4401)


async def test_pending_auth_sockets_are_capped(make_relay):
    relay = make_relay(RELAY_MAX_PENDING_AUTH="2")
    channel = relay.channel_v1()
    path = f"/v1/ws/{channel['channel']}"
    idle = [await connect(relay.ws_url(path), max_size=None) for _ in range(2)]
    try:
        with pytest.raises(InvalidStatus) as refused:
            await connect(relay.ws_url(path), max_size=None)
        assert refused.value.response.status_code == 503
    finally:
        for websocket in idle:
            await websocket.close()
    # Leaving an idle socket releases its slot, so a new upgrade is accepted.
    deadline = time.monotonic() + 5
    while True:
        try:
            async with connect(relay.ws_url(path), max_size=None) as websocket:
                await websocket.send(json.dumps({"auth": channel["host_token"]}))
                assert await read_event(websocket) == "ready"
            return
        except (InvalidStatus, OSError):
            assert time.monotonic() < deadline, "the pending-auth counter never released"
            await asyncio.sleep(0.05)


async def test_a_late_auth_is_4401(relay):
    channel = relay.channel_v1()
    async with v1_socket(relay, channel["channel"]) as websocket:
        await asyncio.sleep(5.5)
        with pytest.raises(Exception) as closed:
            await websocket.send(json.dumps({"auth": channel["host_token"]}))
            await recv(websocket)
        assert close_code(closed.value) == 4401


async def test_a_malformed_auth_is_4401(relay):
    channel = relay.channel_v1()
    for first in (
        b"not json at all",
        b'{"auth": 5}',
        b'{"no_auth": true}',
        b'{"auth": "' + channel["host_token"].encode() + b'"} trailing',
    ):
        async with v1_socket(relay, channel["channel"]) as websocket:
            await websocket.send(first.decode())
            await expect_close(websocket, 4401)
    async with v1_socket(relay, channel["channel"]) as websocket:
        await websocket.send(b"\x01binary")
        await expect_close(websocket, 4401)


async def test_a_foreign_origin_is_allowed(relay):
    # A browser or WebView always sends Origin. Authentication is the bearer
    # token in the first frame, never a cookie, so the upgrade must not be
    # refused for a cross-site origin.
    channel = relay.channel_v1()
    async with ws_connect(
        relay, f"/v1/ws/{channel['channel']}", origin="https://app.example"
    ) as websocket:
        await websocket.send(json.dumps({"auth": channel["host_token"]}))
        assert await read_event(websocket) == "ready"


async def test_ready_comes_before_peer_connected(relay):
    channel = relay.channel_v1()
    async with v1_socket(relay, channel["channel"], channel["host_token"]) as host:
        assert await read_event(host) == "ready"
        async with v1_socket(
            relay, channel["channel"], channel["guest_token"]
        ) as guest:
            assert await read_event(guest) == "ready"
            assert await read_event(guest) == "peer_connected"
            assert await read_event(host) == "peer_connected"


async def test_a_text_frame_after_auth_is_4400(relay):
    channel = relay.channel_v1()
    async with v1_socket(relay, channel["channel"], channel["host_token"]) as host:
        assert await read_event(host) == "ready"
        await host.send("hello")
        await expect_close(host, 4400)


async def test_a_client_frame_that_is_not_data_is_4400(relay):
    channel = relay.channel_v1()
    async with v1_socket(relay, channel["channel"], channel["host_token"]) as host:
        assert await read_event(host) == "ready"
        await host.send(b"\x02not data")
        await expect_close(host, 4400)


async def test_a_frame_body_over_one_mib_is_4413(relay):
    channel = relay.channel_v1()
    async with v1_socket(relay, channel["channel"], channel["host_token"]) as host:
        assert await read_event(host) == "ready"
        await host.send(b"\x01" + b"x" * (1 << 20 + 1))
        await expect_close(host, 4413)


async def test_it_forwards_a_frame_byte_for_byte(relay):
    channel = relay.channel_v1()
    payload = b"\x01" + bytes(range(256)) * 8
    async with v1_socket(relay, channel["channel"], channel["host_token"]) as host:
        assert await read_event(host) == "ready"
        async with v1_socket(
            relay, channel["channel"], channel["guest_token"]
        ) as guest:
            assert await read_event(guest) == "ready"
            assert await read_event(guest) == "peer_connected"
            assert await read_event(host) == "peer_connected"
            await host.send(payload)
            assert await recv(guest) == payload
            reply = b"\x01hello back"
            await guest.send(reply)
            assert await recv(host) == reply


async def test_a_frame_for_an_absent_peer_is_dropped(relay):
    channel = relay.channel_v1()
    async with v1_socket(relay, channel["channel"], channel["host_token"]) as host:
        assert await read_event(host) == "ready"
        await host.send(b"\x01while nobody listens")
        async with v1_socket(
            relay, channel["channel"], channel["guest_token"]
        ) as guest:
            assert await read_event(guest) == "ready"
            assert await read_event(guest) == "peer_connected"
            with pytest.raises(asyncio.TimeoutError):
                await recv(guest, 0.5)


async def test_a_newer_socket_sends_replaced_and_closes_4409(relay):
    channel = relay.channel_v1()
    async with v1_socket(relay, channel["channel"], channel["host_token"]) as old:
        assert await read_event(old) == "ready"
        async with v1_socket(relay, channel["channel"], channel["host_token"]) as new:
            assert await read_event(old) == "replaced"
            await expect_close(old, 4409)
            assert await read_event(new) == "ready"


async def test_a_replaced_socket_leaving_late_says_nothing(relay):
    channel = relay.channel_v1()
    async with v1_socket(relay, channel["channel"], channel["guest_token"]) as guest:
        assert await read_event(guest) == "ready"
        async with v1_socket(relay, channel["channel"], channel["host_token"]) as old:
            assert await read_event(old) == "ready"
            assert await read_event(old) == "peer_connected"
            assert await read_event(guest) == "peer_connected"
            async with v1_socket(relay, channel["channel"], channel["host_token"]) as new:
                assert await read_event(old) == "replaced"
                await expect_close(old, 4409)
                assert await read_event(new) == "ready"
                assert await read_event(new) == "peer_connected"
                assert await read_event(guest) == "peer_connected"
                with pytest.raises(asyncio.TimeoutError):
                    await read_event(guest, 0.5)
                await guest.send(b"\x01" + b"z" * 40)
                assert await recv(new) == b"\x01" + b"z" * 40


async def test_delete_closes_both_sockets_with_4410(relay):
    channel = relay.channel_v1()
    async with v1_socket(relay, channel["channel"], channel["host_token"]) as host:
        assert await read_event(host) == "ready"
        async with v1_socket(
            relay, channel["channel"], channel["guest_token"]
        ) as guest:
            assert await read_event(guest) == "ready"
            assert await read_event(guest) == "peer_connected"
            response = httpx.delete(
                relay.url(f"/v1/channels/{channel['channel']}"),
                headers={"Authorization": f"Bearer {channel['host_token']}"},
            )
            assert response.status_code == 204
            await expect_close(host, 4410)
            await expect_close(guest, 4410)


def test_only_the_host_token_deletes(relay):
    channel = relay.channel_v1()
    url = relay.url(f"/v1/channels/{channel['channel']}")
    assert httpx.delete(
        url, headers={"Authorization": f"Bearer {channel['guest_token']}"}
    ).status_code == 404
    assert httpx.delete(
        url, headers={"Authorization": f"Bearer {mint('holder-1')}"}
    ).status_code == 404
    assert httpx.delete(relay.url("/v1/channels/unknown")).status_code == 404
    assert httpx.delete(
        url, headers={"Authorization": f"Bearer {channel['host_token']}"}
    ).status_code == 204
    assert httpx.delete(
        url, headers={"Authorization": f"Bearer {channel['host_token']}"}
    ).status_code == 404


async def test_bytes_per_day_closes_with_4429_and_refuses_auth(relay):
    token = mint("holder-bytes", channels=10, creates_per_minute=10, bytes_per_day=10)
    channel = relay.channel_v1(token)
    async with v1_socket(relay, channel["channel"], channel["host_token"]) as host:
        assert await read_event(host) == "ready"
        async with v1_socket(
            relay, channel["channel"], channel["guest_token"]
        ) as guest:
            assert await read_event(guest) == "ready"
            assert await read_event(guest) == "peer_connected"
            assert await read_event(host) == "peer_connected"
            # Eleven bytes forwarded, one over the ten allowed.
            frame = b"\x01" + b"x" * 10
            await host.send(frame)
            assert await recv(guest) == frame
            await expect_close(guest, 4429)
            await expect_close(host, 4429)
    # A wrong token is still 4401: authentication comes before quota.
    async with v1_socket(relay, channel["channel"], "wrong-token") as bad:
        await expect_close(bad, 4401)
    async with v1_socket(relay, channel["channel"], channel["host_token"]) as over:
        await expect_close(over, 4429)


async def test_a_v1_channel_survives_a_restart(relay):
    channel = relay.channel_v1()
    relay.restart()
    async with v1_socket(relay, channel["channel"], channel["host_token"]) as host:
        assert await read_event(host) == "ready"
