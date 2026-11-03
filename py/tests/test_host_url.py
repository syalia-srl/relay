"""H1: the host may reach its relay by a URL different from the guests'."""

from __future__ import annotations

import asyncio
import json
from contextlib import suppress
from pathlib import Path

import pytest
from hostile import HostileProxy
from relay import Guest, Host, Relay
from relayfixture import OPERATOR_KEY
from support import GuestInbox, HostInbox, unpair_all, wait_until


def test_host_url_policy() -> None:
    with pytest.raises(ValueError):
        Relay("wss://relay.example", key="key", host_url="ws://relay.example")
    with pytest.raises(ValueError):
        Relay("wss://relay.example", key="key", host_url="ws://203.0.113.7")
    assert Relay("wss://relay.example", key="key", host_url="ws://relay:8010").host_url == "ws://relay:8010"
    assert Relay("wss://relay.example", key="key", host_url="ws://127.0.0.1:8010").host_url == "ws://127.0.0.1:8010"
    assert Relay("wss://relay.example", key="key").host_url == "wss://relay.example"


async def test_host_uses_its_own_relay_url(relay, tmp_path: Path) -> None:
    proxy = HostileProxy("127.0.0.1", relay.url, relay.loopback_http)
    await proxy.start()
    host = None
    guest = None
    try:
        host = await Host.open(
            str(tmp_path / "host"),
            relays=[Relay(relay.url, key=OPERATOR_KEY, host_url=proxy.url)],
        )
        pairing = await host.pair("pixel-7")
        assert proxy.http_requests > 0, "the host did not create its channel through its host URL"
        await wait_until(lambda: proxy.websockets > 0)

        payload = json.loads(pairing.payload)
        assert [entry["url"] for entry in payload["relays"]] == [relay.url]

        guest = await Guest.open(str(tmp_path / "guest"))
        link = await asyncio.wait_for(guest.pair(pairing.payload), 10)
        device = await asyncio.wait_for(pairing.confirm(link.code), 10)
        await asyncio.wait_for(link.bound(), 10)

        received, replies = HostInbox(host), GuestInbox(link)
        try:
            await link.send(b"ping")
            await wait_until(lambda: received.has(b"ping"))
            await device.send(b"pong")
            await wait_until(lambda: replies.has(b"pong"))
        finally:
            await received.stop()
            await replies.stop()
    finally:
        if guest is not None:
            with suppress(Exception):
                await asyncio.wait_for(unpair_all(guest), 20)
        if host is not None:
            await host.close()
        await proxy.stop()
