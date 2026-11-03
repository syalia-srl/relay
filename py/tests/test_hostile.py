"""A hostile relay between the library and the real relay binary."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from pathlib import Path

import pytest
from hostile import HostileProxy
from relay import Guest, Host, Relay, RelayError
from relayfixture import OPERATOR_KEY
from support import GuestInbox, HostInbox, send_until, unpair_all, wait_until

FAULTS = ["drop", "duplicate", "reorder", "delay", "relabel", "flip"]


@pytest.mark.parametrize("action", FAULTS)
async def test_hostile_relay(relay, tmp_path: Path, action: str) -> None:
    proxy = HostileProxy(relay.address, relay.url, relay.loopback_http)
    await proxy.start()
    host = None
    guest = None
    try:
        host = await Host.open(str(tmp_path / "host"), relays=[Relay(proxy.url, key=OPERATOR_KEY)])
        pairing = await host.pair("pixel-7")
        guest = await Guest.open(str(tmp_path / "guest"))
        link = await asyncio.wait_for(guest.pair(pairing.payload), 10)
        device = await pairing.confirm(link.code)
        await asyncio.wait_for(link.bound(), 10)

        received, replies = HostInbox(host), GuestInbox(link)
        try:
            await link.send(b"sync")
            await wait_until(lambda: received.has(b"sync"))
            await device.send(b"sync")
            await wait_until(lambda: replies.has(b"sync"))

            proxy.arm("up", action)
            proxy.arm("down", action)
            for send, message in ((link.send, b"one"), (device.send, b"two")):
                try:
                    await send(message)
                except RelayError:
                    pass
            await send_until(link.send, b"after", lambda: received.has(b"after"), 30)
            await send_until(device.send, b"after", lambda: replies.has(b"after"), 30)

            sent = {b"sync", b"one", b"two", b"after"}
            assert all(message in sent for _, message in received.messages), received.messages
            assert all(message in sent for message in replies.messages), replies.messages
            assert received.has(b"after") and replies.has(b"after")
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
