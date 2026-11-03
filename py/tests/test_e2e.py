"""A host and a guest through the real relay binary."""

from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path

import pytest
from relay import Guest, Host, PairingFailed, Relay, Revoked, WrongCode
from relayfixture import OPERATOR_KEY
from relayfixture import Relay as RelayProcess
from support import GuestInbox, HostInbox, send_until, unpair_all, wait_until


async def pair(relay, tmp_path: Path) -> tuple[Host, Guest, object, object]:
    """The pairing of API.md, with both sides already bound."""
    host = await Host.open(str(tmp_path / "host"), relays=[Relay(relay.url, key=OPERATOR_KEY)])
    pairing = await host.pair("pixel-7")
    guest = await Guest.open(str(tmp_path / "guest"))
    link = await asyncio.wait_for(guest.pair(pairing.payload), 10)
    assert link.code.isdigit() and len(link.code) == 6
    # A web application confirms in a later request, finding the pairing by id.
    device = await asyncio.wait_for(host.pairing(pairing.device).confirm(link.code), 10)
    await asyncio.wait_for(link.bound(), 10)
    return host, guest, device, link


async def test_pair_and_send_both_ways(relay, tmp_path: Path) -> None:
    host, guest, device, link = await pair(relay, tmp_path)
    received, replies = HostInbox(host), GuestInbox(link)
    try:
        assert device.connected
        await link.send(b"ping")
        await wait_until(lambda: received.messages == [(device.id, b"ping")])
        await device.send(b"pong")
        await wait_until(lambda: replies.messages == [b"pong"])

        big = bytes(index % 251 for index in range(200_000))
        await link.send(big)
        await wait_until(lambda: received.has(big), 20)
        await device.send(big)
        await wait_until(lambda: replies.has(big), 20)

        assert stat.S_IMODE(os.stat(tmp_path / "host").st_mode) == 0o600
        assert stat.S_IMODE(os.stat(tmp_path / "guest").st_mode) == 0o600
    finally:
        await received.stop()
        await replies.stop()
        await unpair_all(guest)
        await host.close()


async def test_restart_both_sides(relay, tmp_path: Path) -> None:
    host, guest, _, _ = await pair(relay, tmp_path)
    link = guest.hosts[0]
    received, replies = HostInbox(host), GuestInbox(link)
    await link.send(b"before")
    await wait_until(lambda: received.has(b"before"))
    await received.stop()
    await replies.stop()

    await host.close()
    await guest.close()

    host = await Host.open(str(tmp_path / "host"), relays=[Relay(relay.url, key=OPERATOR_KEY)])
    guest = await Guest.open(str(tmp_path / "guest"))
    try:
        assert [bound.name for bound in host.devices] == ["pixel-7"]
        assert len(guest.hosts) == 1
        link = guest.hosts[0]
        await asyncio.wait_for(link.bound(), 20)

        received, replies = HostInbox(host), GuestInbox(link)
        try:
            await link.send(b"after")
            await wait_until(lambda: received.has(b"after"), 20)
            await host.devices[0].send(b"back")
            await wait_until(lambda: replies.has(b"back"), 20)
        finally:
            await received.stop()
            await replies.stop()
    finally:
        await unpair_all(guest)
        await host.close()


async def test_revoke(relay, tmp_path: Path) -> None:
    host, guest, device, link = await pair(relay, tmp_path)
    try:
        messages = link.__aiter__()
        await host.revoke(device)
        with pytest.raises(Revoked):
            await asyncio.wait_for(anext(messages), 10)
        assert host.devices == []
        assert guest.hosts == []
    finally:
        await host.close()


async def test_unpair_forgets_both_sides(relay, tmp_path: Path) -> None:
    host, guest, _, _ = await pair(relay, tmp_path)
    await unpair_all(guest)
    await wait_until(lambda: host.devices == [])
    await host.close()

    host = await Host.open(str(tmp_path / "host"), relays=[Relay(relay.url, key=OPERATOR_KEY)])
    guest = await Guest.open(str(tmp_path / "guest"))
    try:
        assert host.devices == []
        assert guest.hosts == []
    finally:
        await host.close()


async def test_wrong_codes(relay, tmp_path: Path) -> None:
    host = await Host.open(str(tmp_path / "host"), relays=[Relay(relay.url, key=OPERATOR_KEY)])
    pairing = await host.pair("pixel-7")
    guest = await Guest.open(str(tmp_path / "guest"))
    try:
        link = await asyncio.wait_for(guest.pair(pairing.payload), 10)
        wrong = "000000" if link.code != "000000" else "111111"
        with pytest.raises(WrongCode) as error:
            await pairing.confirm("١٢٣٤٥٦")
        assert error.value.tries_left == 2
        with pytest.raises(WrongCode):
            await pairing.confirm(wrong)
        with pytest.raises(PairingFailed):
            await pairing.confirm(wrong)
        with pytest.raises(PairingFailed):
            host.pairing(pairing.device)
    finally:
        await guest.close()
        await host.close()


async def test_moves_to_the_second_relay(tmp_path: Path, relay_binary: str) -> None:
    first = RelayProcess(tmp_path / "first", relay_binary)
    second = RelayProcess(tmp_path / "second", relay_binary)
    try:
        host = await Host.open(
            str(tmp_path / "host"),
            relays=[Relay(first.url, key=OPERATOR_KEY), Relay(second.url, key=OPERATOR_KEY)],
        )
        pairing = await host.pair("pixel-7")
        guest = await Guest.open(str(tmp_path / "guest"))
        link = await asyncio.wait_for(guest.pair(pairing.payload), 10)
        device = await pairing.confirm(link.code)
        await asyncio.wait_for(link.bound(), 10)
        received, replies = HostInbox(host), GuestInbox(link)
        try:
            await link.send(b"on the first")
            await wait_until(lambda: received.has(b"on the first"))

            first.stop()
            await send_until(link.send, b"on the second", lambda: received.has(b"on the second"), 30)
            await device.send(b"back again")
            await wait_until(lambda: replies.has(b"back again"), 20)
        finally:
            await received.stop()
            await replies.stop()
            await unpair_all(guest)
            await host.close()
    finally:
        first.stop()
        second.stop()
