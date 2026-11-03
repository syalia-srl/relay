"""Small helpers the end-to-end and hostile-relay tests share."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress

from relay import RelayError


class HostInbox:
    """Collects what ``async for device, message in host`` yields."""

    def __init__(self, host) -> None:
        self.messages: list[tuple[str, bytes]] = []
        self._task = asyncio.create_task(self._collect(host))

    async def _collect(self, host) -> None:
        async for device, message in host:
            self.messages.append((device.id, message))

    async def stop(self) -> None:
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task

    def has(self, message: bytes) -> bool:
        return any(received == message for _, received in self.messages)


class GuestInbox:
    """Collects what ``async for message in host`` yields."""

    def __init__(self, link) -> None:
        self.messages: list[bytes] = []
        self._task = asyncio.create_task(self._collect(link))

    async def _collect(self, link) -> None:
        async for message in link:
            self.messages.append(message)

    async def stop(self) -> None:
        self._task.cancel()
        with suppress(asyncio.CancelledError):
            await self._task

    def has(self, message: bytes) -> bool:
        return message in self.messages


async def wait_until(predicate: Callable[[], bool], timeout: float = 10.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


async def send_until(
    send: Callable[[bytes], object],
    message: bytes,
    delivered: Callable[[], bool],
    timeout: float = 20.0,
) -> None:
    """Retry a send while the library reconnects, until the peer has it."""
    async with asyncio.timeout(timeout):
        while not delivered():
            try:
                await send(message)
            except RelayError:
                pass
            await asyncio.sleep(0.05)


async def unpair_all(guest) -> None:
    for link in guest.hosts:
        await link.unpair()
