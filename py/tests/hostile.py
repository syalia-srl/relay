"""A relay proxy that can drop, duplicate, reorder, delay, relabel or flip frames."""

from __future__ import annotations

import asyncio
import urllib.error
import urllib.request
from collections import deque
from http import HTTPStatus

from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosed, WebSocketException
from websockets.http11 import Request, Response

HTTP_TIMEOUT = 10


class HostileProxy:
    """A WebSocket and HTTP relay in front of the real one, with armed faults.

    Each armed fault damages one data frame in its direction, on whichever of
    the two client sockets sends the next one. Everything else is forwarded.
    """

    def __init__(self, address: str, target: str, http_target: str):
        self.address = address
        self.target = target
        self.http_target = http_target
        self.port: int | None = None
        self._faults: dict[str, deque[tuple[str, float]]] = {"up": deque(), "down": deque()}
        self._server = None
        self._connections: set[object] = set()
        self.http_requests = 0
        self.websockets = 0

    @property
    def url(self) -> str:
        return f"ws://{self.address}:{self.port}"

    async def start(self) -> None:
        self._server = await serve(
            self._handler, self.address, 0, max_size=None, process_request=self._process_request
        )
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for connection in list(self._connections):
            await connection.close()

    def arm(self, direction: str, action: str, delay: float = 0.3) -> None:
        self._faults[direction].append((action, delay))

    async def _process_request(self, connection, request: Request) -> Response | None:
        if request.headers.get("Upgrade", "").lower() == "websocket":
            return None
        self.http_requests += 1
        status, body = await asyncio.to_thread(
            _forward, request.method, self.http_target + request.path, request.headers
        )
        return Response(status, HTTPStatus(status).phrase, Headers(), body)

    async def _handler(self, websocket) -> None:
        upstream = None
        pipes: list[asyncio.Task] = []
        try:
            upstream = await connect(self.target + websocket.request.path, max_size=None)
            self.websockets += 1
            self._connections.update((websocket, upstream))
            pipes = [
                asyncio.create_task(self._pipe(websocket, upstream, "up")),
                asyncio.create_task(self._pipe(upstream, websocket, "down")),
            ]
            await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
        except (WebSocketException, OSError):
            pass
        finally:
            for pipe in pipes:
                pipe.cancel()
            await asyncio.gather(*pipes, return_exceptions=True)
            self._connections.discard(websocket)
            self._connections.discard(upstream)
            if upstream is not None:
                await upstream.close()
            await websocket.close()

    async def _pipe(self, source, destination, direction: str) -> None:
        held: bytes | None = None
        try:
            while True:
                message = await source.recv()
                if isinstance(message, str) or not message or message[:1] != b"\x01":
                    await destination.send(message)
                    continue
                if held is not None:
                    current, held = held, None
                    await destination.send(message)
                    await destination.send(current)
                    continue
                fault = self._faults[direction].popleft() if self._faults[direction] else None
                if fault is None:
                    await destination.send(message)
                    continue
                action, delay = fault
                if action == "drop":
                    continue
                if action == "duplicate":
                    await destination.send(message)
                    await destination.send(message)
                elif action == "reorder":
                    held = message
                elif action == "delay":
                    await asyncio.sleep(delay)
                    await destination.send(message)
                elif action == "relabel":
                    await destination.send(b"\x01\x05")
                elif action == "flip":
                    await destination.send(message[:3] + bytes([message[3] ^ 0x01]) + message[4:])
                else:
                    await destination.send(message)
        except ConnectionClosed:
            pass


def _forward(method: str, url: str, headers: Headers) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url, method=method, headers={"Authorization": headers.get("Authorization", "")}
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except OSError:
        return 503, b""
