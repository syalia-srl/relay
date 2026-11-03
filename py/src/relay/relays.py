"""The relay side of L1: URL policy, the HTTP API, the socket and backoff."""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, WebSocketException

from .errors import ProtocolViolation, RelayError
from .strictjson import is_b64url, loads

_PRIVATE_V4 = tuple(
    ip_network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_PRIVATE_V6 = ip_network("fc00::/7")

HTTP_TIMEOUT = 10
# One L1 frame is at most 65,536 bytes and a system frame is tiny.
MAX_RELAY_FRAME = 65537
# The small JSON the host reads from the relay is under 200 bytes.
MAX_RELAY_BODY = 65536


def url_allowed(url: object) -> bool:
    """PROTOCOL.md §8.1: the relay URLs a guest and a host may exchange."""
    if not isinstance(url, str) or len(url) > 2048:
        return False
    try:
        parts = urlsplit(url)
        host = parts.hostname
        if not host or parts.username is not None or parts.password is not None:
            return False
        if parts.query or parts.fragment:
            return False
        if parts.port is not None and not 1 <= parts.port <= 65535:
            return False
        if parts.scheme == "wss":
            return True
        if parts.scheme != "ws" or "%" in host:
            return False
        address = ip_address(host)
    except ValueError:
        return False
    if address.version == 4:
        return any(address in network for network in _PRIVATE_V4)
    return address in _PRIVATE_V6


def host_url_allowed(url: object) -> bool:
    """PROTOCOL.md §2.3 for the URL a host reaches a relay by for itself."""
    if not isinstance(url, str) or len(url) > 2048:
        return False
    try:
        parts = urlsplit(url)
        host = parts.hostname
        if not host or parts.username is not None or parts.password is not None:
            return False
        if parts.query or parts.fragment:
            return False
        if parts.port is not None and not 1 <= parts.port <= 65535:
            return False
        if parts.scheme == "wss":
            return True
        if parts.scheme != "ws" or "%" in host:
            return False
        try:
            address = ip_address(host)
        except ValueError:
            # A dotless name is a container or compose service name, not a LAN host.
            return "." not in host
    except ValueError:
        return False
    if address.version == 4:
        return address.is_loopback or any(address in network for network in _PRIVATE_V4)
    return address.is_loopback or address in _PRIVATE_V6


class Relay:
    """A relay the host application uses, with the project key that creates channels."""

    __slots__ = ("host_url", "key", "url")

    def __init__(self, url: str, *, key: str, host_url: str | None = None):
        if not url_allowed(url):
            raise ValueError(f"relay URL fails the policy of PROTOCOL.md §8.1: {url}")
        own_url = url if host_url is None else host_url
        if not host_url_allowed(own_url):
            raise ValueError(f"host URL fails the policy of PROTOCOL.md §2.3: {own_url}")
        self.url = url
        self.host_url = own_url
        self.key = key


@dataclass(frozen=True)
class RelayEntry:
    """One relay, its channel and the guest token, as section 4 defines it."""

    url: str
    channel: str
    token: str

    @classmethod
    def from_json(cls, value: object) -> RelayEntry | None:
        if not isinstance(value, dict):
            return None
        url = value.get("url")
        channel = value.get("channel")
        token = value.get("token")
        if not isinstance(url, str) or not is_b64url(channel, 22) or not is_b64url(token, 43):
            return None
        return cls(url=url, channel=channel, token=token)

    def to_json(self) -> dict[str, str]:
        return {"url": self.url, "channel": self.channel, "token": self.token}


@dataclass(frozen=True)
class Credentials:
    channel: str
    host_token: str
    guest_token: str


def _strip_one_slash(base: str) -> str:
    return base.removesuffix("/")


def ws_url(base: str, channel: str) -> str:
    return f"{_strip_one_slash(base)}/v1/ws/{channel}"


def _http_base(base: str) -> str:
    parts = urlsplit(base)
    scheme = {"ws": "http", "wss": "https"}[parts.scheme]
    return f"{scheme}://{parts.netloc}{_strip_one_slash(parts.path)}"


async def create_channel(relay: Relay) -> Credentials:
    """POST /v1/channels with the relay's project key (PROTOCOL.md §2.3)."""
    status, body = await asyncio.to_thread(
        _request, "POST", _http_base(relay.host_url) + "/v1/channels", relay.key, b""
    )
    if status != 201:
        raise RelayError(f"creating a channel failed with HTTP {status}")
    try:
        value = loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise RelayError("the relay answered invalid JSON") from error
    if not isinstance(value, dict):
        raise RelayError("the relay answered invalid JSON")
    channel, host_token, guest_token = value.get("channel"), value.get("host_token"), value.get("guest_token")
    if not is_b64url(channel, 22) or not is_b64url(host_token, 43) or not is_b64url(guest_token, 43):
        raise RelayError("the relay answered invalid credentials")
    return Credentials(channel=channel, host_token=host_token, guest_token=guest_token)


async def delete_channel(url: str, channel: str, host_token: str) -> bool:
    """Delete a channel. False means the relay no longer had it."""
    status, _ = await asyncio.to_thread(
        _request,
        "DELETE",
        _http_base(url) + f"/v1/channels/{channel}",
        host_token,
        None,
    )
    if status == 204:
        return True
    if status == 404:
        return False
    raise RelayError(f"deleting a channel failed with HTTP {status}")


def _request(method: str, url: str, bearer: str, body: bytes | None) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        method=method,
        data=body,
        headers={"Authorization": f"Bearer {bearer}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            return response.status, response.read(MAX_RELAY_BODY)
    except urllib.error.HTTPError as error:
        return error.code, error.read(MAX_RELAY_BODY)
    except OSError as error:
        raise RelayError(f"the relay answered nothing: {error}") from error


class SocketClosed(Exception):
    """The relay closed the WebSocket, with the code it sent."""

    def __init__(self, code: int):
        super().__init__(f"the relay closed with {code}")
        self.code = code


class ChannelGone(SocketClosed):
    """The relay no longer has the channel (4401 or 4410)."""


class Socket:
    """One authenticated L0 socket, carrying L1 frames."""

    def __init__(self, base: str, channel: str, token: str):
        self._url = ws_url(base, channel)
        self._token = token
        self._websocket = None
        self._send_lock = asyncio.Lock()

    async def open(self) -> None:
        """Connect, send `auth` and wait for `ready`."""
        try:
            self._websocket = await connect(self._url, max_size=MAX_RELAY_FRAME)
            await self._websocket.send(json.dumps({"auth": self._token}))
            while True:
                message = await self._websocket.recv()
                if not isinstance(message, bytes) or message[:1] != b"\x00":
                    raise ProtocolViolation("the relay sent a frame before ready")
                if _system_event(message) == "ready":
                    return
        except ConnectionClosed as closed:
            raise _closed(closed) from closed
        except (WebSocketException, OSError) as error:
            raise RelayError(f"cannot use the relay: {error}") from error

    async def recv(self) -> bytes:
        """The next L1 frame. Presence events are skipped."""
        try:
            while True:
                message = await self._open_websocket().recv()
                if not isinstance(message, bytes):
                    raise ProtocolViolation("the relay sent a text frame")
                if message[:1] == b"\x00":
                    continue
                if message[:1] == b"\x01":
                    return message[1:]
                raise ProtocolViolation("the relay sent an unknown frame")
        except ConnectionClosed as closed:
            raise _closed(closed) from closed

    async def send_all(self, frames: list[bytes]) -> None:
        try:
            async with self._send_lock:
                for frame in frames:
                    await self._open_websocket().send(b"\x01" + frame)
        except ConnectionClosed as closed:
            raise _closed(closed) from closed

    def _open_websocket(self):
        # Another task may close the socket while this one sends or reads.
        if self._websocket is None:
            raise SocketClosed(1006)
        return self._websocket

    async def close(self) -> None:
        websocket, self._websocket = self._websocket, None
        if websocket is None:
            return
        try:
            await websocket.close()
        except (WebSocketException, OSError):
            pass


def _system_event(frame: bytes) -> str | None:
    try:
        value = json.loads(frame[1:])
    except ValueError:
        return None
    return value.get("event") if isinstance(value, dict) and isinstance(value.get("event"), str) else None


def _closed(closed: ConnectionClosed) -> SocketClosed:
    code = closed.rcvd.code if closed.rcvd is not None else 1006
    return ChannelGone(code) if code in (4401, 4410) else SocketClosed(code)


class Backoff:
    """Section 8.2: 1 second, doubling, at most 60, back to 1 after a success."""

    def __init__(self) -> None:
        self._delay = 1.0

    def next(self) -> float:
        delay = self._delay
        self._delay = min(2 * self._delay, 60.0)
        return delay

    def reset(self) -> None:
        self._delay = 1.0


def seconds_until_utc_midnight(now: datetime | None = None) -> float:
    """How long a relay over its daily byte quota stays unusable."""
    if now is None:
        now = datetime.now(UTC)
    tomorrow = (now + timedelta(days=1)).date()
    return (datetime.combine(tomorrow, time.min, tzinfo=UTC) - now).total_seconds()
