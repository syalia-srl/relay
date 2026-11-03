"""The host role: pairing, bound devices, channels and revocation."""

from __future__ import annotations

import asyncio
import hmac
import secrets
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Self

from cryptography.exceptions import InvalidTag

from . import store
from .control import encode_control, parse_control
from .errors import PairingFailed, ProtocolViolation, RelayError, WrongCode
from .frames import (
    ABORT,
    ACCEPT,
    CONNECT,
    KIND_APPLICATION,
    KIND_CONTROL,
    MAX_TRANSPORT,
    MIN_TRANSPORT,
    PAIR,
    TRANSPORT,
    frame,
    pairing_code,
    prologue,
)
from .keys import MemoryKey
from .noise import HandshakeState
from .payload import Payload
from .relays import (
    Backoff,
    ChannelGone,
    Relay,
    RelayEntry,
    Socket,
    SocketClosed,
    create_channel,
    delete_channel,
    seconds_until_utc_midnight,
    url_allowed,
)
from .session import Session

PAIRING_LIFETIME = 300
CONFIRMATION_LIFETIME = 600
MAX_PENDING = 4
MAX_UNMATCHED_CODES = 3
SOCKET_TIMEOUT = 10


class _Candidate:
    def __init__(self, guest: bytes, session: Session, code: str | None):
        self.guest = guest
        self.session = session
        self.code = code


class _Channel:
    def __init__(
        self,
        channel: str,
        url: str,
        host_token: str,
        guest_token: str,
        dev: str,
        *,
        pairing: bool,
    ):
        self.id = channel
        self.url = url
        self.host_token = host_token
        self.guest_token = guest_token
        self.dev = dev
        self.pairing = pairing
        self.guest: bytes | None = None
        self.session: Session | None = None
        self.candidate: _Candidate | None = None
        self.socket: Socket | None = None
        self.task: asyncio.Task | None = None
        self.stopped = False


class Device:
    """A bound guest. ``id`` and ``name`` are the host's, ``connected`` is live."""

    def __init__(self, host: Host, dev: str, name: str, guest: bytes):
        self._host = host
        self._id = dev
        self._name = name
        self._guest = guest
        self._channels: dict[str, _Channel] = {}
        self._current: _Channel | None = None
        self._ready = asyncio.Event()

    @property
    def id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def connected(self) -> bool:
        return self._current is not None and self._current.session is not None

    async def send(self, message: bytes) -> None:
        await self._host._send(self, message)


class Pairing:
    """One open pairing: the payload to show, and the code a person types."""

    def __init__(self, host: Host, dev: str, name: str, psk: bytes, expires: int):
        self._host = host
        self.dev = dev
        self._name = name
        self._psk = psk
        self.expires = expires
        self._payload = ""
        self.channels: list[_Channel] = []
        self.pending: dict[bytes, str] = {}
        self.unmatched = 0
        self.confirming = False
        self.bound = False
        self.bound_key: bytes | None = None
        self.ended = False
        self.expiry: asyncio.Task | None = None
        self.deadline: asyncio.Task | None = None

    @property
    def device(self) -> str:
        """The device id this pairing binds, to find it again with ``Host.pairing``."""
        return self.dev

    @property
    def payload(self) -> str:
        """The JSON of section 4, for a QR or copied text."""
        return self._payload

    async def confirm(self, code: str) -> Device:
        """Bind the pending key whose code the person typed (PROTOCOL.md §5.5)."""
        return await self._host._confirm(self, code)


class Host:
    """The long-lived side: one static key, many bound devices."""

    def __init__(self, path: Path, private: bytes, relays: tuple[Relay, ...]):
        self._path = path
        self._private = private
        self._static = MemoryKey(private)
        self._relays = relays
        self._devices: dict[str, Device] = {}
        self._pairings: dict[str, Pairing] = {}
        self._faulty: set[str] = set()
        self._paused: dict[str, float] = {}
        # Messages wait here until the application iterates; a full inbox makes
        # the channel readers wait, which pushes back on the relay.
        self._inbox: asyncio.Queue[tuple[Device, bytes] | None] = asyncio.Queue(maxsize=64)
        self._closed = False

    @classmethod
    async def open(cls, path: str | Path, *, relays: list[Relay] | tuple[Relay, ...]) -> Host:
        if not relays:
            raise ValueError("a host needs at least one relay")
        where = Path(path)
        state = store.load(where)
        if state is None:
            private = secrets.token_bytes(32)
        else:
            try:
                private = bytes.fromhex(state["static"])
            except (KeyError, TypeError, ValueError) as error:
                raise RelayError("the state file is damaged") from error
        host = cls(where, private, tuple(relays))
        if state is not None:
            host._load(state)
        else:
            host._save()
        for device in host._devices.values():
            for channel in device._channels.values():
                host._start(channel)
        return host

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    @property
    def devices(self) -> list[Device]:
        return list(self._devices.values())

    def pairing(self, device: str) -> Pairing:
        """The open pairing for ``device``, so another request can confirm it."""
        pairing = self._pairings.get(device)
        if pairing is None or pairing.bound:
            raise PairingFailed("the pairing has ended")
        return pairing

    async def pair(self, name: str) -> Pairing:
        """Open one pairing on every usable relay and build its payload (section 5.2)."""
        dev = secrets.token_hex(8)
        psk = secrets.token_bytes(32)
        pairing = Pairing(self, dev, name, psk, int(time.time()) + PAIRING_LIFETIME)
        pairing.channels = await self._create_channels(dev, pairing=True)
        if not pairing.channels:
            raise RelayError("no relay created a pairing channel")
        self._pairings[dev] = pairing
        for channel in pairing.channels:
            self._start(channel)
        pairing._payload = Payload(
            dev=dev,
            host_public=self._static.public,
            psk=psk,
            expires=pairing.expires,
            relays=tuple(
                RelayEntry(url=channel.url, channel=channel.id, token=channel.guest_token)
                for channel in pairing.channels
            ),
        ).encode()
        pairing.expiry = asyncio.create_task(self._expire(pairing))
        return pairing

    async def revoke(self, device: Device) -> None:
        """Send `revoked`, then delete the device's channels (PROTOCOL.md §10.5)."""
        if self._devices.get(device.id) is not device:
            return
        channel = device._current
        if channel is not None and channel.session is not None and channel.socket is not None:
            try:
                await channel.session.send(channel.socket, KIND_CONTROL, encode_control("revoked"))
            except (RelayError, SocketClosed):
                pass
        await self._remove_device(device.id)

    async def close(self) -> None:
        """Stop every socket. Bound devices and their channels stay on disk."""
        if self._closed:
            return
        self._closed = True
        ephemeral: list[_Channel] = []
        for pairing in list(self._pairings.values()):
            pairing.ended = True
            self._cancel(pairing)
            ephemeral.extend(pairing.channels)
        self._pairings.clear()
        for channel in ephemeral:
            await self._stop_channel(channel)
        await self._delete_channels(ephemeral)
        for device in self._devices.values():
            device._ready.set()
            for channel in device._channels.values():
                await self._stop_channel(channel)
        # The channel tasks are stopped, so nothing else fills the inbox now.
        if self._inbox.full():
            self._inbox.get_nowait()
        self._inbox.put_nowait(None)

    async def __aiter__(self) -> AsyncIterator[tuple[Device, bytes]]:
        while (item := await self._inbox.get()) is not None:
            yield item

    # -- pairing ----------------------------------------------------------

    async def _confirm(self, pairing: Pairing, code: str) -> Device:
        if self._pairings.get(pairing.dev) is not pairing or pairing.bound:
            raise PairingFailed("the pairing has ended")
        if pairing.confirming:
            raise PairingFailed("this pairing is already being confirmed")
        # Typed text may hold anything; only six ASCII digits can match a code.
        typed = code.strip().encode("ascii", "replace")
        matches = [key for key, value in pairing.pending.items() if hmac.compare_digest(value.encode(), typed)]
        if len(matches) != 1:
            if not matches:
                pairing.unmatched += 1
                if pairing.unmatched < MAX_UNMATCHED_CODES:
                    raise WrongCode(MAX_UNMATCHED_CODES - pairing.unmatched)
            await self._end_pairing(pairing)
            if matches:
                raise PairingFailed("two pending keys have that code")
            raise PairingFailed("too many wrong codes")

        guest = matches[0]
        pairing.confirming = True
        try:
            channels = await self._create_channels(pairing.dev, pairing=False, guest=guest)
        finally:
            pairing.confirming = False
        if self._pairings.get(pairing.dev) is not pairing:
            await self._delete_channels(channels)
            raise PairingFailed("the pairing has ended")
        if not channels:
            await self._end_pairing(pairing)
            raise PairingFailed("no relay created a device channel")

        device = Device(self, pairing.dev, pairing._name, guest)
        device._channels = {channel.id: channel for channel in channels}
        self._devices[pairing.dev] = device
        pairing.bound = True
        pairing.bound_key = guest
        pairing.pending.clear()
        pairing._psk = b""
        if pairing.expiry is not None:
            pairing.expiry.cancel()

        # PROTOCOL.md §5.5: forget the other pending keys and their sessions.
        for channel in pairing.channels:
            channel.candidate = None
            if channel.guest != guest:
                await self._abort_channel(channel)
        self._save()
        for channel in channels:
            self._start(channel)
        pairing.deadline = asyncio.create_task(self._deadline(pairing))

        for channel in pairing.channels:
            if channel.guest == guest and channel.session is not None and channel.socket is not None:
                await self._send_relays(pairing, channel)
                break
        return device

    async def _expire(self, pairing: Pairing) -> None:
        await asyncio.sleep(max(0, pairing.expires - time.time()))
        if self._pairings.get(pairing.dev) is pairing and not pairing.bound:
            await self._end_pairing(pairing)

    async def _deadline(self, pairing: Pairing) -> None:
        await asyncio.sleep(CONFIRMATION_LIFETIME)
        if self._pairings.get(pairing.dev) is pairing:
            # PROTOCOL.md §5.5: the guest never reached its device channels.
            await self._end_pairing(pairing)

    async def _end_pairing(self, pairing: Pairing) -> None:
        if self._pairings.pop(pairing.dev, None) is not pairing:
            return
        pairing.ended = True
        self._cancel(pairing)
        channels = list(pairing.channels)
        if pairing.bound:
            device = self._devices.pop(pairing.dev, None)
            if device is not None:
                device._ready.set()
                device._current = None
                channels.extend(device._channels.values())
                self._save()
        await self._stop_channels(channels)
        await self._delete_channels(channels)

    async def _finish_pairing(self, pairing: Pairing) -> None:
        """The guest reached a device channel: the pairing channels can go."""
        if self._pairings.pop(pairing.dev, None) is not pairing:
            return
        pairing.ended = True
        self._cancel(pairing)
        await self._stop_channels(pairing.channels)
        await self._delete_channels(pairing.channels)

    @staticmethod
    def _cancel(pairing: Pairing) -> None:
        for task in (pairing.expiry, pairing.deadline):
            if task is not None and task is not asyncio.current_task():
                task.cancel()

    async def _remove_device(self, dev: str) -> None:
        device = self._devices.pop(dev, None)
        if device is None:
            return
        device._ready.set()
        device._current = None
        channels = list(device._channels.values())
        pairing = self._pairings.pop(dev, None)
        if pairing is not None:
            pairing.ended = True
            self._cancel(pairing)
            channels.extend(pairing.channels)
        self._save()
        await self._stop_channels(channels)
        await self._delete_channels(channels)

    # -- channels ---------------------------------------------------------

    def _usable(self) -> tuple[Relay, ...]:
        now = time.time()
        return tuple(
            relay
            for relay in self._relays
            if relay.url not in self._faulty and self._paused.get(relay.url, 0) <= now
        )

    async def _create_channels(self, dev: str, *, pairing: bool, guest: bytes | None = None) -> list[_Channel]:
        relays = self._usable()
        results = await asyncio.gather(*(create_channel(relay) for relay in relays), return_exceptions=True)
        held = {channel.id for channel in self._all_channels()}
        channels = []
        for relay, result in zip(relays, results, strict=True):
            # PROTOCOL.md §3.1: a channel id the host already holds, on any relay,
            # is a failed creation.
            if isinstance(result, BaseException) or result.channel in held:
                continue
            held.add(result.channel)
            channel = _Channel(
                channel=result.channel,
                url=relay.url,
                host_token=result.host_token,
                guest_token=result.guest_token,
                dev=dev,
                pairing=pairing,
            )
            channel.guest = guest
            channels.append(channel)
        return channels

    def _start(self, channel: _Channel) -> None:
        channel.task = asyncio.create_task(self._run_channel(channel))

    def _all_channels(self) -> list[_Channel]:
        channels = [channel for pairing in self._pairings.values() for channel in pairing.channels]
        channels += [channel for device in self._devices.values() for channel in device._channels.values()]
        return channels

    async def _stop_channel(self, channel: _Channel) -> None:
        channel.stopped = True
        socket, channel.socket = channel.socket, None
        if socket is not None:
            await socket.close()
        if channel.task is not None and channel.task is not asyncio.current_task():
            channel.task.cancel()

    async def _stop_channels(self, channels: list[_Channel]) -> None:
        for channel in channels:
            await self._stop_channel(channel)

    async def _delete_channels(self, channels: list[_Channel]) -> None:
        if not channels:
            return
        await asyncio.gather(
            *(delete_channel(channel.url, channel.id, channel.host_token) for channel in channels),
            return_exceptions=True,
        )

    def _forget_channel(self, channel: _Channel) -> None:
        """PROTOCOL.md §8.4: the relay no longer has it, so stop using it."""
        channel.stopped = True
        if self._closed:
            return
        if channel.pairing:
            pairing = self._pairings.get(channel.dev)
            if pairing is not None and channel in pairing.channels:
                pairing.channels.remove(channel)
        else:
            device = self._devices.get(channel.dev)
            if device is not None:
                device._channels.pop(channel.id, None)
                self._save()

    def _pause(self, url: str) -> None:
        self._paused[url] = time.time() + seconds_until_utc_midnight()

    async def _fault(self, url: str) -> None:
        self._faulty.add(url)
        current = asyncio.current_task()
        for channel in self._all_channels():
            if channel.url == url and channel.task is not current:
                await self._stop_channel(channel)

    # -- sockets ----------------------------------------------------------

    async def _run_channel(self, channel: _Channel) -> None:
        backoff = Backoff()
        while not channel.stopped and not self._closed:
            if channel.url in self._faulty:
                return
            paused = self._paused.get(channel.url, 0) - time.time()
            if paused > 0:
                await asyncio.sleep(paused)
                continue
            socket = Socket(channel.url, channel.id, channel.host_token)
            try:
                async with asyncio.timeout(SOCKET_TIMEOUT):
                    await socket.open()
            except ChannelGone:
                await socket.close()
                self._forget_channel(channel)
                return
            except TimeoutError:
                await socket.close()
                await asyncio.sleep(backoff.next())
                continue
            except SocketClosed as closed:
                await socket.close()
                if closed.code in (4400, 4413):
                    await self._fault(channel.url)
                    return
                if closed.code == 4429:
                    self._pause(channel.url)
                    continue
                await asyncio.sleep(backoff.next())
                continue
            except Exception:
                # Any other failure, a bug included, costs this attempt and not the channel.
                await socket.close()
                await asyncio.sleep(backoff.next())
                continue
            backoff.reset()
            channel.socket = socket
            try:
                while not channel.stopped and not self._closed:
                    await self._handle(channel, socket, await socket.recv())
            except ChannelGone:
                self._forget_channel(channel)
                return
            except SocketClosed as closed:
                if closed.code in (4400, 4413):
                    await self._fault(channel.url)
                    return
                if closed.code == 4429:
                    self._pause(channel.url)
            except Exception:
                # Anything else ends this socket only; the channel reconnects.
                pass
            finally:
                channel.socket = None
                self._drop_session(channel)
                await socket.close()
            if channel.stopped or self._closed:
                return
            await asyncio.sleep(backoff.next())

    def _drop_session(self, channel: _Channel) -> None:
        channel.session = None
        channel.candidate = None
        device = self._devices.get(channel.dev)
        if device is not None and device._current is channel:
            device._current = None
            device._ready.clear()

    # -- inbound frames ---------------------------------------------------

    async def _handle(self, channel: _Channel, socket: Socket, data: bytes) -> None:
        if not data:
            await self._abort(channel, socket, keep_current=False)
            return
        frame_type, body = data[0], data[1:]
        if frame_type == PAIR:
            await self._on_pair(channel, socket, body)
        elif frame_type == CONNECT:
            await self._on_connect(channel, socket, body)
        elif frame_type == TRANSPORT:
            await self._on_transport(channel, socket, body)
        elif frame_type == ABORT and not body:
            channel.candidate = None
            self._drop_session(channel)
        else:
            # ACCEPT, or an unknown type: the host never receives either.
            await self._abort(channel, socket, keep_current=False)

    async def _on_pair(self, channel: _Channel, socket: Socket, body: bytes) -> None:
        pairing = self._pairings.get(channel.dev)
        if (
            not channel.pairing
            or pairing is None
            or pairing.bound
            or time.time() > pairing.expires
            or len(body) != 96
            or len(pairing.pending) >= MAX_PENDING
        ):
            await self._abort(channel, socket, keep_current=True)
            return
        try:
            handshake = HandshakeState(
                "IKpsk1",
                False,
                prologue(channel.dev, channel.id),
                self._static,
                None,
                pairing._psk,
            )
            handshake.read_message(body)
            guest = handshake.remote_static
            assert guest is not None
            if guest in pairing.pending:
                await self._abort(channel, socket, keep_current=True)
                return
            answer = handshake.write_message()
        except (InvalidTag, ProtocolViolation):
            await self._abort(channel, socket, keep_current=True)
            return
        channel.candidate = _Candidate(guest, Session.responder(handshake), pairing_code(handshake.handshake_hash))
        await socket.send_all([frame(ACCEPT, answer)])

    async def _on_connect(self, channel: _Channel, socket: Socket, body: bytes) -> None:
        if len(body) != 48:
            await self._abort(channel, socket, keep_current=True)
            return
        if channel.pairing:
            pairing = self._pairings.get(channel.dev)
            if pairing is None:
                await self._abort(channel, socket, keep_current=True)
                return
            keys = [pairing.bound_key] if pairing.bound else list(pairing.pending)
        else:
            device = self._devices.get(channel.dev)
            keys = [device._guest] if device is not None else []
        for key in keys:
            if key is None:
                continue
            try:
                handshake = HandshakeState("KK", False, prologue(channel.dev, channel.id), self._static, key)
                handshake.read_message(body)
                answer = handshake.write_message()
            except (InvalidTag, ProtocolViolation):
                continue
            channel.candidate = _Candidate(key, Session.responder(handshake), None)
            await socket.send_all([frame(ACCEPT, answer)])
            return
        await self._abort(channel, socket, keep_current=True)

    async def _on_transport(self, channel: _Channel, socket: Socket, body: bytes) -> None:
        if not MIN_TRANSPORT <= len(body) <= MAX_TRANSPORT:
            await self._abort(channel, socket, keep_current=False)
            return
        candidate = channel.candidate
        if candidate is not None:
            try:
                kind, message = candidate.session.decrypt(body)
            except InvalidTag:
                kind = None
            except ProtocolViolation:
                await self._abort(channel, socket, keep_current=False)
                return
            if kind is not None:
                await self._promote(channel, socket, candidate, kind, message)
                return
        if channel.session is None:
            await self._abort(channel, socket, keep_current=False)
            return
        try:
            kind, message = channel.session.decrypt(body)
        except (InvalidTag, ProtocolViolation):
            await self._abort(channel, socket, keep_current=False)
            return
        # PROTOCOL.md §6.3: the current session decrypted it, so the candidate goes.
        channel.candidate = None
        if message is None:
            return
        await self._process(channel, socket, channel.session, kind, message)

    async def _promote(
        self, channel: _Channel, socket: Socket, candidate: _Candidate, kind: int, message: bytes | None
    ) -> None:
        # PROTOCOL.md §6.1: a promoted candidate's first frame is a ping.
        if message is None or kind != KIND_CONTROL:
            await self._abort(channel, socket, keep_current=False)
            return
        try:
            control = parse_control(message.decode("utf-8"), "host")
        except (UnicodeDecodeError, ProtocolViolation):
            await self._abort(channel, socket, keep_current=False)
            return
        if control is None or control.op != "ping":
            await self._abort(channel, socket, keep_current=False)
            return

        channel.candidate = None
        channel.session = candidate.session
        channel.guest = candidate.guest
        if channel.pairing:
            pairing = self._pairings.get(channel.dev)
            if pairing is None:
                await self._abort(channel, socket, keep_current=False)
                return
            if not pairing.bound:
                if candidate.guest not in pairing.pending:
                    # PROTOCOL.md §5.3: one pairing holds at most four pending keys.
                    if len(pairing.pending) >= MAX_PENDING or candidate.code is None:
                        await self._abort(channel, socket, keep_current=False)
                        return
                    pairing.pending[candidate.guest] = candidate.code
            elif candidate.guest == pairing.bound_key:
                # PROTOCOL.md §5.5: the guest may have missed the list on the
                # socket it had at confirmation, so every promotion carries it.
                await self._send_relays(pairing, channel)
        await channel.session.send(socket, KIND_CONTROL, encode_control("pong"))
        if not channel.pairing:
            await self._promoted_device(channel)

    async def _promoted_device(self, channel: _Channel) -> None:
        device = self._devices.get(channel.dev)
        if device is None:
            return
        device._current = channel
        device._ready.set()
        pairing = self._pairings.get(channel.dev)
        if pairing is not None and pairing.bound:
            await self._finish_pairing(pairing)

    async def _process(
        self, channel: _Channel, socket: Socket, session: Session, kind: int, message: bytes
    ) -> None:
        if kind == KIND_APPLICATION:
            if channel.pairing:
                await self._abort(channel, socket, keep_current=False)
                return
            await self._deliver(channel.dev, message)
            return
        try:
            control = parse_control(message.decode("utf-8"), "host")
        except (UnicodeDecodeError, ProtocolViolation):
            await self._abort(channel, socket, keep_current=False)
            return
        if control is None:
            return
        if control.op == "ping":
            await session.send(socket, KIND_CONTROL, encode_control("pong"))
        elif control.op == "close":
            await session.send(socket, KIND_CONTROL, encode_control("closed"))
            if channel.pairing:
                pairing = self._pairings.get(channel.dev)
                if pairing is not None:
                    await self._end_pairing(pairing)
            else:
                await self._remove_device(channel.dev)

    async def _abort(self, channel: _Channel, socket: Socket, *, keep_current: bool) -> None:
        channel.candidate = None
        if not keep_current:
            self._drop_session(channel)
        try:
            await socket.send_all([frame(ABORT, b"")])
        except SocketClosed:
            pass

    async def _abort_channel(self, channel: _Channel) -> None:
        channel.candidate = None
        if channel.session is not None and channel.socket is not None:
            try:
                await channel.socket.send_all([frame(ABORT, b"")])
            except SocketClosed:
                pass
        self._drop_session(channel)

    async def _send_relays(self, pairing: Pairing, channel: _Channel) -> None:
        device = self._devices.get(pairing.dev)
        if device is None or channel.session is None or channel.socket is None:
            return
        entries = tuple(
            RelayEntry(url=item.url, channel=item.id, token=item.guest_token)
            for item in device._channels.values()
        )
        try:
            await channel.session.send(channel.socket, KIND_CONTROL, encode_control("relays", entries))
        except (RelayError, SocketClosed):
            pass

    async def _deliver(self, dev: str, message: bytes) -> None:
        device = self._devices.get(dev)
        if device is None:
            return
        await self._inbox.put((device, message))

    async def _send(self, device: Device, message: bytes) -> None:
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("a message is bytes")
        payload = bytes(message)
        while True:
            if self._closed:
                raise RelayError("the host is closed")
            if self._devices.get(device.id) is not device:
                raise RelayError("the device is not bound")
            if not device._channels:
                raise RelayError("the device has no channel left")
            channel = device._current
            if channel is not None and channel.session is not None and channel.socket is not None:
                try:
                    await channel.session.send(channel.socket, KIND_APPLICATION, payload)
                    return
                except SocketClosed:
                    pass
            device._ready.clear()
            await device._ready.wait()

    # -- state ------------------------------------------------------------

    def _save(self) -> None:
        store.save(
            self._path,
            {
                "static": self._private.hex(),
                "devices": [
                    {
                        "id": device.id,
                        "name": device.name,
                        "guest": device._guest.hex(),
                        "channels": [
                            {
                                "url": channel.url,
                                "channel": channel.id,
                                "host_token": channel.host_token,
                                "guest_token": channel.guest_token,
                            }
                            for channel in device._channels.values()
                        ],
                    }
                    for device in self._devices.values()
                ],
            },
        )

    def _load(self, state: dict) -> None:
        devices = state.get("devices")
        if not isinstance(devices, list):
            raise RelayError("the state file has no device list")
        try:
            for item in devices:
                device = Device(self, item["id"], item["name"], bytes.fromhex(item["guest"]))
                for stored in item["channels"]:
                    if not url_allowed(stored["url"]):
                        continue
                    channel = _Channel(
                        channel=stored["channel"],
                        url=stored["url"],
                        host_token=stored["host_token"],
                        guest_token=stored["guest_token"],
                        dev=device.id,
                        pairing=False,
                    )
                    channel.guest = device._guest
                    device._channels[channel.id] = channel
                self._devices[device.id] = device
        except (KeyError, TypeError, ValueError) as error:
            raise RelayError("the state file is damaged") from error
