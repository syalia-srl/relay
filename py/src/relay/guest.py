"""The guest role: first contact, relay choice and device connections."""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Self

from cryptography.exceptions import InvalidTag

from . import store
from .control import encode_control, parse_control
from .errors import PairingFailed, ProtocolViolation, RelayError, Revoked
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
from .keys import MemoryKey, StaticKey
from .noise import HandshakeState
from .payload import parse_payload
from .relays import (
    Backoff,
    ChannelGone,
    RelayEntry,
    Socket,
    SocketClosed,
    seconds_until_utc_midnight,
    url_allowed,
)
from .session import Session

CONNECT_TIMEOUT = 1.5
UPGRADE_INTERVAL = 60
GONE_ROUNDS = 3
UNPAIR_TIMEOUT = 10


class _Reconnect(Exception):
    """This session is over; go back to step 1 of PROTOCOL.md §8.2."""


class _Done(Exception):
    """The link reached a final state."""


class PairedHost:
    """A host this guest paired with. The iterator raises ``Revoked`` when it is revoked."""

    def __init__(
        self,
        guest: Guest,
        dev: str,
        host_public: bytes,
        relays: list[RelayEntry],
        static: StaticKey,
        *,
        private: bytes | None,
        expires: int | None,
    ):
        self._guest = guest
        self._dev = dev
        self._host_public = host_public
        self._relays = relays
        self._static = static
        self._private = private
        self._expires = expires
        self._psk: bytes | None = None
        self._state = "pairing" if expires is not None else "bound"
        self._error: RelayError | None = None
        self._code = ""
        self._pending_code: str | None = None
        self._ready = False
        self._session: Session | None = None
        self._socket: Socket | None = None
        self._unpairing = False
        self._paused: dict[str, float] = {}
        self._inbox: asyncio.Queue = asyncio.Queue(maxsize=64)
        self._condition = asyncio.Condition()
        self._task: asyncio.Task | None = None
        self._deadline: asyncio.Task | None = None

    @property
    def code(self) -> str:
        """The six digits the person types into the host, once the host has the key."""
        return self._code

    async def bound(self) -> None:
        """Return once the device channels carry a session."""
        async with self._condition:
            await self._condition.wait_for(
                lambda: (self._ready and self._state == "bound") or self._terminal()
            )
        self._raise_terminal()
        if self._state == "closed":
            raise RelayError("the host no longer has this guest")

    async def send(self, message: bytes) -> None:
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("a message is bytes")
        payload = bytes(message)
        while True:
            async with self._condition:
                await self._condition.wait_for(
                    lambda: (self._ready and self._state == "bound") or self._terminal()
                )
            self._raise_terminal()
            if self._state == "closed":
                raise RelayError("the host no longer has this guest")
            session, socket = self._session, self._socket
            if session is None or socket is None:
                continue
            try:
                await session.send(socket, KIND_APPLICATION, payload)
                return
            except SocketClosed:
                self._ready = False

    async def unpair(self) -> None:
        """Send `close` and wait for `closed`, then forget this host."""
        await self._unpair()

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self._messages()

    async def _messages(self) -> AsyncIterator[bytes]:
        while True:
            if self._terminal() and self._inbox.empty():
                self._raise_terminal()
                return
            message = await self._inbox.get()
            if message is None:
                self._raise_terminal()
                return
            yield message

    def _terminal(self) -> bool:
        return self._state in ("closed", "revoked", "failed")

    def _terminal_error(self) -> RelayError | None:
        if self._state == "revoked":
            return Revoked("the host revoked this guest")
        return self._error

    def _raise_terminal(self) -> None:
        error = self._terminal_error()
        if error is not None:
            raise error

    async def _notify(self) -> None:
        if self._terminal():
            self._wake()
        async with self._condition:
            self._condition.notify_all()

    def _wake(self) -> None:
        """Unblock an iterator that is waiting on the inbox."""
        try:
            self._inbox.put_nowait(None)
        except asyncio.QueueFull:
            pass

    def _start(self) -> None:
        self._task = asyncio.create_task(self._run())
        if self._expires is not None:
            self._deadline = asyncio.create_task(self._expire())

    def _cancel_deadline(self) -> None:
        if self._deadline is not None:
            self._deadline.cancel()

    # -- the relay loop ---------------------------------------------------

    async def _run(self) -> None:
        backoff = Backoff()
        gone_rounds = 0
        while not self._terminal():
            established = False
            all_gone = True
            for position in range(len(self._relays)):
                if self._terminal():
                    return
                entry = self._relays[position]
                if self._paused.get(entry.url, 0) > time.time():
                    all_gone = False
                    continue
                try:
                    socket, session = await self._connect(entry)
                except ChannelGone:
                    continue
                except SocketClosed as closed:
                    if closed.code == 4429:
                        self._paused[entry.url] = time.time() + seconds_until_utc_midnight()
                    all_gone = False
                    continue
                except (RelayError, ProtocolViolation, OSError):
                    all_gone = False
                    continue
                established = True
                backoff.reset()
                try:
                    await self._serve(socket, session, position)
                except _Reconnect:
                    pass
                except _Done:
                    return
                except (SocketClosed, RelayError, ProtocolViolation, OSError):
                    # PROTOCOL.md §8.2 step 3: a socket that closes goes back to step 1.
                    pass
                finally:
                    self._ready = False
                    self._pending_code = None
                    self._session = None
                    self._socket = None
                    await socket.close()
                break
            if self._terminal():
                return
            if established:
                gone_rounds = 0
                continue
            if all_gone and self._relays:
                gone_rounds += 1
                if gone_rounds >= GONE_ROUNDS:
                    await self._gone()
                    return
            else:
                gone_rounds = 0
            await asyncio.sleep(backoff.next())

    async def _connect(self, entry: RelayEntry) -> tuple[Socket, Session]:
        """Open one socket and get to `accept` within 1.5 s (PROTOCOL.md §8.2)."""
        socket = Socket(entry.url, entry.channel, entry.token)
        try:
            async with asyncio.timeout(CONNECT_TIMEOUT):
                await socket.open()
                if self._state in ("pending", "bound"):
                    handshake = HandshakeState(
                        "KK", True, prologue(self._dev, entry.channel), self._static, self._host_public
                    )
                    await socket.send_all([frame(CONNECT, handshake.write_message())])
                else:
                    handshake = HandshakeState(
                        "IKpsk1",
                        True,
                        prologue(self._dev, entry.channel),
                        self._static,
                        self._host_public,
                        self._psk,
                    )
                    await socket.send_all([frame(PAIR, handshake.write_message())])
                answer = await socket.recv()
                if not answer or answer[0] != ACCEPT or len(answer) != 49:
                    raise ProtocolViolation("expected an accept frame")
                handshake.read_message(answer[1:])
        except BaseException:
            await socket.close()
            raise
        if self._state == "pairing":
            self._pending_code = pairing_code(handshake.handshake_hash)
        session = Session.initiator(handshake)
        # PROTOCOL.md §6.1: the guest's first transport frame is a ping.
        await session.send(socket, KIND_CONTROL, encode_control("ping"))
        return socket, session

    async def _serve(self, socket: Socket, session: Session, position: int) -> None:
        self._socket, self._session = socket, session
        deadline = asyncio.get_running_loop().time() + UPGRADE_INTERVAL
        while not self._terminal():
            if position > 0:
                try:
                    incoming = await asyncio.wait_for(
                        socket.recv(), max(0.1, deadline - asyncio.get_running_loop().time())
                    )
                except TimeoutError:
                    deadline = asyncio.get_running_loop().time() + UPGRADE_INTERVAL
                    moved = await self._earlier(position)
                    if moved is None:
                        continue
                    new_socket, new_session, new_position = moved
                    self._ready = False
                    previous, socket, session = socket, new_socket, new_session
                    position = new_position
                    self._socket, self._session = socket, session
                    await previous.close()
                    continue
            else:
                incoming = await socket.recv()
            await self._receive(socket, session, incoming)

    async def _earlier(self, position: int) -> tuple[Socket, Session, int] | None:
        """PROTOCOL.md §8.2 step 2: move up when an earlier relay gets to `accept`."""
        for earlier in range(position):
            entry = self._relays[earlier]
            if self._paused.get(entry.url, 0) > time.time():
                continue
            try:
                socket, session = await self._connect(entry)
            except (ChannelGone, RelayError, ProtocolViolation, OSError):
                continue
            return socket, session, earlier
        return None

    async def _receive(self, socket: Socket, session: Session, incoming: bytes) -> None:
        if not incoming:
            raise _Reconnect
        frame_type, body = incoming[0], incoming[1:]
        if frame_type == ABORT:
            raise _Reconnect
        if frame_type != TRANSPORT:
            await self._abort(socket)
            raise _Reconnect
        if not MIN_TRANSPORT <= len(body) <= MAX_TRANSPORT:
            await self._abort(socket)
            raise _Reconnect
        try:
            kind, message = session.decrypt(body)
        except (InvalidTag, ProtocolViolation):
            await self._abort(socket)
            raise _Reconnect from None
        if message is not None:
            await self._process(socket, session, kind, message)

    async def _process(self, socket: Socket, session: Session, kind: int, message: bytes) -> None:
        if kind == KIND_APPLICATION:
            # PROTOCOL.md §5.4: a pending guest has no access of any kind.
            if self._state != "bound":
                await self._abort(socket)
                raise _Reconnect
            await self._inbox.put(message)
            return
        try:
            control = parse_control(message.decode("utf-8"), "guest")
        except (UnicodeDecodeError, ProtocolViolation):
            await self._abort(socket)
            raise _Reconnect from None
        if control is None:
            return
        if control.op == "ping":
            await session.send(socket, KIND_CONTROL, encode_control("pong"))
        elif control.op == "pong":
            await self._on_pong(socket, session)
        elif control.op == "relays":
            self._relays = list(control.relays)
            self._state = "bound"
            self._psk = None
            self._guest._store(self)
            await self._notify()
            # PROTOCOL.md §8.3: replace the list and start over at step 1.
            raise _Reconnect
        elif control.op == "closed":
            self._state = "closed"
            self._guest._forget(self)
            await self._notify()
            raise _Done
        elif control.op == "revoked":
            self._state = "revoked"
            self._guest._forget(self)
            await self._notify()
            raise _Done

    async def _on_pong(self, socket: Socket, session: Session) -> None:
        self._ready = True
        if self._state == "pairing":
            # The host sends `pong` only after promoting the key (PROTOCOL.md §5.3).
            self._code = self._pending_code or ""
            self._pending_code = None
            self._state = "pending"
            self._cancel_deadline()
        if self._unpairing:
            await session.send(socket, KIND_CONTROL, encode_control("close"))
        await self._notify()

    async def _expire(self) -> None:
        await asyncio.sleep(max(0, self._expires - time.time() + 60))
        if not self._terminal():
            await self._fail(PairingFailed("the pairing payload expired"))

    async def _gone(self) -> None:
        # PROTOCOL.md §8.4: every relay lost the channel, three rounds in a row.
        if self._state == "bound":
            self._state = "revoked"
            self._guest._forget(self)
        else:
            await self._fail(PairingFailed("every relay lost the channel"))
            return
        await self._notify()

    async def _fail(self, error: RelayError) -> None:
        if self._terminal():
            return
        self._error = error
        self._state = "failed"
        self._guest._forget(self)
        task = self._task
        if task is not None and task is not asyncio.current_task():
            task.cancel()
        await self._notify()

    async def _unpair(self) -> None:
        async with self._condition:
            if self._state == "pairing":
                # No key is pending at the host yet, so there is nothing to close.
                self._state = "closed"
                self._wake()
                self._cancel_deadline()
                task = self._task
                if task is not None and task is not asyncio.current_task():
                    task.cancel()
                self._guest._forget(self)
                return
            self._unpairing = not self._terminal()
            session, socket = self._session, self._socket
            paired = self._state in ("pending", "bound")
        if self._terminal():
            self._cancel_deadline()
            self._guest._forget(self)
            return
        if paired and session is not None and socket is not None and self._ready:
            try:
                await session.send(socket, KIND_CONTROL, encode_control("close"))
            except (RelayError, SocketClosed):
                pass
        try:
            async with asyncio.timeout(UNPAIR_TIMEOUT):
                async with self._condition:
                    await self._condition.wait_for(
                        lambda: self._state in ("closed", "revoked", "failed")
                    )
        except TimeoutError:
            # PROTOCOL.md §9.1 keeps the key until `closed`; a guest whose host is
            # unreachable still has to be able to unpair, so it forgets locally.
            self._state = "closed"
            self._wake()
            task = self._task
            if task is not None and task is not asyncio.current_task():
                task.cancel()
        self._cancel_deadline()
        self._guest._forget(self)

    async def _abort(self, socket: Socket) -> None:
        try:
            await socket.send_all([frame(ABORT, b"")])
        except (RelayError, SocketClosed):
            pass

    async def _stop(self) -> None:
        self._cancel_deadline()
        if self._task is not None:
            self._task.cancel()
        if self._socket is not None:
            await self._socket.close()


class Guest:
    """The side that pairs with a host, then carries messages to it."""

    def __init__(self, path: Path, key: StaticKey | None):
        self._path = path
        self._key = key
        self._hosts: dict[str, PairedHost] = {}

    @classmethod
    async def open(cls, path: str | Path, *, key: StaticKey | None = None) -> Guest:
        """Open the guest at ``path``; ``key`` is any object with .public and dh()."""
        where = Path(path)
        guest = cls(where, key)
        state = store.load(where)
        if state is None:
            return guest
        hosts = state.get("hosts")
        if not isinstance(hosts, list):
            raise RelayError("the state file has no host list")
        try:
            for item in hosts:
                relays = []
                for stored in item["relays"]:
                    entry = RelayEntry.from_json(stored)
                    if entry is None or not url_allowed(entry.url):
                        raise RelayError("the state file has a bad relay entry")
                    relays.append(entry)
                private = item.get("static")
                if key is not None:
                    if private is not None:
                        raise RelayError("this state already holds a guest key")
                    static = key
                elif private is None:
                    raise RelayError("this state was paired with a native key; pass it to open")
                else:
                    static = MemoryKey(bytes.fromhex(private))
                link = PairedHost(
                    guest,
                    item["dev"],
                    bytes.fromhex(item["host"]),
                    relays,
                    static,
                    private=bytes.fromhex(private) if private is not None else None,
                    expires=None,
                )
                guest._hosts[link._dev] = link
        except (KeyError, TypeError, ValueError) as error:
            raise RelayError("the state file is damaged") from error
        for link in guest._hosts.values():
            link._start()
        return guest

    @property
    def hosts(self) -> list[PairedHost]:
        return list(self._hosts.values())

    async def pair(self, payload: str) -> PairedHost:
        """First contact with a host, from the payload it showed."""
        parsed = parse_payload(payload)
        if self._key is not None and self._hosts:
            # PROTOCOL.md §3: one gs serves one pairing, and a native key cannot
            # mint another, so a second pairing needs its own Guest.
            raise RelayError("this guest key is already paired; a fresh key pairs again")
        private = None if self._key is not None else secrets.token_bytes(32)
        static = self._key if self._key is not None else MemoryKey(private)
        link = PairedHost(
            self,
            parsed.dev,
            parsed.host_public,
            list(parsed.relays),
            static,
            private=private,
            expires=parsed.expires,
        )
        link._psk = parsed.psk
        self._hosts[link._dev] = link
        link._start()
        async with link._condition:
            await link._condition.wait_for(lambda: link._code != "" or link._terminal())
        if link._terminal():
            link._raise_terminal()
            raise PairingFailed("the pairing ended before the host showed a code")
        return link

    async def close(self) -> None:
        """Stop every connection. Paired hosts stay on disk."""
        for link in self._hosts.values():
            await link._stop()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    def _forget(self, link: PairedHost) -> None:
        if self._hosts.get(link._dev) is link:
            del self._hosts[link._dev]
            self._save()

    def _store(self, link: PairedHost) -> None:
        if self._hosts.get(link._dev) is link:
            self._save()

    def _save(self) -> None:
        store.save(
            self._path,
            {
                "hosts": [
                    {
                        "dev": link._dev,
                        "host": link._host_public.hex(),
                        "relays": [entry.to_json() for entry in link._relays],
                        **({"static": link._private.hex()} if link._private is not None else {}),
                    }
                    for link in self._hosts.values()
                    # A pairing that a restart interrupts starts over from a new payload.
                    if link._state == "bound"
                ]
            },
        )
