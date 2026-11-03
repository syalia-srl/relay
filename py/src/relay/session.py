"""One established L1 session: transport frames, fragments and rekey."""

from __future__ import annotations

import asyncio

from .errors import ProtocolViolation
from .frames import (
    KIND_APPLICATION,
    KIND_CONTROL,
    MAX_PAYLOAD,
    MAX_TRANSPORT,
    MIN_TRANSPORT,
    TRANSPORT,
    FragmentAssembler,
)
from .noise import CipherState, HandshakeState
from .relays import Socket


class Session:
    """The transport state of one side of one connection."""

    def __init__(self, send: CipherState, receive: CipherState):
        self._send = send
        self._receive = receive
        self._fragments = FragmentAssembler()
        # A whole message's fragments must reach the socket together, and their
        # nonces in order, whichever task sends them (PROTOCOL.md §7.2).
        self._lock = asyncio.Lock()

    @classmethod
    def initiator(cls, handshake: HandshakeState) -> Session:
        first, second = handshake.split()
        return cls(send=first, receive=second)

    @classmethod
    def responder(cls, handshake: HandshakeState) -> Session:
        first, second = handshake.split()
        # PROTOCOL.md §6.2: c1 carries guest-to-host frames and c2 host-to-guest.
        return cls(send=second, receive=first)

    def frames(self, kind: int, message: bytes) -> list[bytes]:
        """The L1 transport frames for one application or control message."""
        if kind not in (KIND_APPLICATION, KIND_CONTROL):
            raise ProtocolViolation("unknown message kind")
        parts = [message[i : i + MAX_PAYLOAD] for i in range(0, len(message), MAX_PAYLOAD)] or [b""]
        frames = []
        for index, part in enumerate(parts):
            plaintext = bytes([kind, 1 if index < len(parts) - 1 else 0]) + part
            frames.append(bytes([TRANSPORT]) + self._send.encrypt(b"", plaintext))
        return frames

    async def send(self, socket: Socket, kind: int, message: bytes) -> None:
        async with self._lock:
            await socket.send_all(self.frames(kind, message))

    def decrypt(self, body: bytes) -> tuple[int, bytes | None]:
        """Decrypt one transport frame; None means more fragments follow."""
        if not MIN_TRANSPORT <= len(body) <= MAX_TRANSPORT:
            raise ProtocolViolation("a transport frame has the wrong length")
        plaintext = self._receive.decrypt(b"", body)
        kind, flags = plaintext[0], plaintext[1]
        if kind not in (KIND_APPLICATION, KIND_CONTROL):
            raise ProtocolViolation("unknown message kind")
        if flags & ~0x01:
            raise ProtocolViolation("unknown transport flags")
        return kind, self._fragments.push(kind, bool(flags & 0x01), plaintext[2:])
