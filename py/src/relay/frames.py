"""L1 frame types, the prologue, the pairing code and fragment reassembly."""

from __future__ import annotations

import hashlib
import struct

from .errors import ProtocolViolation

PAIR = 0x01
CONNECT = 0x02
ACCEPT = 0x03
TRANSPORT = 0x04
ABORT = 0x05

KIND_APPLICATION = 0x00
KIND_CONTROL = 0x01

MAX_PAYLOAD = 65_517
MAX_MESSAGE = 16_777_216
MIN_TRANSPORT = 18
MAX_TRANSPORT = 65_535


def prologue(dev: str, channel: str) -> bytes:
    """PROTOCOL.md §3.1: bind a handshake to one device and one channel."""
    device = dev.encode("ascii")
    identifier = channel.encode("ascii")
    return (
        b"relay-channel/3"
        + struct.pack(">H", len(device))
        + device
        + struct.pack(">H", len(identifier))
        + identifier
    )


def pairing_code(handshake_hash: bytes) -> str:
    """PROTOCOL.md §5.6: the six digits the person types into the host."""
    digest = hashlib.sha256(b"relay-channel/3 pairing code" + handshake_hash).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def frame(frame_type: int, body: bytes) -> bytes:
    return bytes([frame_type]) + body


class FragmentAssembler:
    """Reassembles one direction's message, refusing interleaved fragments."""

    def __init__(self) -> None:
        self._kind: int | None = None
        self._parts: list[bytes] = []
        self._size = 0

    def push(self, kind: int, more: bool, payload: bytes) -> bytes | None:
        if self._kind is None:
            self._kind = kind
        elif kind != self._kind:
            raise ProtocolViolation("a fragment changed kind")
        self._size += len(payload)
        # PROTOCOL.md §7.2: the payloads of one message add up to at most 16 MiB.
        if self._size > MAX_MESSAGE:
            raise ProtocolViolation("a message is larger than 16 MiB")
        self._parts.append(payload)
        if more:
            return None
        message = b"".join(self._parts)
        self._kind = None
        self._parts = []
        self._size = 0
        return message
