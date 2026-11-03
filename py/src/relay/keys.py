"""Static X25519 keys.

A role holds its own static key behind :class:`StaticKey` and the peer's as 32
public bytes. Keeping the private half behind this interface is what lets a guest
run its key in native code: the library only ever asks for a Diffie-Hellman result.
"""

from __future__ import annotations

from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

KEY_SIZE = 32


def x25519_dh(private: bytes, public: bytes) -> bytes:
    """The raw X25519 shared secret for one pair of keys."""
    return X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(public))


class StaticKey(Protocol):
    """A static key pair that computes Diffie-Hellman without yielding its private half."""

    @property
    def public(self) -> bytes:
        """The 32-byte public key."""

    def dh(self, peer_public: bytes) -> bytes:
        """The 32-byte X25519 shared secret with ``peer_public``."""


class MemoryKey:
    """A :class:`StaticKey` whose private half lives in process memory."""

    def __init__(self, private: bytes):
        if len(private) != KEY_SIZE:
            raise ValueError("an X25519 private key is 32 bytes")
        self._private = private
        self._public = X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    @classmethod
    def generate(cls) -> MemoryKey:
        return cls(X25519PrivateKey.generate().private_bytes_raw())

    @property
    def public(self) -> bytes:
        return self._public

    def dh(self, peer_public: bytes) -> bytes:
        return x25519_dh(self._private, peer_public)
