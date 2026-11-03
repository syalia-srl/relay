"""A minimal Noise Protocol Framework (revision 34) for the channel protocol.

Only the suite 25519_AESGCM_SHA256 and the two patterns PROTOCOL.md uses are
implemented: IKpsk1 for pairing and KK for every later connection. This is the
same shape as ``vectors/tools/noise_ref.py``, which generates the vectors.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import RelayError
from .keys import StaticKey, x25519_dh

HASHLEN = 32
DHLEN = 32
MAX_NONCE = 2**64 - 1
REKEY_EVERY = 2**20

_IKPSK1 = ([], ["s"], [["e", "es", "s", "ss", "psk"], ["e", "ee", "se"]])
_KK = (["s"], ["s"], [["e", "es", "ss"], ["e", "ee", "se"]])


class ProtocolViolation(RelayError):
    """A frame or message breaks PROTOCOL.md."""


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hkdf(chaining_key: bytes, ikm: bytes, outputs: int) -> list[bytes]:
    temp = hmac.new(chaining_key, ikm, hashlib.sha256).digest()
    out: list[bytes] = []
    previous = b""
    for index in range(1, outputs + 1):
        previous = hmac.new(temp, previous + bytes([index]), hashlib.sha256).digest()
        out.append(previous)
    return out


def _nonce(n: int) -> bytes:
    return b"\x00" * 4 + struct.pack(">Q", n)


def rekey(key: bytes) -> bytes:
    """Noise's ``Rekey()`` for AES-GCM."""
    return AESGCM(key).encrypt(_nonce(MAX_NONCE), b"\x00" * 32, b"")[:32]


class CipherState:
    """A Noise cipher state: an optional key and a 64-bit message counter."""

    def __init__(self, key: bytes | None = None, nonce: int = 0):
        self._key = key
        self._nonce = nonce

    @property
    def key(self) -> bytes | None:
        return self._key

    @property
    def nonce(self) -> int:
        return self._nonce

    def encrypt(self, associated_data: bytes, plaintext: bytes) -> bytes:
        if self._key is None:
            return plaintext
        if self._nonce == MAX_NONCE:
            # PROTOCOL.md §7.3: a session whose nonce would reach 2^64 - 1 is closed.
            raise ProtocolViolation("the transport nonce is exhausted")
        ciphertext = AESGCM(self._key).encrypt(_nonce(self._nonce), plaintext, associated_data)
        self._nonce += 1
        # PROTOCOL.md §7.3: both ends rekey after the frame whose nonce is 2^20 - 1.
        if self._nonce % REKEY_EVERY == 0:
            self._key = rekey(self._key)
        return ciphertext

    def decrypt(self, associated_data: bytes, ciphertext: bytes) -> bytes:
        if self._key is None:
            return ciphertext
        if self._nonce == MAX_NONCE:
            raise ProtocolViolation("the transport nonce is exhausted")
        # A failed tag leaves the counter alone, so a candidate and the current
        # session can each try the same frame (PROTOCOL.md §6.3).
        plaintext = AESGCM(self._key).decrypt(_nonce(self._nonce), ciphertext, associated_data)
        self._nonce += 1
        if self._nonce % REKEY_EVERY == 0:
            self._key = rekey(self._key)
        return plaintext


class HandshakeState:
    """One side of an IKpsk1 or KK handshake."""

    def __init__(
        self,
        pattern: str,
        initiator: bool,
        prologue: bytes,
        static: StaticKey,
        remote_static: bytes | None,
        psk: bytes | None = None,
        ephemeral: bytes | None = None,
    ):
        if pattern == "IKpsk1":
            pre_initiator, pre_responder, self._messages = _IKPSK1
            if psk is None:
                raise ValueError("IKpsk1 needs a psk")
        elif pattern == "KK":
            pre_initiator, pre_responder, self._messages = _KK
        else:
            raise ValueError(f"unsupported Noise pattern {pattern}")
        self._initiator = initiator
        self._static = static
        self._remote_static = remote_static
        self._psk = psk
        self._fixed_ephemeral = ephemeral
        self._ephemeral: bytes | None = None
        self._remote_ephemeral: bytes | None = None
        self._index = 0

        name = f"Noise_{pattern}_25519_AESGCM_SHA256".encode()
        self._h = name.ljust(HASHLEN, b"\x00") if len(name) <= HASHLEN else _sha256(name)
        self._ck = self._h
        self._cipher = CipherState()
        self._psk_mode = pattern == "IKpsk1"
        self._mix_hash(prologue)
        for token in pre_initiator:
            self._mix_hash(static.public if initiator else remote_static)
        for token in pre_responder:
            self._mix_hash(remote_static if initiator else static.public)

    @property
    def handshake_hash(self) -> bytes:
        return self._h

    @property
    def remote_static(self) -> bytes | None:
        return self._remote_static

    def finished(self) -> bool:
        return self._index == len(self._messages)

    def _mix_hash(self, data: bytes | None) -> None:
        if data is None:
            raise ValueError("a pre-message static key is missing")
        self._h = _sha256(self._h + data)

    def _mix_key(self, ikm: bytes) -> None:
        self._ck, key = _hkdf(self._ck, ikm, 2)
        self._cipher = CipherState(key)

    def _mix_key_and_hash(self, ikm: bytes) -> None:
        self._ck, temp_h, key = _hkdf(self._ck, ikm, 3)
        self._mix_hash(temp_h)
        self._cipher = CipherState(key)

    def _encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ciphertext = self._cipher.encrypt(self._h, plaintext)
        self._mix_hash(ciphertext)
        return ciphertext

    def _decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        plaintext = self._cipher.decrypt(self._h, ciphertext)
        self._mix_hash(ciphertext)
        return plaintext

    def _dh(self, token: str) -> bytes:
        # "xy": x belongs to the initiator, y to the responder.
        mine, theirs = (token[0], token[1]) if self._initiator else (token[1], token[0])
        remote = self._remote_ephemeral if theirs == "e" else self._remote_static
        if remote is None:
            raise ProtocolViolation(f"{token} has no remote key")
        private = self._ephemeral if mine == "e" else None
        try:
            if private is not None:
                return x25519_dh(private, remote)
            return self._static.dh(remote)
        except ValueError as error:
            raise ProtocolViolation("a remote X25519 key is invalid") from error

    def write_message(self, payload: bytes = b"") -> bytes:
        if self.finished():
            raise ProtocolViolation("the handshake is already finished")
        out = b""
        for token in self._messages[self._index]:
            if token == "e":
                self._ephemeral = (
                    self._fixed_ephemeral
                    if self._fixed_ephemeral is not None
                    else X25519PrivateKey.generate().private_bytes_raw()
                )
                public = X25519PrivateKey.from_private_bytes(self._ephemeral).public_key().public_bytes_raw()
                out += public
                self._mix_hash(public)
                if self._psk_mode:
                    self._mix_key(public)
            elif token == "s":
                out += self._encrypt_and_hash(self._static.public)
            elif token == "psk":
                assert self._psk is not None
                self._mix_key_and_hash(self._psk)
            else:
                self._mix_key(self._dh(token))
        out += self._encrypt_and_hash(payload)
        self._index += 1
        return out

    def read_message(self, message: bytes) -> bytes:
        if self.finished():
            raise ProtocolViolation("the handshake is already finished")
        for token in self._messages[self._index]:
            if token == "e":
                if len(message) < DHLEN:
                    raise ProtocolViolation("a handshake message is too short")
                self._remote_ephemeral, message = message[:DHLEN], message[DHLEN:]
                self._mix_hash(self._remote_ephemeral)
                if self._psk_mode:
                    self._mix_key(self._remote_ephemeral)
            elif token == "s":
                size = DHLEN + 16 if self._cipher.key is not None else DHLEN
                if len(message) < size:
                    raise ProtocolViolation("a handshake message is too short")
                ciphertext, message = message[:size], message[size:]
                self._remote_static = self._decrypt_and_hash(ciphertext)
            elif token == "psk":
                assert self._psk is not None
                self._mix_key_and_hash(self._psk)
            else:
                self._mix_key(self._dh(token))
        payload = self._decrypt_and_hash(message)
        self._index += 1
        return payload

    def split(self) -> tuple[CipherState, CipherState]:
        if not self.finished():
            raise ProtocolViolation("the handshake is not finished")
        key1, key2 = _hkdf(self._ck, b"", 2)
        return CipherState(key1), CipherState(key2)
