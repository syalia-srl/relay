"""A minimal Noise Protocol Framework (revision 34) for generating test vectors.

Only what the channel protocol uses: the patterns IKpsk1 and KK with the suite
25519_AESGCM_SHA256. Written from the specification, checked against the
published cacophony vectors and against the noiseprotocol package. It is a
reference for vectors, not a library to ship.
"""

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HASHLEN = 32
DHLEN = 32
MAX_NONCE = 2**64 - 1

PATTERNS = {
    # name: (initiator pre-message, responder pre-message, message patterns)
    "IKpsk1": ([], ["s"], [["e", "es", "s", "ss", "psk"], ["e", "ee", "se"]]),
    "KK": (["s"], ["s"], [["e", "es", "ss"], ["e", "ee", "se"]]),
}


def public_key(private: bytes) -> bytes:
    key = X25519PrivateKey.from_private_bytes(private).public_key()
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def dh(private: bytes, public: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(public))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf(chaining_key: bytes, ikm: bytes, outputs: int) -> list[bytes]:
    temp = hmac.new(chaining_key, ikm, hashlib.sha256).digest()
    out, prev = [], b""
    for i in range(1, outputs + 1):
        prev = hmac.new(temp, prev + bytes([i]), hashlib.sha256).digest()
        out.append(prev)
    return out


def nonce_bytes(n: int) -> bytes:
    return b"\x00" * 4 + struct.pack(">Q", n)


class CipherState:
    def __init__(self, key: bytes | None = None):
        self.k = key
        self.n = 0

    def encrypt(self, ad: bytes, plaintext: bytes) -> bytes:
        if self.k is None:
            return plaintext
        if self.n == MAX_NONCE:
            raise ValueError("nonce exhausted")
        out = AESGCM(self.k).encrypt(nonce_bytes(self.n), plaintext, ad)
        self.n += 1
        return out

    def decrypt(self, ad: bytes, ciphertext: bytes) -> bytes:
        if self.k is None:
            return ciphertext
        if self.n == MAX_NONCE:
            raise ValueError("nonce exhausted")
        out = AESGCM(self.k).decrypt(nonce_bytes(self.n), ciphertext, ad)  # raises InvalidTag
        self.n += 1
        return out

    def rekey(self) -> None:
        self.k = rekey(self.k)


def rekey(key: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce_bytes(MAX_NONCE), b"\x00" * 32, b"")[:32]


class HandshakeState:
    def __init__(self, pattern: str, initiator: bool, prologue: bytes, s: bytes, rs: bytes | None,
                 psk: bytes | None = None, e: bytes | None = None):
        self.pattern = pattern
        self.initiator = initiator
        self.s, self.rs, self.psk = s, rs, psk
        self.fixed_e = e
        self.e = self.re = None
        name = f"Noise_{pattern}_25519_AESGCM_SHA256".encode()
        self.h = name.ljust(HASHLEN, b"\x00") if len(name) <= HASHLEN else sha256(name)
        self.ck = self.h
        self.cipher = CipherState()
        self.psk_mode = "psk" in pattern
        self.mix_hash(prologue)
        pre_i, pre_r, self.messages = PATTERNS[pattern]
        for token in pre_i:
            assert token == "s"
            self.mix_hash(public_key(s) if initiator else rs)
        for token in pre_r:
            assert token == "s"
            self.mix_hash(rs if initiator else public_key(s))
        self.index = 0

    def mix_hash(self, data: bytes) -> None:
        self.h = sha256(self.h + data)

    def mix_key(self, ikm: bytes) -> None:
        self.ck, k = hkdf(self.ck, ikm, 2)
        self.cipher = CipherState(k)

    def mix_key_and_hash(self, ikm: bytes) -> None:
        self.ck, temp_h, k = hkdf(self.ck, ikm, 3)
        self.mix_hash(temp_h)
        self.cipher = CipherState(k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        ct = self.cipher.encrypt(self.h, plaintext)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        pt = self.cipher.decrypt(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return pt

    def _dh(self, token: str) -> bytes:
        # token "xy": x is the initiator's key, y the responder's.
        mine, theirs = (token[0], token[1]) if self.initiator else (token[1], token[0])
        private = self.e if mine == "e" else self.s
        remote = self.re if theirs == "e" else self.rs
        return dh(private, remote)

    def write_message(self, payload: bytes = b"") -> bytes:
        out = b""
        for token in self.messages[self.index]:
            if token == "e":
                self.e = self.fixed_e if self.fixed_e is not None else X25519PrivateKey.generate().private_bytes_raw()
                pub = public_key(self.e)
                out += pub
                self.mix_hash(pub)
                if self.psk_mode:
                    self.mix_key(pub)
            elif token == "s":
                out += self.encrypt_and_hash(public_key(self.s))
            elif token == "psk":
                self.mix_key_and_hash(self.psk)
            else:
                self.mix_key(self._dh(token))
        out += self.encrypt_and_hash(payload)
        self.index += 1
        return out

    def read_message(self, message: bytes) -> bytes:
        for token in self.messages[self.index]:
            if token == "e":
                self.re, message = message[:DHLEN], message[DHLEN:]
                self.mix_hash(self.re)
                if self.psk_mode:
                    self.mix_key(self.re)
            elif token == "s":
                size = DHLEN + 16 if self.cipher.k is not None else DHLEN
                ct, message = message[:size], message[size:]
                self.rs = self.decrypt_and_hash(ct)
            elif token == "psk":
                self.mix_key_and_hash(self.psk)
            else:
                self.mix_key(self._dh(token))
        payload = self.decrypt_and_hash(message)
        self.index += 1
        return payload

    def finished(self) -> bool:
        return self.index == len(self.messages)

    def split(self) -> tuple[CipherState, CipherState]:
        k1, k2 = hkdf(self.ck, b"", 2)
        return CipherState(k1), CipherState(k2)
