"""Relay tokens of PROTOCOL.md section 2.2.

The relay checks tokens, not the host or the guest; this module exists so the
whole of ``vectors/relay_token.json`` is checked against the library too.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .strictjson import is_integer, loads

MAX_TOKEN = 4096
_STRINGS = {"iss": 64, "aud": 64, "sub": 128}
_INTEGERS = ("exp", "channels", "creates_per_minute", "bytes_per_day")


def _decode(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)


def verify_relay_token(token: str, issuers: dict[str, bytes], relay_id: str, now: int) -> bool:
    """Whether ``token`` is valid for ``relay_id`` at ``now``."""
    if not isinstance(token, str) or len(token.encode("utf-8")) > MAX_TOKEN:
        return False
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "rt1":
        return False
    try:
        payload = _decode(parts[1])
        signature = _decode(parts[2])
        claims: Any = loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return False
    if not isinstance(claims, dict):
        return False
    for field, length in _STRINGS.items():
        value = claims.get(field)
        if not isinstance(value, str) or not 1 <= len(value) <= length:
            return False
    if any(not is_integer(claims.get(field)) for field in _INTEGERS):
        return False
    if claims["iss"] not in issuers or claims["aud"] != relay_id:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(issuers[claims["iss"]]).verify(
            signature, f"rt1.{parts[1]}".encode("ascii")
        )
    except (InvalidSignature, ValueError, TypeError):
        return False
    return claims["exp"] > now
