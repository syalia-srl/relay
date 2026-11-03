"""The pairing payload of PROTOCOL.md section 4."""

from __future__ import annotations

import json
import time

from .errors import PayloadInvalid
from .relays import RelayEntry, url_allowed
from .strictjson import is_hex64, is_integer, loads

_DEVICE_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


def _valid_device(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 64 and all(char in _DEVICE_CHARS for char in value)


class Payload:
    """Everything a guest needs for the first contact, kept out of the relay."""

    __slots__ = ("dev", "expires", "host_public", "psk", "relays")

    def __init__(
        self, dev: str, host_public: bytes, psk: bytes, expires: int, relays: tuple[RelayEntry, ...]
    ):
        self.dev = dev
        self.host_public = host_public
        self.psk = psk
        self.expires = expires
        self.relays = relays

    def encode(self) -> str:
        value = {
            "v": 3,
            "hs": self.host_public.hex(),
            "psk": self.psk.hex(),
            "dev": self.dev,
            "exp": self.expires,
            "relays": [entry.to_json() for entry in self.relays],
        }
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def parse_payload(text: str, now: int | None = None) -> Payload:
    """Check a payload as a guest and keep the relays that pass section 8.1."""
    if now is None:
        now = int(time.time())
    try:
        value = loads(text)
    except ValueError as error:
        raise PayloadInvalid("the payload is not JSON") from error
    if not isinstance(value, dict):
        raise PayloadInvalid("the payload is not an object")
    if not is_integer(value.get("v")) or value["v"] != 3:
        raise PayloadInvalid("unknown payload version")
    if not is_hex64(value.get("hs")):
        raise PayloadInvalid("invalid host public key")
    if not is_hex64(value.get("psk")):
        raise PayloadInvalid("invalid pairing secret")
    dev = value.get("dev")
    if not isinstance(dev, str) or not _valid_device(dev):
        raise PayloadInvalid("invalid device id")
    expires = value.get("exp")
    if not is_integer(expires):
        raise PayloadInvalid("invalid expiry")
    # PROTOCOL.md §4: a guest SHOULD refuse a payload past exp by more than 60 s.
    if now > expires + 60:
        raise PayloadInvalid("the pairing payload has expired")
    name = value.get("name")
    if name is not None and (not isinstance(name, str) or len(name) > 100):
        raise PayloadInvalid("invalid name")
    url = value.get("url")
    if url is not None and (not isinstance(url, str) or len(url) > 2048):
        raise PayloadInvalid("invalid url")

    raw_relays = value.get("relays")
    if not isinstance(raw_relays, list) or not 1 <= len(raw_relays) <= 16:
        raise PayloadInvalid("invalid relay list")
    entries: list[RelayEntry] = []
    for raw in raw_relays:
        entry = RelayEntry.from_json(raw)
        if entry is None:
            raise PayloadInvalid("invalid relay entry")
        entries.append(entry)
    kept = tuple(entry for entry in entries if url_allowed(entry.url))
    if not kept:
        raise PayloadInvalid("no relay passes the URL policy")

    return Payload(
        dev=dev,
        host_public=bytes.fromhex(value["hs"]),
        psk=bytes.fromhex(value["psk"]),
        expires=expires,
        relays=kept,
    )
