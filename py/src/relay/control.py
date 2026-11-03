"""Control messages of PROTOCOL.md section 9.1."""

from __future__ import annotations

import json
from dataclasses import dataclass

from .errors import ProtocolViolation
from .relays import RelayEntry, url_allowed
from .strictjson import loads

# The side entitled to send each op; None means either side.
_SENDERS = {
    "relays": "host",
    "close": "guest",
    "closed": "host",
    "revoked": "host",
    "ping": None,
    "pong": None,
}


@dataclass(frozen=True)
class Control:
    op: str
    relays: tuple[RelayEntry, ...] = ()


def parse_control(text: str, receiver: str) -> Control | None:
    """Apply, ignore (None) or abort (raise) one control message."""
    try:
        value = loads(text)
    except ValueError as error:
        raise ProtocolViolation("the control message is not JSON") from error
    if not isinstance(value, dict) or not isinstance(value.get("op"), str):
        raise ProtocolViolation("the control message has no op")
    op = value["op"]
    if op not in _SENDERS:
        return None
    sender = _SENDERS[op]
    if sender is not None and sender == receiver:
        raise ProtocolViolation(f"{op} came from the wrong side")
    if op != "relays":
        return Control(op)
    raw = value.get("relays")
    if not isinstance(raw, list) or not 1 <= len(raw) <= 16:
        raise ProtocolViolation("invalid relay list")
    entries: list[RelayEntry] = []
    for item in raw:
        entry = RelayEntry.from_json(item)
        if entry is None:
            raise ProtocolViolation("invalid relay entry")
        entries.append(entry)
    kept = tuple(entry for entry in entries if url_allowed(entry.url))
    # PROTOCOL.md §8.3: filter the list as a whole and ignore it if nothing is left.
    return Control(op="relays", relays=kept) if kept else None


def encode_control(op: str, relays: tuple[RelayEntry, ...] | None = None) -> bytes:
    value: dict[str, object] = {"op": op}
    if relays is not None:
        value["relays"] = [entry.to_json() for entry in relays]
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
