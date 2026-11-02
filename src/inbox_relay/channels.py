"""Channels: two-slot pipes, kept across a restart.

The store survives a restart because a paired device has no way to get a new
channel by itself: if the relay forgets one, that phone is dead until its
person pairs it again. What is kept on disk is the channel id and a SHA-256 of
each slot token, never a token, so a copy of the file opens no slot.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field

from fastapi import WebSocket

log = logging.getLogger("inbox_relay.channels")

# A channel whose phone never came is a QR nobody scanned: gone after an hour.
UNCLAIMED_TTL = 3600
# A paired channel with neither side connected for this long is abandoned.
# Long on purpose: an install switched off for a holiday must find it again.
IDLE_TTL = 30 * 24 * 3600


def _token() -> str:
    return secrets.token_hex(32)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class Channel:
    channel_id: str
    hash_mobile: str
    hash_bridge: str
    # The plaintext tokens exist only in the creating request's answer.
    token_mobile: str | None = field(default=None, repr=False)
    token_bridge: str | None = field(default=None, repr=False)
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    mobile_seen: bool = False
    ws_mobile: WebSocket | None = field(default=None, repr=False)
    ws_bridge: WebSocket | None = field(default=None, repr=False)

    def touch(self) -> None:
        self.last_seen = time.time()

    def ws_for_side(self, side: str) -> WebSocket | None:
        return self.ws_mobile if side == "mobile" else self.ws_bridge

    def set_ws(self, side: str, ws: WebSocket | None) -> None:
        if side == "mobile":
            self.ws_mobile = ws
        else:
            self.ws_bridge = ws

    def other_side(self, side: str) -> str:
        return "bridge" if side == "mobile" else "mobile"

    def other_ws(self, side: str) -> WebSocket | None:
        return self.ws_for_side(self.other_side(side))

    def row(self) -> dict:
        return {
            "channel_id": self.channel_id,
            "hash_mobile": self.hash_mobile,
            "hash_bridge": self.hash_bridge,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "mobile_seen": self.mobile_seen,
        }


class ChannelStore:
    def __init__(self, path: str | None = None) -> None:
        self._path = path
        self._channels: dict[str, Channel] = {}
        self._hashes: dict[str, tuple[str, str]] = {}  # sha256(token) -> (channel_id, side)
        if path:
            self._load()

    def __len__(self) -> int:
        return len(self._channels)

    def _index(self, ch: Channel) -> None:
        self._channels[ch.channel_id] = ch
        self._hashes[ch.hash_mobile] = (ch.channel_id, "mobile")
        self._hashes[ch.hash_bridge] = (ch.channel_id, "bridge")

    def _load(self) -> None:
        try:
            with open(self._path) as f:
                rows = json.load(f).get("channels", [])
        except FileNotFoundError:
            return
        for row in rows:
            try:
                self._index(Channel(**row))
            except TypeError:
                continue
        log.info("loaded %d channel(s)", len(self._channels))

    def save(self) -> None:
        if not self._path:
            return
        payload = json.dumps({"channels": [ch.row() for ch in self._channels.values()]})
        tmp = f"{self._path}.{os.getpid()}.tmp"
        try:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
                f.write(payload)
            os.replace(tmp, self._path)
        except OSError:
            log.warning("channel store not writable; channels will not survive a restart")

    def create(self) -> Channel:
        token_mobile, token_bridge = _token(), _token()
        ch = Channel(
            channel_id=_token(),
            hash_mobile=_digest(token_mobile),
            hash_bridge=_digest(token_bridge),
            token_mobile=token_mobile,
            token_bridge=token_bridge,
        )
        self._index(ch)
        self.save()
        return ch

    def get(self, channel_id: str) -> Channel | None:
        return self._channels.get(channel_id)

    def get_by_token(self, token: str) -> tuple[Channel, str] | None:
        entry = self._hashes.get(_digest(token))
        if entry is None:
            return None
        channel_id, side = entry
        ch = self._channels.get(channel_id)
        if ch is None:
            return None
        return ch, side

    def remove(self, channel_id: str) -> None:
        ch = self._channels.pop(channel_id, None)
        if ch:
            self._hashes.pop(ch.hash_mobile, None)
            self._hashes.pop(ch.hash_bridge, None)
            self.save()

    def gc(self, now: float | None = None) -> int:
        """Drop unscanned and abandoned channels; a connected one always stays."""
        now = time.time() if now is None else now
        gone = [
            ch.channel_id for ch in self._channels.values()
            if ch.ws_mobile is None and ch.ws_bridge is None and (
                (not ch.mobile_seen and now - ch.created_at > UNCLAIMED_TTL)
                or now - ch.last_seen > IDLE_TTL
            )
        ]
        for channel_id in gone:
            self.remove(channel_id)
        return len(gone)
