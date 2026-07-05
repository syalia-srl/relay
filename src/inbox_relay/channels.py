from __future__ import annotations
import secrets
import time
from dataclasses import dataclass, field
from fastapi import WebSocket


def _token() -> str:
    return secrets.token_hex(32)


@dataclass
class Channel:
    channel_id: str
    token_mobile: str
    token_bridge: str
    ws_mobile: WebSocket | None = field(default=None, repr=False)
    ws_bridge: WebSocket | None = field(default=None, repr=False)
    last_activity: float = field(default_factory=time.monotonic)

    def touch(self) -> None:
        self.last_activity = time.monotonic()

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


class ChannelStore:
    def __init__(self) -> None:
        self._channels: dict[str, Channel] = {}
        self._tokens: dict[str, tuple[str, str]] = {}  # token -> (channel_id, side)

    def create(self) -> Channel:
        ch = Channel(
            channel_id=_token(),
            token_mobile=_token(),
            token_bridge=_token(),
        )
        self._channels[ch.channel_id] = ch
        self._tokens[ch.token_mobile] = (ch.channel_id, "mobile")
        self._tokens[ch.token_bridge] = (ch.channel_id, "bridge")
        return ch

    def get(self, channel_id: str) -> Channel | None:
        return self._channels.get(channel_id)

    def get_by_token(self, token: str) -> tuple[Channel, str] | None:
        entry = self._tokens.get(token)
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
            self._tokens.pop(ch.token_mobile, None)
            self._tokens.pop(ch.token_bridge, None)
