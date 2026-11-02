from __future__ import annotations
import logging
import os
import time

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from .channels import ChannelStore
from .protocol import system_frame, PEER_CONNECTED, PEER_DISCONNECTED

log = logging.getLogger("inbox_relay.router")
router = APIRouter()
store = ChannelStore(os.environ.get("RELAY_STATE_PATH", "/data/channels.json"))

# Anyone can ask for a channel, so creation is bounded: a flood cannot grow the
# store without limit, and unscanned channels leave after an hour (gc).
MAX_CHANNELS = int(os.environ.get("RELAY_MAX_CHANNELS", "50000"))
CREATE_BURST = int(os.environ.get("RELAY_CREATE_BURST", "30"))
CREATE_PER_SECOND = float(os.environ.get("RELAY_CREATE_PER_MINUTE", "30")) / 60

# A slot taken over by a newer socket of the same side (a phone that changed
# networks before its old socket timed out).
CLOSE_REPLACED = 4409


class Bucket:
    def __init__(self, burst: int, rate: float) -> None:
        self.burst, self.rate = burst, rate
        self.level, self.at = float(burst), time.monotonic()

    def take(self) -> bool:
        now = time.monotonic()
        self.level = min(self.burst, self.level + (now - self.at) * self.rate)
        self.at = now
        if self.level < 1:
            return False
        self.level -= 1
        return True


create_bucket = Bucket(CREATE_BURST, CREATE_PER_SECOND)


async def _send_safe(ws: WebSocket, data: bytes) -> None:
    try:
        if ws.client_state == WebSocketState.CONNECTED:
            await ws.send_bytes(data)
    except Exception:
        pass


@router.post("/channels")
async def create_channel():
    if len(store) >= MAX_CHANNELS:
        raise HTTPException(status_code=503, detail="relay full")
    if not create_bucket.take():
        raise HTTPException(status_code=429, detail="too many channels created")
    ch = store.create()
    return {
        "channel_id": ch.channel_id,
        "token_mobile": ch.token_mobile,
        "token_bridge": ch.token_bridge,
    }


@router.websocket("/ws/{channel_id}")
async def ws_endpoint(ws: WebSocket, channel_id: str, token: str = ""):
    # Refused before the handshake completes: a wrong or forgotten slot gets an
    # HTTP 403, never an open socket that a client counts as a connection.
    entry = store.get_by_token(token)
    if entry is None or entry[0].channel_id != channel_id:
        await ws.close(code=4403)
        return
    await ws.accept()

    ch, side = entry
    previous = ch.ws_for_side(side)
    ch.set_ws(side, ws)
    ch.touch()
    if side == "mobile" and not ch.mobile_seen:
        ch.mobile_seen = True
        store.save()
    if previous is not None:
        try:
            await previous.close(code=CLOSE_REPLACED)
        except Exception:
            pass

    # Notify the other side that this peer connected
    other_ws = ch.other_ws(side)
    if other_ws is not None:
        await _send_safe(other_ws, system_frame(PEER_CONNECTED))
        # Also notify this peer that the other side exists
        await _send_safe(ws, system_frame(PEER_CONNECTED))

    try:
        while True:
            data = await ws.receive_bytes()
            ch.touch()
            peer_ws = ch.other_ws(side)
            if peer_ws is not None:
                await _send_safe(peer_ws, data)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        # Only the socket that still holds the slot frees it: a replaced one
        # leaving late must not orphan its successor.
        if ch.ws_for_side(side) is ws:
            ch.set_ws(side, None)
            ch.touch()
            peer_ws = ch.other_ws(side)
            if peer_ws is not None:
                await _send_safe(peer_ws, system_frame(PEER_DISCONNECTED))
        log.info("ws disconnected: channel=%s… side=%s", channel_id[:8], side)
