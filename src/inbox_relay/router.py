from __future__ import annotations
import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from .channels import Channel, ChannelStore
from .protocol import system_frame, PEER_CONNECTED, PEER_DISCONNECTED

log = logging.getLogger("inbox_relay.router")
router = APIRouter()
store = ChannelStore()


async def _send_safe(ws: WebSocket, data: bytes) -> None:
    try:
        if ws.client_state == WebSocketState.CONNECTED:
            await ws.send_bytes(data)
    except Exception:
        pass


@router.post("/channels")
async def create_channel():
    ch = store.create()
    return {
        "channel_id": ch.channel_id,
        "token_mobile": ch.token_mobile,
        "token_bridge": ch.token_bridge,
    }


@router.websocket("/ws/{channel_id}")
async def ws_endpoint(ws: WebSocket, channel_id: str, token: str = ""):
    await ws.accept()

    entry = store.get_by_token(token)
    if entry is None or entry[0].channel_id != channel_id:
        await ws.close(code=4403)
        return

    ch, side = entry
    ch.set_ws(side, ws)
    ch.touch()

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
    except WebSocketDisconnect:
        pass
    finally:
        ch.set_ws(side, None)
        # Notify other side of disconnection
        peer_ws = ch.other_ws(side)
        if peer_ws is not None:
            await _send_safe(peer_ws, system_frame(PEER_DISCONNECTED))
        log.info("ws disconnected: channel=%s side=%s", channel_id, side)
