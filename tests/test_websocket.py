# tests/test_websocket.py
import json
import pytest
from fastapi.testclient import TestClient
from inbox_relay.main import app

client = TestClient(app)


def test_create_channel():
    r = client.post("/channels")
    assert r.status_code == 200
    body = r.json()
    assert "channel_id" in body
    assert "token_mobile" in body
    assert "token_bridge" in body


def test_ws_rejects_bad_token():
    r = client.post("/channels")
    ch = r.json()
    with client.websocket_connect(
        f"/ws/{ch['channel_id']}?token=bad"
    ) as ws:
        # Should be closed immediately
        with pytest.raises(Exception):
            ws.receive_bytes()


def test_ws_relay_message():
    r = client.post("/channels")
    ch = r.json()
    payload = b'\x01' + b'hello encrypted'

    with (
        client.websocket_connect(f"/ws/{ch['channel_id']}?token={ch['token_mobile']}") as ws_m,
        client.websocket_connect(f"/ws/{ch['channel_id']}?token={ch['token_bridge']}") as ws_b,
    ):
        # mobile sends, bridge receives peer_connected first then data
        peer_connected = ws_b.receive_bytes()
        assert peer_connected[0:1] == b'\x00'
        event = json.loads(peer_connected[1:])
        assert event["event"] == "peer_connected"

        ws_m.send_bytes(payload)
        received = ws_b.receive_bytes()
        assert received == payload


def test_ws_presence_on_disconnect():
    r = client.post("/channels")
    ch = r.json()

    with client.websocket_connect(
        f"/ws/{ch['channel_id']}?token={ch['token_bridge']}"
    ) as ws_b:
        with client.websocket_connect(
            f"/ws/{ch['channel_id']}?token={ch['token_mobile']}"
        ) as ws_m:
            # bridge gets peer_connected
            msg = ws_b.receive_bytes()
            assert json.loads(msg[1:])["event"] == "peer_connected"
        # mobile disconnected → bridge gets peer_disconnected
        msg = ws_b.receive_bytes()
        assert json.loads(msg[1:])["event"] == "peer_disconnected"
