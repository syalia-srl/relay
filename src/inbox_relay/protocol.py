import json

SIDE_MOBILE = "mobile"
SIDE_BRIDGE = "bridge"

def system_frame(event: str) -> bytes:
    """Build a relay system message frame."""
    return b'\x00' + json.dumps({"type": "system", "event": event}).encode()

PEER_CONNECTED = "peer_connected"
PEER_DISCONNECTED = "peer_disconnected"
