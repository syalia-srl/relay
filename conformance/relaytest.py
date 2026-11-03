"""A black-box relay: the suite only speaks HTTP and WebSocket to it."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import socket
import subprocess
import time
from base64 import urlsafe_b64encode
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

RELAY_ID = "relay.test"
ISSUER = "test-issuer"

# A fixed seed keeps the fixture keys stable; only the clock moves.
ISSUER_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("5e" * 32))
ISSUER_PUB = ISSUER_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

OPERATOR_KEY = "operator-key-0123456789"
LOCAL_KEY = "local-unlimited-key"


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def keys_file(keys: list[dict] | None = None) -> dict:
    if keys is None:
        keys = [
            {
                "id": "operator",
                "sha256": sha256_hex(OPERATOR_KEY),
                "channels": 1000,
                "creates_per_minute": 1000,
                "bytes_per_day": 100_000_000,
            },
            # An install's own relay.
            {"id": "local", "sha256": sha256_hex(LOCAL_KEY), "unlimited": True},
        ]
    return {"relay_id": RELAY_ID, "issuers": {ISSUER: ISSUER_PUB}, "keys": keys}


def b64(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def mint(
    sub: str = "s-1",
    *,
    iss: str = ISSUER,
    aud: str = RELAY_ID,
    exp: int | None = None,
    channels: int = 100,
    creates_per_minute: int = 100,
    bytes_per_day: int = 100_000,
    key: Ed25519PrivateKey = ISSUER_KEY,
    payload: bytes | None = None,
) -> str:
    """Mint an rt1 token the way an issuer would."""
    if exp is None:
        exp = int(time.time()) + 3600
    if payload is None:
        payload = json.dumps(
            {
                "iss": iss,
                "aud": aud,
                "sub": sub,
                "exp": exp,
                "channels": channels,
                "creates_per_minute": creates_per_minute,
                "bytes_per_day": bytes_per_day,
            },
            separators=(",", ":"),
        ).encode()
    body = b64(payload)
    signature = key.sign(b"rt1." + body.encode())
    return f"rt1.{body}.{b64(signature)}"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Relay:
    """One relay process with its own port, state file and keys file."""

    def __init__(self, root: Path, env: dict[str, str] | None = None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        self.state_path = self.root / "channels.json"
        self.keys_path = self.root / "keys.json"
        self.keys_path.write_text(json.dumps(keys_file()))
        self.log_path = self.root / "relay.log"
        self.extra_env = dict(env or {})
        self.proc: subprocess.Popen | None = None
        self.start()

    def start(self) -> None:
        env = os.environ.copy()
        env.update(
            {
                "RELAY_ADDR": f"127.0.0.1:{self.port}",
                "RELAY_STATE_PATH": str(self.state_path),
                "RELAY_KEYS_PATH": str(self.keys_path),
                "RELAY_V0": "on",
            }
        )
        env.update(self.extra_env)
        binary = os.environ["RELAY_BIN"]
        self.log = self.log_path.open("ab")
        self.proc = subprocess.Popen(
            [binary],
            env=env,
            stdout=self.log,
            stderr=self.log,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"the relay exited at once:\n{self.logs()}")
            with socket.socket() as probe:
                probe.settimeout(0.1)
                if probe.connect_ex(("127.0.0.1", self.port)) == 0:
                    return
            time.sleep(0.02)
        self.stop()
        raise RuntimeError(f"the relay never listened:\n{self.logs()}")

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        self.proc = None
        self.log.close()

    def restart(self) -> None:
        self.stop()
        self.start()

    def logs(self) -> str:
        try:
            return self.log_path.read_text(errors="replace")
        except FileNotFoundError:
            return ""

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def ws_url(self, path: str) -> str:
        return f"ws://127.0.0.1:{self.port}{path}"

    def create_v0(self) -> dict:
        response = httpx.post(self.url("/channels"))
        assert response.status_code == 200, response.text
        return response.json()

    def create_v1(self, key: str) -> httpx.Response:
        return httpx.post(
            self.url("/v1/channels"),
            headers={"Authorization": f"Bearer {key}"},
        )

    def channel_v1(self, key: str = OPERATOR_KEY) -> dict:
        response = self.create_v1(key)
        assert response.status_code == 201, response.text
        return response.json()


@asynccontextmanager
async def ws_connect(relay: Relay, path: str, origin: str | None = None):
    websocket = await connect(relay.ws_url(path), max_size=None, origin=origin)
    try:
        yield websocket
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@asynccontextmanager
async def v1_socket(relay: Relay, channel_id: str, token: str | None = None):
    async with ws_connect(relay, f"/v1/ws/{channel_id}") as websocket:
        if token is not None:
            await websocket.send(json.dumps({"auth": token}))
        yield websocket


async def recv(websocket, timeout: float = 5) -> bytes:
    return await asyncio.wait_for(websocket.recv(), timeout)


async def read_event(websocket, timeout: float = 5) -> str:
    """The next frame must be a system frame; return its event."""
    frame = await recv(websocket, timeout)
    assert isinstance(frame, bytes), frame
    assert frame[:1] == b"\x00", frame
    return json.loads(frame[1:])["event"]


def close_code(closed: ConnectionClosed) -> int:
    """The code the peer sent, or 1006 when the socket just died."""
    return closed.rcvd.code if closed.rcvd is not None else 1006


async def expect_close(websocket, code: int, timeout: float = 5) -> None:
    """Drain frames until the socket closes, and insist on the code."""
    try:
        while True:
            await asyncio.wait_for(websocket.recv(), timeout)
    except ConnectionClosed as closed:
        assert close_code(closed) == code, f"closed with {close_code(closed)}, want {code}"
