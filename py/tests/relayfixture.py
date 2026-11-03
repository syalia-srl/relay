"""A real Go relay, started the way the conformance suite starts it."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import subprocess
import time
from pathlib import Path

from relay.relays import url_allowed

RELAY_ID = "relay.test"
ISSUER = "test-issuer"
ISSUER_PUBLIC = "5e" * 32
OPERATOR_KEY = "operator-key-0123456789"


def keys_file() -> dict:
    return {
        "relay_id": RELAY_ID,
        "issuers": {ISSUER: ISSUER_PUBLIC},
        "keys": [
            {
                "id": "operator",
                "sha256": hashlib.sha256(OPERATOR_KEY.encode()).hexdigest(),
                "channels": 1000,
                "creates_per_minute": 1000,
                "bytes_per_day": 100_000_000,
            }
        ],
    }


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("0.0.0.0", 0))
        return probe.getsockname()[1]


def private_address() -> str:
    """A private address this machine owns, which the URL policy of §8.1 accepts."""
    configured = os.environ.get("RELAY_TEST_ADDR")
    if configured:
        return configured
    try:
        output = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        output = ""
    for line in output.splitlines():
        fields = line.split()
        if "inet" in fields:
            address = fields[fields.index("inet") + 1].split("/")[0]
            if url_allowed(f"ws://{address}"):
                return address
    raise RuntimeError("no private IPv4 address to serve the relay on; set RELAY_TEST_ADDR")


class Relay:
    """One relay process with its own port, state file and keys file."""

    def __init__(self, root: Path, binary: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.address = private_address()
        self.port = _free_port()
        self.state_path = self.root / "channels.json"
        self.keys_path = self.root / "keys.json"
        self.keys_path.write_text(json.dumps(keys_file()))
        self.log_path = self.root / "relay.log"
        self.binary = binary
        self.log: object | None = None
        self.proc: subprocess.Popen | None = None
        self.start()

    @property
    def url(self) -> str:
        return f"ws://{self.address}:{self.port}"

    @property
    def loopback_http(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        env = os.environ.copy()
        env.update(
            {
                "RELAY_ADDR": f"0.0.0.0:{self.port}",
                "RELAY_STATE_PATH": str(self.state_path),
                "RELAY_KEYS_PATH": str(self.keys_path),
                "RELAY_V0": "off",
            }
        )
        self.log = self.log_path.open("ab")
        self.proc = subprocess.Popen([self.binary], env=env, stdout=self.log, stderr=self.log)
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
        if self.log is not None:
            self.log.close()
            self.log = None

    def logs(self) -> str:
        try:
            return self.log_path.read_text(errors="replace")
        except FileNotFoundError:
            return ""
