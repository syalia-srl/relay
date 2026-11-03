#!/usr/bin/env python3
"""Run the three worked examples against one freshly started relay.

The relay listens on a private address, because a guest accepts `ws://` only to
one (PROTOCOL.md 8.1). Set RELAY_BIN to the built binary, or build
`server/relay` first. Set RELAY_TEST_ADDR to skip the address search.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KEY = "example-key"


def private_address() -> str:
    configured = os.environ.get("RELAY_TEST_ADDR")
    if configured:
        return configured
    output = subprocess.run(
        ["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, check=True
    ).stdout
    for line in output.splitlines():
        fields = line.split()
        if "inet" not in fields:
            continue
        address = fields[fields.index("inet") + 1].split("/")[0]
        if address.startswith(("10.", "192.168.")) or address.startswith("172."):
            return address
    raise SystemExit("no private IPv4 address; set RELAY_TEST_ADDR")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("", 0))
        return probe.getsockname()[1]


def wait_until_up(url: str) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1):
                return
        except urllib.error.HTTPError:
            return
        except OSError:
            time.sleep(0.1)
    raise SystemExit(f"the relay did not answer at {url}")


def main() -> int:
    binary = os.environ.get("RELAY_BIN") or str(ROOT / "server" / "relay")
    if not Path(binary).exists():
        raise SystemExit(f"build the relay or set RELAY_BIN (looked for {binary})")
    address = private_address()
    port = free_port()
    with tempfile.TemporaryDirectory() as directory:
        keys = Path(directory) / "keys.json"
        keys.write_text(
            json.dumps(
                {
                    "relay_id": "relay.example",
                    "issuers": {},
                    "keys": [
                        {
                            "id": "example",
                            "sha256": hashlib.sha256(KEY.encode()).hexdigest(),
                            "unlimited": True,
                        }
                    ],
                }
            )
        )
        environment = os.environ | {
            "RELAY_ADDR": f"{address}:{port}",
            "RELAY_STATE_PATH": str(Path(directory) / "channels.json"),
            "RELAY_KEYS_PATH": str(keys),
            "RELAY_URL": f"ws://{address}:{port}",
            "RELAY_KEY": KEY,
        }
        relay = subprocess.Popen([binary], env=environment)
        try:
            wait_until_up(f"http://{address}:{port}/")
            runs = [
                (
                    "python",
                    [
                        "uv",
                        "run",
                        "--project",
                        str(ROOT / "py"),
                        "python",
                        str(ROOT / "py" / "examples" / "echo.py"),
                    ],
                    ROOT,
                ),
                ("javascript", ["node", "examples/echo.mjs"], ROOT / "js"),
                (
                    "go",
                    ["go", "run", "./examples/echo"],
                    ROOT / "go",
                ),
            ]
            for name, command, cwd in runs:
                print(f"--- {name}", flush=True)
                subprocess.run(command, cwd=cwd, env=environment, check=True)
        finally:
            relay.terminate()
            relay.wait(timeout=10)
    print(f"3 examples passed against one relay")
    return 0


if __name__ == "__main__":
    sys.exit(main())
