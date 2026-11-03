"""Fixtures shared by the library's tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from relayfixture import Relay

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def relay_binary() -> str:
    binary = os.environ.get("RELAY_BIN") or str(ROOT / "server" / "relay")
    if not Path(binary).exists():
        pytest.fail(f"build the Go relay or set RELAY_BIN (looked for {binary})")
    return binary


@pytest.fixture
def relay(tmp_path: Path, relay_binary: str):
    instance = Relay(tmp_path / "relay", relay_binary)
    try:
        yield instance
    finally:
        instance.stop()
