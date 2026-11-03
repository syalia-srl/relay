import os

import pytest

from relaytest import Relay

if "RELAY_BIN" not in os.environ:
    pytest.exit("set RELAY_BIN to the relay binary under test", returncode=2)


@pytest.fixture
def make_relay(tmp_path):
    """A relay of its own, with extra environment when a test needs it."""
    created: list[Relay] = []

    def make(**env: str) -> Relay:
        relay = Relay(tmp_path / f"relay{len(created)}", env)
        created.append(relay)
        return relay

    yield make
    for relay in created:
        relay.stop()


@pytest.fixture
def relay(make_relay):
    return make_relay()
