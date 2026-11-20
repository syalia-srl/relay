"""A JS member (js/src/rooms, run with node) and a Python RoomMember in one room, on the
real relay built from server/ (RELAY_BIN): create, invite, join, both post with a blob,
both read each other's, the notification socket, a state round trip, a custodian's
remove after which the Python member rotates, and an owner's remove of the Python
member after which it reads nothing new.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from relay.rooms import RoomClient, RoomError, RoomMember, _http, new_signing_key, public_jwk, software_device_keys
from relayfixture import Relay, keys_file

DRIVER = Path(__file__).with_name("rooms_js_member.mjs")
CREDENTIAL = "rooms-operator-key-0123456789"


class JsMembers:
    def __init__(self) -> None:
        self.proc = subprocess.Popen(
            ["node", str(DRIVER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
        )

    def __call__(self, member: str, op: str, **args) -> dict:
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps({"id": member, "op": op, **args}) + "\n")
        answer = json.loads(self.proc.stdout.readline())
        if not answer["ok"]:
            raise AssertionError(f"js {member} {op}: {answer['error']}")
        return answer["result"]

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(10)


@pytest.fixture
def rooms_relay(tmp_path: Path, relay_binary: str):
    keys = keys_file()
    keys["keys"].append(
        {
            "id": "rooms",
            "sha256": hashlib.sha256(CREDENTIAL.encode()).hexdigest(),
            "channels": 10,
            "creates_per_minute": 100,
            "bytes_per_day": 100_000_000,
            "rooms": {"max": 10, "stored_bytes": 100_000_000, "retention_days": 30, "blob_bytes": 1_000_000},
        }
    )
    instance = Relay(tmp_path / "relay", relay_binary, keys=keys, env={"RELAY_ROOMS_PATH": str(tmp_path / "rooms.db")})
    try:
        yield instance
    finally:
        instance.stop()


@pytest.fixture
def js():
    if shutil.which("node") is None:
        if os.environ.get("CI"):
            pytest.fail("node is required for the cross-language rooms test")
        pytest.skip("node not found")
    members = JsMembers()
    try:
        yield members
    finally:
        members.close()


def newest_epoch(base: str, token: str, room: str) -> dict:
    answer, _ = _http(base, token, "GET", f"/{room}/epochs?after=0")
    return answer["epochs"][-1]


def test_a_js_member_and_a_python_member_in_one_room(rooms_relay: Relay, js: JsMembers) -> None:
    base = rooms_relay.loopback_http
    custodian_key = new_signing_key()

    # JS a creates the room; the Python member p and JS b join with links a makes.
    a = js("a", "create", baseUrl=base, credential=CREDENTIAL, custodianSignPub=public_jwk(custodian_key))
    sign, recv = software_device_keys()
    p = RoomMember.join(js("a", "invite")["link"], sign_key=sign, recv_key=recv, base_url=base)
    assert newest_epoch(base, a["token"], a["room"])["creator"] == p.device, "the Python joiner made its epoch"
    b = js("b", "join", link=js("a", "invite")["link"], baseUrl=base)

    # Both languages post with a blob, and each reads the other's.
    p.post(b"from python", blob=b"python file")
    js("a", "send", text="from js", file="js file")
    js("b", "send", text="from b")
    seen = p.sync()
    assert [(m.device, m.plaintext, m.status) for m in seen] == [
        (p.device, b"from python", "ok"),
        (a["device"], b"from js", "ok"),
        (b["device"], b"from b", "ok"),
    ]
    assert p.blob(seen[1].blob) == b"js file"
    at_a = js("a", "sync")
    assert [(m["device"], m["text"], m.get("file")) for m in at_a["messages"]] == [
        (p.device, "from python", "python file"),
        (a["device"], "from js", "js file"),
        (b["device"], "from b", None),
    ]
    assert at_a["refused"] == [] and at_a["gaps"] == []

    # The notification socket names the next message's sequence.
    async def hint() -> int:
        stream = p.watch()
        first = asyncio.ensure_future(anext(stream))
        await asyncio.sleep(0.5)  # the socket is open and has sent its tokens
        sent = await asyncio.to_thread(js, "a", "send", text="ping")
        seq = await asyncio.wait_for(first, 10)
        await stream.aclose()
        return seq, sent["seq"]

    got, sent = asyncio.run(hint())
    assert got == sent

    # The member goes on from its sealed state.
    p = RoomMember.from_state(p.state(), sign_key=sign, recv_key=recv)
    assert [m.plaintext for m in p.sync()] == [b"ping"]

    # The custodian (Python, RoomClient) removes b; p makes the next epoch before it posts.
    custodian = a["custodian"]
    RoomClient(base, custodian["token"], room=a["room"], device=custodian["device"], key=custodian_key).remove(
        b["device"]
    )
    p.post(b"b has left")
    newest = newest_epoch(base, a["token"], a["room"])
    assert newest["creator"] == p.device
    assert set(newest["wraps"]) == {a["device"], p.device}
    at_a = js("a", "sync")
    assert [(m["text"], m["epoch"]) for m in at_a["messages"]][-1] == ("b has left", newest["n"])
    with pytest.raises(AssertionError, match="401"):
        js("b", "sync")

    # The JS owner removes p and rotates; p reads nothing new.
    assert js("a", "remove", devices=[p.device])["failed"] == []
    js("a", "send", text="p has left")
    newest = newest_epoch(base, a["token"], a["room"])
    assert newest["creator"] == a["device"]
    assert set(newest["wraps"]) == {a["device"]}
    with pytest.raises(RoomError) as caught:
        p.sync()
    assert caught.value.status == 401
    assert newest["n"] not in p.epoch_keys
