"""relay.rooms: the rooms vectors it covers (encoding, roster) and RoomClient against a stub mailbox."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.serialization import load_der_private_key
from relay.rooms import (
    RoomClient,
    RoomError,
    RosterInvalid,
    canonical,
    new_signing_key,
    public_jwk,
    record_hash,
    sign_entry,
    unb64,
    verify_roster,
    verify_signature,
)
from relay.rooms import _join_body, _sign  # the join is the joiner's to sign; the test plays the joiner

VECTORS = Path(__file__).resolve().parents[2] / "vectors"


def load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / name).read_text())


def test_canonical_json() -> None:
    for case in load("rooms_encoding.json")["canonical"]:
        assert canonical(case["object"]) == case["canonical"]


def test_signatures_to_accept_and_refuse() -> None:
    for case in load("rooms_encoding.json")["signatures"]:
        assert verify_signature(case["public_jwk"], case["object"], case["sig"]) is case["valid"], case["name"]


def test_public_jwk_is_reduced() -> None:
    v = load("rooms_encoding.json")["public_jwk"]
    key = load_der_private_key(_pkcs8_from_jwk(v["jwk"]), None)
    assert public_jwk(key) == v["reduced"]


def _pkcs8_from_jwk(jwk: dict) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.derive_private_key(int.from_bytes(unb64(jwk["d"]), "big"), ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def test_valid_roster_replays_to_its_state() -> None:
    v = load("rooms_roster.json")
    roster = verify_roster(v["valid"]["records"], room=v["room"])
    assert roster.state() == v["valid"]["state"]


@pytest.mark.parametrize("case", load("rooms_roster.json")["refused"], ids=lambda c: c["name"])
def test_refused_rosters(case: dict) -> None:
    with pytest.raises(RosterInvalid) as caught:
        verify_roster(case["records"])
    assert (caught.value.index, caught.value.reason) == (case["first_invalid"], case["reason"])
    assert caught.value.roster.n == case["first_invalid"]


def test_another_rooms_roster_is_refused() -> None:
    v = load("rooms_roster.json")
    with pytest.raises(RosterInvalid) as caught:
        verify_roster(v["valid"]["records"], room="AAAAAAAAAAAAAAAAAAAAAA")
    assert (caught.value.index, caught.value.reason) == (0, "room")


def test_sign_entry_verifies_and_chains() -> None:
    creator, custodian = new_signing_key(), new_signing_key()
    genesis = {
        "kind": "genesis",
        "by": "AAAAAAAAAAAAAAAAAAAAAA",
        "room": "QkF6e-ZNRW8V6NXMuzu1bw",
        "creator": {"device": "AAAAAAAAAAAAAAAAAAAAAA", "sign_pub": public_jwk(creator), "recv_pub": public_jwk(new_signing_key())},
        "custodian": {"device": "BBBBBBBBBBBBBBBBBBBBBA", "sign_pub": public_jwk(custodian)},
    }
    first = sign_entry(creator, genesis, 1, "")
    roster = verify_roster([first])
    assert roster.head == record_hash(first)
    second = sign_entry(custodian, {"kind": "remove", "by": "BBBBBBBBBBBBBBBBBBBBBA", "devices": ["AAAAAAAAAAAAAAAAAAAAAA"]}, 2, roster.head)
    after = verify_roster([first, second])  # the custodian, an owner, removes the creator
    assert after.devices["AAAAAAAAAAAAAAAAAAAAAA"]["status"] == "removed"
    assert after.readers() == []
    forged = sign_entry(creator, second["entry"], 2, roster.head)  # signed by a key that is not `by`'s
    with pytest.raises(RosterInvalid) as caught:
        verify_roster([first, forged])
    assert (caught.value.index, caught.value.reason) == (1, "signature")


# --- RoomClient against a stub of the mailbox routes it calls ---


class Stub:
    """Just the routes RoomClient calls, as ROOMS.md 3.4 describes them, for one room."""

    def __init__(self, room: str) -> None:
        self.room, self.roster, self.calls = room, [], []
        self.revoked: set[str] = set()
        self.owners: dict[str, bool] = {}
        self.deleted = False
        self.before_post: Any = None
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _answer(self, status: int, body: Any = None) -> None:
                self.send_response(status)
                self.send_header("Relay-Room-Watermark", "1")
                data = b"" if body is None else json.dumps(body).encode()
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _route(self) -> None:
                size = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(size)) if size else None
                path = self.path.split("?")[0]
                stub.calls.append((self.command, path.removeprefix(f"/v1/rooms/{stub.room}"), body))
                if self.headers.get("Authorization") != "Bearer custodian-token":
                    return self._answer(401, {"error": "unauthorized"})
                if stub.deleted:
                    return self._answer(410, {"error": "gone"})
                rest = path.removeprefix(f"/v1/rooms/{stub.room}")
                if rest == "/roster" and self.command == "GET":
                    return self._answer(200, {"entries": [{**r, "signer": "x"} for r in stub.roster]})
                if rest == "/roster" and self.command == "POST":
                    if stub.before_post:
                        stub.before_post(body)
                    if body["n"] != len(stub.roster) + 1:
                        return self._answer(409, {"error": "conflict"})
                    stub.roster.append(body)
                    return self._answer(201, {})
                if rest == "/invites" and self.command == "POST":
                    return self._answer(201, {"invite": "InviteIdOfTheRelay0000", "token": "T" * 43})
                if rest.startswith("/invites/") and self.command == "DELETE":
                    return self._answer(204)
                if rest.startswith("/devices/") and self.command == "DELETE":
                    stub.revoked.add(rest.split("/")[-1])
                    return self._answer(204)
                if rest == "/owners" and self.command == "POST":
                    stub.owners[body["device"]] = body["owner"]
                    return self._answer(204)
                if rest == "" and self.command == "GET":
                    return self._answer(200, {"room": stub.room, "devices": [], "limits": {}, "stored_bytes": 0,
                                              "read_only_since": None})
                if rest == "" and self.command == "DELETE":
                    stub.deleted = True
                    return self._answer(204)
                return self._answer(404, {"error": "not_found"})

            do_GET = do_POST = do_DELETE = _route

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def room() -> Any:
    room_id = "QkF6e-ZNRW8V6NXMuzu1bw"
    stub = Stub(room_id)
    creator, custodian = new_signing_key(), new_signing_key()
    a, k = "AAAAAAAAAAAAAAAAAAAAAA", "KKKKKKKKKKKKKKKKKKKKKA"
    genesis = {
        "kind": "genesis",
        "by": a,
        "room": room_id,
        "creator": {"device": a, "sign_pub": public_jwk(creator), "recv_pub": public_jwk(new_signing_key())},
        "custodian": {"device": k, "sign_pub": public_jwk(custodian)},
    }
    stub.roster.append(sign_entry(creator, genesis, 1, ""))
    client = RoomClient(stub.url, "custodian-token", room=room_id, device=k, key=custodian)
    yield stub, client
    stub.server.shutdown()


def test_room_client_invites_promotes_and_removes(room: Any) -> None:
    stub, client = room
    expires = int(time.time()) + 86400
    made = client.invite(2, expires)
    assert made["fragment"].startswith(f"v1.127.0.0.1:{stub.server.server_address[1]}.{client.room}.")
    assert ("POST", "/invites", {"uses": 2, "expires_at": expires}) in stub.calls

    # A device joins with the link's invite key.
    invite_key = load_der_private_key(unb64(made["invite_key"]), None)
    joiner, b = new_signing_key(), "BBBBBBBBBBBBBBBBBBBBBA"
    join = {"kind": "join", "by": b, "invite": made["invite_key_id"], "device": b, "at": expires - 10,
            "sign_pub": public_jwk(joiner), "recv_pub": public_jwk(new_signing_key())}
    join["invite_sig"] = _sign(invite_key, _join_body(join))
    roster = client.roster()
    stub.roster.append(sign_entry(joiner, join, roster.n + 1, roster.head))

    client.set_owner(b, True)
    assert client.roster().devices[b]["role"] == "owner"
    assert stub.owners == {b: True}
    client.remove(b)
    after = client.roster()
    assert after.devices[b]["status"] == "removed"
    assert stub.revoked == {b}
    assert [r["entry"]["kind"] for r in after.records] == ["genesis", "invite", "join", "promote", "remove"]
    assert client.info()["room"] == client.room
    assert client.watermark == 1
    client.delete()
    with pytest.raises(RoomError) as caught:
        client.info()
    assert (caught.value.status, caught.value.code) == (410, "gone")


def test_room_client_append_retries_after_a_409(room: Any) -> None:
    stub, client = room
    raced: list[bool] = []

    def another_owner_first(record: dict) -> None:
        if not raced:  # another owner's record lands at the same n first: this post gets a 409
            raced.append(True)
            entry = {"kind": "invite", "by": client.device, "invite": "R" * 21 + "A",
                     "invite_pub": public_jwk(new_signing_key()), "uses": 1, "expires_at": 2_000_000_000,
                     "approval": False}
            stub.roster.append(sign_entry(client.key, entry, record["n"], record["prev"]))

    stub.before_post = another_owner_first
    record = client.append({"kind": "invite", "invite": "S" * 21 + "A", "invite_pub": public_jwk(new_signing_key()),
                            "uses": 1, "expires_at": 2_000_000_000, "approval": False})
    assert raced and record["n"] == 3
    assert [r["entry"]["invite"] for r in client.roster().records[1:]] == ["R" * 21 + "A", "S" * 21 + "A"]
