"""Rooms, ROOMS.md 3.1 and 3.6: credentials, room quotas, read-only and lifetime."""

import json
import signal

import pytest

from relaytest import LOCAL_KEY, OPERATOR_KEY, ROOM_QUOTA, ROOMS_KEY, keys_file, mint, sha256_hex
from roomtest import DAY, call, create, error, new_room

TOKEN_QUOTA = {"rooms": 2, "room_stored_bytes": 100_000, "room_retention_days": 7, "room_blob_bytes": 5_000}


def room_token(relay, sub="install-1", lives=3600):
    return mint(sub, exp=relay.now() + lives, extra=TOKEN_QUOTA)


# --- creation and the credential (section 15: refused without a room quota and with a device token)


def test_no_credential_is_401(relay):
    r = call(relay, "POST", "", None, json={})
    assert r.status_code == 401 and error(r) == "unauthorized"
    assert create(relay, "not-a-key").status_code == 401
    assert create(relay, "rt1.not.a.token").status_code == 401
    assert call(relay, "GET", "/quota", None).status_code == 401


@pytest.mark.parametrize("key", ["operator", "unlimited", "token"])
def test_a_credential_without_a_room_quota_is_403(relay, key):
    credential = {"operator": OPERATOR_KEY, "unlimited": LOCAL_KEY, "token": mint("no-rooms")}[key]
    r = create(relay, credential)
    assert r.status_code == 403 and error(r) == "forbidden"
    assert call(relay, "GET", "/quota", credential).status_code == 403
    # It still works for channels.
    assert relay.create_v1(credential).status_code == 201


def test_a_device_token_cannot_create_a_room(relay):
    room = new_room(relay)
    assert create(relay, room.owner.token).status_code == 401
    assert call(relay, "GET", "/quota", room.owner.token).status_code == 401


def test_creation_answers_ids_tokens_and_limits(relay):
    r = create(relay)
    assert r.status_code == 201
    body = r.json()
    assert len(body["room"]) == 22 and len(body["device"]) == 22 and len(body["token"]) == 43
    assert len(body["custodian"]["device"]) == 22 and len(body["custodian"]["token"]) == 43
    assert body["device"] != body["custodian"]["device"]
    assert body["limits"] == {"max_bytes": ROOM_QUOTA["stored_bytes"], "retention_days": 30,
                              "blob_bytes": ROOM_QUOTA["blob_bytes"]}


def test_limits_are_clamped_to_the_credential(relay):
    r = create(relay, max_bytes=1000, retention_days=7)
    assert r.json()["limits"] == {"max_bytes": 1000, "retention_days": 7, "blob_bytes": ROOM_QUOTA["blob_bytes"]}
    r = create(relay, max_bytes=10**12, retention_days=365)
    assert r.json()["limits"]["max_bytes"] == ROOM_QUOTA["stored_bytes"]
    assert r.json()["limits"]["retention_days"] == ROOM_QUOTA["retention_days"]
    for bad in ({"max_bytes": 0}, {"retention_days": 7.5}, {"retention_days": "7"}):
        assert create(relay, **bad).status_code == 400


@pytest.mark.parametrize("body", [
    {},
    {"owner": {"sign_pub": {"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"}}},
    "not an object",
])
def test_a_malformed_create_is_400(relay, body):
    r = call(relay, "POST", "", ROOMS_KEY, json=body)
    assert r.status_code == 400 and error(r) == "bad_request"


def test_a_duplicate_key_is_400(relay):
    r = call(relay, "POST", "", ROOMS_KEY, content=b'{"owner":{},"owner":{}}')
    assert r.status_code == 400


def test_the_number_of_rooms_is_capped(relay):
    rooms = [new_room(relay) for _ in range(ROOM_QUOTA["max"])]
    r = create(relay)
    assert r.status_code == 507 and error(r) == "full"
    # A deleted room stops counting.
    assert rooms[0].call("DELETE", "", rooms[0].owner).status_code == 204
    assert create(relay).status_code == 201


def test_quota_reports_use(relay):
    room = new_room(relay)
    assert room.post(ct_bytes=100).status_code == 201
    r = call(relay, "GET", "/quota", ROOMS_KEY)
    assert r.status_code == 200
    assert r.json() == {
        "rooms": {"max": ROOM_QUOTA["max"], "used": 1},
        "stored_bytes": {"max": ROOM_QUOTA["stored_bytes"], "used": 100},
        "retention_days": ROOM_QUOTA["retention_days"],
        "blob_bytes": ROOM_QUOTA["blob_bytes"],
        "read_only_since": None,
    }


def test_a_relay_token_quota_and_its_room_limits(relay):
    token = room_token(relay)
    r = call(relay, "GET", "/quota", token)
    assert r.status_code == 200
    assert r.json()["rooms"] == {"max": 2, "used": 0}
    room = new_room(relay, token)
    assert room.limits == {"max_bytes": 100_000, "retention_days": 7, "blob_bytes": 5_000}


def test_a_renewed_token_with_the_same_sub_keeps_its_rooms(relay):
    new_room(relay, room_token(relay))
    renewed = room_token(relay)
    assert call(relay, "GET", "/quota", renewed).json()["rooms"]["used"] == 1
    other = room_token(relay, sub="install-2")
    assert call(relay, "GET", "/quota", other).json()["rooms"]["used"] == 0


# --- read-only (ROOMS.md 3.6)


def test_a_renewed_token_at_quota_keeps_rooms_writable_and_a_lapse_makes_them_read_only(relay):
    room = new_room(relay, room_token(relay, lives=3600))
    relay.advance(1800)
    renewed_exp = relay.now() + 7200
    renewed = mint("install-1", exp=renewed_exp, extra=TOKEN_QUOTA)
    assert call(relay, "GET", "/quota", renewed).status_code == 200
    relay.advance(3600)  # past the first token's expiry
    assert room.post().status_code == 201
    assert room.state()["read_only_since"] is None

    relay.advance(7200)  # past the renewed token's expiry
    r = room.post()
    assert r.status_code == 423 and error(r) == "read_only"
    state = room.state()
    assert state["read_only_since"] == renewed_exp
    # Reads, acks, removals and deletion still work; other writes answer 423.
    assert room.messages().status_code == 200
    assert room.ack(1).status_code == 204
    assert room.call("POST", "/invites", room.owner, json={"uses": 1, "expires_at": relay.now() + 60}).status_code == 423
    assert room.epoch(2).status_code == 423
    assert room.call("PUT", "/push", room.owner, json={"token": "t"}).status_code == 423

    # Presenting a valid token for the same (iss, sub) ends it.
    assert call(relay, "GET", "/quota", room_token(relay)).status_code == 200
    assert room.state()["read_only_since"] is None
    assert room.post().status_code == 201


def test_a_room_read_only_for_30_days_is_deleted(relay):
    room = new_room(relay, room_token(relay, lives=60))
    relay.advance(120)
    assert room.post().status_code == 423
    relay.advance(29 * DAY)
    assert room.state()["read_only_since"] is not None
    relay.advance(DAY)
    r = room.call("GET", "", room.owner)
    assert r.status_code == 410 and error(r) == "gone"


def test_an_operator_key_that_leaves_the_file_makes_its_rooms_read_only(relay):
    room = new_room(relay)
    keys = keys_file()
    keys["keys"] = [k for k in keys["keys"] if k["sha256"] != sha256_hex(ROOMS_KEY)]
    relay.keys_path.write_text(json.dumps(keys))
    relay.proc.send_signal(signal.SIGHUP)
    relay.wait_for_log("reloaded")
    assert room.post().status_code == 423
    assert room.state()["read_only_since"] is not None
    # Back in the file and presented again: writable.
    relay.keys_path.write_text(json.dumps(keys_file()))
    relay.proc.send_signal(signal.SIGHUP)
    relay.wait_for_log("reloaded", count=2)
    assert call(relay, "GET", "/quota", ROOMS_KEY).status_code == 200
    assert room.post().status_code == 201


def test_a_token_that_loses_its_room_quota_makes_its_rooms_read_only(relay):
    room = new_room(relay, room_token(relay))
    assert call(relay, "GET", "/quota", mint("install-1", exp=relay.now() + 3600)).status_code == 403
    assert room.post().status_code == 423


# --- lifetime


def test_a_room_without_genesis_is_deleted_after_an_hour(relay):
    room = new_room(relay, set_up=False)
    set_up = new_room(relay)
    relay.advance(3599)
    assert room.state()["room"] == room.id
    relay.advance(2)
    assert room.call("GET", "", room.owner).status_code == 410
    assert set_up.state()["room"] == set_up.id
    assert call(relay, "GET", "/quota", ROOMS_KEY).json()["rooms"]["used"] == 1


def test_rooms_survive_a_restart(relay):
    room = new_room(relay)
    member = room.member()
    seq = room.post().json()["seq"]
    relay.restart()
    assert [m["seq"] for m in room.messages(member).json()["messages"]] == [seq]
    assert room.post(member).status_code == 201
    assert relay.rooms_path.stat().st_mode & 0o077 == 0
