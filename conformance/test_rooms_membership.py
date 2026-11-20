"""Rooms, ROOMS.md 3.2 to 3.4: tokens, roles, invites, joins, roster, epochs, owners."""

import pytest

from roomtest import DAY, Device, call, error, jwk, new_room, rand


def test_every_device_answer_carries_the_watermark(relay):
    room = new_room(relay)
    for r in (room.call("GET", "", room.owner), room.messages(), room.post(), room.epoch(1)):
        assert r.headers["Relay-Room-Watermark"] == "1", r
    # Not before the token is accepted.
    assert "Relay-Room-Watermark" not in room.call("GET", "", "nope").headers


def test_tokens_are_scoped_to_their_room(relay):
    one, two = new_room(relay), new_room(relay)
    r = two.call("GET", "", one.owner)
    assert r.status_code == 401 and error(r) == "unauthorized"
    assert two.call("GET", "", None).status_code == 401
    assert two.call("GET", "", "x" * 43).status_code == 401


def test_an_unknown_room_is_404(relay):
    room = new_room(relay)
    r = call(relay, "GET", "/" + rand(16), room.owner.token)
    assert r.status_code == 404 and error(r) == "not_found"


def test_room_state_lists_devices_kinds_and_roles(relay):
    room = new_room(relay)
    member = room.member()
    state = room.state(member)
    assert state["room"] == room.id
    assert state["devices"] == [
        {"device": room.owner.id, "kind": "device", "role": "owner", "last_ack_at": None},
        {"device": room.custodian.id, "kind": "custodian", "role": "owner", "last_ack_at": None},
        {"device": member.id, "kind": "device", "role": "member", "last_ack_at": None},
    ]
    assert state["limits"] == room.limits and state["stored_bytes"] == 0 and state["read_only_since"] is None


# --- invites (section 15: invites only by owners; join tokens counted and expired)


def test_invites_only_by_owners(relay):
    room = new_room(relay)
    member = room.member()
    body = {"uses": 1, "expires_at": relay.now() + 60}
    r = room.call("POST", "/invites", member, json=body)
    assert r.status_code == 403 and error(r) == "forbidden"
    # The custodian is an owner.
    assert room.call("POST", "/invites", room.custodian, json=body).status_code == 201


@pytest.mark.parametrize("body", [
    {"uses": 0, "expires_at": "+60"},
    {"uses": 1001, "expires_at": "+60"},
    {"uses": 1, "expires_at": "-1"},
    {"uses": 1, "expires_at": f"+{30 * DAY + 60}"},
    {"uses": 1.0, "expires_at": "+60"},
    {"uses": 1},
])
def test_an_invite_out_of_range_is_400(relay, body):
    room = new_room(relay)
    body = dict(body)
    if "expires_at" in body:
        body["expires_at"] = relay.now() + int(body["expires_at"])
    assert room.call("POST", "/invites", room.owner, json=body).status_code == 400


def test_join_tokens_are_counted(relay):
    room = new_room(relay)
    token = room.invite(uses=2)
    assert room.join(token).status_code == 201
    assert room.join(token).status_code == 201
    r = room.join(token)
    assert r.status_code == 409 and error(r) == "conflict"


def test_join_tokens_expire(relay):
    room = new_room(relay)
    token = room.invite(expires_in=600)
    relay.advance(601)
    assert room.join(token).status_code == 409


def test_a_closed_invite_admits_nobody(relay):
    room = new_room(relay)
    r = room.call("POST", "/invites", room.owner, json={"uses": 5, "expires_at": relay.now() + 60})
    invite, token = r.json()["invite"], r.json()["token"]
    member = room.member()
    assert room.call("DELETE", f"/invites/{invite}", member).status_code == 403
    assert room.call("DELETE", f"/invites/{invite}", room.owner).status_code == 204
    assert room.join(token).status_code == 401
    assert room.call("DELETE", f"/invites/{rand(16)}", room.owner).status_code == 404


def test_a_join_token_is_scoped_to_its_room(relay):
    one, two = new_room(relay), new_room(relay)
    token = one.invite()
    assert two.join(token).status_code == 401
    assert one.join("x" * 43).status_code == 401
    assert one.join(None).status_code == 401
    # A device token is not a join token.
    assert one.join(one.owner.token).status_code == 401


def test_a_join_checks_only_the_form_of_keys(relay):
    room = new_room(relay)
    token = room.invite()
    bad = room.call("POST", "/join", token, json={"sign_pub": jwk(), "recv_pub": {"kty": "EC"}})
    assert bad.status_code == 400
    extra = {**jwk(), "d": rand(32), "ext": True}
    assert room.call("POST", "/join", token, json={"sign_pub": extra, "recv_pub": jwk()}).status_code == 201


# --- roster and epochs


def test_roster_records_are_appended_in_order(relay):
    room = new_room(relay)
    member = room.member()
    assert room.roster(3, member).status_code == 409
    assert room.roster(1, member).status_code == 409
    assert room.roster(2, member, prev="h1", device=member.id).status_code == 201
    entries = room.call("GET", "/roster", member).json()["entries"]
    assert [e["n"] for e in entries] == [1, 2]
    assert entries[1]["signer"] == member.id and entries[0]["signer"] == room.owner.id
    assert entries[1]["entry"] == {"kind": "join", "by": member.id, "device": member.id}
    assert entries[1]["prev"] == "h1"
    assert [e["n"] for e in room.call("GET", "/roster", member, params={"after": 1}).json()["entries"]] == [2]


def test_a_roster_record_over_64_kib_is_413(relay):
    room = new_room(relay)
    r = room.roster(2, pad="x" * (64 * 1024))
    assert r.status_code == 413 and error(r) == "too_large"


def test_a_json_body_over_1_mib_is_413(relay):
    room = new_room(relay)
    r = room.call("POST", "/roster", room.owner, content=b'{"n":2,"pad":"' + b"x" * (1 << 20) + b'"}')
    assert r.status_code == 413


@pytest.mark.parametrize("record", [
    {"n": 2, "entry": "text", "sig": "s", "prev": "p"},
    {"n": 2, "entry": {}, "sig": 1, "prev": "p"},
    {"n": "2", "entry": {}, "sig": "s", "prev": "p"},
    {"entry": {}, "sig": "s", "prev": "p"},
])
def test_a_malformed_roster_record_is_400(relay, record):
    room = new_room(relay)
    assert room.call("POST", "/roster", room.owner, json=record).status_code == 400


def test_epochs_are_taken_only_as_the_next(relay):
    room = new_room(relay)
    member = room.member()
    assert room.epoch(3, member).status_code == 409
    assert room.epoch(1, member).status_code == 409
    # The relay never checks whom an epoch is wrapped for.
    assert room.epoch(2, member, wraps={rand(16): {"anything": True}}).status_code == 201
    assert room.epoch(2, room.owner).status_code == 409
    epochs = room.call("GET", "/epochs", member, params={"after": 1}).json()["epochs"]
    assert [(e["n"], e["creator"]) for e in epochs] == [(2, member.id)]


def test_an_epoch_roster_is_an_opaque_integer_returned_as_posted(relay):
    room = new_room(relay)
    member = room.member()
    # Never compared with the roster, which holds one record here.
    assert room.epoch(2, member, roster=7).status_code == 201
    assert room.epoch(3, member, roster=0).status_code == 201
    epochs = room.call("GET", "/epochs", member).json()["epochs"]
    assert [(e["n"], e["roster"]) for e in epochs] == [(1, 1), (2, 7), (3, 0)]
    body = {"n": 4, "creator": member.id, "wraps": {}, "sig": rand(64)}
    for bad in ({}, {"roster": -1}, {"roster": 1.5}, {"roster": "1"}, {"roster": None}):
        r = room.call("POST", "/epochs", member, json={**body, **bad})
        assert r.status_code == 400 and error(r) == "bad_request", bad


def test_an_epoch_creator_must_be_the_caller(relay):
    room = new_room(relay)
    member = room.member()
    body = {"n": 2, "roster": 1, "creator": room.owner.id, "wraps": {}, "sig": rand(64)}
    assert room.call("POST", "/epochs", member, json=body).status_code == 403


def test_the_custodian_holds_no_epoch_key(relay):
    room = new_room(relay)
    c = room.custodian
    for r in (
        room.epoch(2, c),
        room.messages(c),
        room.post(c),
        room.call("PUT", f"/blobs/{rand(16)}", c, content=b"x" * 28),
        room.call("GET", f"/blobs/{rand(16)}", c),
    ):
        assert r.status_code == 403, r
    # It may manage the room and read its roster.
    assert room.call("GET", "/roster", c).status_code == 200
    assert room.ack(0, c).status_code == 204


# --- the relay's view of membership


def test_owners_promote_and_demote_but_never_leave_none(relay):
    room = new_room(relay)
    member = room.member()
    assert room.call("POST", "/owners", member, json={"device": member.id, "owner": True}).status_code == 403
    assert room.call("POST", "/owners", room.owner, json={"device": member.id, "owner": True}).status_code == 204
    assert room.call("POST", "/invites", member, json={"uses": 1, "expires_at": relay.now() + 60}).status_code == 201
    assert room.call("POST", "/owners", member, json={"device": room.owner.id, "owner": False}).status_code == 204
    assert room.call("POST", "/owners", member, json={"device": room.custodian.id, "owner": False}).status_code == 204
    r = room.call("POST", "/owners", member, json={"device": member.id, "owner": False})
    assert r.status_code == 409
    assert room.call("POST", "/owners", member, json={"device": rand(16), "owner": True}).status_code == 404
    assert room.call("POST", "/owners", member, json={"device": member.id, "owner": "yes"}).status_code == 400


def test_a_removed_device_is_locked_out_and_can_join_again_as_new(relay):
    room = new_room(relay)
    member = room.member()
    assert room.call("DELETE", f"/devices/{member.id}", room.owner).status_code == 204
    assert room.call("GET", "", member).status_code == 401
    assert room.post(member).status_code == 401
    assert member.id not in [d["device"] for d in room.state()["devices"]]
    assert room.call("DELETE", f"/devices/{member.id}", room.owner).status_code == 404
    again = room.member()
    assert again.id != member.id


def test_a_device_removes_itself_but_a_member_removes_no_one_else(relay):
    room = new_room(relay)
    a, b = room.member(), room.member()
    assert room.call("DELETE", f"/devices/{b.id}", a).status_code == 403
    assert room.call("DELETE", f"/devices/{a.id}", a).status_code == 204
    assert room.call("GET", "", a).status_code == 401


def test_the_last_owner_cannot_be_removed(relay):
    room = new_room(relay)
    assert room.call("DELETE", f"/devices/{room.custodian.id}", room.owner).status_code == 204
    r = room.call("DELETE", f"/devices/{room.owner.id}", room.owner)
    assert r.status_code == 409


# --- deletion


def test_deleting_a_room_erases_it_and_leaves_others(relay):
    room, other = new_room(relay), new_room(relay)
    member = room.member()
    token = room.invite()
    assert room.post().status_code == 201
    assert room.call("DELETE", "", member).status_code == 403
    assert room.call("DELETE", "", room.owner).status_code == 204
    for device in (room.owner, member):
        r = room.call("GET", "", device)
        assert r.status_code == 410 and error(r) == "gone"
    assert room.call("DELETE", "", room.owner).status_code == 410
    assert room.join(token).status_code == 401
    assert other.state()["room"] == other.id
    relay.advance(29 * DAY)
    assert room.call("GET", "", room.owner).status_code == 410


# --- push (stored; sending is a stub until a gateway exists)


def test_push_tokens_are_stored_and_never_shown(relay):
    room = new_room(relay)
    member = room.member()
    assert room.call("PUT", "/push", member, json={"token": "fcm:abc"}).status_code == 204
    assert "fcm:abc" not in room.call("GET", "", room.owner).text
    assert room.call("PUT", "/push", member, json={"token": None}).status_code == 204
    assert room.call("PUT", "/push", room.custodian, json={"token": "t"}).status_code == 204
    for bad in ({"token": "x" * 4097}, {"token": 1}, {}):
        assert room.call("PUT", "/push", member, json=bad).status_code == 400
