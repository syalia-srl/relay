"""RoomMember (C13) against the fake relay of rooms_fake.py: the member flow, the state
round trip, and a relay that lies (ROOMS.md 1 and 6), ported from js/test/rooms_hostile.test.js:
it adds a device, forges a join and an epoch, drops a roster record, replays a message,
swaps blobs and posts an epoch with a removed device's keys. And the epoch rules of
ROOMS.md 4.4: after a custodian's remove a remaining member makes the next epoch
before it sends, and two members that race get one 201 and one 409.
"""

from __future__ import annotations

import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from relay.rooms import (
    RecvKey,
    SignKey,
    Refused,
    RoomClient,
    RoomError,
    RoomMember,
    _join_body,
    _sign,
    make_epoch,
    new_signing_key,
    public_jwk,
    seal_message,
    sign_entry,
    software_device_keys,
)
from rooms_fake import CREDENTIAL, FakeRoomRelay


@pytest.fixture
def relay():
    instance = FakeRoomRelay()
    try:
        yield instance
    finally:
        instance.stop()


def in_a_week() -> int:
    return int(time.time()) + 7 * 86400


class Room:
    def __init__(self, a: RoomMember, members: list[RoomMember], custodian: dict, keys: dict):
        self.a, self.members, self.custodian, self.keys = a, members, custodian, keys


def room_with(relay: FakeRoomRelay, count: int = 0, *, approval: bool = False) -> Room:
    custodian_key = new_signing_key()
    sign, recv = software_device_keys()
    a = RoomMember.create(relay.url, CREDENTIAL, sign_key=sign, recv_key=recv, custodian_sign_pub=public_jwk(custodian_key))
    keys = {a.device: (sign, recv)}
    members = []
    for _ in range(count):
        made = a.invite(1, in_a_week(), approval=approval, app_url="https://app.example/j")
        s, r = software_device_keys()
        m = RoomMember.join(made["link"], sign_key=s, recv_key=r, base_url=relay.url)
        keys[m.device] = (s, r)
        members.append(m)
    custodian = {"key": custodian_key, **a.created["custodian"]}
    return Room(a, members, custodian, keys)


def custodian_remove(relay: FakeRoomRelay, room: Room, devices: list[str]) -> None:
    c = room.custodian
    RoomClient(relay.url, c["token"], room=room.a.room, device=c["device"], key=c["key"]).remove(devices)


def texts(messages) -> list[bytes]:
    return [m.plaintext for m in messages if m.status == "ok"]


def wrapped_for(relay: FakeRoomRelay, room_id: str, device: str) -> list[int]:
    return [e["n"] for e in relay.room(room_id)["epochs"] if device in e["wraps"]]


# --- the member flow ---


def test_create_join_post_sync_blob_ack(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 1)
    a, b = room.a, room.members[0]
    seq = a.post(b"hello", blob=b"a file")
    seen = b.sync()
    assert [(m.status, m.device, m.n, m.plaintext, m.seq) for m in seen] == [("ok", a.device, 1, b"hello", seq)]
    assert b.blob(seen[0].blob) == b"a file"
    b.post(b"hi back")
    assert texts(a.sync()) == [b"hello", b"hi back"]
    assert a.sync() == []
    b.ack(seq)
    assert relay.room(a.room)["devices"][b.device]["ack"] == seq


def test_state_round_trip_mid_conversation(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 1)
    a, b = room.a, room.members[0]
    a.post(b"one")
    assert texts(b.sync()) == [b"one"]
    b.post(b"two", blob=b"file two")
    state = b.state()
    assert "sign_key" not in str(state) and "recv_key" not in str(state)
    sign, recv = room.keys[b.device]
    b2 = RoomMember.from_state(state, sign_key=sign, recv_key=recv)
    assert b2.state() == state
    a.post(b"three")
    seen = b2.sync()
    assert [(m.plaintext, m.status) for m in seen] == [(b"two", "ok"), (b"three", "ok")]
    assert b2.blob(seen[0].blob) == b"file two"
    b2.post(b"four")
    assert texts(a.sync()) == [b"one", b"two", b"three", b"four"]
    assert [m.n for m in a.sync()] == []
    assert relay.room(a.room)["messages"][-1]["n"] == 2, "the counter went on from the state"


def test_a_post_the_relay_took_but_did_not_answer_is_resent_with_its_cid(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 1)
    a, b = room.a, room.members[0]
    a.post(b"first")
    real = a._call
    calls = {"n": 0}

    def flaky(method: str, path: str = "", **kw):
        if path == "/messages" and method == "POST" and calls["n"] < 3:
            calls["n"] += 1
            real(method, path, **kw)  # the relay takes it, the answer is lost
            raise ConnectionResetError("lost")
        return real(method, path, **kw)

    a._call = flaky
    with pytest.raises(ConnectionResetError):
        a.post(b"second")
    assert a.state()["pending"] is not None
    a._call = real
    a.post(b"third")
    assert texts(b.sync()) == [b"first", b"second", b"third"]
    assert len(relay.room(a.room)["messages"]) == 3, "one message stored per cid"


def test_approval_holds_a_newcomer_until_an_owner_approves(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 1, approval=True)
    a, b = room.a, room.members[0]
    assert not b.is_active()
    a.post(b"before approval")
    assert [m.status for m in b.sync()] == ["refused"]
    n = a.approve(b.device)
    assert b.device in relay.room(a.room)["epochs"][n - 1]["wraps"]
    a.post(b"after approval")
    assert texts(b.sync()) == [b"after approval"]


def test_sync_makes_the_epoch_a_custodian_remove_requires(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 2)
    a, (b, c) = room.a, room.members
    before = len(relay.room(a.room)["epochs"])
    custodian_remove(relay, room, [c.device])
    assert b.sync() == []
    epochs = relay.room(a.room)["epochs"]
    assert len(epochs) == before + 1
    assert epochs[-1]["creator"] == b.device
    assert set(epochs[-1]["wraps"]) == {a.device, b.device}


def test_gaps_show_as_missing_and_expired(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 1)
    a, b = room.a, room.members[0]
    a.post(b"1")
    b.sync()
    a.post(b"2")
    a.post(b"3")
    store = relay.room(a.room)["messages"]
    store[:] = [m for m in store if m["n"] != 2]  # the relay withholds message 2 while the watermark says it holds it
    seen = b.sync()
    assert [(m.status, m.n) for m in seen] == [("missing", 2), ("ok", 3)]
    a.post(b"4")
    a.post(b"5")
    relay.room(a.room)["watermark"] = store[-1]["seq"] + 2  # retention deleted 4
    store[:] = [m for m in store if m["n"] != 4]
    seen = b.sync()
    assert [(m.status, m.n) for m in seen] == [("expired", 4), ("ok", 5)]


# --- the hostile relay (js/test/rooms_hostile.test.js) ---


def test_hostile_a_device_the_relay_adds_gets_no_key(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 2)
    a, (b, c) = room.a, room.members
    intruder = relay.add_device(a.room)
    assert any(d["device"] == intruder["device"] for d in a.info()["devices"]), "the relay shows it"
    a.remove([c.device])
    a.post(b"after the removal")
    b.post(b"b too")
    assert wrapped_for(relay, a.room, intruder["device"]) == []
    assert set(relay.room(a.room)["epochs"][-1]["wraps"]) == {a.device, b.device}


def test_hostile_a_forged_join_breaks_the_roster_and_its_epoch_is_refused(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 1)
    a, b = room.a, room.members[0]
    sign, recv = software_device_keys()
    intruder = relay.add_device(a.room)["device"]
    a.refresh()
    invite_id = next(iter(a.roster.invites))
    entry = {
        "kind": "join", "by": intruder, "invite": invite_id, "device": intruder, "at": int(time.time()),
        "sign_pub": sign.sign_pub, "recv_pub": recv.recv_pub,
    }
    entry["invite_sig"] = _sign(sign, _join_body(entry))  # no invite key: it signs with its own
    forged = sign_entry(sign, entry, a.roster.n + 1, a.roster.head)
    relay.room(a.room)["roster"].append({**forged, "signer": intruder})
    n = len(relay.room(a.room)["epochs"]) + 1
    recipients = {d: recv.recv_pub for d in (a.device, b.device, intruder)}
    epoch, _ = make_epoch(a.room, n, a.roster.n, intruder, sign, recipients)
    relay.room(a.room)["epochs"].append(epoch)

    a.post(b"still private")
    assert (a.roster_error.reason, a.roster_error.index) == ("invite_signature", 3)
    assert intruder not in a.roster.devices
    assert a.refused_epochs[n] == "creator"
    sent_epoch = relay.room(a.room)["messages"][-1]["epoch"]
    assert sent_epoch != n
    assert intruder not in relay.room(a.room)["epochs"][sent_epoch - 1]["wraps"]
    assert texts(b.sync()) == [b"still private"]
    assert b.roster_error.reason == "invite_signature"


def test_hostile_a_removed_devices_epoch_after_a_member_rotated_is_refused(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 2)
    a, (b, c) = room.a, room.members
    a.remove([c.device])
    a.post(b"after the removal")
    assert texts(b.sync()) == [b"after the removal"]
    removed_at = b.roster.n
    assert b.accepted[max(b.accepted)]["roster"] >= removed_at, "a member already rotated"

    # The relay holds c's keys: an epoch naming the record before c's removal, and a message under it.
    c_sign, _ = room.keys[c.device]
    n = len(relay.room(a.room)["epochs"]) + 1
    recipients = {d: room.keys[d][1].recv_pub for d in (a.device, b.device, c.device)}
    epoch, key = make_epoch(a.room, n, removed_at - 1, c.device, c_sign, recipients)
    relay.room(a.room)["epochs"].append(epoch)
    sealed = seal_message(a.room, n, c.device, 1, key, c_sign, b"from the relay")
    seq = relay.post_message(a.room, {"device": c.device, "cid": "AAAAAAAAAAAAAAAAAAAAAA", **sealed})

    seen = b.sync()
    assert b.refused_epochs[n] == "roster_order"
    assert n not in b.accepted
    assert [(m.seq, m.device, m.status, m.reason, m.plaintext) for m in seen] == [
        (seq, c.device, "refused", "epoch", None)
    ]
    b.post(b"still private")
    sent_epoch = relay.room(a.room)["messages"][-1]["epoch"]
    assert sent_epoch != n
    assert c.device not in relay.room(a.room)["epochs"][sent_epoch - 1]["wraps"]


def test_hostile_a_dropped_roster_record_shows_the_roster_broken(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 1)
    a = room.a
    relay.hostile.roster = lambda entries, _room: [r for r in entries if r["n"] != 2]
    sign, recv = room.keys[a.device]
    fresh = RoomMember(relay.url, a.token, room=a.room, device=a.device, sign_key=sign, recv_key=recv)
    fresh.refresh()
    assert (fresh.roster_error.reason, fresh.roster_error.index, fresh.roster.n) == ("n", 1, 1)


def test_hostile_a_replayed_message_is_refused_and_a_forged_one_too(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 1)
    a, b = room.a, room.members[0]
    a.post(b"pay 10")

    def lie(messages, _room):
        original = next((m for m in messages if m["device"] == a.device), None)
        if original is None:
            return messages
        replay = {**original, "seq": 1000, "cid": "AAAAAAAAAAAAAAAAAAAAAA"}
        ct = original["ct"]
        forged = {**original, "seq": 1001, "n": 7, "ct": ("B" if ct[0] == "A" else "A") + ct[1:]}
        return [*messages, replay, forged]

    relay.hostile.messages = lie
    seen = b.sync()
    assert texts(seen) == [b"pay 10"]
    assert [(m.seq, m.status, m.reason) for m in seen if m.status != "ok"] == [
        (1000, "refused", "replay"),
        (1001, "refused", "signature"),
    ]


def test_hostile_swapped_blobs_fail_to_open(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 1)
    a, b = room.a, room.members[0]
    a.post(b"one", blob=b"first file")
    a.post(b"two", blob=b"second file")
    seen = b.sync()
    one, two = seen[0].blob, seen[1].blob
    blobs = relay.room(a.room)["blobs"]
    relay.hostile.blob = lambda _r, i, body: blobs[two] if i == one else blobs[one] if i == two else body
    for blob_id in (one, two):
        with pytest.raises(Refused) as caught:
            b.blob(blob_id)
        assert caught.value.reason == "decrypt"
    relay.hostile.blob = None
    assert b.blob(one) == b"first file"
    assert b.sync() == []


def test_epochs_after_a_custodians_remove_a_member_rotates_before_it_sends(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 2)
    a, (b, c) = room.a, room.members
    b.refresh()
    before = len(relay.room(a.room)["epochs"])
    assert c.device in relay.room(a.room)["epochs"][-1]["wraps"]
    custodian_remove(relay, room, [c.device])
    b.post(b"c has left")
    epochs = relay.room(a.room)["epochs"]
    assert len(epochs) == before + 1
    assert relay.room(a.room)["messages"][-1]["epoch"] == before + 1
    assert epochs[-1]["creator"] == b.device
    assert set(epochs[-1]["wraps"]) == {a.device, b.device}
    assert texts(a.sync()) == [b"c has left"]
    with pytest.raises(RoomError) as caught:
        c.sync()
    assert caught.value.status == 401


def test_epochs_two_members_that_race_get_one_201_and_one_409(relay: FakeRoomRelay) -> None:
    room = room_with(relay, 2)
    a, (b, c) = room.a, room.members
    a.refresh()
    b.refresh()
    before = len(relay.room(a.room)["epochs"])
    custodian_remove(relay, room, [c.device])
    start = len(relay.log)
    relay.hold_epochs(2)
    errors: list[BaseException] = []

    def send(member: RoomMember, text: bytes) -> None:
        try:
            member.post(text)
        except BaseException as error:  # noqa: BLE001
            errors.append(error)

    threads = [threading.Thread(target=send, args=(a, b"from a")), threading.Thread(target=send, args=(b, b"from b"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert errors == []
    posts = [line for line in relay.log[start:] if line == f"POST /v1/rooms/{a.room}/epochs"]
    assert len(posts) == 2, "both made an epoch"
    epochs = relay.room(a.room)["epochs"]
    assert len(epochs) == before + 1, "one 201, one 409, and the loser made no third"
    assert [m["epoch"] for m in relay.room(a.room)["messages"][-2:]] == [before + 1, before + 1]
    assert c.device not in epochs[-1]["wraps"]
    assert sorted(texts(a.sync())) == [b"from a", b"from b"]


def test_a_link_with_another_host_is_refused_before_any_call(relay: FakeRoomRelay) -> None:
    sign, recv = software_device_keys()
    with pytest.raises(RoomError) as caught:
        RoomMember.join("https://app.example/j#v1.Relay.example.x.y.z", sign_key=sign, recv_key=recv, base_url=relay.url)
    assert caught.value.code == "bad_link"
    assert relay.log == []


@pytest.mark.parametrize("cls", [SignKey, RecvKey])
@pytest.mark.parametrize("curve", [ec.SECP224R1, ec.SECP384R1])
def test_device_keys_take_only_p256(cls, curve):
    with pytest.raises(ValueError, match="P-256"):
        cls(ec.generate_private_key(curve()))


def test_device_keys_from_a_p256_private_key():
    private = ec.generate_private_key(ec.SECP256R1())
    sign_key, recv_key = SignKey(private), RecvKey(ec.generate_private_key(ec.SECP256R1()))
    assert sign_key.sign_pub == public_jwk(private) and len(sign_key.sign(b"x")) == 64
    assert len(recv_key.derive(sign_key.sign_pub)) == 32
