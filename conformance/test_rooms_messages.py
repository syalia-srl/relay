"""Rooms, ROOMS.md 3.4 to 3.6: messages, blobs, acks, retention, caps and the socket."""

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from relaytest import ROOM_QUOTA, ROOMS_KEY, expect_close, recv, ws_connect
from roomtest import DAY, call, cid, error, new_room, rand


def seqs(response):
    return [m["seq"] for m in response.json()["messages"]]


# --- posting and reading


def test_a_message_is_returned_as_posted(relay):
    room = new_room(relay)
    member = room.member()
    body = {"cid": cid(), "epoch": 1, "n": 1, "iv": rand(12), "ct": rand(40), "sig": rand(64)}
    r = room.call("POST", "/messages", member, json=body)
    assert r.status_code == 201 and r.json() == {"seq": 1}
    got = room.messages().json()
    assert got["watermark"] == 1
    (m,) = got["messages"]
    assert m == {**body, "seq": 1, "device": member.id, "at": m["at"]}
    assert abs(m["at"] - relay.now()) < 5


def test_messages_after_a_sequence_with_a_limit(relay):
    room = new_room(relay)
    for _ in range(5):
        assert room.post().status_code == 201
    assert seqs(room.messages(after=2)) == [3, 4, 5]
    assert seqs(room.messages(after=0, limit=2)) == [1, 2]
    for bad in ({"limit": 0}, {"limit": 501}, {"after": -1}, {"after": "x"}):
        assert room.messages(**bad).status_code == 400


def test_fifty_concurrent_posts_get_fifty_distinct_sequences(relay):
    room = new_room(relay)
    members = [room.member() for _ in range(5)]
    with ThreadPoolExecutor(50) as pool:
        results = list(pool.map(lambda i: room.post(members[i % 5]), range(50)))
    assert all(r.status_code == 201 for r in results)
    assert sorted(r.json()["seq"] for r in results) == list(range(1, 51))
    assert seqs(room.messages(limit=500)) == list(range(1, 51))


def test_a_retried_message_is_stored_once(relay):
    room = new_room(relay)
    member = room.member()
    body = {"cid": cid(), "epoch": 1, "n": 1, "iv": rand(12), "ct": rand(40), "sig": rand(64)}
    first = room.call("POST", "/messages", member, json=body)
    again = room.call("POST", "/messages", member, json=body)
    assert first.status_code == 201 and again.status_code == 200
    assert again.json() == first.json()
    # The same cid from another device is another message.
    assert room.call("POST", "/messages", room.owner, json=body).status_code == 201
    assert len(room.messages().json()["messages"]) == 2


@pytest.mark.parametrize("field,value", [
    ("cid", "bad id!"),
    ("cid", rand(12)),
    ("epoch", 0),
    ("n", 1.5),
    ("iv", rand(16)),
    ("iv", rand(12) + "="),
    ("ct", "not base64!"),
    ("sig", rand(70)),
    ("blob", "short"),
])
def test_a_malformed_message_is_400(relay, field, value):
    room = new_room(relay)
    assert room.post(**{field: value}).status_code == 400


def test_a_ciphertext_over_64_kib_is_413(relay):
    room = new_room(relay)
    assert room.post(ct_bytes=65536).status_code == 201
    assert room.post(ct_bytes=65537).status_code == 413


def test_a_strict_json_body(relay):
    room = new_room(relay)
    dup = b'{"seq":1,"seq":2}'
    assert room.call("POST", "/ack", room.owner, content=dup).status_code == 400
    assert room.call("POST", "/ack", room.owner, content=b"seq=1").status_code == 400


# --- blobs


def test_blobs_need_a_device_and_stay_opaque(relay):
    room = new_room(relay)
    member = room.member()
    blob, data = rand(16), b"sealed file " * 100
    assert room.call("PUT", f"/blobs/{blob}", member, content=data).status_code == 201
    assert room.call("PUT", f"/blobs/{blob}", member, content=data).status_code == 409
    assert room.call("PUT", f"/blobs/{blob}", room.owner, content=b"other").status_code == 409
    assert room.call("GET", f"/blobs/{blob}", None).status_code == 401
    r = room.call("GET", f"/blobs/{blob}", room.owner)
    assert r.status_code == 200 and r.content == data
    assert room.call("GET", f"/blobs/{rand(16)}", room.owner).status_code == 404
    assert room.call("PUT", "/blobs/not-an-id", member, content=data).status_code == 400
    assert room.state()["stored_bytes"] == len(data)


def test_a_blob_over_the_room_size_is_413(relay):
    room = new_room(relay)
    limit = ROOM_QUOTA["blob_bytes"]
    assert room.call("PUT", f"/blobs/{rand(16)}", room.owner, content=b"x" * limit).status_code == 201
    r = room.call("PUT", f"/blobs/{rand(16)}", room.owner, content=b"x" * (limit + 1))
    assert r.status_code == 413 and error(r) == "too_large"


# --- caps (section 15: quota refusals)


def test_a_full_room_is_507_and_leaves_the_others_working(relay):
    small = new_room(relay, max_bytes=1000)
    other = new_room(relay)
    assert small.post(ct_bytes=600).status_code == 201
    r = small.post(ct_bytes=600)
    assert r.status_code == 507 and error(r) == "full"
    assert small.call("PUT", f"/blobs/{rand(16)}", small.owner, content=b"x" * 600).status_code == 507
    assert len(small.messages().json()["messages"]) == 1
    assert other.post(ct_bytes=600).status_code == 201


def test_the_credential_stored_bytes_are_shared_by_its_rooms(relay):
    one, two = new_room(relay), new_room(relay)
    blob = ROOM_QUOTA["blob_bytes"]
    for room in (one, two):
        for _ in range(ROOM_QUOTA["stored_bytes"] // (2 * blob)):
            assert room.call("PUT", f"/blobs/{rand(16)}", room.owner, content=b"x" * blob).status_code == 201
    assert call(relay, "GET", "/quota", ROOMS_KEY).json()["stored_bytes"]["used"] == ROOM_QUOTA["stored_bytes"]
    assert one.post(ct_bytes=1).status_code == 507
    assert two.call("PUT", f"/blobs/{rand(16)}", two.owner, content=b"x").status_code == 507


# --- acks and retention (section 15: deletion after acks and at retention)


def test_messages_are_deleted_once_every_device_acked_them(relay):
    room = new_room(relay)
    member = room.member()
    for _ in range(3):
        room.post()
    assert room.ack(2).status_code == 204
    assert room.messages().json()["watermark"] == 1
    assert room.ack(1, member).status_code == 204
    got = room.messages()
    assert got.json()["watermark"] == 2 and seqs(got) == [2, 3]
    assert got.headers["Relay-Room-Watermark"] == "2"
    room.ack(3, member)
    assert room.messages().json()["watermark"] == 3
    assert room.state()["stored_bytes"] == 40
    # An ack past the end counts only up to the last message.
    room.ack(99)
    room.ack(99, member)
    got = room.messages().json()
    assert got == {"messages": [], "watermark": 4}
    assert room.post().json()["seq"] == 4


def test_an_ack_records_the_time_and_never_goes_back(relay):
    room = new_room(relay)
    member = room.member()
    for _ in range(3):
        room.post()
    room.ack(3, member)
    room.ack(1, member)
    room.ack(3)
    assert room.messages().json()["watermark"] == 4
    devices = {d["device"]: d for d in room.state()["devices"]}
    assert abs(devices[member.id]["last_ack_at"] - relay.now()) < 5


def test_the_custodian_holds_nothing_back(relay):
    room = new_room(relay)
    room.post()
    room.ack(1)
    assert room.messages().json()["watermark"] == 2


def test_messages_are_deleted_at_retention(relay):
    room = new_room(relay, retention_days=2)
    member = room.member()
    room.post()
    relay.advance(DAY)
    room.post()
    room.ack(0, member)  # member stays recent and holds both back
    relay.advance(DAY)
    room.ack(0, member)
    got = room.messages()
    assert got.json()["watermark"] == 2 and seqs(got) == [2]


def test_a_device_silent_for_14_days_holds_nothing_back(relay):
    room = new_room(relay)
    silent = room.member()
    room.ack(0, silent)
    room.post()
    room.ack(1)
    relay.advance(13 * DAY)
    room.ack(1)
    assert room.messages().json()["watermark"] == 1
    relay.advance(DAY)
    room.ack(1)
    assert room.messages().json()["watermark"] == 2


def test_a_device_that_never_acked_holds_back_for_14_days_from_joining(relay):
    room = new_room(relay)
    room.member()
    room.post()
    room.ack(1)
    relay.advance(14 * DAY - 10)
    room.ack(1)
    assert room.messages().json()["watermark"] == 1
    relay.advance(20)
    room.ack(1)
    assert room.messages().json()["watermark"] == 2


def test_a_blob_goes_with_its_message(relay):
    room = new_room(relay)
    blob = rand(16)
    assert room.call("PUT", f"/blobs/{blob}", room.owner, content=b"x" * 100).status_code == 201
    assert room.post(blob=blob).status_code == 201
    assert room.state()["stored_bytes"] == 140
    room.ack(1)
    assert room.call("GET", f"/blobs/{blob}", room.owner).status_code == 404
    assert room.state()["stored_bytes"] == 0


def test_a_blob_no_message_names_lives_one_day(relay):
    room = new_room(relay)
    member = room.member()
    blob = rand(16)
    room.call("PUT", f"/blobs/{blob}", room.owner, content=b"x" * 100)
    relay.advance(DAY - 10)
    room.ack(0, member)
    assert room.call("GET", f"/blobs/{blob}", room.owner).status_code == 200
    relay.advance(20)
    room.ack(0, member)
    assert room.call("GET", f"/blobs/{blob}", room.owner).status_code == 404


# --- the notification socket (ROOMS.md 3.5)


async def test_the_socket_hints_each_arrival(relay):
    one, two = new_room(relay), new_room(relay)
    member = one.member()
    async with ws_connect(relay, "/v1/rooms/ws") as ws:
        await ws.send(json.dumps({"tokens": [member.token, two.owner.token, "unknown"]}))
        await asyncio.sleep(0.2)
        await asyncio.to_thread(one.post)
        assert json.loads(await recv(ws)) == {"room": one.id, "seq": 1}
        await asyncio.to_thread(two.post)
        assert json.loads(await recv(ws)) == {"room": two.id, "seq": 1}


@pytest.mark.parametrize("first", [
    json.dumps({"tokens": ["unknown"]}),
    json.dumps({"tokens": []}),
    json.dumps({"tokens": ["t"] * 257}),
    json.dumps({"auth": "t"}),
    "not json",
])
async def test_the_socket_without_an_accepted_token_is_4401(relay, first):
    async with ws_connect(relay, "/v1/rooms/ws") as ws:
        await ws.send(first)
        await expect_close(ws, 4401)


async def test_the_socket_needs_a_text_frame_in_5_seconds(relay):
    room = new_room(relay)
    async with ws_connect(relay, "/v1/rooms/ws") as ws:
        await ws.send(json.dumps({"tokens": [room.owner.token]}).encode())
        await expect_close(ws, 4401)
    async with ws_connect(relay, "/v1/rooms/ws") as ws:
        await expect_close(ws, 4401, timeout=8)


async def test_a_socket_left_with_nothing_to_watch_is_4410(relay):
    one, two = new_room(relay), new_room(relay)
    member = one.member()
    async with ws_connect(relay, "/v1/rooms/ws") as ws:
        await ws.send(json.dumps({"tokens": [member.token, two.owner.token]}))
        await asyncio.sleep(0.2)
        assert (await asyncio.to_thread(two.call, "DELETE", "", two.owner)).status_code == 204
        await asyncio.to_thread(one.post)
        assert json.loads(await recv(ws)) == {"room": one.id, "seq": 1}
        await asyncio.to_thread(one.call, "DELETE", f"/devices/{member.id}", one.owner)
        await expect_close(ws, 4410)


async def test_a_revoked_or_deleted_token_opens_no_socket(relay):
    room = new_room(relay)
    member = room.member()
    room.call("DELETE", f"/devices/{member.id}", room.owner)
    async with ws_connect(relay, "/v1/rooms/ws") as ws:
        await ws.send(json.dumps({"tokens": [member.token]}))
        await expect_close(ws, 4401)


def test_join_rotate_post_and_read(relay):
    """A joiner takes the next epoch, posts under it, and everyone reads in order."""
    room = new_room(relay)
    joiner = room.member()
    assert room.roster(2, joiner, device=joiner.id).status_code == 201
    wraps = {d.id: {"eph": {}, "iv": rand(12), "ct": rand(48)} for d in (room.owner, joiner)}
    assert room.epoch(2, joiner, wraps=wraps).status_code == 201
    assert room.post(joiner, epoch=2).json() == {"seq": 1}
    assert room.post(room.owner, epoch=2, n=1).json() == {"seq": 2}
    got = room.messages(joiner).json()["messages"]
    assert [(m["seq"], m["device"], m["epoch"]) for m in got] == [(1, joiner.id, 2), (2, room.owner.id, 2)]
    assert [e["n"] for e in room.call("GET", "/epochs", joiner).json()["epochs"]] == [1, 2]
