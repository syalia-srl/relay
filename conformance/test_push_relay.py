"""The relay's call to the push gateway (ROOMS.md 3.7, contract C11).

A fake gateway on loopback stands for the configured URL. RELAY_TEST_PUSH_SCALE,
test-only, shortens the 2 s batch window and the 1/4/16 s backoff where a test
needs it; the batching test runs at the real 2 s.
"""

from __future__ import annotations

import json
import socket
import threading
import time

import pytest

from pushtest import GATEWAY_KEY, FakeGateway, FakeServer, Seen, json_answer
from roomtest import Device, Room, cid, new_room, rand

WAKE = "/v1/wake"


@pytest.fixture
def gateway():
    fake = FakeGateway()
    yield fake
    fake.close()


@pytest.fixture
def key_path(tmp_path):
    path = tmp_path / "push.key"
    path.write_text(GATEWAY_KEY + "\n")
    path.chmod(0o600)
    return path


def push_relay(make_relay, gateway: FakeServer, key_path, scale: str | None = None, **env):
    extra = {"RELAY_PUSH_URL": gateway.url(WAKE), "RELAY_PUSH_KEY_PATH": str(key_path), **env}
    if scale is not None:
        extra["RELAY_TEST_PUSH_SCALE"] = scale
    return make_relay(**extra)


def set_push(room: Room, device: Device, token: str | None) -> None:
    r = room.call("PUT", "/push", device, json={"token": token})
    assert r.status_code == 204, r.text


def room_with_phones(relay, *tokens: str) -> tuple[Room, list[Device]]:
    """A set-up room whose owner holds tokens[0] and one member per further token."""
    room = new_room(relay)
    devices = [room.owner]
    for _ in tokens[1:]:
        devices.append(room.member())
    for device, token in zip(devices, tokens):
        set_push(room, device, token)
    return room, devices


def posted(room: Room, by: Device) -> None:
    r = room.post(by)
    assert r.status_code == 201, r.text


def quiet(fake: FakeServer, seconds: float) -> list[Seen]:
    """Wait a while and return what arrived; for asserting that nothing more does."""
    time.sleep(seconds)
    return fake.requests()


class FakeProxy:
    """A forward proxy that only records who tried to reach out through it."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.hits: list[bytes] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                try:
                    self.hits.append(conn.recv(4096))
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass

    def close(self):
        self.sock.close()


# --- off by default ---


def test_push_is_off_by_default(make_relay, gateway, key_path):
    """No RELAY_PUSH_URL: the relay makes no outbound call at all, even with a key
    file and devices holding push tokens. Any attempt to reach a non-loopback host
    would go through the proxy named in the environment; nothing reaches it."""
    proxy = FakeProxy()
    try:
        url = f"http://127.0.0.1:{proxy.port}"
        relay = make_relay(RELAY_PUSH_KEY_PATH=str(key_path), HTTPS_PROXY=url, HTTP_PROXY=url)
        room, devices = room_with_phones(relay, "tok-owner", "tok-a", "tok-b")
        for device in devices:
            posted(room, device)
        assert quiet(gateway, 3) == []
        assert proxy.hits == []
        assert "push is off" in relay.logs()
    finally:
        proxy.close()


def test_url_set_but_key_missing_turns_push_off(make_relay, gateway, tmp_path):
    relay = make_relay(RELAY_PUSH_URL=gateway.url(WAKE), RELAY_PUSH_KEY_PATH=str(tmp_path / "absent.key"))
    room, devices = room_with_phones(relay, "tok-owner", "tok-a")
    posted(room, devices[0])
    r = room.messages(devices[1])
    assert r.status_code == 200 and len(r.json()["messages"]) == 1
    assert quiet(gateway, 3) == []
    assert relay.logs().count("push gateway key not readable; push is off") == 1
    assert "tok-" not in relay.logs()


@pytest.mark.parametrize("url", ["http://push.example/v1/wake", "ftp://127.0.0.1/x", "not a url"])
def test_a_url_that_is_not_https_turns_push_off(make_relay, key_path, url):
    relay = make_relay(RELAY_PUSH_URL=url, RELAY_PUSH_KEY_PATH=str(key_path))
    room, devices = room_with_phones(relay, "tok-owner", "tok-a")
    posted(room, devices[0])
    assert "push gateway URL must be https; push is off" in relay.logs()


# --- what the relay sends, and where ---


def test_the_relay_calls_only_the_configured_url_with_only_tokens(make_relay, gateway, key_path):
    relay = push_relay(make_relay, gateway, key_path, scale="0.1")
    room, (owner, a, b) = room_with_phones(relay, "tok-owner", "tok-a", "tok-b")
    custodian = room.custodian
    set_push(room, custodian, "tok-custodian")  # a custodian is never woken
    posted(room, owner)
    (seen,) = gateway.wait(1)
    assert quiet(gateway, 1) == [seen]

    assert seen.method == "POST"
    assert seen.path == WAKE
    assert seen.headers["host"] == f"127.0.0.1:{gateway.port}"
    assert seen.headers["authorization"] == f"Bearer {GATEWAY_KEY}"
    assert seen.headers["content-type"].startswith("application/json")
    body = seen.json()
    assert list(body) == ["tokens"]
    assert sorted(body["tokens"]) == ["tok-a", "tok-b"]
    # Never the sender's own token, and nothing that names the room or a device.
    raw = seen.body.decode() + json.dumps(seen.headers)
    for secret in ["tok-owner", "tok-custodian", room.id, owner.id, a.id, b.id, owner.token, a.token]:
        assert secret not in raw


def test_the_relay_does_not_follow_redirects(make_relay, key_path):
    elsewhere = FakeGateway()
    redirect = FakeGateway(lambda seen: (307, {"Location": elsewhere.url(WAKE)}, b""))
    try:
        relay = push_relay(make_relay, redirect, key_path, scale="0.05")
        room, (owner, _) = room_with_phones(relay, "tok-owner", "tok-a")
        posted(room, owner)
        redirect.wait(1)
        time.sleep(1.5)  # past every scaled retry
        assert elsewhere.requests() == []
    finally:
        elsewhere.close()
        redirect.close()


def test_revoked_devices_and_cleared_tokens_are_not_sent(make_relay, gateway, key_path):
    relay = push_relay(make_relay, gateway, key_path, scale="0.1")
    room, (owner, a, b, c) = room_with_phones(relay, "tok-owner", "tok-a", "tok-b", "tok-c")
    assert room.call("DELETE", f"/devices/{b.id}", owner).status_code == 204
    set_push(room, c, None)
    posted(room, owner)
    (seen,) = gateway.wait(1)
    assert seen.json()["tokens"] == ["tok-a"]


def test_a_repeated_cid_wakes_nobody_twice(make_relay, gateway, key_path):
    relay = push_relay(make_relay, gateway, key_path, scale="0.1")
    room, (owner, _) = room_with_phones(relay, "tok-owner", "tok-a")
    body = {"cid": cid(), "epoch": 1, "n": 1, "iv": rand(12), "ct": rand(40), "sig": rand(64)}
    assert room.call("POST", "/messages", owner, json=body).status_code == 201
    gateway.wait(1)
    assert room.call("POST", "/messages", owner, json=body).status_code == 200
    assert len(quiet(gateway, 1)) == 1


# --- batching ---


def test_batching_and_dedup_across_messages_and_rooms(make_relay, gateway, key_path):
    """At the real 2 s window: one phone in two rooms, several messages, one call
    in which each token appears once."""
    relay = push_relay(make_relay, gateway, key_path)
    room1, (o1, p1, q1) = room_with_phones(relay, "tok-o1", "tok-phone", "tok-q")
    room2, (o2, p2) = room_with_phones(relay, "tok-o2", "tok-phone")
    start = time.monotonic()
    for _ in range(3):
        posted(room1, o1)
        posted(room2, o2)
    posted(room1, q1)
    (seen,) = gateway.wait(1, timeout=10)
    assert seen.at - start >= 1.9, "the first call waits for the 2 s window"
    tokens = seen.json()["tokens"]
    assert len(tokens) == len(set(tokens))
    # q1 posted: o1 is woken; q1 itself is woken by the others' messages.
    assert sorted(tokens) == ["tok-o1", "tok-phone", "tok-q"]
    assert quiet(gateway, 3) == [seen]

    # The next window starts with the next message and is again 2 s long.
    posted(room2, p2)
    first, second = gateway.wait(2, timeout=10)
    assert second.at - first.at >= 1.9
    assert second.json()["tokens"] == ["tok-o2"]


def test_more_than_500_tokens_split_into_calls_of_at_most_500(make_relay, gateway, key_path):
    relay = push_relay(make_relay, gateway, key_path, scale="0.5")
    room = new_room(relay)
    set_push(room, room.owner, "tok-owner")
    invite = room.invite(uses=600)
    for i in range(501):
        r = room.join(invite)
        assert r.status_code == 201, r.text
        set_push(room, Device(r.json()["device"], r.json()["token"]), f"tok-{i:04d}")
    posted(room, room.owner)
    gateway.wait(2)
    calls = quiet(gateway, 1.5)
    sizes = sorted(len(seen.json()["tokens"]) for seen in calls)
    assert sizes == [1, 500]
    every = [t for seen in calls for t in seen.json()["tokens"]]
    assert sorted(every) == [f"tok-{i:04d}" for i in range(501)]


# --- answers ---


def test_invalid_tokens_are_cleared(make_relay, key_path):
    gateway = FakeGateway(lambda seen: json_answer(200, {"invalid": ["tok-gone", "tok-never-sent"]}))
    try:
        relay = push_relay(make_relay, gateway, key_path, scale="0.1")
        room, (owner, a, gone) = room_with_phones(relay, "tok-owner", "tok-a", "tok-gone")
        other, (o2, gone2) = room_with_phones(relay, "tok-never-sent", "tok-gone")
        posted(room, owner)
        (first,) = gateway.wait(1)
        assert sorted(first.json()["tokens"]) == ["tok-a", "tok-gone"]
        time.sleep(0.5)

        posted(room, owner)
        posted(other, gone2)
        gateway.wait(2)
        later = [t for seen in quiet(gateway, 1)[1:] for t in seen.json()["tokens"]]
        # tok-gone is cleared everywhere it was set; a token the gateway named
        # but the relay never sent in that batch is kept.
        assert sorted(later) == ["tok-a", "tok-never-sent"]
    finally:
        gateway.close()


@pytest.mark.parametrize("status", [400, 401])
def test_400_and_401_are_not_retried(make_relay, key_path, status):
    gateway = FakeGateway(lambda seen: json_answer(status, {"error": "no"}))
    try:
        relay = push_relay(make_relay, gateway, key_path, scale="0.05")
        room, (owner, _) = room_with_phones(relay, "tok-owner", "tok-a")
        posted(room, owner)
        gateway.wait(1)
        assert len(quiet(gateway, 2)) == 1
        assert f"status {status}" in relay.logs()
        assert "tok-" not in relay.logs()
    finally:
        gateway.close()


def test_5xx_retries_at_1_4_16_then_drops(make_relay, key_path):
    gateway = FakeGateway(lambda seen: json_answer(503, {"error": "busy"}))
    try:
        # Scale 0.1: the waits are 0.1, 0.4 and 1.6 s.
        relay = push_relay(make_relay, gateway, key_path, scale="0.1")
        room, (owner, _) = room_with_phones(relay, "tok-owner", "tok-a")
        posted(room, owner)
        calls = gateway.wait(4, timeout=10)
        calls = quiet(gateway, 2)
        assert len(calls) == 4, "one call and three retries, then the batch is dropped"
        gaps = [b.at - a.at for a, b in zip(calls, calls[1:])]
        for gap, want in zip(gaps, [0.1, 0.4, 1.6]):
            assert want * 0.9 <= gap <= want + 1.0, gaps
        assert all(seen.json() == {"tokens": ["tok-a"]} for seen in calls)
        relay.wait_for_log("push batch dropped")
        assert "tok-" not in relay.logs()
    finally:
        gateway.close()


def test_a_retry_that_succeeds_delivers_the_batch(make_relay, key_path):
    answers = iter([json_answer(502, {}), json_answer(200, {"invalid": []})])
    gateway = FakeGateway(lambda seen: next(answers))
    try:
        relay = push_relay(make_relay, gateway, key_path, scale="0.1")
        room, (owner, _) = room_with_phones(relay, "tok-owner", "tok-a")
        posted(room, owner)
        assert len(gateway.wait(2)) == 2
        assert len(quiet(gateway, 2.5)) == 2
        assert "push batch dropped" not in relay.logs()
    finally:
        gateway.close()


def test_429_waits_for_retry_after(make_relay, key_path):
    answers = iter([json_answer(429, {"error": "slow down"}, {"Retry-After": "2"}), json_answer(200, {"invalid": []})])
    gateway = FakeGateway(lambda seen: next(answers))
    try:
        # Retry-After is honoured as given; the test scale does not shorten it.
        relay = push_relay(make_relay, gateway, key_path, scale="0.05")
        room, (owner, _) = room_with_phones(relay, "tok-owner", "tok-a")
        posted(room, owner)
        first, second = gateway.wait(2, timeout=10)
        assert 1.9 <= second.at - first.at <= 4
        assert second.json() == {"tokens": ["tok-a"]}
    finally:
        gateway.close()


def test_posting_never_waits_on_the_gateway(make_relay, key_path):
    release = threading.Event()

    def slow(seen):
        release.wait(10)
        return json_answer(200, {"invalid": []})

    gateway = FakeGateway(slow)
    try:
        relay = push_relay(make_relay, gateway, key_path, scale="0.05")
        room, (owner, _) = room_with_phones(relay, "tok-owner", "tok-a")
        posted(room, owner)
        gateway.wait(1)
        start = time.monotonic()
        posted(room, owner)
        assert time.monotonic() - start < 1
    finally:
        release.set()
        gateway.close()
