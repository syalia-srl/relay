"""The push gateway, server/cmd/pushgw (contract C11), against a fake FCM and
OAuth server, and the relay calling it end to end.

The service account is generated per test with a throwaway RSA key; its
token_uri points at the fake.
"""

from __future__ import annotations

import time

import httpx
import pytest

from pushtest import GATEWAY_KEY, PROJECT, FakeFCM, Gateway, gateway_keys
from test_push_relay import posted, room_with_phones


@pytest.fixture
def fcm():
    fake = FakeFCM()
    yield fake
    fake.close()


@pytest.fixture
def make_gateway(tmp_path, fcm):
    started: list[Gateway] = []

    def make(**kw) -> Gateway:
        gw = Gateway(tmp_path / f"gw{len(started)}", fcm, **kw)
        started.append(gw)
        return gw

    yield make
    for gw in started:
        gw.stop()


def wake(gw: Gateway, tokens, key: str | None = GATEWAY_KEY, body=None) -> httpx.Response:
    headers = {} if key is None else {"Authorization": f"Bearer {key}"}
    return httpx.post(gw.url(), headers=headers, json={"tokens": tokens} if body is None else body, timeout=30)


def expected_message(token: str) -> dict:
    return {"message": {"token": token, "data": {"w": "1"}, "android": {"priority": "high"}}}


def test_a_bad_key_is_refused(make_gateway, fcm):
    gw = make_gateway()
    assert wake(gw, ["tok-a"], key="wrong-key").status_code == 401
    assert wake(gw, ["tok-a"], key=None).status_code == 401
    assert fcm.requests() == []


def test_a_missing_keys_file_refuses_every_key(make_gateway, fcm):
    gw = make_gateway(keys=None)
    assert wake(gw, ["tok-a"]).status_code == 401
    assert fcm.requests() == []


def test_sighup_rereads_the_keys(make_gateway):
    gw = make_gateway(keys=gateway_keys(("old", "old-key-0123456789", 100)))
    assert wake(gw, ["tok-a"]).status_code == 401
    gw.write_keys(gateway_keys(("relay", GATEWAY_KEY, 100)))
    gw.reload()
    assert wake(gw, ["tok-a"]).status_code == 200
    assert wake(gw, ["tok-a"], key="old-key-0123456789").status_code == 401


def test_one_data_only_message_per_token(make_gateway, fcm):
    gw = make_gateway()
    r = wake(gw, ["tok-a", "tok-b"])
    assert r.status_code == 200, r.text
    assert r.json() == {"invalid": []}
    sends = fcm.sends()
    assert len(sends) == 2
    for seen in sends:
        assert seen.method == "POST"
        assert seen.path == f"/v1/projects/{PROJECT}/messages:send"
        assert seen.headers["authorization"] == f"Bearer {fcm.access_tokens[0]}"
    assert sorted((s.json() for s in sends), key=lambda m: m["message"]["token"]) == [
        expected_message("tok-a"),
        expected_message("tok-b"),
    ]
    assert fcm.jwt_errors == []


def test_the_access_token_is_cached(make_gateway, fcm):
    gw = make_gateway()
    for _ in range(3):
        assert wake(gw, ["tok-a"]).status_code == 200
    assert len(fcm.grants()) == 1
    assert len(fcm.sends()) == 3


def test_unregistered_and_invalid_argument_are_invalid(make_gateway, fcm):
    gw = make_gateway()
    r = wake(gw, ["tok-a", "unregistered-1", "badarg-1"])
    assert r.status_code == 200, r.text
    assert sorted(r.json()["invalid"]) == ["badarg-1", "unregistered-1"]
    assert len(fcm.sends()) == 3


def test_fcm_5xx_answers_503_with_retry_after_and_marks_nothing(make_gateway):
    gw = make_gateway()
    r = wake(gw, ["tok-a", "fail-1", "unregistered-1"])
    assert r.status_code == 503
    assert int(r.headers["Retry-After"]) >= 1
    assert "invalid" not in r.text


def test_per_minute_limit_answers_429_with_retry_after(make_gateway):
    gw = make_gateway(keys=gateway_keys(("relay", GATEWAY_KEY, 2)))
    assert wake(gw, ["tok-a"]).status_code == 200
    assert wake(gw, ["tok-a"]).status_code == 200
    r = wake(gw, ["tok-a"])
    assert r.status_code == 429
    assert 1 <= int(r.headers["Retry-After"]) <= 60


@pytest.mark.parametrize(
    "body",
    [
        {"tokens": []},
        {"tokens": [f"t{i}" for i in range(501)]},
        {"tokens": ["tok-a"], "room": "r"},
        {"tokens": [""]},
        {"tokens": [1]},
        {"tokens": ["x" * 4097]},
        {},
    ],
)
def test_a_body_that_is_not_1_to_500_tokens_and_nothing_else_is_refused(make_gateway, fcm, body):
    gw = make_gateway()
    assert wake(gw, None, body=body).status_code == 400
    assert fcm.sends() == []


def test_no_log_line_carries_a_token_or_the_credentials(make_gateway, fcm):
    gw = make_gateway()
    wake(gw, ["tok-secret-a", "unregistered-secret", "fail-secret"])
    wake(gw, ["tok-secret-b"], key="wrong-key")
    logs = gw.logs()
    assert "secret" not in logs
    assert GATEWAY_KEY not in logs
    assert "PRIVATE KEY" not in logs and fcm.access_tokens[0] not in logs
    assert "pushgw@" not in logs


# --- end to end: relay → pushgw → fake FCM ---


def test_relay_to_gateway_to_fcm(make_relay, make_gateway, fcm, tmp_path):
    gw = make_gateway()
    key = tmp_path / "push.key"
    key.write_text(GATEWAY_KEY)
    key.chmod(0o600)
    relay = make_relay(RELAY_PUSH_URL=gw.url(), RELAY_PUSH_KEY_PATH=str(key), RELAY_TEST_PUSH_SCALE="0.1")
    room, (owner, a, gone) = room_with_phones(relay, "tok-owner", "tok-a", "unregistered-x")
    posted(room, owner)
    fcm.wait(3)  # one grant, two sends
    time.sleep(0.5)
    assert sorted(s.json()["message"]["token"] for s in fcm.sends()) == ["tok-a", "unregistered-x"]

    # The gateway marked unregistered-x invalid; the relay cleared it.
    posted(room, owner)
    deadline = time.monotonic() + 5
    while len(fcm.sends()) < 3 and time.monotonic() < deadline:
        time.sleep(0.05)
    time.sleep(0.5)
    assert [s.json()["message"]["token"] for s in fcm.sends()[2:]] == ["tok-a"]


def test_gateway_429_makes_the_relay_wait_and_the_batch_arrives(make_relay, make_gateway, fcm, tmp_path):
    """per_minute 1: the second batch gets 429 with Retry-After (up to 60 s);
    the relay waits for it, retries, and the batch reaches FCM."""
    gw = make_gateway(keys=gateway_keys(("relay", GATEWAY_KEY, 1)))
    key = tmp_path / "push.key"
    key.write_text(GATEWAY_KEY)
    key.chmod(0o600)
    relay = make_relay(RELAY_PUSH_URL=gw.url(), RELAY_PUSH_KEY_PATH=str(key), RELAY_TEST_PUSH_SCALE="0.1")
    room, (owner, a) = room_with_phones(relay, "tok-owner", "tok-a")
    posted(room, owner)
    fcm.wait(2)  # grant + first send
    posted(room, a)
    deadline = time.monotonic() + 75
    while len(fcm.sends()) < 2:
        assert time.monotonic() < deadline, relay.logs()
        time.sleep(0.2)
    assert [s.json()["message"]["token"] for s in fcm.sends()] == ["tok-a", "tok-owner"]
    assert "status 429" in relay.logs()
    assert "push batch dropped" not in relay.logs()
