"""Rooms, ROOMS.md 3.3: every room route answers a browser on any origin."""

import httpx
import pytest

from roomtest import auth, new_room

ORIGIN = {"Origin": "https://app.example"}


def cors(response: httpx.Response) -> dict:
    return {k.lower(): v for k, v in response.headers.items() if k.lower().startswith("access-control-")}


@pytest.mark.parametrize(
    "path,method",
    [("", "POST"), ("/quota", "GET"), ("/abc/messages", "POST"), ("/abc/blobs/x", "PUT"), ("/abc/invites/i", "DELETE")],
)
def test_a_preflight_is_204_with_the_cors_headers(relay, path, method):
    r = httpx.request(
        "OPTIONS",
        relay.url(f"/v1/rooms{path}"),
        headers={**ORIGIN, "Access-Control-Request-Method": method,
                 "Access-Control-Request-Headers": "authorization, content-type"},
    )
    assert r.status_code == 204
    h = cors(r)
    assert h["access-control-allow-origin"] == "*"
    assert {m.strip() for m in h["access-control-allow-methods"].split(",")} == {"GET", "POST", "PUT", "DELETE"}
    assert {x.strip().lower() for x in h["access-control-allow-headers"].split(",")} == {"authorization", "content-type"}
    assert "access-control-allow-credentials" not in h


def test_answers_expose_the_watermark_to_a_page(relay):
    room = new_room(relay)
    r = httpx.get(relay.url(f"/v1/rooms/{room.id}/messages"), headers={**ORIGIN, **auth(room.owner.token)})
    assert r.status_code == 200 and "relay-room-watermark" in {k.lower() for k in r.headers}
    h = cors(r)
    assert h["access-control-allow-origin"] == "*"
    assert h["access-control-expose-headers"] == "Relay-Room-Watermark"
    assert "access-control-allow-credentials" not in h


def test_errors_carry_the_cors_headers_too(relay):
    r = httpx.get(relay.url("/v1/rooms/quota"), headers=ORIGIN)
    assert r.status_code == 401 and cors(r)["access-control-allow-origin"] == "*"


def test_channel_routes_have_no_cors(relay):
    r = httpx.post(relay.url("/v1/channels"), headers=ORIGIN)
    assert cors(r) == {}
    r = httpx.request("OPTIONS", relay.url("/v1/channels"), headers={**ORIGIN, "Access-Control-Request-Method": "POST"})
    assert cors(r) == {}
