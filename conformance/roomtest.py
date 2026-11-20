"""Helpers for the rooms suite (ROOMS.md section 3): a black-box client of /v1/rooms.

The relay checks only the form of keys, signatures and ciphertext, so the suite
uses random bytes of the right shape and never real cryptography.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx

from relaytest import ROOMS_KEY, Relay, b64

DAY = 86400


def rand(n: int) -> str:
    return b64(os.urandom(n))


def jwk() -> dict:
    return {"kty": "EC", "crv": "P-256", "x": rand(32), "y": rand(32)}


def cid() -> str:
    """A client id: 16 random bytes."""
    return rand(16)


def auth(token: str | None) -> dict:
    return {} if token is None else {"Authorization": f"Bearer {token}"}


def call(relay: Relay, method: str, path: str, token: str | None = None, **kw) -> httpx.Response:
    return httpx.request(method, relay.url(f"/v1/rooms{path}"), headers=auth(token), timeout=30, **kw)


def error(response: httpx.Response) -> str:
    return response.json()["error"]


def create(relay: Relay, key: str = ROOMS_KEY, **fields) -> httpx.Response:
    body = {"owner": {"sign_pub": jwk(), "recv_pub": jwk()}, "custodian": {"sign_pub": jwk()}, **fields}
    return call(relay, "POST", "", key, json=body)


@dataclass
class Device:
    id: str
    token: str


@dataclass
class Room:
    relay: Relay
    id: str
    owner: Device
    custodian: Device
    limits: dict

    def call(self, method: str, path: str, device: Device | str | None, **kw) -> httpx.Response:
        token = device.token if isinstance(device, Device) else device
        return call(self.relay, method, f"/{self.id}{path}", token, **kw)

    def invite(self, by: Device | None = None, uses: int = 10, expires_in: int = DAY) -> str:
        r = self.call("POST", "/invites", by or self.owner, json={"uses": uses, "expires_at": self.relay.now() + expires_in})
        assert r.status_code == 201, r.text
        return r.json()["token"]

    def join(self, token: str) -> httpx.Response:
        return self.call("POST", "/join", token, json={"sign_pub": jwk(), "recv_pub": jwk()})

    def member(self) -> Device:
        r = self.join(self.invite())
        assert r.status_code == 201, r.text
        return Device(r.json()["device"], r.json()["token"])

    def roster(self, n: int, by: Device | None = None, prev: str = "", **entry) -> httpx.Response:
        record = {"n": n, "entry": {"kind": "genesis" if n == 1 else "join", "by": (by or self.owner).id, **entry},
                  "sig": rand(64), "prev": prev}
        return self.call("POST", "/roster", by or self.owner, json=record)

    def epoch(self, n: int, by: Device | None = None, wraps: dict | None = None, roster: int = 1) -> httpx.Response:
        by = by or self.owner
        wraps = wraps if wraps is not None else {by.id: {"eph": jwk(), "iv": rand(12), "ct": rand(48)}}
        body = {"n": n, "roster": roster, "creator": by.id, "wraps": wraps, "sig": rand(64)}
        return self.call("POST", "/epochs", by, json=body)

    def post(self, by: Device | None = None, ct_bytes: int = 40, **fields) -> httpx.Response:
        body = {"cid": cid(), "epoch": 1, "n": 1, "iv": rand(12), "ct": rand(ct_bytes), "sig": rand(64), **fields}
        return self.call("POST", "/messages", by or self.owner, json=body)

    def messages(self, by: Device | None = None, after: int = 0, **params) -> httpx.Response:
        return self.call("GET", "/messages", by or self.owner, params={"after": after, **params})

    def ack(self, seq: int, by: Device | None = None) -> httpx.Response:
        return self.call("POST", "/ack", by or self.owner, json={"seq": seq})

    def state(self, by: Device | None = None) -> dict:
        r = self.call("GET", "", by or self.owner)
        assert r.status_code == 200, r.text
        return r.json()


def new_room(relay: Relay, key: str = ROOMS_KEY, set_up: bool = True, **fields) -> Room:
    """A room with its genesis record and epoch 1, as a creator's client leaves it."""
    r = create(relay, key, **fields)
    assert r.status_code == 201, r.text
    body = r.json()
    room = Room(relay, body["room"], Device(body["device"], body["token"]),
                Device(body["custodian"]["device"], body["custodian"]["token"]), body["limits"])
    if set_up:
        assert room.roster(1).status_code == 201
        assert room.epoch(1).status_code == 201
    return room
