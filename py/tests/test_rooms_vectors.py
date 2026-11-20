"""Every vectors/rooms_*.json case on the member side of relay.rooms (ROOMS.md section 8).

rooms_encoding.json and rooms_roster.json are checked in test_rooms.py (C6).
rooms_quota.json is the relay's side (credentials and room limits); the Go server's
unit tests replay it, and no member code parses a quota, so it is not checked here.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from relay.rooms import (
    RecvKey,
    Refused,
    accept_epoch,
    blob_aad,
    canonical,
    count_messages,
    epoch_body,
    message_aad,
    message_body,
    open_blob,
    open_epoch,
    open_message,
    parse_invite_link,
    seal_blob,
    seal_message,
    unb64,
    verify_roster,
    wrap_for,
    wrap_info,
    wrap_key,
)

VECTORS = Path(__file__).resolve().parents[2] / "vectors"


def load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / name).read_text())


def private_key(jwk: dict) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(unb64(jwk["d"]), "big"), ec.SECP256R1())


class ZeroSign:
    """A C3 signing key that signs nothing: sealing is checked by its ciphertext alone."""

    def sign(self, data: bytes) -> bytes:
        return bytes(64)


def test_epoch_every_intermediate_value_of_each_wrap() -> None:
    v = load("rooms_epoch.json")
    epoch_key = bytes.fromhex(v["epoch_key"])
    assert canonical(epoch_body(v["room"], v["epoch"])) == v["signed_canonical"]
    for w in v["wraps"]:
        recv = RecvKey(private_key(w["recv_private_jwk"]))
        secret = recv.derive(w["wrap"]["eph"])
        assert secret.hex() == w["ecdh_secret"]
        assert wrap_info(v["room"], v["epoch"]["n"], w["device"]) == w["hkdf_info"]
        assert wrap_key(secret, w["hkdf_info"]).hex() == w["wrap_key"]
        made = wrap_for(
            v["room"],
            v["epoch"]["n"],
            w["device"],
            recv.recv_pub,
            epoch_key,
            eph=private_key(w["eph_private_jwk"]),
            iv=bytes.fromhex(w["iv"]),
        )
        assert made == w["wrap"] == v["epoch"]["wraps"][w["device"]]
        assert open_epoch(v["room"], v["epoch"], w["device"], recv).hex() == v["epoch_key"]


def test_epoch_accepted_and_refused() -> None:
    v = load("rooms_epoch.json")
    roster = verify_roster(v["roster"], room=v["room"])
    accept_epoch(roster, v["room"], v["epoch"])
    with pytest.raises(Refused) as caught:
        accept_epoch(roster, "AAAAAAAAAAAAAAAAAAAAAA", v["epoch"])
    assert caught.value.reason == "room"

    def verified(n: int):
        return verify_roster(v["full_roster"][:n], room=v["room"])

    for case in v["accepted"]:
        accept_epoch(verified(case["verified"]), v["room"], case["epoch"], case["before"])
    for case in v["refused"]:
        with pytest.raises(Refused) as caught:
            accept_epoch(verified(case["verified"]), v["room"], case["epoch"], case["before"])
        assert caught.value.reason == case["reason"], case["name"]


def message_context():
    e, v = load("rooms_epoch.json"), load("rooms_message.json")
    roster = verify_roster(e["roster"], room=e["room"])
    accept_epoch(roster, e["room"], e["epoch"])
    epochs = {v["epoch"]: e["epoch"]}
    keys = {v["epoch"]: bytes.fromhex(v["epoch_key"])}

    def sign_pub(device: str):
        d = roster.devices.get(device)
        return d["sign_pub"] if d else None

    return v, epochs, keys, sign_pub


def test_messages_open_and_seal_to_the_same_bytes() -> None:
    v, epochs, keys, sign_pub = message_context()
    for case in v["cases"]:
        m = case["message"]
        assert message_aad(v["room"], m["epoch"], m["device"], m["n"]) == case["additional_data"]
        assert canonical(message_body(v["room"], m)) == case["signed_canonical"]
        assert v["senders"][m["device"]] == sign_pub(m["device"])
        assert open_message(v["room"], m, epochs, keys, sign_pub).hex() == case["plaintext"]
        sealed = seal_message(
            v["room"],
            m["epoch"],
            m["device"],
            m["n"],
            bytes.fromhex(v["epoch_key"]),
            ZeroSign(),
            bytes.fromhex(case["plaintext"]),
            blob=m.get("blob"),
            iv=unb64(m["iv"]),
        )
        assert sealed["ct"] == m["ct"]


@pytest.mark.parametrize("case", load("rooms_message.json")["refused"], ids=lambda c: c["name"])
def test_refused_messages(case: dict) -> None:
    v, epochs, keys, sign_pub = message_context()
    with pytest.raises(Refused) as caught:
        open_message(v["room"], case["message"], epochs, keys, sign_pub)
    assert caught.value.reason == case["reason"]


@pytest.mark.parametrize("case", load("rooms_message.json")["counters"], ids=lambda c: c["name"])
def test_counters_replays_and_gaps(case: dict) -> None:
    results, gaps, after = count_messages(case["state"], case["watermark"], case["messages"])
    assert results == case["results"]
    assert gaps == case["gaps"]
    assert after == case["state_after"]


def test_blobs_seal_open_and_refuse() -> None:
    v = load("rooms_blob.json")
    key = bytes.fromhex(v["epoch_key"])
    for case in v["cases"]:
        assert blob_aad(v["room"], case["blob"]) == case["additional_data"], case["name"]
        if isinstance(case["plaintext"], str):
            plaintext = bytes.fromhex(case["plaintext"])
        else:
            plaintext = bytes(i % 251 for i in range(case["plaintext"]["length"]))
            assert hashlib.sha256(plaintext).hexdigest() == case["plaintext"]["sha256"]
        sealed = seal_blob(v["room"], case["blob"], key, plaintext, iv=bytes.fromhex(case["iv"]))
        if isinstance(case["body"], str):
            assert sealed.hex() == case["body"], case["name"]
        else:
            assert {"sha256": hashlib.sha256(sealed).hexdigest(), "length": len(sealed)} == case["body"]
        assert open_blob(v["room"], case["blob"], key, sealed) == plaintext
    for case in v["refused"]:
        with pytest.raises(Refused) as caught:
            open_blob(v["room"], case["blob"], key, bytes.fromhex(case["body"]))
        assert caught.value.reason == "decrypt", case.get("name")


@pytest.mark.parametrize("case", load("rooms_invite_link.json")["cases"], ids=lambda c: c["name"])
def test_invite_links(case: dict) -> None:
    parsed = parse_invite_link(case["text"])
    if not case["valid"]:
        assert parsed is None
        return
    assert parsed is not None
    base = parsed.pop("relay_base_url")
    assert parsed == case["parsed"]
    assert base == case["relay_base_url"]
