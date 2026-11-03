"""Every test vector in vectors/ and the cacophony subset, checked against the library."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from relay.control import parse_control
from relay.errors import PayloadInvalid, ProtocolViolation
from relay.frames import ACCEPT, KIND_APPLICATION, PAIR, frame, pairing_code, prologue
from relay.keys import MemoryKey
from relay.noise import REKEY_EVERY, CipherState, HandshakeState, rekey
from relay.payload import parse_payload
from relay.relays import url_allowed
from relay.session import Session

VECTORS = Path(__file__).resolve().parents[2] / "vectors"


def load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / name).read_text())


def static(vector: dict[str, Any], role: str) -> MemoryKey:
    return MemoryKey(bytes.fromhex(vector[f"{role}_static_private"]))


def handshake(
    vector: dict[str, Any], role: str, initiator: bool, pattern: str, psk: bytes | None
) -> HandshakeState:
    remote = bytes.fromhex(vector["guest_static_public"] if role == "host" else vector["host_static_public"])
    return HandshakeState(
        pattern,
        initiator,
        bytes.fromhex(vector["prologue"]),
        static(vector, role),
        remote,
        psk,
        bytes.fromhex(vector[f"{role}_ephemeral_private"]),
    )


def check_frame(frame_bytes: bytes, expected: str | dict[str, Any]) -> None:
    whole = b"\x01" + frame_bytes
    if isinstance(expected, str):
        assert whole.hex() == expected
    else:
        assert hashlib.sha256(whole).hexdigest() == expected["sha256"]
        assert len(whole) == expected["length"]


def check_handshake(vector: dict[str, Any], pattern: str, first: int, psk: bytes | None) -> None:
    guest = handshake(vector, "guest", True, pattern, psk)
    host = handshake(vector, "host", False, pattern, psk)

    message1 = guest.write_message()
    assert message1.hex() == vector["message1"]
    assert (b"\x01" + frame(first, message1)).hex() == vector["frame1"]
    host.read_message(message1)
    assert host.remote_static == bytes.fromhex(vector["guest_static_public"])

    message2 = host.write_message()
    assert message2.hex() == vector["message2"]
    assert (b"\x01" + frame(ACCEPT, message2)).hex() == vector["frame2"]
    guest.read_message(message2)
    assert guest.handshake_hash == host.handshake_hash == bytes.fromhex(vector["handshake_hash"])
    if pattern == "IKpsk1":
        assert pairing_code(guest.handshake_hash) == vector["pairing_code"]

    guest_session = Session.initiator(guest)
    host_session = Session.responder(host)
    detail = vector.get("fragmented_message")
    big = bytes(i % 251 for i in range(detail["length"])) if detail else b""
    fragment_positions: list[int] = detail["frames"] if detail else []
    big_frames: list[bytes] = []
    for index, item in enumerate(vector["transport"]):
        if item["sender"] == "guest":
            sender, receiver = guest_session, host_session
        else:
            sender, receiver = host_session, guest_session
        if index in fragment_positions:
            if not big_frames:
                big_frames = sender.frames(KIND_APPLICATION, big)
            frame_bytes = big_frames[fragment_positions.index(index)]
            check_frame(frame_bytes, item["frame"])
            expected = (KIND_APPLICATION, big if index == fragment_positions[-1] else None)
        else:
            plaintext = bytes.fromhex(item["plaintext"])
            frames = sender.frames(plaintext[0], plaintext[2:])
            assert len(frames) == 1
            assert (b"\x01" + frames[0]).hex() == item["frame"]
            frame_bytes = frames[0]
            expected = (plaintext[0], plaintext[2:])
        assert receiver.decrypt(frame_bytes[1:]) == expected


def test_pairing_vector() -> None:
    case = load("pairing.json")["cases"][0]
    check_handshake(case, "IKpsk1", PAIR, bytes.fromhex(case["psk"]))


@pytest.mark.parametrize("refused", load("pairing.json")["refused"], ids=lambda case: case["name"])
def test_pairing_vector_refused(refused: dict[str, Any]) -> None:
    case = load("pairing.json")["cases"][0]
    host = HandshakeState(
        "IKpsk1",
        False,
        prologue("dev_01", refused["channel"]),
        MemoryKey(bytes.fromhex(case["host_static_private"])),
        None,
        bytes.fromhex(case["psk"]),
    )
    with pytest.raises(InvalidTag):
        host.read_message(bytes.fromhex(refused["message1"]))


def test_connect_vector() -> None:
    check_handshake(load("connect.json")["cases"][0], "KK", 0x02, None)


def test_connect_vector_refused() -> None:
    file = load("connect.json")
    case = file["cases"][0]
    host = HandshakeState(
        "KK",
        False,
        prologue("dev_01", case["channel"]),
        MemoryKey(bytes.fromhex(case["host_static_private"])),
        bytes.fromhex(case["guest_static_public"]),
    )
    with pytest.raises(InvalidTag):
        host.read_message(bytes.fromhex(file["refused"][0]["message1"]))


def test_rekey_vectors() -> None:
    for case in load("rekey.json")["cases"]:
        cipher = CipherState(bytes.fromhex(case["key"]), nonce=REKEY_EVERY - 1)
        assert cipher.encrypt(b"", bytes.fromhex(case["plaintext_before"])).hex() == case["ciphertext_before"]
        assert cipher.key.hex() == case["rekeyed"] == rekey(bytes.fromhex(case["key"])).hex()
        assert cipher.nonce == REKEY_EVERY
        assert cipher.encrypt(b"", bytes.fromhex(case["plaintext_after"])).hex() == case["ciphertext_after"]
        assert cipher.nonce == REKEY_EVERY + 1


def test_prologue_vectors() -> None:
    for case in load("prologue.json")["cases"]:
        assert prologue(case["dev"], case["channel"]).hex() == case["prologue"]


def test_pairing_code_vectors() -> None:
    for case in load("pairing_code.json")["cases"]:
        assert pairing_code(bytes.fromhex(case["h"])) == case["code"]


def test_url_policy_vectors() -> None:
    for case in load("url_policy.json")["cases"]:
        assert url_allowed(case["url"]) is case["allowed"], case["url"]


def test_pairing_payload_vectors() -> None:
    file = load("pairing_payload.json")
    for case in file["cases"]:
        if case["valid"]:
            payload = parse_payload(case["text"], case["now"])
            original = json.loads(case["text"])["relays"]
            kept = [(entry.url, entry.channel, entry.token) for entry in payload.relays]
            expected = [
                (original[index]["url"], original[index]["channel"], original[index]["token"])
                for index in case["relays_kept"]
            ]
            assert kept == expected, case["name"]
        else:
            with pytest.raises(PayloadInvalid):
                parse_payload(case["text"], case["now"])


def test_control_vectors() -> None:
    for case in load("control.json")["cases"]:
        if case["result"] == "apply":
            assert parse_control(case["text"], case["receiver"]) is not None, case["text"]
        elif case["result"] == "ignore":
            assert parse_control(case["text"], case["receiver"]) is None, case["text"]
        else:
            with pytest.raises(ProtocolViolation):
                parse_control(case["text"], case["receiver"])


def test_cacophony_vectors() -> None:
    patterns = {
        "Noise_IKpsk1_25519_AESGCM_SHA256": "IKpsk1",
        "Noise_KK_25519_AESGCM_SHA256": "KK",
    }
    vectors = [
        vector
        for vector in json.loads((VECTORS / "tools/cacophony_subset.json").read_text())["vectors"]
        if vector["protocol_name"] in patterns
    ]
    assert sorted(vector["protocol_name"] for vector in vectors) == sorted(patterns)
    for vector in vectors:
        check_cacophony(vector, patterns[vector["protocol_name"]])


def check_cacophony(vector: dict[str, Any], pattern: str) -> None:
    def key(name: str) -> bytes | None:
        return bytes.fromhex(vector[name]) if name in vector else None

    initiator = HandshakeState(
        pattern,
        True,
        key("init_prologue") or b"",
        MemoryKey(key("init_static")),
        key("init_remote_static"),
        bytes.fromhex(vector["init_psks"][0]) if vector.get("init_psks") else None,
        key("init_ephemeral"),
    )
    responder = HandshakeState(
        pattern,
        False,
        key("resp_prologue") or b"",
        MemoryKey(key("resp_static")),
        key("resp_remote_static"),
        bytes.fromhex(vector["resp_psks"][0]) if vector.get("resp_psks") else None,
        key("resp_ephemeral"),
    )
    sessions: tuple[CipherState, CipherState, CipherState, CipherState] | None = None
    for index, message in enumerate(vector["messages"]):
        payload = bytes.fromhex(message["payload"])
        expected = bytes.fromhex(message["ciphertext"])
        initiator_sends = index % 2 == 0
        if sessions is None:
            sender = initiator if initiator_sends else responder
            receiver = responder if initiator_sends else initiator
            ciphertext = sender.write_message(payload)
            assert ciphertext == expected, f"handshake message {index}"
            assert receiver.read_message(ciphertext) == payload
            if initiator.finished():
                assert initiator.handshake_hash == responder.handshake_hash == bytes.fromhex(
                    vector["handshake_hash"]
                )
                i1, i2 = initiator.split()
                r1, r2 = responder.split()
                sessions = (i1, i2, r1, r2)
        else:
            i1, i2, r1, r2 = sessions
            sender, receiver = (i1, r1) if initiator_sends else (r2, i2)
            ciphertext = sender.encrypt(b"", payload)
            assert ciphertext == expected, f"transport message {index}"
            assert receiver.decrypt(b"", ciphertext) == payload


def test_a_low_order_ephemeral_key_is_a_protocol_violation() -> None:
    # The host and guest catch errors.ProtocolViolation; a relay that sends an
    # all-zero key must not raise anything else out of their socket loops.
    host, guest = MemoryKey.generate(), MemoryKey.generate()
    responder = HandshakeState("KK", False, b"", host, guest.public)
    with pytest.raises(ProtocolViolation):
        responder.read_message(bytes(48))
