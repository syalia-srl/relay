"""Generate the JSON test vectors of PROTOCOL.md into vectors/.

Usage: python generate.py [--check]
With --check it regenerates in memory and fails if any file in vectors/ differs.
Every handshake and transport transcript is also replayed through the noiseprotocol
package, so the vectors rest on two implementations that agree.
"""

import base64
import hashlib
import ipaddress
import json
import struct
import sys
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
# Internal module of noiseprotocol, safe because pyproject.toml pins noiseprotocol==0.3.1.
from noise.backends.default.ciphers import AESGCMCipher
from noise.connection import Keypair, NoiseConnection

import rooms_ref as rooms
from noise_ref import CipherState, HandshakeState, public_key, rekey

OUT = Path(__file__).resolve().parent.parent

PAIR, CONNECT, ACCEPT, TRANSPORT, ABORT = 0x01, 0x02, 0x03, 0x04, 0x05
APP, CONTROL = 0x00, 0x01
MAX_PAYLOAD = 65517
REKEY_EVERY = 2**20


def seed(label: str) -> bytes:
    """Deterministic 32 bytes for a named test key."""
    return hashlib.sha256(b"relay-channel/3 vectors " + label.encode()).digest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def prologue(dev: str, channel: str) -> bytes:
    d, c = dev.encode(), channel.encode()
    return b"relay-channel/3" + struct.pack(">H", len(d)) + d + struct.pack(">H", len(c)) + c


def pairing_code(h: bytes) -> str:
    digest = hashlib.sha256(b"relay-channel/3 pairing code" + h).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def l0(l1_frame: bytes) -> bytes:
    return b"\x01" + l1_frame


def plaintext(kind: int, more: bool, payload: bytes) -> bytes:
    return bytes([kind, 1 if more else 0]) + payload


def control(op: dict) -> bytes:
    return json.dumps(op, separators=(",", ":")).encode()


def fragments(kind: int, message: bytes) -> list[bytes]:
    parts = [message[i:i + MAX_PAYLOAD] for i in range(0, len(message), MAX_PAYLOAD)] or [b""]
    return [plaintext(kind, i < len(parts) - 1, p) for i, p in enumerate(parts)]


# --- URL policy (section 8.1) ---

def url_allowed(url: str) -> bool:
    try:
        if len(url) > 2048:
            return False
        parts = urlsplit(url)
        host = parts.hostname
        if parts.username or parts.password or parts.query or parts.fragment or not host:
            return False
        if parts.port is not None and parts.port == 0:  # .port raises ValueError past 65535
            return False
        if parts.scheme == "wss":
            return True
        if parts.scheme != "ws" or "%" in host:
            return False
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.version == 4:
        return any(address in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    return address in ipaddress.ip_network("fc00::/7")


URLS = [
    ("wss://relay.example", True),
    ("wss://relay.example:8443/base/", True),
    ("wss://203.0.113.7", True),
    ("ws://192.168.1.10:8010", True),
    ("ws://10.0.0.1", True),
    ("ws://172.16.0.1", True),
    ("ws://172.31.255.254:80", True),
    ("ws://[fd12:3456::1]:8010", True),
    ("ws://[fc00::1]", True),
    ("ws://172.32.0.1", False),
    ("ws://11.0.0.1", False),
    ("ws://203.0.113.7", False),
    ("ws://127.0.0.1:8010", False),
    ("ws://169.254.1.1", False),
    ("ws://[::1]", False),
    ("ws://[fe80::1]", False),
    ("ws://[2001:db8::1]", False),
    ("ws://relay.local", False),
    ("ws://relay.example", False),
    ("ws://localhost", False),
    ("ws:10.0.0.1", False),
    ("ws:/10.0.0.1", False),
    ("http://192.168.1.10", False),
    ("https://relay.example", False),
    ("wss://user:pass@relay.example", False),
    ("wss://relay.example/?x=1", False),
    ("wss://relay.example/#f", False),
    ("wss://", False),
    ("relay.example", False),
    ("ws://[::ffff:192.168.1.10]", False),
    ("ws://[fd12::1%25eth0]", False),
    ("wss://relay.example:0", False),
    ("wss://relay.example:65536", False),
    ("wss://relay.example/" + "a" * 2030, False),
    ("wss://relay.example/" + "a" * 2028, True),
]


def url_policy() -> dict:
    cases = []
    for url, allowed in URLS:
        assert url_allowed(url) == allowed, url
        cases.append({"url": url, "allowed": allowed})
    return {"description": "PROTOCOL.md 8.1: which relay URLs a host and a guest accept.", "cases": cases}


# --- pairing payload (section 4) ---

def strict_json(raw):
    """Parse JSON, refusing duplicate keys (PROTOCOL.md 1). Raises ValueError."""
    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(items)
    return json.loads(raw, object_pairs_hook=pairs)


def is_hex64(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**53 - 1


def is_b64url(value, length: int) -> bool:
    chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    return isinstance(value, str) and len(value) == length and set(value) <= chars


def is_relay_entry(entry) -> bool:
    return (isinstance(entry, dict) and isinstance(entry.get("url"), str)
            and is_b64url(entry.get("channel"), 22) and is_b64url(entry.get("token"), 43))


def check_payload(payload, now: int) -> list[int] | None:
    """The indexes of the relays a guest keeps, or None when it refuses the payload."""
    dev_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
    if not isinstance(payload, dict) or not is_int(payload.get("v")) or payload["v"] != 3:
        return None
    if not is_hex64(payload.get("hs")) or not is_hex64(payload.get("psk")):
        return None
    dev = payload.get("dev")
    if not isinstance(dev, str) or not 1 <= len(dev) <= 64 or not set(dev) <= dev_chars:
        return None
    if not is_int(payload.get("exp")) or now > payload["exp"] + 60:
        return None
    if "name" in payload and (not isinstance(payload["name"], str) or len(payload["name"]) > 100):
        return None
    if "url" in payload and (not isinstance(payload["url"], str) or len(payload["url"]) > 2048):
        return None
    relays = payload.get("relays")
    if not isinstance(relays, list) or not 1 <= len(relays) <= 16:
        return None
    if not all(is_relay_entry(r) for r in relays):
        return None
    kept = [i for i, r in enumerate(relays) if url_allowed(r["url"])]
    return kept or None


def payload_cases() -> dict:
    hs = public_key(seed("host static")).hex()
    psk = seed("pairing psk").hex()
    relays = [{"url": "ws://192.168.1.10:8010", "channel": "AAECAwQFBgcICQoLDA0ODw", "token": "t" * 43},
              {"url": "wss://relay.example", "channel": "EBESExQVFhcYGRobHB0eHw", "token": "u" * 43}]
    entry = lambda url: {**relays[1], "url": url}  # noqa: E731
    base = {"v": 3, "hs": hs, "psk": psk, "dev": "dev_01", "exp": 1800000300, "relays": relays,
            "name": "Office", "url": "https://office.example"}
    now = 1800000000
    variants = [
        ("valid", base, True, [0, 1]),
        ("valid without optional fields", {k: v for k, v in base.items() if k not in ("name", "url")}, True, [0, 1]),
        ("unknown fields are ignored", {**base, "extra": {"a": 1}}, True, [0, 1]),
        ("a relay failing the URL policy is dropped",
         {**base, "relays": [entry("ws://relay.local"), relays[1]]}, True, [1]),
        ("no relay passes the URL policy",
         {**base, "relays": [entry("ws://8.8.8.8")]}, False, None),
        ("a channel id of 21 characters", {**base, "relays": [{**relays[1], "channel": "A" * 21}]}, False, None),
        ("a token with a character outside base64url",
         {**base, "relays": [{**relays[1], "token": "u" * 42 + "="}]}, False, None),
        ("a relay entry without a token",
         {**base, "relays": [{k: v for k, v in relays[1].items() if k != "token"}]}, False, None),
        ("a bad entry fails the payload even if another is good",
         {**base, "relays": [{**relays[0], "channel": "x"}, relays[1]]}, False, None),
        ("empty relay list", {**base, "relays": []}, False, None),
        ("17 relays", {**base, "relays": [relays[1]] * 17}, False, None),
        ("version 2", {**base, "v": 2}, False, None),
        ("version as a string", {**base, "v": "3"}, False, None),
        ("version as 3.0", {**base, "v": 3.0}, False, None),
        ("hs too short", {**base, "hs": hs[:62]}, False, None),
        ("hs in uppercase", {**base, "hs": hs.upper()}, False, None),
        ("psk not hex", {**base, "psk": "z" * 64}, False, None),
        ("dev with a slash", {**base, "dev": "dev/01"}, False, None),
        ("dev empty", {**base, "dev": ""}, False, None),
        ("dev of 65 characters", {**base, "dev": "d" * 65}, False, None),
        ("exp missing", {k: v for k, v in base.items() if k != "exp"}, False, None),
        ("expired by more than 60 s", {**base, "exp": now - 61}, False, None),
        ("expired by less than 60 s", {**base, "exp": now - 59}, True, [0, 1]),
        ("expired by exactly 60 s", {**base, "exp": now - 60}, True, [0, 1]),
        ("name of 101 characters", {**base, "name": "n" * 101}, False, None),
        ("not an object", [base], False, None),
    ]
    cases = []
    texts = [(n, json.dumps(p, separators=(",", ":")), v, k) for n, p, v, k in variants]
    good = json.dumps(base, separators=(",", ":"))
    texts.append(("a duplicate key", good[:-1] + ',"dev":"dev_02"}', False, None))
    texts.append(("not JSON", good[:-1], False, None))
    for name, text, valid, kept in texts:
        try:
            result = check_payload(strict_json(text), now)
        except ValueError:
            result = None
        assert result == (kept if valid else None), name
        case = {"name": name, "now": now, "text": text, "valid": valid}
        if valid:
            case["relays_kept"] = kept
        cases.append(case)
    return {"description": "PROTOCOL.md 4: pairing payloads a guest accepts or refuses at time `now`. "
                           "relays_kept lists the indexes of the relays that survive the URL policy.",
            "cases": cases}


# --- prologue and pairing code (sections 3.1, 5.3) ---

def prologue_cases() -> dict:
    cases = []
    for dev, channel in [("dev_01", "AAECAwQFBgcICQoLDA0ODw"), ("a", "b"), ("d" * 64, "c" * 22)]:
        cases.append({"dev": dev, "channel": channel, "prologue": prologue(dev, channel).hex()})
    return {"description": "PROTOCOL.md 3.1: the prologue for a device id and a channel id.", "cases": cases}


def code_cases() -> dict:
    cases = [{"h": seed(f"h {i}").hex(), "code": pairing_code(seed(f"h {i}"))} for i in range(8)]
    zero = bytes(32)
    cases.append({"h": zero.hex(), "code": pairing_code(zero)})
    return {"description": "PROTOCOL.md 5.3: the 6-digit pairing code for a handshake hash h.", "cases": cases}


# --- handshakes and transport (sections 5, 6, 7) ---

def check_with_noiseprotocol(pattern: str, prol: bytes, keys: dict, psk: bytes | None,
                             messages: list[bytes], transport: list[tuple[str, bytes, bytes]], h: bytes) -> None:
    """Replay a transcript through the noiseprotocol package and require identical bytes."""
    name = f"Noise_{pattern}_25519_AESGCM_SHA256".encode()
    sides = {}
    for role, initiator in (("guest", True), ("host", False)):
        n = NoiseConnection.from_name(name)
        n.set_as_initiator() if initiator else n.set_as_responder()
        n.set_prologue(prol)
        n.set_keypair_from_private_bytes(Keypair.STATIC, keys[f"{role}_static"])
        n.set_keypair_from_private_bytes(Keypair.EPHEMERAL, keys[f"{role}_ephemeral"])
        other = "host" if role == "guest" else "guest"
        if pattern == "KK" or role == "guest":
            n.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, public_key(keys[f"{other}_static"]))
        if psk is not None:
            n.set_psks(psk=psk)
        n.start_handshake()
        sides[role] = n
    assert sides["guest"].write_message() == messages[0]
    sides["host"].read_message(messages[0])
    assert sides["host"].write_message() == messages[1]
    sides["guest"].read_message(messages[1])
    assert sides["guest"].get_handshake_hash() == h
    for sender, pt, ct in transport:
        receiver = "host" if sender == "guest" else "guest"
        assert sides[sender].encrypt(pt) == ct
        assert sides[receiver].decrypt(ct) == pt


def handshake(pattern: str, dev: str, channel: str, keys: dict, psk: bytes | None,
              transport: list[tuple[str, bytes]]) -> dict:
    prol = prologue(dev, channel)
    host_rs = public_key(keys["guest_static"]) if pattern == "KK" else None
    guest = HandshakeState(pattern, True, prol, keys["guest_static"], public_key(keys["host_static"]),
                           psk, keys["guest_ephemeral"])
    host = HandshakeState(pattern, False, prol, keys["host_static"], host_rs, psk, keys["host_ephemeral"])
    m1 = guest.write_message()
    host.read_message(m1)
    assert host.rs == public_key(keys["guest_static"])
    m2 = host.write_message()
    guest.read_message(m2)
    assert guest.h == host.h
    g_send, g_recv = guest.split()
    h_recv, h_send = host.split()
    ciphers = {"guest": g_send, "host": h_send}
    readers = {"guest": h_recv, "host": g_recv}
    frames, replay = [], []
    for sender, pt in transport:
        ct = ciphers[sender].encrypt(b"", pt)
        assert readers[sender].decrypt(b"", ct) == pt
        replay.append((sender, pt, ct))
        frames.append({"sender": sender, "plaintext": pt.hex(), "frame": l0(bytes([TRANSPORT]) + ct).hex()})
    check_with_noiseprotocol(pattern, prol, keys, psk, [m1, m2], replay, guest.h)
    first = PAIR if pattern == "IKpsk1" else CONNECT
    out = {
        "protocol_name": f"Noise_{pattern}_25519_AESGCM_SHA256",
        "dev": dev,
        "channel": channel,
        "prologue": prol.hex(),
        "host_static_private": keys["host_static"].hex(),
        "host_static_public": public_key(keys["host_static"]).hex(),
        "guest_static_private": keys["guest_static"].hex(),
        "guest_static_public": public_key(keys["guest_static"]).hex(),
        "guest_ephemeral_private": keys["guest_ephemeral"].hex(),
        "host_ephemeral_private": keys["host_ephemeral"].hex(),
    }
    if psk is not None:
        out["psk"] = psk.hex()
    out.update({
        "message1": m1.hex(),
        "frame1": l0(bytes([first]) + m1).hex(),
        "message2": m2.hex(),
        "frame2": l0(bytes([ACCEPT]) + m2).hex(),
        "handshake_hash": guest.h.hex(),
        "transport": frames,
    })
    if pattern == "IKpsk1":
        out["pairing_code"] = pairing_code(guest.h)
    return out


def keys_for(label: str) -> dict:
    return {k: seed(f"{label} {k}") for k in ("host_static", "guest_static", "guest_ephemeral", "host_ephemeral")}


def pairing_vectors() -> dict:
    keys = keys_for("pairing")
    keys["host_static"] = seed("host static")
    psk = seed("pairing psk")
    relays = control({"op": "relays", "relays": [
        {"url": "ws://192.168.1.10:8010", "channel": "ICEiIyQlJicoKSorLC0uLw", "token": "v" * 43},
        {"url": "wss://relay.example", "channel": "MDEyMzQ1Njc4OTo7PD0-Pw", "token": "w" * 43}]})
    good = handshake("IKpsk1", "dev_01", "AAECAwQFBgcICQoLDA0ODw", keys, psk, [
        ("guest", plaintext(CONTROL, False, control({"op": "ping"}))),
        ("host", plaintext(CONTROL, False, control({"op": "pong"}))),
        ("host", plaintext(CONTROL, False, relays)),
    ])
    # The same first message built with a wrong psk: the host must refuse it.
    wrong = HandshakeState("IKpsk1", True, prologue("dev_01", "AAECAwQFBgcICQoLDA0ODw"), keys["guest_static"],
                           public_key(keys["host_static"]), seed("wrong psk"), keys["guest_ephemeral"])
    m1_wrong = wrong.write_message()
    host = HandshakeState("IKpsk1", False, prologue("dev_01", "AAECAwQFBgcICQoLDA0ODw"), keys["host_static"],
                          None, psk, keys["host_ephemeral"])
    try:
        host.read_message(m1_wrong)
        raise AssertionError("a wrong psk was accepted")
    except Exception as e:  # cryptography's InvalidTag
        assert type(e).__name__ == "InvalidTag", e
    # The right message on another channel: the prologue differs, so it fails too.
    host = HandshakeState("IKpsk1", False, prologue("dev_01", "EBESExQVFhcYGRobHB0eHw"), keys["host_static"],
                          None, psk, keys["host_ephemeral"])
    try:
        host.read_message(bytes.fromhex(good["message1"]))
        raise AssertionError("a message moved to another channel was accepted")
    except Exception as e:
        assert type(e).__name__ == "InvalidTag", e
    good["confirmed_before_frame"] = 2
    return {
        "description": "PROTOCOL.md 5: a pairing with Noise_IKpsk1. The guest sends `frame1`, the host answers "
                       "`frame2`, both derive `pairing_code`, then the transport frames follow in order. The guest shows "
                       "the code after the `pong` (transport index 1); the person types it into the host before "
                       "the transport frame at 0-based index `confirmed_before_frame`, the first one a host may "
                       "send only after confirmation (`relays`). "
                       "Frames are whole L0 data frames (0x01, then the L1 type byte). `refused` lists first "
                       "messages the host must fail to read.",
        "cases": [good],
        "refused": [
            {"name": "built with a wrong psk", "psk_used": seed("wrong psk").hex(), "channel": good["channel"],
             "message1": m1_wrong.hex()},
            {"name": "the valid message1, read on another channel", "channel": "EBESExQVFhcYGRobHB0eHw",
             "message1": good["message1"]},
        ],
    }


def connect_vectors() -> dict:
    keys = keys_for("connect")
    keys["host_static"] = seed("host static")
    big = bytes(i % 251 for i in range(2 * MAX_PAYLOAD + 10))
    transport = [("guest", plaintext(CONTROL, False, control({"op": "ping"}))),
                 ("host", plaintext(CONTROL, False, control({"op": "pong"}))),
                 ("guest", plaintext(APP, False, b"")),
                 ("guest", plaintext(APP, False, b"hello host"))]
    transport += [("host", p) for p in fragments(APP, big)]
    transport += [("host", plaintext(CONTROL, False, control({"op": "revoked"})))]
    case = handshake("KK", "dev_01", "ICEiIyQlJicoKSorLC0uLw", keys, None, transport)
    # Keep the file small: the three fragments of the big message are given by digest.
    for frame in case["transport"]:
        if len(frame["plaintext"]) > 2000:
            pt, fr = bytes.fromhex(frame["plaintext"]), bytes.fromhex(frame["frame"])
            frame["plaintext"] = {"sha256": hashlib.sha256(pt).hexdigest(), "length": len(pt),
                                  "head": pt[:2].hex()}
            frame["frame"] = {"sha256": hashlib.sha256(fr).hexdigest(), "length": len(fr)}
    case["fragmented_message"] = {"kind": APP, "length": len(big), "content": "byte i is i mod 251",
                                  "sha256": hashlib.sha256(big).hexdigest(),
                                  "frames": list(range(4, 4 + len(fragments(APP, big))))}
    assert case["fragmented_message"]["frames"] == [4, 5, 6]
    # A KK first message from a guest key that is not bound must fail to read.
    stranger = HandshakeState("KK", True, prologue("dev_01", case["channel"]), seed("stranger static"),
                              public_key(keys["host_static"]), None, keys["guest_ephemeral"])
    m1 = stranger.write_message()
    host = HandshakeState("KK", False, prologue("dev_01", case["channel"]), keys["host_static"],
                          public_key(keys["guest_static"]), None, keys["host_ephemeral"])
    try:
        host.read_message(m1)
        raise AssertionError("an unbound guest key was accepted")
    except Exception as e:
        assert type(e).__name__ == "InvalidTag", e
    return {
        "description": "PROTOCOL.md 6 and 7: a connection with Noise_KK, then transport frames in order, "
                       "including an empty message and a message in three fragments (given by digest). "
                       "`refused` lists first messages the host must fail to read.",
        "cases": [case],
        "refused": [{"name": "from a guest key that is not bound", "guest_static_private": seed("stranger static").hex(),
                     "message1": m1.hex()}],
    }


def rekey_vectors() -> dict:
    cases = []
    for i in range(2):
        k = seed(f"rekey {i}")
        before = CipherState(k)
        before.n = REKEY_EVERY - 1
        pt = plaintext(APP, False, b"last before rekey")
        ct_before = before.encrypt(b"", pt)
        before.rekey()
        theirs = AESGCMCipher()
        theirs.initialize(k)
        assert before.k == rekey(k) == theirs.rekey(k)
        pt2 = plaintext(APP, False, b"first after rekey")
        ct_after = before.encrypt(b"", pt2)
        assert before.n == REKEY_EVERY + 1
        cases.append({"key": k.hex(), "rekeyed": rekey(k).hex(),
                      "nonce_before": REKEY_EVERY - 1, "plaintext_before": pt.hex(), "ciphertext_before": ct_before.hex(),
                      "nonce_after": REKEY_EVERY, "plaintext_after": pt2.hex(), "ciphertext_after": ct_after.hex()})
    return {"description": "PROTOCOL.md 7.3: a cipher state that has key `key` at nonce 2^20 - 1 encrypts "
                           "`plaintext_before`, rekeys to `rekeyed`, and encrypts `plaintext_after` at nonce 2^20.",
            "cases": cases}


# --- relay tokens (section 2.2) ---

def relay_token_vectors() -> dict:
    issuer = Ed25519PrivateKey.from_private_bytes(seed("issuer"))
    other = Ed25519PrivateKey.from_private_bytes(seed("other issuer"))
    issuer_pub = issuer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    now = 1800000000

    def token(payload, key=issuer, raw=None) -> str:
        body = "rt1." + b64url(raw if raw is not None else json.dumps(payload, separators=(",", ":")).encode())
        return body + "." + b64url(key.sign(body.encode()))

    claims = {"iss": "syalia", "aud": "relay.example", "sub": "i_7f3a9c", "exp": now + 86400, "channels": 64,
              "creates_per_minute": 10, "bytes_per_day": 200_000_000}
    good = token(claims)
    head, _, sig = good.rpartition(".")
    flipped = head + "." + b64url(bytes([base64.urlsafe_b64decode(sig + "==")[0] ^ 1]) +
                                  base64.urlsafe_b64decode(sig + "==")[1:])
    def noncanonical(text: str) -> str:
        """The same bytes with non-zero trailing bits in the last base64 digit."""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        index = alphabet.index(text[-1])
        return text[:-1] + alphabet[index | 1]

    payload = json.dumps(claims, separators=(",", ":")).encode()
    spaced = payload + b" "
    spaced_body = "rt1." + noncanonical(b64url(spaced))
    cases = [
        ("valid", good, True),
        ("valid, with an unknown field", token({**claims, "note": "x"}), True),
        ("payload with base64 padding", "rt1." + good.split(".")[1] + "=." + good.split(".")[2], False),
        ("signature with base64 padding", good + "=", False),
        ("signature with non-canonical trailing bits", head + "." + noncanonical(sig), False),
        ("payload with non-canonical trailing bits", spaced_body + "." + b64url(issuer.sign(spaced_body.encode())), False),
        ("signed by another key", token(claims, other), False),
        ("signature with one bit flipped", flipped, False),
        ("unknown issuer", token({**claims, "iss": "nobody"}), False),
        ("expired", token({**claims, "exp": now - 1}), False),
        ("missing sub", token({k: v for k, v in claims.items() if k != "sub"}), False),
        ("channels as a string", token({**claims, "channels": "64"}), False),
        ("payload is not JSON", token(None, raw=b"not json"), False),
        ("payload is a JSON array", token(None, raw=b"[1,2]"), False),
        ("wrong prefix", "rt2." + good[4:], False),
        ("for another relay", token({**claims, "aud": "other.example"}), False),
        ("expiring exactly now", token({**claims, "exp": now}), False),
        ("negative channels", token({**claims, "channels": -1}), False),
        ("bytes_per_day as a float", token({**claims, "bytes_per_day": 1.5e8}), False),
        ("empty sub", token({**claims, "sub": ""}), False),
        ("sub of 128 characters", token({**claims, "sub": "s" * 128}), True),
        ("empty iss", token({**claims, "iss": ""}), False),
        ("aud of 65 characters", token({**claims, "aud": "a" * 65}), False),
        ("sub of 129 characters", token({**claims, "sub": "s" * 129}), False),
        ("a duplicate key", token(None, raw=json.dumps(claims, separators=(",", ":"))[:-1].encode()
                                  + b',"channels":9999}'), False),
        ("longer than 4096 bytes", token({**claims, "pad": "p" * 4000}), False),
        ("payload edited after signing", "rt1." + b64url(json.dumps({**claims, "channels": 9999},
                                                                    separators=(",", ":")).encode()) + "." + sig, False),
    ]
    for _, t, valid in cases:
        assert verify_relay_token(t, {"syalia": issuer_pub}, "relay.example", now) == valid, t
    return {"description": "PROTOCOL.md 2.2: relay tokens checked at time `now`, by the relay whose own id is `relay_id`, "
                           "against the issuers in `issuers` "
                           "(issuer id to Ed25519 public key).",
            "now": now, "relay_id": "relay.example", "issuers": {"syalia": issuer_pub.hex()},
            "issuer_private_seed": seed("issuer").hex(),
            "cases": [{"name": n, "token": t, "valid": v} for n, t, v in cases]}


def strict_b64(text: str) -> bytes:
    """Unpadded base64url with canonical trailing bits, as the relay requires."""
    if "=" in text:
        raise ValueError("padding")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != text:
        raise ValueError("non-canonical")
    return raw


def verify_relay_token(token: str, issuers: dict, relay_id: str, now: int) -> bool:
    if len(token.encode()) > 4096:
        return False
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != "rt1":
        return False
    try:
        raw = strict_b64(parts[1])
        sig = strict_b64(parts[2])
        claims = strict_json(raw)
    except ValueError:
        return False
    if not isinstance(claims, dict):
        return False
    strings = {"iss": 64, "aud": 64, "sub": 128}
    if any(not isinstance(claims.get(k), str) or not 1 <= len(claims[k]) <= n for k, n in strings.items()):
        return False
    if any(not is_int(claims.get(k)) for k in ("exp", "channels", "creates_per_minute", "bytes_per_day")):
        return False
    if claims["iss"] not in issuers or claims["aud"] != relay_id:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(issuers[claims["iss"]]).verify(sig, f"rt1.{parts[1]}".encode())
    except Exception:
        return False
    return claims["exp"] > now


def check_control(text: str, receiver: str):
    """'apply', 'ignore' or 'abort' for a control message arriving at `receiver` (PROTOCOL.md 9.1)."""
    senders = {"relays": "host", "close": "guest", "closed": "host", "revoked": "host", "ping": None, "pong": None}
    try:
        msg = strict_json(text)
    except ValueError:
        return "abort"
    if not isinstance(msg, dict) or not isinstance(msg.get("op"), str):
        return "abort"
    op = msg["op"]
    if op not in senders:
        return "ignore"
    if senders[op] is not None and senders[op] == receiver:
        return "abort"
    if op == "relays":
        relays = msg.get("relays")
        if not isinstance(relays, list) or not 1 <= len(relays) <= 16 or not all(is_relay_entry(r) for r in relays):
            return "abort"
        if not any(url_allowed(r["url"]) for r in relays):
            return "ignore"
    return "apply"


def control_vectors() -> dict:
    entry = {"url": "wss://relay.example", "channel": "MDEyMzQ1Njc4OTo7PD0-Pw", "token": "w" * 43}
    cases = [
        ('{"op":"ping"}', "host", "apply"),
        ('{"op":"ping"}', "guest", "apply"),
        ('{"op":"pong","n":1}', "guest", "apply"),
        ('{"op":"close"}', "host", "apply"),
        ('{"op":"close"}', "guest", "abort"),
        ('{"op":"closed"}', "guest", "apply"),
        ('{"op":"revoked"}', "guest", "apply"),
        ('{"op":"revoked"}', "host", "abort"),
        (json.dumps({"op": "relays", "relays": [entry]}), "guest", "apply"),
        (json.dumps({"op": "relays", "relays": [entry]}), "host", "abort"),
        (json.dumps({"op": "relays", "relays": []}), "guest", "abort"),
        (json.dumps({"op": "relays", "relays": [entry] * 17}), "guest", "abort"),
        (json.dumps({"op": "relays", "relays": [{**entry, "token": "short"}]}), "guest", "abort"),
        (json.dumps({"op": "relays", "relays": [{**entry, "url": "ws://relay.local"}]}), "guest", "ignore"),
        ('{"op":"hello"}', "host", "ignore"),
        ('{"op":"PING"}', "host", "ignore"),
        ('{"op":1}', "host", "abort"),
        ('{"type":"ping"}', "host", "abort"),
        ('["ping"]', "host", "abort"),
        ('{"op":"ping","op":"close"}', "host", "abort"),
        ('{"op":"ping"', "host", "abort"),
    ]
    out = []
    for text, receiver, result in cases:
        assert check_control(text, receiver) == result, (text, receiver)
        out.append({"text": text, "receiver": receiver, "result": result})
    return {"description": "PROTOCOL.md 9.1: what the receiver does with a control message: apply it, ignore it, "
                           "or abort. A `relays` list whose every URL fails the policy is ignored (8.3).",
            "cases": out}


# --- rooms (ROOMS.md) ---

def rseed(label: str) -> bytes:
    """Deterministic 32 bytes for a named room test value."""
    return hashlib.sha256(b"relay-rooms/1 vectors " + label.encode()).digest()


def rid(label: str) -> str:
    """A deterministic 16-byte id, base64url (ROOMS.md 2)."""
    return b64url(rseed(label)[:16])


def must_fail(fn, *args, reason: str | None = None) -> str:
    """Call fn, require rooms_ref.Refused, and return its reason."""
    try:
        fn(*args)
    except rooms.Refused as e:
        assert reason is None or e.reason == reason, (e.reason, reason)
        return e.reason
    raise AssertionError(f"accepted, expected {reason}")


def flip_b64(text: str, byte: int = 0) -> str:
    raw = bytearray(strict_b64(text))
    raw[byte] ^= 1
    return b64url(bytes(raw))


def encoding_vectors() -> dict:
    objects = [
        {"b": 1, "a": [True, False, None], "c": {"z": "", "y": "x"}},
        {"v": "relay-roster-1", "n": 2, "prev": "", "entry": {"kind": "invite"}},
        {"text": "ñandú «sí»   \"q\" \\ \n\t\u0001 \U0001f600"},
        {"n": 9007199254740991, "empty": {}, "list": []},
    ]
    canon = [{"object": o, "canonical": rooms.canonical(o)} for o in objects]
    assert canon[0]["canonical"] == '{"a":[true,false,null],"b":1,"c":{"y":"x","z":""}}'
    assert canon[2]["canonical"] == '{"text":"ñandú «sí»   \\"q\\" \\\\ \\n\\t\\u0001 \U0001f600"}'
    key = rooms.signing_key(rseed("encoding signer"))
    other = rooms.signing_key(rseed("encoding other"))
    obj = objects[1]
    sig = rooms.sign(key, obj)
    raw = strict_b64(sig)
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    high = b64url(r.to_bytes(32, "big") + (rooms.P256_N - s).to_bytes(32, "big"))
    sigs = [
        ("valid", rooms.public_jwk(key), sig, True),
        ("the same signature with s replaced by n - s", rooms.public_jwk(key), high, True),
        ("one bit flipped", rooms.public_jwk(key), flip_b64(sig, 40), False),
        ("another key", rooms.public_jwk(other), sig, False),
        ("63 bytes", rooms.public_jwk(key), b64url(raw[:63]), False),
        ("DER instead of r||s", rooms.public_jwk(key), b64url(rooms.der_signature(raw)), False),
        ("base64 padding", rooms.public_jwk(key), sig + "=", False),
        ("a JWK with extra members is reduced first",
         {**rooms.public_jwk(key), "ext": True, "key_ops": ["verify"]}, sig, True),
    ]
    cases = []
    for name, jwk, s_, valid in sigs:
        assert rooms.verify(jwk, obj, s_) == valid, name
        cases.append({"name": name, "public_jwk": jwk, "object": obj, "sig": s_, "valid": valid})
    full = {**rooms.public_jwk(key), "d": rooms.private_d(key), "ext": True, "key_ops": ["sign"]}
    return {"description": "ROOMS.md 2: canonical JSON (sorted keys, no spaces, UTF-8, non-ASCII unescaped), "
                           "ECDSA P-256 SHA-256 signatures as 64 raw bytes r||s over the canonical JSON, base64url "
                           "without padding, and the reduction of a JWK to kty, crv, x, y. A verifier accepts "
                           "either s or n - s.",
            "canonical": canon,
            "signatures": cases,
            "public_jwk": {"jwk": full, "reduced": rooms.reduce_jwk(full)}}


class RosterBuilder:
    """Builds a signed roster record by record, keeping the chain."""

    def __init__(self):
        self.records = []

    def add(self, key, entry: dict) -> dict:
        prev = rooms.record_hash(self.records[-1]) if self.records else ""
        record = rooms.sign_entry(key, entry, len(self.records) + 1, prev)
        self.records.append(record)
        return record


def roster_world() -> dict:
    """The keys and ids of the roster, epoch and message vectors."""
    names = ["creator", "custodian", "ben", "dana", "ben phone 2", "relay"]
    world = {"room": rid("room"), "keys": {}, "recv": {}, "devices": {}}
    for n in names:
        world["keys"][n] = rooms.signing_key(rseed(f"{n} sign"))
        world["recv"][n] = rooms.signing_key(rseed(f"{n} recv"))
        world["devices"][n] = rid(f"{n} device")
    for n in ("invite 1", "invite 2", "invite 3", "invite relay"):
        world["keys"][n] = rooms.signing_key(rseed(n))
        world["devices"][n] = rid(n)
    return world


def join_entry(w: dict, who: str, invite: str, at: int, invite_key=None) -> dict:
    body = {"invite": w["devices"][invite], "device": w["devices"][who], "at": at,
            "sign_pub": rooms.public_jwk(w["keys"][who]), "recv_pub": rooms.public_jwk(w["recv"][who])}
    return {"kind": "join", "by": w["devices"][who], **body,
            "invite_sig": rooms.sign(invite_key or w["keys"][invite], rooms.join_body(body))}


def valid_roster(w: dict) -> tuple[RosterBuilder, list[str]]:
    d, k = w["devices"], w["keys"]
    pub = lambda n: rooms.public_jwk(k[n])  # noqa: E731
    b = RosterBuilder()
    steps = []

    def add(signer, entry, what):
        b.add(k[signer], entry)
        steps.append(what)

    add("creator", {"kind": "genesis", "by": d["creator"], "room": w["room"],
                    "creator": {"device": d["creator"], "sign_pub": pub("creator"),
                                "recv_pub": rooms.public_jwk(w["recv"]["creator"])},
                    "custodian": {"device": d["custodian"], "sign_pub": pub("custodian")}},
        "genesis: the creator and the custodian, both owners")
    add("creator", {"kind": "invite", "by": d["creator"], "invite": d["invite 1"], "invite_pub": pub("invite 1"),
                    "uses": 2, "expires_at": 1800259200, "approval": False},
        "invite 1, two uses, no approval")
    add("ben", join_entry(w, "ben", "invite 1", 1800000100), "ben joins with invite 1")
    add("custodian", {"kind": "invite", "by": d["custodian"], "invite": d["invite 2"], "invite_pub": pub("invite 2"),
                      "uses": 1, "expires_at": 1800259200, "approval": True},
        "the custodian makes invite 2, which needs approval")
    add("dana", join_entry(w, "dana", "invite 2", 1800000200), "dana joins with invite 2 and is pending")
    add("creator", {"kind": "approve", "by": d["creator"], "device": d["dana"]}, "the creator approves dana")
    add("ben phone 2", join_entry(w, "ben phone 2", "invite 1", 1800000300),
        "ben's second phone joins with invite 1, its last use")
    add("ben", {"kind": "link", "by": d["ben"], "device": d["ben phone 2"],
                "device_sig": rooms.sign(k["ben phone 2"], rooms.link_body(d["ben"], d["ben phone 2"]))},
        "ben links his second phone")
    add("creator", {"kind": "promote", "by": d["creator"], "device": d["ben"]}, "the creator promotes ben")
    add("custodian", {"kind": "demote", "by": d["custodian"], "device": d["ben"]}, "the custodian demotes ben")
    add("creator", {"kind": "invite", "by": d["creator"], "invite": d["invite 3"], "invite_pub": pub("invite 3"),
                    "uses": 5, "expires_at": 1800259200, "approval": False}, "invite 3")
    add("creator", {"kind": "close-invite", "by": d["creator"], "invite": d["invite 3"]}, "invite 3 is closed")
    add("ben", {"kind": "remove", "by": d["ben"], "devices": [d["ben phone 2"]]}, "ben removes his second phone")
    add("dana", {"kind": "remove", "by": d["dana"], "devices": [d["dana"]]}, "dana leaves")
    return b, steps


def roster_vectors() -> dict:
    w = roster_world()
    d, k = w["devices"], w["keys"]
    good, steps = valid_roster(w)
    roster = rooms.verify_roster(good.records)
    state = rooms.roster_state(roster)
    assert state["devices"][d["creator"]] == {"kind": "device", "role": "owner", "status": "active",
                                              "member": d["creator"]}
    assert state["devices"][d["custodian"]]["kind"] == "custodian"
    assert state["devices"][d["ben"]]["role"] == "member"
    assert state["devices"][d["ben phone 2"]]["status"] == "removed"
    assert state["devices"][d["ben phone 2"]]["member"] == d["ben"]
    assert state["devices"][d["dana"]]["status"] == "removed"
    assert state["invites"][d["invite 3"]]["closed"] and state["invites"][d["invite 1"]]["used"] == 2
    # Every prefix of a valid roster is valid: a relay that withholds the newest entries is not caught by replay.
    for i in range(1, len(good.records)):
        rooms.verify_roster(good.records[:i])

    def bad(name: str, records: list, index: int, reason: str) -> dict:
        assert must_fail(rooms.verify_roster, records, reason=reason) == reason, name
        try:
            rooms.verify_roster(records)
        except rooms.Refused as e:
            assert e.index == index, (name, e.index, index)
        return {"name": name, "records": records, "first_invalid": index, "reason": reason}

    def prefix_plus(n: int, signer, entry: dict, mutate=None) -> list:
        b = RosterBuilder()
        b.records = [dict(r) for r in good.records[:n]]
        rec = b.add(k[signer] if isinstance(signer, str) else signer, entry)
        if mutate:
            b.records[-1] = mutate(dict(rec))
        return b.records

    def last_owner_demote() -> list:
        b = RosterBuilder()
        b.records = [dict(good.records[0])]
        b.add(k["creator"], {"kind": "remove", "by": d["creator"], "devices": [d["custodian"]]})
        b.add(k["creator"], {"kind": "demote", "by": d["creator"], "device": d["creator"]})
        return b.records

    r = good.records
    pub = lambda n: rooms.public_jwk(k[n])  # noqa: E731
    refused = [
        bad("a signature with one bit flipped", r[:2] + [{**r[2], "sig": flip_b64(r[2]["sig"], 5)}] + r[3:4], 2,
            "signature"),
        bad("an entry signed by the right device over another entry",
            r[:1] + [{**r[1], "entry": {**r[1]["entry"], "uses": 99}}], 1, "signature"),
        bad("a broken chain: prev names another hash", r[:3] + [{**r[3], "prev": r[1]["prev"]}], 3, "chain"),
        bad("a dropped entry in the middle", r[:2] + r[3:5], 2, "n"),
        bad("the first entry is not a genesis", prefix_plus(0, "creator", r[1]["entry"]), 0, "genesis"),
        bad("a genesis after the first entry",
            prefix_plus(1, "creator", {**r[0]["entry"]}), 1, "genesis"),
        bad("an invite signed by a member", prefix_plus(
            3, "ben", {"kind": "invite", "by": d["ben"], "invite": rid("x"), "invite_pub": pub("invite 3"),
                       "uses": 1, "expires_at": 1800259200, "approval": False}), 3, "not_owner"),
        bad("a join whose invite signature is by another key (a relay adding a device)",
            prefix_plus(2, "relay", join_entry({**w, "devices": {**d, "ben": d["relay"]},
                                                "keys": {**k, "ben": k["relay"]},
                                                "recv": {**w["recv"], "ben": w["recv"]["relay"]}},
                                               "ben", "invite 1", 1800000100, invite_key=k["invite relay"])),
            2, "invite_signature"),
        bad("a join for an invite that is not in the roster",
            prefix_plus(2, "relay", join_entry({**w, "devices": {**d, "ben": d["relay"]},
                                                "keys": {**k, "ben": k["relay"]},
                                                "recv": {**w["recv"], "ben": w["recv"]["relay"]}},
                                               "ben", "invite relay", 1800000100)),
            2, "invite_unknown"),
        bad("a join past the invite's uses",
            prefix_plus(7, "relay", join_entry({**w, "devices": {**d, "ben": d["relay"]},
                                                "keys": {**k, "ben": k["relay"]},
                                                "recv": {**w["recv"], "ben": w["recv"]["relay"]}},
                                               "ben", "invite 1", 1800000400)),
            7, "invite_used"),
        bad("a join at the invite's expiry",
            prefix_plus(2, "ben", join_entry(w, "ben", "invite 1", 1800259200)), 2, "invite_expired"),
        bad("a join under a closed invite",
            prefix_plus(12, "relay", join_entry({**w, "devices": {**d, "ben": d["relay"]},
                                                 "keys": {**k, "ben": k["relay"]},
                                                 "recv": {**w["recv"], "ben": w["recv"]["relay"]}},
                                                "ben", "invite 3", 1800000500)),
            12, "invite_closed"),
        bad("a join that reuses a device id", prefix_plus(
            2, "ben", join_entry({**w, "devices": {**d, "ben": d["creator"]}}, "ben", "invite 1", 1800000100)),
            2, "device"),
        bad("a pending device signs an entry", prefix_plus(
            5, "dana", {"kind": "remove", "by": d["dana"], "devices": [d["dana"]]}), 5, "signer"),
        bad("a removed device signs an entry", prefix_plus(
            14, "dana", {"kind": "remove", "by": d["dana"], "devices": [d["ben"]]}), 14, "signer"),
        bad("a member removes another member's device", prefix_plus(
            12, "ben", {"kind": "remove", "by": d["ben"], "devices": [d["dana"]]}), 12, "not_owner"),
        bad("a remove that leaves no owner", prefix_plus(
            3, "creator", {"kind": "remove", "by": d["creator"], "devices": [d["creator"], d["custodian"]]}),
            3, "last_owner"),
        bad("a demote of the last owner", last_owner_demote(), 2, "last_owner"),
        bad("a link without the device's own signature", prefix_plus(
            7, "ben", {"kind": "link", "by": d["ben"], "device": d["ben phone 2"],
                       "device_sig": rooms.sign(k["relay"], rooms.link_body(d["ben"], d["ben phone 2"]))}),
            7, "link_signature"),
        bad("an approve of a device that is not pending", prefix_plus(
            3, "creator", {"kind": "approve", "by": d["creator"], "device": d["ben"]}), 3, "state"),
        bad("a promote by the device itself", prefix_plus(
            3, "ben", {"kind": "promote", "by": d["ben"], "device": d["ben"]}), 3, "not_owner"),
        bad("an unknown entry kind", prefix_plus(
            3, "creator", {"kind": "rename", "by": d["creator"]}), 3, "kind"),
        bad("a record whose n is not its position", r[:2] + [{**r[2], "n": 4}], 2, "n"),
    ]
    return {"description": "ROOMS.md 4.2: the signed roster. `records` are as GET /roster returns them, without "
                           "`signer`. `valid` replays every entry kind; `state` is what replay yields. Each case in "
                           "`refused` is refused at the 0-based record `first_invalid`, and every record before it "
                           "stands; `reason` is informative.",
            "room": w["room"],
            "valid": {"records": good.records, "steps": steps, "state": state},
            "refused": refused}


def epoch_setup():
    w = roster_world()
    good, _ = valid_roster(w)
    records = good.records[:5]  # creator, custodian and ben active; dana pending
    return w, records, rooms.verify_roster(records)


def private_jwk(key) -> dict:
    return {**rooms.public_jwk(key), "d": rooms.private_d(key)}


def make_test_epoch(w, n: int, creator: str, recipients: list[str], signer=None, label: str = "") -> tuple:
    d = w["devices"]
    key = rseed(f"epoch {n} key{label}")
    ephs = {d[r]: rooms.signing_key(rseed(f"epoch {n} eph {r}{label}")) for r in recipients}
    ivs = {d[r]: rseed(f"epoch {n} iv {r}{label}")[:12] for r in recipients}
    epoch = rooms.make_epoch(w["room"], n, d[creator], signer or w["keys"][creator], key,
                             {d[r]: rooms.public_jwk(w["recv"][r]) for r in recipients}, ephs, ivs)
    return key, ephs, ivs, epoch


def epoch_vectors() -> dict:
    w, records, roster = epoch_setup()
    d = w["devices"]
    key, ephs, ivs, epoch = make_test_epoch(w, 2, "ben", ["creator", "ben"])
    rooms.accept_epoch(roster, w["room"], epoch)
    wraps = []
    for who in ("creator", "ben"):
        dev = d[who]
        assert rooms.open_epoch(w["room"], epoch, dev, w["recv"][who]) == key
        secret = rooms.ecdh(w["recv"][who], epoch["wraps"][dev]["eph"])
        assert secret == rooms.ecdh(ephs[dev], rooms.public_jwk(w["recv"][who]))
        info = rooms.wrap_info(w["room"], 2, dev)
        wraps.append({"device": dev, "recv_private_jwk": private_jwk(w["recv"][who]),
                      "eph_private_jwk": private_jwk(ephs[dev]), "ecdh_secret": secret.hex(),
                      "hkdf_info": info, "wrap_key": rooms.wrap_key(secret, info).hex(), "iv": ivs[dev].hex(),
                      "wrap": epoch["wraps"][dev]})
    _, _, _, for_pending = make_test_epoch(w, 2, "ben", ["creator", "ben", "dana"], label=" pending")
    _, _, _, for_stranger = make_test_epoch(w, 2, "ben", ["creator", "ben", "relay"], label=" stranger")
    _, _, _, by_custodian = make_test_epoch(w, 2, "custodian", ["creator", "ben"], label=" custodian")
    _, _, _, forged = make_test_epoch(w, 2, "ben", ["creator", "ben"], signer=w["keys"]["relay"], label=" forged")
    refused = []
    for name, ep, reason in [
        ("wrapped for a device the roster does not have (a relay adding a device)", for_stranger, "unknown_device"),
        ("wrapped for a device still waiting for approval", for_pending, "unknown_device"),
        ("created by the custodian, which has no receiving key", by_custodian, "creator"),
        ("signed by a key that is not the creator's", forged, "signature"),
        ("a wrap replaced after signing", {**epoch, "wraps": {**epoch["wraps"], d["ben"]: for_stranger["wraps"][d["ben"]]}},
         "signature"),
    ]:
        must_fail(rooms.accept_epoch, roster, w["room"], ep, reason=reason)
        refused.append({"name": name, "epoch": ep, "reason": reason})
    return {"description": "ROOMS.md 4.4: epoch 2, created by `creator` for two devices, as POST /epochs sends it. "
                           "`roster` holds the records the receivers have verified. For each wrap: the raw ECDH secret "
                           "(what deviceKeys.derive returns for the wrap's `eph`), the HKDF info, the AES-256-GCM wrap "
                           "key and the IV. Fixed ephemeral keys and IVs make the bytes reproducible; an "
                           "implementation draws fresh ones. `refused` epochs fail the receiver's check.",
            "room": w["room"], "roster": records, "epoch_key": key.hex(), "epoch": epoch,
            "signed_canonical": rooms.canonical(rooms.epoch_body(w["room"], epoch)), "wraps": wraps,
            "refused": refused}


def message_vectors() -> dict:
    w, records, roster = epoch_setup()
    d, k = w["devices"], w["keys"]
    key, _, _, epoch = make_test_epoch(w, 2, "ben", ["creator", "ben"])
    epochs, keys = {2: epoch}, {2: key}

    def msg(who: str, n: int, seq: int, plaintext: bytes, blob: str | None = None, signer=None, aad_device=None):
        m = rooms.seal_message(w["room"], 2, d[who], n, key, signer or k[who], plaintext,
                               rseed(f"msg iv {who} {n}")[:12], blob=blob, aad_device=aad_device)
        return {"seq": seq, "device": d[who], "cid": rid(f"cid {who} {n}"), **m, "at": 1800000400 + seq}

    plain = [("ben", 1, 1, b'{"type":"text","body":"hola"}', None),
             ("creator", 1, 2, b'{"type":"text","body":"buenas, \xc3\xb1and\xc3\xba"}', None),
             ("ben", 2, 3, b'{"type":"file","name":"plan.pdf"}', rid("blob 1"))]
    cases = []
    for who, n, seq, pt, blob in plain:
        m = msg(who, n, seq, pt, blob)
        assert rooms.open_message(w["room"], roster, epochs, keys, m) == pt
        cases.append({"message": m, "plaintext": pt.hex(),
                      "additional_data": rooms.msg_aad(w["room"], 2, d[who], n).decode(),
                      "signed_canonical": rooms.canonical(rooms.msg_body(w["room"], m))})
    good = cases[0]["message"]
    refused = []
    for name, m, reason in [
        ("a signature with one bit flipped", {**good, "sig": flip_b64(good["sig"], 3)}, "signature"),
        ("relabelled as another device's", {**good, "device": d["creator"]}, "signature"),
        ("its counter changed", {**good, "n": 7}, "signature"),
        ("under an epoch the receiver does not have", {**good, "epoch": 3}, "epoch"),
        ("from a device the epoch was not wrapped for (the custodian)",
         msg("custodian", 1, 4, b'{"type":"text","body":"x"}'), "not_wrapped"),
        ("sealed by its sender with another device's additional data",
         msg("ben", 3, 5, b'{"type":"text","body":"x"}', aad_device=d["creator"]), "decrypt"),
    ]:
        must_fail(rooms.open_message, w["room"], roster, epochs, keys, m, reason=reason)
        refused.append({"name": name, "message": m, "reason": reason})

    a, b = d["ben"], d["creator"]
    counter_cases = [
        ("in order", {}, 1, [(1, a, 1), (2, b, 1), (3, a, 2)], ["accept"] * 3, []),
        ("a replayed counter is dropped", {a: (2, 3)}, 1, [(4, a, 2), (5, a, 3), (6, a, 3)],
         ["drop", "accept", "drop"], []),
        ("a gap the relay still owes", {a: (2, 3)}, 1, [(5, a, 4)], ["accept"],
         [{"device": a, "after_n": 2, "before_n": 4, "cause": "missing"}]),
        ("a gap below the watermark was deleted by age", {a: (2, 3)}, 10, [(12, a, 5)], ["accept"],
         [{"device": a, "after_n": 2, "before_n": 5, "cause": "expired"}]),
        ("a watermark just past the last seen sequence still owes the gap", {a: (2, 3)}, 4, [(6, a, 4)],
         ["accept"], [{"device": a, "after_n": 2, "before_n": 4, "cause": "missing"}]),
        ("the first message seen from a device sets its baseline", {}, 1, [(9, b, 7)], ["accept"], []),
    ]
    counters = []
    for name, state, watermark, incoming, results, gaps in counter_cases:
        st = {dev: {"n": n, "seq": s} for dev, (n, s) in state.items()}
        got_results, got_gaps, after = rooms.count(st, watermark, [{"seq": s, "device": dv, "n": n}
                                                                   for s, dv, n in incoming])
        assert (got_results, got_gaps) == (results, gaps), name
        counters.append({"name": name, "state": st, "watermark": watermark,
                         "messages": [{"seq": s, "device": dv, "n": n} for s, dv, n in incoming],
                         "results": results, "gaps": gaps, "state_after": after})
    return {"description": "ROOMS.md 4.5: messages under epoch 2 as GET /messages returns them, their plaintext, "
                           "additional data and signed canonical JSON. Fixed IVs make the bytes reproducible. "
                           "`refused` messages fail to open, after the roster and epoch of rooms_epoch.json. "
                           "`counters` gives a receiver's per-device state {n, seq}, the watermark of the answer, "
                           "the messages in sequence order, and what the receiver does with each, the gaps it "
                           "reports and its state afterwards.",
            "room": w["room"], "epoch": 2, "epoch_key": key.hex(),
            "senders": {d[n]: rooms.public_jwk(k[n]) for n in ("ben", "creator", "custodian")},
            "cases": cases, "refused": refused, "counters": counters}


def blob_vectors() -> dict:
    w = roster_world()
    key = rseed("epoch 2 key")
    big = bytes(i % 251 for i in range(70000))
    cases = []
    for name, pt in [("a short file", b"%PDF-1.7 hello"), ("an empty file", b""), ("70000 bytes", big)]:
        blob = rid(f"blob {name}")
        iv = rseed(f"blob iv {name}")[:12]
        body = rooms.seal_blob(w["room"], blob, key, pt, iv)
        assert rooms.open_blob(w["room"], blob, key, body) == pt
        case = {"name": name, "blob": blob, "iv": iv.hex(),
                "additional_data": rooms.blob_aad(w["room"], blob).decode()}
        if len(pt) > 1000:
            case["plaintext"] = {"sha256": hashlib.sha256(pt).hexdigest(), "length": len(pt),
                                 "content": "byte i is i mod 251"}
            case["body"] = {"sha256": hashlib.sha256(body).hexdigest(), "length": len(body)}
        else:
            case["plaintext"], case["body"] = pt.hex(), body.hex()
        cases.append(case)
    good = bytes.fromhex(cases[0]["body"])
    refused = []
    for name, blob, body in [("read under another blob id", rid("blob other"), good),
                             ("one bit flipped in the tag", cases[0]["blob"], good[:-1] + bytes([good[-1] ^ 1])),
                             ("truncated to the IV and 15 bytes", cases[0]["blob"], good[:27])]:
        must_fail(rooms.open_blob, w["room"], blob, key, body, reason="decrypt")
        refused.append({"name": name, "blob": blob, "body": body.hex()})
    return {"description": "ROOMS.md 4.6: blobs sealed under an epoch key. The body PUT to the relay is the 12-byte "
                           "IV followed by the AES-256-GCM ciphertext and tag. Large values are given by digest. "
                           "`refused` bodies fail to open.",
            "room": w["room"], "epoch_key": key.hex(), "cases": cases, "refused": refused}


def pkcs8_without_public(d: bytes) -> bytes:
    alg = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    inner = bytes.fromhex("3025020101") + b"\x04\x20" + d
    return b"\x30\x41\x02\x01\x00" + alg + b"\x04\x27" + inner


def invite_link_vectors() -> dict:
    w = roster_world()
    key = w["keys"]["invite 1"]
    pk = b64url(rooms.pkcs8(key))
    room, token = w["room"], b64url(rseed("join token"))
    frag = lambda host, r=room, t=token, kk=pk: f"v1.{host}.{r}.{t}.{kk}"  # noqa: E731
    other = b64url(rooms.pkcs8(rooms.signing_key(rseed("p384"), curve="P-384")))
    bare = b64url(pkcs8_without_public(rooms.private_scalar(key)))
    cases = [
        ("a link", "https://app.example/j#" + frag("relay.example"), "relay.example"),
        ("a host with a port", "https://app.example/j#" + frag("relay.example:8443"), "relay.example:8443"),
        ("an IPv4 address with a port", "https://app.example/j#" + frag("203.0.113.7:8010"), "203.0.113.7:8010"),
        ("a host of one label", "https://app.example/j#" + frag("relay"), "relay"),
        ("the fragment pasted alone", frag("relay.example"), "relay.example"),
        ("a host with many labels and a hyphen", "https://app.example/j#" + frag("a-b.c.relay.example"),
         "a-b.c.relay.example"),
        ("version 2", "https://app.example/j#v2" + frag("relay.example")[2:], None),
        ("a host in uppercase", "https://app.example/j#" + frag("Relay.example"), None),
        ("an empty host label", "https://app.example/j#" + frag("relay..example"), None),
        ("a host with an underscore", "https://app.example/j#" + frag("re_lay.example"), None),
        ("an IPv6 literal", "https://app.example/j#" + frag("[2001:db8::1]:8443"), None),
        ("port 0", "https://app.example/j#" + frag("relay.example:0"), None),
        ("port 65536", "https://app.example/j#" + frag("relay.example:65536"), None),
        ("a port with a leading zero", "https://app.example/j#" + frag("relay.example:08443"), None),
        ("no host", "https://app.example/j#v1." + f"{room}.{token}.{pk}", None),
        ("a room id of 21 characters", "https://app.example/j#" + frag("relay.example", r=room[:21]), None),
        ("a join token with padding", "https://app.example/j#" + frag("relay.example", t=token + "="), None),
        ("a join token of 42 characters", "https://app.example/j#" + frag("relay.example", t=token[:42]), None),
        ("a trailing dot", "https://app.example/j#" + frag("relay.example") + ".", None),
        ("an invite key that is the raw 32-byte scalar",
         "https://app.example/j#" + frag("relay.example", kk=b64url(rooms.private_scalar(key))), None),
        ("an invite key on P-384", "https://app.example/j#" + frag("relay.example", kk=other), None),
        ("an invite key without its public key", "https://app.example/j#" + frag("relay.example", kk=bare), None),
    ]
    out = []
    for name, text, host in cases:
        parsed = rooms.parse_invite_link(text)
        if host is None:
            assert parsed is None, name
            out.append({"name": name, "text": text, "valid": False})
            continue
        assert parsed == {"relay_host": host, "room": room, "join_token": token, "invite_key": pk,
                          "invite_pub": rooms.public_jwk(key)}, name
        out.append({"name": name, "text": text, "valid": True, "parsed": parsed,
                    "relay_base_url": f"https://{host}"})
    return {"description": "ROOMS.md 5: invite links. A valid link parses into the relay host, room id, join token "
                           "and invite key (base64url PKCS#8 of a P-256 key with its public key); `invite_pub` is "
                           "that public key as a reduced JWK, which the joiner looks up in the roster. "
                           "A reader takes the text after the first `#`, or the whole text when it has none.",
            "invite_private_jwk": private_jwk(key), "cases": out}


def quota_vectors() -> dict:
    full = {"max": 200, "stored_bytes": 20_000_000_000, "retention_days": 30, "blob_bytes": 52_428_800}
    base_key = {"id": "install", "sha256": "0" * 64, "channels": 64, "creates_per_minute": 10,
                "bytes_per_day": 200_000_000}
    keys = [
        ("a key with a room quota", {**base_key, "rooms": full}, full),
        ("a key without rooms", base_key, None),
        ("rooms.max 0", {**base_key, "rooms": {**full, "max": 0}}, None),
        ("rooms without blob_bytes", {**base_key, "rooms": {k: v for k, v in full.items() if k != "blob_bytes"}},
         None),
        ("rooms.stored_bytes as a string", {**base_key, "rooms": {**full, "stored_bytes": "1"}}, None),
        ("rooms.retention_days 0", {**base_key, "rooms": {**full, "retention_days": 0}}, None),
        ("unlimited without rooms", {"id": "local", "sha256": "0" * 64, "unlimited": True}, None),
        ("unlimited with rooms", {"id": "local", "sha256": "0" * 64, "unlimited": True, "rooms": full}, full),
    ]
    claims = {"iss": "issuer", "aud": "relay.example", "sub": "i_7f3a9c", "exp": 1800086400, "channels": 64,
              "creates_per_minute": 10, "bytes_per_day": 200_000_000}
    room_claims = {"rooms": 50, "room_stored_bytes": 5_000_000_000, "room_retention_days": 30,
                   "room_blob_bytes": 52_428_800}
    tok_quota = {"max": 50, "stored_bytes": 5_000_000_000, "retention_days": 30, "blob_bytes": 52_428_800}
    tokens = [
        ("a token with a room quota", {**claims, **room_claims}, tok_quota),
        ("a token without room fields", claims, None),
        ("rooms 0", {**claims, **room_claims, "rooms": 0}, None),
        ("room_blob_bytes missing", {**claims, **{k: v for k, v in room_claims.items() if k != "room_blob_bytes"}},
         None),
        ("rooms as a string", {**claims, **room_claims, "rooms": "50"}, None),
        ("room_stored_bytes negative", {**claims, **room_claims, "room_stored_bytes": -1}, None),
    ]
    cases = []
    for name, entry, want in keys:
        assert rooms.key_room_quota(entry) == want, name
        cases.append({"name": name, "keys_entry": entry, "room_quota": want})
    for name, payload, want in tokens:
        assert rooms.token_room_quota(payload) == want, name
        cases.append({"name": name, "rt1_payload": payload, "room_quota": want})
    creates = []
    for name, req, want in [
        ("nothing asked", {}, {"max_bytes": 2_000_000_000, "retention_days": 30, "blob_bytes": 52_428_800}),
        ("less than the credential", {"max_bytes": 1_000_000, "retention_days": 7},
         {"max_bytes": 1_000_000, "retention_days": 7, "blob_bytes": 52_428_800}),
        ("more than the credential", {"max_bytes": 9 * 10**10, "retention_days": 365},
         {"max_bytes": 20_000_000_000, "retention_days": 30, "blob_bytes": 52_428_800}),
        ("max_bytes 0", {"max_bytes": 0}, None),
        ("retention_days as a float", {"retention_days": 7.5}, None),
    ]:
        assert rooms.room_limits(full, req) == want, name
        creates.append({"name": name, "request": req, "limits": want})
    small = {**full, "stored_bytes": 500_000_000, "retention_days": 10}
    want = {"max_bytes": 500_000_000, "retention_days": 10, "blob_bytes": 52_428_800}
    assert rooms.room_limits(small, {}) == want
    creates.append({"name": "nothing asked, under a credential smaller than the defaults", "room_quota": small,
                    "request": {}, "limits": want})
    return {"description": "PROTOCOL.md 2.2 and ROOMS.md 3.1: the room quota a keys.json entry or a verified rt1 "
                           "payload gives (null: none, POST /v1/rooms answers 403), and the limits of a room created "
                           "with `request` under the quota of the first case (null: 400).",
            "credentials": cases, "creates": creates}


FILES = {
    "url_policy.json": url_policy,
    "pairing_payload.json": payload_cases,
    "prologue.json": prologue_cases,
    "pairing_code.json": code_cases,
    "pairing.json": pairing_vectors,
    "connect.json": connect_vectors,
    "rekey.json": rekey_vectors,
    "relay_token.json": relay_token_vectors,
    "control.json": control_vectors,
    "rooms_encoding.json": encoding_vectors,
    "rooms_roster.json": roster_vectors,
    "rooms_epoch.json": epoch_vectors,
    "rooms_message.json": message_vectors,
    "rooms_blob.json": blob_vectors,
    "rooms_invite_link.json": invite_link_vectors,
    "rooms_quota.json": quota_vectors,
}


def main() -> None:
    check = "--check" in sys.argv
    stale = []
    for name, build in FILES.items():
        text = json.dumps(build(), indent=2) + "\n"
        path = OUT / name
        if check:
            if not path.exists() or path.read_text() != text:
                stale.append(name)
        else:
            path.write_text(text)
    stray = sorted(p.name for p in OUT.glob("*.json") if p.name not in FILES)
    if stray:
        stale.append(f"files the generator does not write: {', '.join(stray)}")
    if stale:
        sys.exit(f"stale vectors: {', '.join(stale)}")
    print(f"{len(FILES)} vector files {'match' if check else 'written'}")


if __name__ == "__main__":
    main()
