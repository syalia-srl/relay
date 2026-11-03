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
