"""A small reference of the room protocol of ROOMS.md, used only to generate vectors/rooms_*.json.

ECDSA and ECDH on P-256, HKDF-SHA-256 and AES-256-GCM from the cryptography package. Signatures are
deterministic (RFC 6979) so the vectors are reproducible; ROOMS.md does not require it.
"""

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (Encoding, NoEncryption, PrivateFormat, PublicFormat,
                                                          load_der_private_key)

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
CURVES = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}
ID_LEN, TOKEN_LEN = 22, 43


class Refused(Exception):
    """A record, epoch, message or blob a client must refuse. `index` is the roster record, when one."""

    def __init__(self, reason: str, index: int | None = None):
        super().__init__(reason if index is None else f"record {index}: {reason}")
        self.reason, self.index = reason, index


# --- encodings (ROOMS.md 2) ---

def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text) -> bytes:
    """Unpadded base64url with canonical trailing bits. Raises ValueError."""
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64(raw) != text:
        raise ValueError("non-canonical")
    return raw


def is_b64(value, length: int) -> bool:
    try:
        return isinstance(value, str) and len(value) == length and unb64(value) is not None
    except ValueError:
        return False


def is_id(value) -> bool:
    return is_b64(value, ID_LEN)


def is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**53 - 1


def canonical(value) -> str:
    """Sorted keys, no spaces, non-ASCII as itself, as JSON.stringify writes strings. Keys are ASCII, numbers integers."""
    def check(v):
        if isinstance(v, float):
            raise ValueError("no floats in signed objects")
        if isinstance(v, dict):
            for k, x in v.items():
                assert k.isascii()
                check(x)
        elif isinstance(v, list):
            for x in v:
                check(x)
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def signing_key(seed: bytes, curve: str = "P-256") -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(int.from_bytes(seed, "big") % (P256_N - 1) + 1, CURVES[curve])


def private_scalar(key) -> bytes:
    return key.private_numbers().private_value.to_bytes(32, "big")


def private_d(key) -> str:
    return b64(private_scalar(key))


def pkcs8(key) -> bytes:
    return key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())


def public_jwk(key) -> dict:
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    n = pub.public_numbers()
    return {"crv": "P-256", "kty": "EC", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}


def reduce_jwk(jwk: dict) -> dict:
    return {k: jwk[k] for k in ("crv", "kty", "x", "y")}


def is_jwk(jwk) -> bool:
    return (isinstance(jwk, dict) and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256"
            and is_b64(jwk.get("x"), 43) and is_b64(jwk.get("y"), 43))


def load_jwk(jwk: dict) -> ec.EllipticCurvePublicKey:
    if not is_jwk(jwk):
        raise ValueError("not a P-256 JWK")
    x, y = (int.from_bytes(unb64(jwk[c]), "big") for c in ("x", "y"))
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def sign(key, obj) -> str:
    der = key.sign(canonical(obj).encode(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    return b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def der_signature(raw: bytes) -> bytes:
    return encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))


def verify(jwk, obj, sig) -> bool:
    try:
        raw = unb64(sig)
        if len(raw) != 64:
            return False
        load_jwk(reduce_jwk(jwk)).verify(der_signature(raw), canonical(obj).encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, KeyError, InvalidSignature):
        return False


# --- roster (ROOMS.md 4.2) ---

def entry_body(entry: dict, n: int, prev: str) -> dict:
    return {"v": "relay-roster-1", "n": n, "prev": prev, "entry": entry}


def sign_entry(key, entry: dict, n: int, prev: str) -> dict:
    """The body of POST /roster."""
    return {"n": n, "entry": entry, "sig": sign(key, entry_body(entry, n, prev)), "prev": prev}


def record_hash(record: dict) -> str:
    body = entry_body(record["entry"], record["n"], record["prev"])
    return b64(hashlib.sha256(canonical(body).encode()).digest())


def join_body(body: dict) -> dict:
    return {"v": "relay-join-1", **{k: body[k] for k in ("invite", "device", "sign_pub", "recv_pub", "at")}}


def link_body(member: str, device: str) -> dict:
    return {"v": "relay-link-1", "member": member, "device": device}


@dataclass
class Roster:
    room: str = ""
    n: int = 0
    head: str = ""
    devices: dict = field(default_factory=dict)
    invites: dict = field(default_factory=dict)

    def active(self, device: str) -> dict | None:
        d = self.devices.get(device)
        return d if d and d["status"] == "active" else None


def roster_state(r: Roster) -> dict:
    return {"room": r.room, "n": r.n, "head": r.head,
            "devices": {i: {k: d[k] for k in ("kind", "role", "status", "member")} for i, d in r.devices.items()},
            "invites": {i: {k: v[k] for k in ("uses", "used", "expires_at", "approval", "closed")}
                        for i, v in r.invites.items()}}


KINDS = {"genesis", "invite", "join", "approve", "link", "remove", "promote", "demote", "close-invite"}


def verify_roster(records: list) -> Roster:
    """Replay every record; raise Refused with the index of the first one that fails."""
    r = Roster()
    for i, rec in enumerate(records):
        try:
            apply_record(r, i, rec)
        except Refused as e:
            raise Refused(e.reason, i) from None
        except (KeyError, TypeError, ValueError, AttributeError):
            raise Refused("record", i) from None
    return r


def apply_record(r: Roster, i: int, rec: dict) -> None:
    if not isinstance(rec, dict) or not all(k in rec for k in ("n", "entry", "sig", "prev")):
        raise Refused("record")
    if not is_int(rec["n"]) or rec["n"] != i + 1:
        raise Refused("n")
    if rec["prev"] != (r.head if i else ""):
        raise Refused("chain")
    e = rec["entry"]
    if not isinstance(e, dict) or not isinstance(e.get("kind"), str) or not is_id(e.get("by")):
        raise Refused("record")
    kind, by = e["kind"], e["by"]
    if kind not in KINDS:
        raise Refused("kind")
    if (i == 0) != (kind == "genesis"):
        raise Refused("genesis")
    if kind == "genesis":
        if not is_id(e["creator"]["device"]) or by != e["creator"]["device"]:
            raise Refused("signer")
        signer_pub = e["creator"]["sign_pub"]
    elif kind == "join":
        if not is_id(e["device"]) or by != e["device"]:
            raise Refused("signer")
        signer_pub = e["sign_pub"]
    else:
        signer = r.active(by)
        if signer is None:
            raise Refused("signer")
        signer_pub = signer["sign_pub"]
    if not is_jwk(signer_pub) or not verify(signer_pub, entry_body(e, rec["n"], rec["prev"]), rec["sig"]):
        raise Refused("signature")
    APPLY[kind](r, e)
    r.n, r.head = i + 1, record_hash(rec)


def new_device(kind, role, sign_pub, recv_pub, member, status="active", invite=None) -> dict:
    return {"kind": kind, "role": role, "status": status, "member": member, "sign_pub": sign_pub,
            "recv_pub": recv_pub, "invite": invite}


def owner(r: Roster, by: str) -> None:
    if r.devices[by]["role"] != "owner":
        raise Refused("not_owner")


def check_owners_left(r: Roster) -> None:
    if not any(d["status"] == "active" and d["role"] == "owner" for d in r.devices.values()):
        raise Refused("last_owner")


def a_genesis(r, e):
    c, k = e["creator"], e["custodian"]
    if not is_id(e["room"]) or not is_id(k["device"]) or not (is_jwk(c["recv_pub"]) and is_jwk(k["sign_pub"])):
        raise Refused("record")
    if c["device"] == k["device"]:
        raise Refused("device")
    r.room = e["room"]
    r.devices[c["device"]] = new_device("device", "owner", c["sign_pub"], c["recv_pub"], c["device"])
    r.devices[k["device"]] = new_device("custodian", "owner", k["sign_pub"], None, k["device"])


def a_invite(r, e):
    owner(r, e["by"])
    if (not is_id(e["invite"]) or not is_jwk(e["invite_pub"]) or not is_int(e["uses"]) or e["uses"] < 1
            or not is_int(e["expires_at"]) or not isinstance(e["approval"], bool) or e["invite"] in r.invites):
        raise Refused("record")
    r.invites[e["invite"]] = {"pub": e["invite_pub"], "uses": e["uses"], "used": 0, "expires_at": e["expires_at"],
                              "approval": e["approval"], "closed": False}


def a_join(r, e):
    if not (is_jwk(e["recv_pub"]) and is_id(e["invite"]) and is_int(e["at"])):
        raise Refused("record")
    if e["device"] in r.devices:
        raise Refused("device")
    inv = r.invites.get(e["invite"])
    if inv is None:
        raise Refused("invite_unknown")
    if not verify(inv["pub"], join_body(e), e["invite_sig"]):
        raise Refused("invite_signature")
    if inv["closed"]:
        raise Refused("invite_closed")
    if inv["used"] >= inv["uses"]:
        raise Refused("invite_used")
    if e["at"] >= inv["expires_at"]:
        raise Refused("invite_expired")
    inv["used"] += 1
    r.devices[e["device"]] = new_device("device", "member", e["sign_pub"], e["recv_pub"], e["device"],
                                        "pending" if inv["approval"] else "active", e["invite"])


def a_approve(r, e):
    owner(r, e["by"])
    d = r.devices.get(e["device"])
    if d is None or d["status"] != "pending":
        raise Refused("state")
    d["status"] = "active"


def a_link(r, e):
    a, b_id = r.devices[e["by"]], e["device"]
    b = r.active(b_id)
    if (a["kind"] != "device" or b is None or b["kind"] != "device" or b_id == e["by"] or b["member"] != b_id
            or any(i != b_id and d["member"] == b_id for i, d in r.devices.items())):
        raise Refused("state")
    if not verify(b["sign_pub"], link_body(a["member"], b_id), e["device_sig"]):
        raise Refused("link_signature")
    b["member"] = a["member"]
    if a["role"] == "owner":
        b["role"] = "owner"


def a_remove(r, e):
    targets = e["devices"]
    if not isinstance(targets, list) or not targets or len(set(targets)) != len(targets):
        raise Refused("record")
    by = r.devices[e["by"]]
    for t in targets:
        d = r.devices.get(t)
        if d is None or d["status"] == "removed":
            raise Refused("state")
        if by["role"] != "owner" and d["member"] != by["member"]:
            raise Refused("not_owner")
    for t in targets:
        r.devices[t]["status"] = "removed"
    check_owners_left(r)


def a_promote(r, e, to="owner", frm="member"):
    owner(r, e["by"])
    d = r.active(e["device"])
    if d is None or d["role"] != frm:
        raise Refused("state")
    d["role"] = to
    check_owners_left(r)


def a_close(r, e):
    owner(r, e["by"])
    inv = r.invites.get(e["invite"])
    if inv is None:
        raise Refused("invite_unknown")
    if inv["closed"]:
        raise Refused("state")
    inv["closed"] = True


APPLY = {"genesis": a_genesis, "invite": a_invite, "join": a_join, "approve": a_approve, "link": a_link,
         "remove": a_remove, "promote": a_promote,
         "demote": lambda r, e: a_promote(r, e, to="member", frm="owner"), "close-invite": a_close}


# --- epochs and wraps (ROOMS.md 4.4) ---

def wrap_info(room: str, n: int, device: str) -> str:
    return f"relay-wrap-1|{room}|{n}|{device}"


def ecdh(private_key, peer_jwk: dict) -> bytes:
    return private_key.exchange(ec.ECDH(), load_jwk(peer_jwk))


def wrap_key(secret: bytes, info: str) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=bytes(32), info=info.encode()).derive(secret)


def epoch_body(room: str, epoch: dict) -> dict:
    return {"v": "relay-epoch-1", "room": room, "n": epoch["n"], "roster": epoch["roster"],
            "creator": epoch["creator"], "wraps": epoch["wraps"]}


def make_epoch(room, n, roster, creator, sign_key, epoch_key, recipients, ephs, ivs) -> dict:
    wraps = {}
    for dev, jwk in recipients.items():
        k = wrap_key(ecdh(ephs[dev], jwk), wrap_info(room, n, dev))
        wraps[dev] = {"eph": public_jwk(ephs[dev]), "iv": b64(ivs[dev]),
                      "ct": b64(AESGCM(k).encrypt(ivs[dev], epoch_key, None))}
    epoch = {"n": n, "roster": roster, "creator": creator, "wraps": wraps}
    epoch["sig"] = sign(sign_key, epoch_body(room, epoch))
    return epoch


def accept_epoch(records: list, room: str, epoch: dict, before: list = ()) -> None:
    """Check `epoch` against the verified roster `records` and the epochs accepted before it.

    The creator and every wrapped device are judged at record `roster`, by replaying records 1..roster;
    `roster` never decreases as `n` grows.
    """
    at = epoch["roster"]
    if not is_int(at) or not 1 <= at <= len(records):
        raise Refused("roster")
    roster = verify_roster(records[:at])
    if roster.room != room:
        raise Refused("room")
    creator = roster.active(epoch["creator"])
    if creator is None or creator["kind"] != "device" or epoch["creator"] not in epoch["wraps"]:
        raise Refused("creator")
    if not verify(creator["sign_pub"], epoch_body(room, epoch), epoch["sig"]):
        raise Refused("signature")
    for dev in epoch["wraps"]:
        d = roster.active(dev)
        if d is None or d["kind"] != "device":
            raise Refused("unknown_device")
    if any(e["n"] < epoch["n"] and e["roster"] > at for e in before):
        raise Refused("roster_order")


def open_epoch(room: str, epoch: dict, device: str, recv_key) -> bytes:
    w = epoch["wraps"][device]
    k = wrap_key(ecdh(recv_key, w["eph"]), wrap_info(room, epoch["n"], device))
    return AESGCM(k).decrypt(unb64(w["iv"]), unb64(w["ct"]), None)


# --- messages (ROOMS.md 4.5) ---

def msg_aad(room: str, epoch: int, device: str, n: int) -> bytes:
    return f"relay-msg-1|{room}|{epoch}|{device}|{n}".encode()


def msg_body(room: str, m: dict) -> dict:
    body = {"v": "relay-msg-1", "room": room, "device": m["device"], "epoch": m["epoch"], "n": m["n"],
            "iv": m["iv"], "ct": m["ct"]}
    if "blob" in m:
        body["blob"] = m["blob"]
    return body


def seal_message(room, epoch, device, n, key, sign_key, plaintext, iv, blob=None, aad_device=None) -> dict:
    ct = AESGCM(key).encrypt(iv, plaintext, msg_aad(room, epoch, aad_device or device, n))
    m = {"epoch": epoch, "n": n, "iv": b64(iv), "ct": b64(ct)}
    if blob is not None:
        m["blob"] = blob
    m["sig"] = sign(sign_key, msg_body(room, {**m, "device": device}))
    return m


def open_message(room: str, roster: Roster, epochs: dict, keys: dict, m: dict) -> bytes:
    epoch = epochs.get(m["epoch"])
    if epoch is None:
        raise Refused("epoch")
    if m["device"] not in epoch["wraps"]:
        raise Refused("not_wrapped")
    if not verify(roster.devices[m["device"]]["sign_pub"], msg_body(room, m), m["sig"]):
        raise Refused("signature")
    try:
        return AESGCM(keys[m["epoch"]]).decrypt(unb64(m["iv"]), unb64(m["ct"]),
                                                msg_aad(room, m["epoch"], m["device"], m["n"]))
    except InvalidTag:
        raise Refused("decrypt") from None


def count(state: dict, watermark: int, messages: list) -> tuple[list, list, dict]:
    """Per-device counters: accept or drop each message, and name the cause of each gap."""
    st = {k: dict(v) for k, v in state.items()}
    results, gaps = [], []
    for m in messages:
        last = st.get(m["device"])
        if last is not None and m["n"] <= last["n"]:
            results.append("drop")
            continue
        if last is not None and m["n"] > last["n"] + 1:
            gaps.append({"device": m["device"], "after_n": last["n"], "before_n": m["n"],
                         "cause": "missing" if watermark <= last["seq"] + 1 else "expired"})
        results.append("accept")
        st[m["device"]] = {"n": m["n"], "seq": m["seq"]}
    return results, gaps, st


# --- blobs (ROOMS.md 4.6) ---

def blob_aad(room: str, blob: str) -> bytes:
    return f"relay-blob-1|{room}|{blob}".encode()


def seal_blob(room: str, blob: str, key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    return iv + AESGCM(key).encrypt(iv, plaintext, blob_aad(room, blob))


def open_blob(room: str, blob: str, key: bytes, body: bytes) -> bytes:
    if len(body) < 28:
        raise Refused("decrypt")
    try:
        return AESGCM(key).decrypt(body[:12], body[12:], blob_aad(room, blob))
    except InvalidTag:
        raise Refused("decrypt") from None


# --- invite links (ROOMS.md 5) ---

HOST = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[1-9][0-9]{0,4})?")


def parse_invite_link(text: str) -> dict | None:
    frag = text.split("#", 1)[1] if "#" in text else text
    parts = frag.split(".")
    if len(parts) < 5 or parts[0] != "v1":
        return None
    host, room, token, key = ".".join(parts[1:-3]), parts[-3], parts[-2], parts[-1]
    if len(host) > 260 or not HOST.fullmatch(host) or (":" in host and int(host.rsplit(":", 1)[1]) > 65535):
        return None
    if not is_id(room) or not is_b64(token, TOKEN_LEN):
        return None
    try:
        der = unb64(key)
        private = load_der_private_key(der, None)
    except (ValueError, TypeError):
        return None
    if not isinstance(private, ec.EllipticCurvePrivateKey) or private.curve.name != "secp256r1":
        return None
    point = private.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    if b"\x03\x42\x00" + point not in der:  # the optional publicKey of RFC 5915 must be present
        return None
    return {"relay_host": host, "room": room, "join_token": token, "invite_key": key,
            "invite_pub": public_jwk(private)}


# --- room quota (PROTOCOL.md 2.2, ROOMS.md 3.1) ---

def _quota(m: int, s: int, d: int, b: int) -> dict | None:
    if m < 1 or d < 1:
        return None
    return {"max": m, "stored_bytes": s, "retention_days": d, "blob_bytes": b}


def key_room_quota(entry: dict) -> dict | None:
    rooms = entry.get("rooms")
    if not isinstance(rooms, dict):
        return None
    vals = [rooms.get(k) for k in ("max", "stored_bytes", "retention_days", "blob_bytes")]
    if not all(is_int(v) for v in vals):
        return None
    return _quota(*vals)


def token_room_quota(payload: dict) -> dict | None:
    vals = [payload.get(k) for k in ("rooms", "room_stored_bytes", "room_retention_days", "room_blob_bytes")]
    if not all(is_int(v) for v in vals):
        return None
    return _quota(*vals)


DEFAULT_MAX_BYTES, DEFAULT_RETENTION_DAYS = 2_000_000_000, 30


def room_limits(quota: dict, request: dict) -> dict | None:
    for k in ("max_bytes", "retention_days"):
        if k in request and (not is_int(request[k]) or request[k] < 1):
            return None
    return {"max_bytes": min(request.get("max_bytes", DEFAULT_MAX_BYTES), quota["stored_bytes"]),
            "retention_days": min(request.get("retention_days", DEFAULT_RETENTION_DAYS), quota["retention_days"]),
            "blob_bytes": quota["blob_bytes"]}
