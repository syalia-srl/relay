"""Rooms (ROOMS.md sections 2, 4 and 5): roster helpers (C6) and the member protocol (C13).

What a party that holds a credential needs to manage a room it can never read: a
P-256 signing key (the custodian's), signed roster records, a full replay of the
roster, and a client for the relay's owner routes. It holds no receiving key and
makes no epoch.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

SigningKey = ec.EllipticCurvePrivateKey

ID_LEN = 22
_B64 = re.compile(r"[A-Za-z0-9_-]*")
_KINDS = {"genesis", "invite", "join", "approve", "link", "remove", "promote", "demote", "close-invite"}

__all__ = [
    "Message",
    "RecvKey",
    "Refused",
    "RoomMember",
    "SignKey",
    "accept_epoch",
    "count_messages",
    "invite_link",
    "make_epoch",
    "open_blob",
    "open_epoch",
    "open_message",
    "parse_invite_link",
    "seal_blob",
    "seal_message",
    "software_device_keys",
    "Roster",
    "RoomClient",
    "RoomError",
    "RosterInvalid",
    "SigningKey",
    "canonical",
    "new_signing_key",
    "public_jwk",
    "record_hash",
    "sign_entry",
    "verify_roster",
    "verify_signature",
]


class RosterInvalid(Exception):
    """A roster refused at record `index` (0-based) for `reason`; the records before it stand."""

    def __init__(self, reason: str, index: int, roster: Roster | None = None):
        super().__init__(f"roster record {index + 1}: {reason}")
        self.reason, self.index, self.roster = reason, index, roster


class RoomError(Exception):
    """An answer of the relay that is not a success: the status and its JSON error code."""

    def __init__(self, status: int, code: str):
        super().__init__(f"{status} {code}")
        self.status, self.code = status, code


class _Refused(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --- encodings (ROOMS.md 2) ---


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: Any) -> bytes:
    """Unpadded base64url with canonical trailing bits. Raises ValueError."""
    if not isinstance(text, str) or not _B64.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64(raw) != text:
        raise ValueError("non-canonical base64url")
    return raw


def _is_b64(value: Any, length: int) -> bool:
    try:
        return isinstance(value, str) and len(value) == length and unb64(value) is not None
    except ValueError:
        return False


def _is_id(value: Any) -> bool:
    return _is_b64(value, ID_LEN)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**53 - 1


def random_id() -> str:
    """16 random bytes in base64url: an invite key id."""
    return b64(secrets.token_bytes(16))


def canonical(value: Any) -> str:
    """Sorted keys, no whitespace, non-ASCII as itself: what JSON.stringify gives over sorted keys."""

    def check(v: Any) -> None:
        if isinstance(v, float):
            raise ValueError("signed objects hold only integers")
        if isinstance(v, dict):
            for x in v.values():
                check(x)
        elif isinstance(v, list):
            for x in v:
                check(x)

    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def new_signing_key() -> SigningKey:
    """A fresh P-256 signing key."""
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(key: SigningKey | ec.EllipticCurvePublicKey) -> dict:
    """The public key as a reduced JWK: kty, crv, x and y."""
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    n = pub.public_numbers()
    return {"crv": "P-256", "kty": "EC", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}


def _is_jwk(jwk: Any) -> bool:
    return (
        isinstance(jwk, dict)
        and jwk.get("kty") == "EC"
        and jwk.get("crv") == "P-256"
        and _is_b64(jwk.get("x"), 43)
        and _is_b64(jwk.get("y"), 43)
    )


def _reduce(jwk: dict) -> dict:
    return {k: jwk[k] for k in ("crv", "kty", "x", "y")}


def _sign(key: Any, obj: Any) -> str:
    """Sign with a cryptography key, or with a C3 key object (`sign(bytes) -> 64 bytes`)."""
    data = canonical(obj).encode()
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raw = key.sign(data)
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != 64:
            raise TypeError("sign() must return 64 bytes r||s")
        return b64(bytes(raw))
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verify_signature(jwk: Any, obj: Any, sig: Any) -> bool:
    """Whether `sig` is a 64-byte r||s signature by `jwk` over the canonical JSON of `obj`."""
    try:
        if not _is_jwk(jwk):
            return False
        raw = unb64(sig)
        if len(raw) != 64:
            return False
        x, y = (int.from_bytes(unb64(jwk[c]), "big") for c in ("x", "y"))
        pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        pub.verify(der, canonical(obj).encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, KeyError, TypeError, InvalidSignature):
        return False


# --- the roster (ROOMS.md 4.2) ---


def _entry_body(entry: dict, n: int, prev: str) -> dict:
    return {"v": "relay-roster-1", "n": n, "prev": prev, "entry": entry}


def sign_entry(key: Any, entry: dict, n: int, prev: str) -> dict:
    """The body of POST /roster: `entry` as record `n` after the record whose hash is `prev`."""
    return {"n": n, "entry": entry, "sig": _sign(key, _entry_body(entry, n, prev)), "prev": prev}


def record_hash(record: dict) -> str:
    """The base64url SHA-256 of the canonical signed object of a record (no signature)."""
    body = _entry_body(record["entry"], record["n"], record["prev"])
    return b64(hashlib.sha256(canonical(body).encode()).digest())


def _join_body(e: dict) -> dict:
    return {"v": "relay-join-1", **{k: e[k] for k in ("invite", "device", "sign_pub", "recv_pub", "at")}}


def _link_body(member: str, device: str) -> dict:
    return {"v": "relay-link-1", "member": member, "device": device}


@dataclass
class Roster:
    """The state a replay yields. Devices and invites are dicts as in vectors/rooms_roster.json, with keys."""

    room: str = ""
    n: int = 0
    head: str = ""
    devices: dict = field(default_factory=dict)
    invites: dict = field(default_factory=dict)
    records: list = field(default_factory=list)

    def active(self, device: str) -> dict | None:
        d = self.devices.get(device)
        return d if d and d["status"] == "active" else None

    def readers(self) -> list[str]:
        """Active devices of kind `device`: who an epoch is wrapped for."""
        return [i for i, d in self.devices.items() if d["status"] == "active" and d["kind"] == "device"]

    def state(self) -> dict:
        """The state in the shape of vectors/rooms_roster.json."""
        return {
            "room": self.room,
            "n": self.n,
            "head": self.head,
            "devices": {i: {k: d[k] for k in ("kind", "role", "status", "member")} for i, d in self.devices.items()},
            "invites": {
                i: {k: v[k] for k in ("uses", "used", "expires_at", "approval", "closed")}
                for i, v in self.invites.items()
            },
        }


def verify_roster(entries: list[dict], room: str | None = None) -> Roster:
    """Replay every record. Raises RosterInvalid at the first that is not valid, with the prefix that stands."""
    r = Roster()
    for i, rec in enumerate(entries):
        try:
            _apply(r, i, rec)
            if i == 0 and room is not None and r.room != room:
                raise _Refused("room")
        except _Refused as e:
            raise RosterInvalid(e.reason, i, r) from None
        except (KeyError, TypeError, ValueError, AttributeError):
            raise RosterInvalid("record", i, r) from None
        r.records.append({k: rec[k] for k in ("n", "entry", "sig", "prev")})
    return r


def _apply(r: Roster, i: int, rec: Any) -> None:
    if not isinstance(rec, dict) or not all(k in rec for k in ("n", "entry", "sig", "prev")):
        raise _Refused("record")
    if not _is_int(rec["n"]) or rec["n"] != i + 1:
        raise _Refused("n")
    if rec["prev"] != (r.head if i else ""):
        raise _Refused("chain")
    e = rec["entry"]
    if not isinstance(e, dict) or not isinstance(e.get("kind"), str) or not _is_id(e.get("by")):
        raise _Refused("record")
    kind, by = e["kind"], e["by"]
    if kind not in _KINDS:
        raise _Refused("kind")
    if (i == 0) != (kind == "genesis"):
        raise _Refused("genesis")
    if kind == "genesis":
        if not _is_id(e["creator"]["device"]) or by != e["creator"]["device"]:
            raise _Refused("signer")
        signer_pub = e["creator"]["sign_pub"]
    elif kind == "join":
        if not _is_id(e["device"]) or by != e["device"]:
            raise _Refused("signer")
        signer_pub = e["sign_pub"]
    else:
        signer = r.active(by)
        if signer is None:
            raise _Refused("signer")
        signer_pub = signer["sign_pub"]
    if not _is_jwk(signer_pub) or not verify_signature(signer_pub, _entry_body(e, rec["n"], rec["prev"]), rec["sig"]):
        raise _Refused("signature")
    _APPLY[kind](r, e)
    for d in r.devices.values():  # the span of records during which each device is active (ROOMS.md 4.4)
        if d["status"] == "active" and d["active_from"] is None:
            d["active_from"] = i + 1
        elif d["status"] == "removed" and d["removed_at"] is None:
            d["removed_at"] = i + 1
    r.n, r.head = i + 1, record_hash(rec)


def _device(kind: str, role: str, sign_pub: dict, recv_pub: dict | None, member: str, status: str = "active") -> dict:
    return {
        "kind": kind,
        "role": role,
        "status": status,
        "member": member,
        "sign_pub": _reduce(sign_pub),
        "recv_pub": _reduce(recv_pub) if recv_pub else None,
        "active_from": None,
        "removed_at": None,
    }


def _owner(r: Roster, by: str) -> None:
    if r.devices[by]["role"] != "owner":
        raise _Refused("not_owner")


def _owners_left(r: Roster) -> None:
    if not any(d["status"] == "active" and d["role"] == "owner" for d in r.devices.values()):
        raise _Refused("last_owner")


def _genesis(r: Roster, e: dict) -> None:
    c, k = e["creator"], e["custodian"]
    if not _is_id(e["room"]) or not _is_id(k["device"]) or not (_is_jwk(c["recv_pub"]) and _is_jwk(k["sign_pub"])):
        raise _Refused("record")
    if c["device"] == k["device"]:
        raise _Refused("device")
    r.room = e["room"]
    r.devices[c["device"]] = _device("device", "owner", c["sign_pub"], c["recv_pub"], c["device"])
    r.devices[k["device"]] = _device("custodian", "owner", k["sign_pub"], None, k["device"])


def _invite(r: Roster, e: dict) -> None:
    _owner(r, e["by"])
    if (
        not _is_id(e["invite"])
        or not _is_jwk(e["invite_pub"])
        or not _is_int(e["uses"])
        or e["uses"] < 1
        or not _is_int(e["expires_at"])
        or not isinstance(e["approval"], bool)
        or e["invite"] in r.invites
    ):
        raise _Refused("record")
    r.invites[e["invite"]] = {
        "pub": _reduce(e["invite_pub"]),
        "uses": e["uses"],
        "used": 0,
        "expires_at": e["expires_at"],
        "approval": e["approval"],
        "closed": False,
    }


def _join(r: Roster, e: dict) -> None:
    if not (_is_jwk(e["recv_pub"]) and _is_id(e["invite"]) and _is_int(e["at"])):
        raise _Refused("record")
    if e["device"] in r.devices:
        raise _Refused("device")
    inv = r.invites.get(e["invite"])
    if inv is None:
        raise _Refused("invite_unknown")
    if not verify_signature(inv["pub"], _join_body(e), e["invite_sig"]):
        raise _Refused("invite_signature")
    if inv["closed"]:
        raise _Refused("invite_closed")
    if inv["used"] >= inv["uses"]:
        raise _Refused("invite_used")
    if e["at"] >= inv["expires_at"]:
        raise _Refused("invite_expired")
    inv["used"] += 1
    status = "pending" if inv["approval"] else "active"
    r.devices[e["device"]] = _device("device", "member", e["sign_pub"], e["recv_pub"], e["device"], status)


def _approve(r: Roster, e: dict) -> None:
    _owner(r, e["by"])
    d = r.devices.get(e["device"])
    if d is None or d["status"] != "pending":
        raise _Refused("state")
    d["status"] = "active"


def _link(r: Roster, e: dict) -> None:
    a, b_id = r.devices[e["by"]], e["device"]
    b = r.active(b_id)
    if (
        a["kind"] != "device"
        or b is None
        or b["kind"] != "device"
        or b_id == e["by"]
        or b["member"] != b_id
        or any(i != b_id and d["member"] == b_id for i, d in r.devices.items())
    ):
        raise _Refused("state")
    if not verify_signature(b["sign_pub"], _link_body(a["member"], b_id), e["device_sig"]):
        raise _Refused("link_signature")
    b["member"] = a["member"]
    if a["role"] == "owner":
        b["role"] = "owner"


def _remove(r: Roster, e: dict) -> None:
    targets = e["devices"]
    if not isinstance(targets, list) or not targets or len(set(targets)) != len(targets):
        raise _Refused("record")
    by = r.devices[e["by"]]
    for t in targets:
        d = r.devices.get(t)
        if d is None or d["status"] == "removed":
            raise _Refused("state")
        if by["role"] != "owner" and d["member"] != by["member"]:
            raise _Refused("not_owner")
    for t in targets:
        r.devices[t]["status"] = "removed"
    _owners_left(r)


def _set_role(r: Roster, e: dict, to: str, frm: str) -> None:
    _owner(r, e["by"])
    d = r.active(e["device"])
    if d is None or d["role"] != frm:
        raise _Refused("state")
    d["role"] = to
    _owners_left(r)


def _close(r: Roster, e: dict) -> None:
    _owner(r, e["by"])
    inv = r.invites.get(e["invite"])
    if inv is None:
        raise _Refused("invite_unknown")
    if inv["closed"]:
        raise _Refused("state")
    inv["closed"] = True


_APPLY = {
    "genesis": _genesis,
    "invite": _invite,
    "join": _join,
    "approve": _approve,
    "link": _link,
    "remove": _remove,
    "promote": lambda r, e: _set_role(r, e, "owner", "member"),
    "demote": lambda r, e: _set_role(r, e, "member", "owner"),
    "close-invite": _close,
}


# --- the relay's owner routes (ROOMS.md 3.4, 4.3) ---


class RoomClient:
    """One device's calls to one room: the custodian's, or any owner's that only manages it.

    `key` and `device` are the signing key and device id that sign roster records; a
    client without them can still read the roster and call the relay. Each change
    is the roster record and the relay call together (ROOMS.md 4.3).
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        room: str,
        device: str | None = None,
        key: SigningKey | None = None,
        timeout: float = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.token, self.room, self.device, self.key, self.timeout = token, room, device, key, timeout
        self.watermark: int | None = None

    def _call(self, method: str, path: str, body: dict | None = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        headers = {"Authorization": f"Bearer {self.token}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        url = f"{self.base_url}/v1/rooms/{self.room}{path}"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                self._watermark(response.headers)
                raw = response.read()
        except urllib.error.HTTPError as error:
            self._watermark(error.headers)
            try:
                code = json.loads(error.read()).get("error", "unknown")
            except (ValueError, AttributeError):
                code = "unknown"
            raise RoomError(error.code, code) from None
        return json.loads(raw) if raw else None

    def _watermark(self, headers: Any) -> None:
        mark = headers.get("Relay-Room-Watermark") if headers else None
        if mark is not None and mark.isdigit():
            self.watermark = int(mark)

    def roster(self) -> Roster:
        """Fetch every record and replay it; raises RosterInvalid when a record fails."""
        entries = self._call("GET", "/roster?after=0")["entries"]
        return verify_roster([{k: e[k] for k in ("n", "entry", "sig", "prev") if k in e} for e in entries], self.room)

    def append(self, entry: dict, tries: int = 5) -> dict:
        """Sign `entry` (its `by` defaults to this device) as the next record and post it; re-read on a 409."""
        if self.key is None or self.device is None:
            raise ValueError("a client without a signing key and device id cannot append")
        entry = {"by": self.device, **entry}
        for attempt in range(tries):
            roster = self.roster()
            record = sign_entry(self.key, entry, roster.n + 1, roster.head)
            try:
                self._call("POST", "/roster", record)
                return record
            except RoomError as error:
                if error.status != 409 or attempt == tries - 1:
                    raise
        raise AssertionError("unreachable")

    def invite(self, uses: int, expires_at: int, approval: bool = False) -> dict:
        """A join token and an `invite` record with a fresh invite key.

        Returns `invite` (the relay's id), `invite_key_id` (the roster's), `token`,
        `invite_key` (PKCS#8 in base64url) and `fragment`, the invite link's fragment.
        """
        made = self._call("POST", "/invites", {"uses": uses, "expires_at": expires_at})
        invite_key = ec.generate_private_key(ec.SECP256R1())
        key_id = random_id()
        self.append(
            {
                "kind": "invite",
                "invite": key_id,
                "invite_pub": public_jwk(invite_key),
                "uses": uses,
                "expires_at": expires_at,
                "approval": approval,
            }
        )
        pkcs8 = b64(
            invite_key.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        host = (urlsplit(self.base_url).netloc or "").lower()
        return {
            "invite": made["invite"],
            "invite_key_id": key_id,
            "token": made["token"],
            "invite_key": pkcs8,
            "fragment": f"v1.{host}.{self.room}.{made['token']}.{pkcs8}",
        }

    def close_invite(self, invite_key_id: str, invite: str | None = None) -> None:
        self.append({"kind": "close-invite", "invite": invite_key_id})
        if invite is not None:
            self._call("DELETE", f"/invites/{invite}")

    def remove(self, device: str | list[str]) -> None:
        """The `remove` record, then the relay's revocation of each device."""
        devices = [device] if isinstance(device, str) else list(device)
        self.append({"kind": "remove", "devices": devices})
        for d in devices:
            self._call("DELETE", f"/devices/{d}")

    def set_owner(self, device: str, owner: bool) -> None:
        """`promote` or `demote`, then the relay's role."""
        self.append({"kind": "promote" if owner else "demote", "device": device})
        self._call("POST", "/owners", {"device": device, "owner": owner})

    def info(self) -> dict:
        return self._call("GET", "")

    def delete(self) -> None:
        self._call("DELETE", "")


# =====================================================================================
# The member side (ROOMS.md 3.5, 4.4 to 4.8 and 5): C13.
# =====================================================================================

TOKEN_LEN = 43
_MAX_TRIES = 5
_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
_HOST = re.compile(rf"{_LABEL}(?:\.{_LABEL})*(?::[1-9][0-9]{{0,4}})?")


class Refused(Exception):
    """Something a member refuses: an epoch, a message, a blob. `reason` names the check (the vectors' reasons)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --- device keys (ROOMS.md 4.1, C3) ---


def _require_p256(private: Any) -> None:
    if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(private.curve, ec.SECP256R1):
        raise ValueError("a device key must be a P-256 private key")


class SignKey:
    """A signing key in the C3 shape: `sign_pub` (JWK) and `sign(bytes) -> 64 bytes r||s`.

    The private key lives in a closure and no method exports it.
    """

    __slots__ = ("sign_pub", "_sign_fn")

    def __init__(self, private: ec.EllipticCurvePrivateKey):
        _require_p256(private)
        self.sign_pub = public_jwk(private)

        def sign(data: bytes) -> bytes:
            r, s = decode_dss_signature(private.sign(bytes(data), ec.ECDSA(hashes.SHA256())))
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")

        self._sign_fn = sign

    def sign(self, data: bytes) -> bytes:
        return self._sign_fn(data)

    def __repr__(self) -> str:
        return f"SignKey(x={self.sign_pub['x'][:8]}…)"


class RecvKey:
    """A receiving key in the C3 shape: `recv_pub` (JWK) and `derive(peer_jwk) -> 32-byte raw ECDH secret`."""

    __slots__ = ("recv_pub", "_derive_fn")

    def __init__(self, private: ec.EllipticCurvePrivateKey):
        _require_p256(private)
        self.recv_pub = public_jwk(private)

        def derive(peer_jwk: dict) -> bytes:
            return private.exchange(ec.ECDH(), _public_key(peer_jwk))

        self._derive_fn = derive

    def derive(self, peer_jwk: dict) -> bytes:
        return self._derive_fn(peer_jwk)

    def __repr__(self) -> str:
        return f"RecvKey(x={self.recv_pub['x'][:8]}…)"


def software_device_keys() -> tuple[SignKey, RecvKey]:
    """Fresh P-256 signing and receiving keys held in memory, private halves not exported."""
    return SignKey(ec.generate_private_key(ec.SECP256R1())), RecvKey(ec.generate_private_key(ec.SECP256R1()))


def _public_key(jwk: Any) -> ec.EllipticCurvePublicKey:
    if not _is_jwk(jwk):
        raise ValueError("not a P-256 JWK")
    x, y = (int.from_bytes(unb64(jwk[c]), "big") for c in ("x", "y"))
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _same_jwk(a: Any, b: Any) -> bool:
    return _is_jwk(a) and _is_jwk(b) and a["x"] == b["x"] and a["y"] == b["y"]


# --- epochs and wraps (ROOMS.md 4.4) ---


def wrap_info(room: str, n: int, device: str) -> str:
    return f"relay-wrap-1|{room}|{n}|{device}"


def wrap_key(secret: bytes, info: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes(32), info=info.encode()).derive(secret)


def _decrypt(key: bytes, iv: bytes, ct: bytes, aad: bytes | None) -> bytes:
    try:
        return AESGCM(key).decrypt(iv, ct, aad)
    except (InvalidTag, ValueError):
        raise Refused("decrypt") from None


def wrap_for(
    room: str,
    n: int,
    device: str,
    recv_pub: dict,
    epoch_key: bytes,
    *,
    eph: ec.EllipticCurvePrivateKey | None = None,
    iv: bytes | None = None,
) -> dict:
    """Wrap `epoch_key` for one device's receiving key; `eph` and `iv` are fresh unless given."""
    eph = eph or ec.generate_private_key(ec.SECP256R1())
    iv = iv if iv is not None else secrets.token_bytes(12)
    secret = eph.exchange(ec.ECDH(), _public_key(recv_pub))
    key = wrap_key(secret, wrap_info(room, n, device))
    return {"eph": public_jwk(eph), "iv": b64(iv), "ct": b64(AESGCM(key).encrypt(iv, epoch_key, None))}


def epoch_body(room: str, epoch: dict) -> dict:
    return {
        "v": "relay-epoch-1",
        "room": room,
        "n": epoch["n"],
        "roster": epoch["roster"],
        "creator": epoch["creator"],
        "wraps": epoch["wraps"],
    }


def make_epoch(
    room: str, n: int, roster: int, creator: str, sign_key: Any, recipients: dict, epoch_key: bytes | None = None
) -> tuple[dict, bytes]:
    """Epoch `n`: a fresh key wrapped for each of `recipients` ({device: recv_pub}), signed. Returns (body, key)."""
    epoch_key = epoch_key if epoch_key is not None else secrets.token_bytes(32)
    wraps = {d: wrap_for(room, n, d, pub, epoch_key) for d, pub in recipients.items()}
    epoch = {"n": n, "roster": roster, "creator": creator, "wraps": wraps}
    epoch["sig"] = _sign(sign_key, epoch_body(room, epoch))
    return epoch, epoch_key


def open_epoch(room: str, epoch: dict, device: str, recv_key: Any) -> bytes:
    """This device's epoch key, through `recv_key.derive`. Raises Refused."""
    wraps = epoch.get("wraps")
    wrap = wraps.get(device) if isinstance(wraps, dict) else None
    if not isinstance(wrap, dict):
        raise Refused("not_wrapped")
    try:
        secret = recv_key.derive(_reduce(wrap["eph"]))
        iv, ct = unb64(wrap["iv"]), unb64(wrap["ct"])
    except (ValueError, KeyError, TypeError):
        raise Refused("decrypt") from None
    raw = _decrypt(wrap_key(secret, wrap_info(room, epoch["n"], device)), iv, ct, None)
    if len(raw) != 32:
        raise Refused("decrypt")
    return raw


def _active_at(d: dict, at: int) -> bool:
    return d["active_from"] is not None and d["active_from"] <= at and (d["removed_at"] is None or at < d["removed_at"])


def accept_epoch(roster: Roster, room: str, epoch: Any, before: Any = ()) -> None:
    """Check an epoch against a verified roster (ROOMS.md 4.4, rules 1 to 5). Raises Refused."""
    if roster.room != room:
        raise Refused("room")
    if not isinstance(epoch, dict) or not _is_int(epoch.get("n")) or epoch["n"] < 1 or not isinstance(
        epoch.get("wraps"), dict
    ):
        raise Refused("record")
    at = epoch.get("roster")
    if not _is_int(at) or not 1 <= at <= roster.n:
        raise Refused("roster")
    creator_id = epoch.get("creator")
    creator = roster.devices.get(creator_id) if isinstance(creator_id, str) else None
    if creator is None or creator["kind"] != "device" or not _active_at(creator, at) or creator_id not in epoch["wraps"]:
        raise Refused("creator")
    if not verify_signature(creator["sign_pub"], epoch_body(room, epoch), epoch.get("sig")):
        raise Refused("signature")
    for device in epoch["wraps"]:
        d = roster.devices.get(device)
        if d is None or d["kind"] != "device" or not _active_at(d, at):
            raise Refused("unknown_device")
    for earlier in before:
        if earlier["n"] < epoch["n"] and earlier["roster"] > at:
            raise Refused("roster_order")


# --- messages (ROOMS.md 4.5) ---


def message_aad(room: str, epoch: int, device: str, n: int) -> str:
    return f"relay-msg-1|{room}|{epoch}|{device}|{n}"


def message_body(room: str, message: dict) -> dict:
    body = {"v": "relay-msg-1", "room": room, **{k: message[k] for k in ("device", "epoch", "n", "iv", "ct")}}
    if "blob" in message:
        body["blob"] = message["blob"]
    return body


def seal_message(
    room: str,
    epoch: int,
    device: str,
    n: int,
    key: bytes,
    sign_key: Any,
    plaintext: bytes,
    *,
    blob: str | None = None,
    iv: bytes | None = None,
) -> dict:
    """Message `n` of `device` under `epoch`: {epoch, n, iv, ct, blob?, sig}."""
    iv = iv if iv is not None else secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(iv, bytes(plaintext), message_aad(room, epoch, device, n).encode())
    message: dict = {"epoch": epoch, "n": n, "iv": b64(iv), "ct": b64(ct)}
    if blob is not None:
        message["blob"] = blob
    message["sig"] = _sign(sign_key, message_body(room, {**message, "device": device}))
    return message


def open_message(room: str, message: dict, epochs: dict, epoch_keys: dict, sign_pub: Any) -> bytes:
    """Open a message as GET /messages returns it. `sign_pub(device)` gives a key from the verified roster."""
    try:
        epoch, key = epochs.get(message["epoch"]), epoch_keys.get(message["epoch"])
    except (KeyError, TypeError):
        raise Refused("record") from None
    if epoch is None or key is None:
        raise Refused("epoch")
    if not isinstance(message.get("device"), str) or message["device"] not in epoch["wraps"]:
        raise Refused("not_wrapped")
    try:
        body = message_body(room, message)
    except KeyError:
        raise Refused("record") from None
    if not verify_signature(sign_pub(message["device"]), body, message.get("sig")):
        raise Refused("signature")
    try:
        iv, ct = unb64(message["iv"]), unb64(message["ct"])
    except ValueError:
        raise Refused("decrypt") from None
    return _decrypt(key, iv, ct, message_aad(room, message["epoch"], message["device"], message["n"]).encode())


def is_replay(counters: dict, device: str, n: int) -> bool:
    """Whether counter `n` from `device` is not above the last one accepted."""
    last = counters.get(device)
    return last is not None and n <= last["n"]


def accept_counter(counters: dict, watermark: int, message: dict) -> dict | None:
    """Take message {device, n, seq} into `counters` (in place); the gap it shows, or None (ROOMS.md 4.5)."""
    last = counters.get(message["device"])
    gap = None
    if last is not None and message["n"] > last["n"] + 1:
        gap = {
            "device": message["device"],
            "after_n": last["n"],
            "before_n": message["n"],
            "cause": "missing" if watermark <= last["seq"] + 1 else "expired",
        }
    counters[message["device"]] = {"n": message["n"], "seq": message["seq"]}
    return gap


def count_messages(counters: dict, watermark: int, messages: list) -> tuple[list, list, dict]:
    """The vectors' form: ("accept" | "drop" per message, gaps, counters after)."""
    after = json.loads(json.dumps(counters))
    results, gaps = [], []
    for m in messages:
        if is_replay(after, m["device"], m["n"]):
            results.append("drop")
            continue
        gap = accept_counter(after, watermark, m)
        if gap:
            gaps.append(gap)
        results.append("accept")
    return results, gaps, after


# --- blobs (ROOMS.md 4.6) ---


def blob_aad(room: str, blob: str) -> str:
    return f"relay-blob-1|{room}|{blob}"


def seal_blob(room: str, blob: str, key: bytes, plaintext: bytes, *, iv: bytes | None = None) -> bytes:
    iv = iv if iv is not None else secrets.token_bytes(12)
    return iv + AESGCM(key).encrypt(iv, bytes(plaintext), blob_aad(room, blob).encode())


def open_blob(room: str, blob: str, key: bytes, body: bytes) -> bytes:
    if len(body) < 28:
        raise Refused("decrypt")
    return _decrypt(key, body[:12], body[12:], blob_aad(room, blob).encode())


# --- invite links (ROOMS.md 5) ---


def parse_invite_link(text: Any) -> dict | None:
    """{relay_host, room, join_token, invite_key, invite_pub, relay_base_url}, or None for a link to refuse."""
    if not isinstance(text, str):
        return None
    parts = text.split("#", 1)[1].split(".") if "#" in text else text.split(".")
    if len(parts) < 5 or parts[0] != "v1":
        return None
    room, token, key = parts[-3:]
    host = ".".join(parts[1:-3])
    if len(host) > 260 or not _HOST.fullmatch(host):
        return None
    if ":" in host and int(host.rsplit(":", 1)[1]) > 65535:
        return None
    if not _is_id(room) or not _is_b64(token, TOKEN_LEN):
        return None
    try:
        der = unb64(key)
        private = serialization.load_der_private_key(der, None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None
    if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(private.curve, ec.SECP256R1):
        return None
    pub = public_jwk(private)
    if b"\x03\x42\x00\x04" + unb64(pub["x"]) + unb64(pub["y"]) not in der:
        return None  # the RFC 5915 ECPrivateKey must carry its public key
    return {
        "relay_host": host,
        "room": room,
        "join_token": token,
        "invite_key": key,
        "invite_pub": pub,
        "relay_base_url": f"https://{host}",
    }


def invite_link(*, relay_host: str, room: str, join_token: str, invite_key: str, app_url: str = "") -> str:
    return f"{app_url.split('#')[0]}#v1.{relay_host.lower()}.{room}.{join_token}.{invite_key}"


# --- the member ---


@dataclass
class Message:
    """One entry of sync(): a message (`ok` or `refused`) or a gap (`missing`, `expired`).

    A gap entry stands right before the message that revealed it: `device` is the
    sender, `n` its first missing counter (the gap runs up to the next `ok` message's
    `n` minus one from that device), `seq` the revealing message's, plaintext None.
    """

    seq: int
    device: str
    epoch: int | None
    n: int | None
    plaintext: bytes | None
    blob: str | None
    at: int | None
    status: str
    reason: str | None = None


def _http(
    base_url: str,
    token: str,
    method: str,
    path: str,
    *,
    json_body: Any = None,
    data: bytes | None = None,
    binary: bool = False,
    timeout: float = 30,
) -> tuple[Any, int | None]:
    """One call under /v1/rooms: (answer, watermark header). Raises RoomError on a non-2xx answer."""
    headers = {"Authorization": f"Bearer {token}"}
    if json_body is not None:
        data = json.dumps(json_body).encode()
        headers["Content-Type"] = "application/json"
    elif data is not None:
        headers["Content-Type"] = "application/octet-stream"
    request = urllib.request.Request(f"{base_url}/v1/rooms{path}", data=data, method=method, headers=headers)

    def mark(h: Any) -> int | None:
        value = h.get("Relay-Room-Watermark") if h else None
        return int(value) if value is not None and value.isdigit() else None

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            watermark = mark(response.headers)
    except urllib.error.HTTPError as error:
        try:
            code = json.loads(error.read()).get("error", "unknown")
        except (ValueError, AttributeError):
            code = "unknown"
        raise RoomError(error.code, code) from None
    if binary:
        return raw, watermark
    return (json.loads(raw) if raw else None), watermark


_NETWORK_ERRORS = (urllib.error.URLError, ConnectionError, TimeoutError, http.client.HTTPException)


class RoomMember:
    """One device in one room: it replays the roster, accepts and opens epochs, seals and
    opens messages and blobs, keeps the per-sender counters, and makes the next epoch
    whenever the current one does not match the roster's readers (ROOMS.md 4.4).

    `sign_key` and `recv_key` are the device's keys in the C3 shape; they never enter
    `state()`. Plaintext is bytes: what it means is the application's.
    """

    def __init__(self, base_url: str, token: str, *, room: str, device: str, sign_key: Any, recv_key: Any,
                 timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        self.token, self.room, self.device = token, room, device
        self.sign_key, self.recv_key, self.timeout = sign_key, recv_key, timeout
        self.records: list[dict] = []
        self.roster: Roster | None = None
        self.roster_error: RosterInvalid | None = None
        self.epochs: dict[int, dict] = {}
        self.accepted: dict[int, dict] = {}
        self.epoch_keys: dict[int, bytes] = {}
        self.refused_epochs: dict[int, str] = {}
        self.sent = 0
        self.last_seq = 0
        self.counters: dict[str, dict] = {}
        self.blobs: dict[str, int] = {}
        self.pending: dict | None = None
        self.watermark: int | None = None
        self.created: dict | None = None
        self._lock = threading.RLock()

    # --- persistence ---

    def state(self) -> dict:
        """What the caller seals and keeps: ids, token, epoch keys, counters, last seq. No private key."""
        with self._lock:
            return {
                "v": 1,
                "base_url": self.base_url,
                "token": self.token,
                "room": self.room,
                "device": self.device,
                "epoch_keys": {str(n): b64(k) for n, k in sorted(self.epoch_keys.items())},
                "sent": self.sent,
                "last_seq": self.last_seq,
                "counters": json.loads(json.dumps(self.counters)),
                "blobs": dict(self.blobs),
                "pending": json.loads(json.dumps(self.pending)),
            }

    @classmethod
    def from_state(cls, state: dict, *, sign_key: Any, recv_key: Any) -> RoomMember:
        if state.get("v") != 1:
            raise ValueError("unknown member state version")
        m = cls(state["base_url"], state["token"], room=state["room"], device=state["device"], sign_key=sign_key,
                recv_key=recv_key)
        m.epoch_keys = {int(n): unb64(k) for n, k in state["epoch_keys"].items()}
        m.sent, m.last_seq = state["sent"], state["last_seq"]
        m.counters = json.loads(json.dumps(state["counters"]))
        m.blobs = dict(state.get("blobs", {}))
        m.pending = state.get("pending")
        return m

    # --- HTTP ---

    def _call(self, method: str, path: str = "", **kw: Any) -> Any:
        answer, watermark = _http(self.base_url, self.token, method, f"/{self.room}{path}", timeout=self.timeout, **kw)
        if watermark is not None:
            self.watermark = watermark
        return answer

    # --- creating and joining (ROOMS.md 4.7, 4.8) ---

    @classmethod
    def create(cls, base_url: str, credential: str, *, sign_key: Any, recv_key: Any, custodian_sign_pub: dict,
               max_bytes: int | None = None, retention_days: int | None = None) -> RoomMember:
        """POST /v1/rooms with a credential the caller holds, then the genesis record and epoch 1.

        The relay's answer (with the custodian's device and token) is kept in `created`.
        """
        body: dict = {
            "owner": {"sign_pub": sign_key.sign_pub, "recv_pub": recv_key.recv_pub},
            "custodian": {"sign_pub": custodian_sign_pub},
        }
        if max_bytes is not None:
            body["max_bytes"] = max_bytes
        if retention_days is not None:
            body["retention_days"] = retention_days
        created, _ = _http(base_url.rstrip("/"), credential, "POST", "", json_body=body)
        m = cls(base_url, created["token"], room=created["room"], device=created["device"], sign_key=sign_key,
                recv_key=recv_key)
        m.created = created
        m.append({
            "kind": "genesis",
            "room": created["room"],
            "creator": {"device": created["device"], "sign_pub": sign_key.sign_pub, "recv_pub": recv_key.recv_pub},
            "custodian": {"device": created["custodian"]["device"], "sign_pub": _reduce(custodian_sign_pub)},
        })
        m.rotate()
        return m

    @classmethod
    def join(cls, link: str, *, sign_key: Any, recv_key: Any, base_url: str | None = None,
             now: int | None = None) -> RoomMember:
        """ROOMS.md 4.8 steps 1 to 4. `base_url` replaces the https://<relay host> the link names."""
        parsed = parse_invite_link(link)
        if parsed is None:
            raise RoomError(0, "bad_link")
        base_url = (base_url or parsed["relay_base_url"]).rstrip("/")
        joined, _ = _http(base_url, parsed["join_token"], "POST", f"/{parsed['room']}/join",
                          json_body={"sign_pub": sign_key.sign_pub, "recv_pub": recv_key.recv_pub})
        m = cls(base_url, joined["token"], room=parsed["room"], device=joined["device"], sign_key=sign_key,
                recv_key=recv_key)
        m.refresh_roster()
        found = [(i, v) for i, v in m.roster.invites.items() if _same_jwk(v["pub"], parsed["invite_pub"])]
        if not found:
            raise RoomError(0, "invite_not_in_roster")
        invite_id, invite = found[0]
        entry = {
            "kind": "join",
            "invite": invite_id,
            "device": joined["device"],
            "at": int(time.time()) if now is None else now,
            "sign_pub": sign_key.sign_pub,
            "recv_pub": recv_key.recv_pub,
        }
        invite_key = serialization.load_der_private_key(unb64(parsed["invite_key"]), None)
        entry["invite_sig"] = _sign(invite_key, _join_body(entry))
        m.append(entry)
        if not invite["approval"]:
            m.refresh()
            m.rotate()
        return m

    # --- the roster ---

    def refresh_roster(self) -> None:
        answer = self._call("GET", f"/roster?after={len(self.records)}")
        entries = answer.get("entries") if isinstance(answer, dict) else None
        if not isinstance(entries, list):
            raise RoomError(0, "bad_answer")
        if not entries and self.roster is not None:
            return
        for e in entries:
            self.records.append({k: v for k, v in e.items() if k != "signer"} if isinstance(e, dict) else e)
        try:
            self.roster, self.roster_error = verify_roster(self.records, room=self.room), None
        except RosterInvalid as error:
            self.roster = error.roster if error.index > 0 and error.roster is not None else Roster()
            self.roster_error = error

    def append(self, entry: dict) -> dict:
        """Sign `entry` (its `by` is this device) as the next record and post it, re-reading on a 409."""
        entry = {"by": self.device, **entry}
        for attempt in range(_MAX_TRIES + 1):
            if self.roster is None:
                self.refresh_roster()
            if self.roster_error is not None:
                raise self.roster_error
            record = sign_entry(self.sign_key, entry, self.roster.n + 1, self.roster.head)
            try:
                self._call("POST", "/roster", json_body=record)
            except RoomError as error:
                if error.status != 409 or attempt >= _MAX_TRIES:
                    raise
                self.refresh_roster()
                continue
            self.refresh_roster()
            return record
        raise AssertionError("unreachable")

    # --- epochs (ROOMS.md 4.4) ---

    def refresh_epochs(self) -> None:
        """Fetch new epochs; accept, open or refuse each. A refusal is final after one fresh roster."""
        answer = self._call("GET", f"/epochs?after={max(self.epochs, default=0)}")
        for epoch in answer.get("epochs", []) if isinstance(answer, dict) else []:
            if isinstance(epoch, dict) and _is_int(epoch.get("n")) and epoch["n"] not in self.epochs:
                self.epochs[epoch["n"]] = epoch
        reread = False
        for n in sorted(self.epochs):
            if n in self.accepted or n in self.refused_epochs:
                continue
            epoch = self.epochs[n]
            try:
                accept_epoch(self.roster, self.room, epoch, self.accepted.values())
            except Refused as error:
                if reread:
                    self.refused_epochs[n] = error.reason
                    continue
                reread = True
                self.refresh_roster()
                try:
                    accept_epoch(self.roster, self.room, epoch, self.accepted.values())
                except Refused as again:
                    self.refused_epochs[n] = again.reason
                    continue
            self.accepted[n] = epoch
            if self.device in epoch["wraps"] and n not in self.epoch_keys:
                try:
                    self.epoch_keys[n] = open_epoch(self.room, epoch, self.device, self.recv_key)
                except Refused as error:
                    self.refused_epochs[n] = error.reason

    def refresh(self) -> None:
        self.refresh_roster()
        self.refresh_epochs()

    def is_active(self) -> bool:
        return self.roster is not None and self.device in self.roster.readers()

    def current_epoch(self) -> int | None:
        """The newest accepted epoch when this device opened it and its wraps are exactly the
        roster's readers now; None when a new epoch is due (ROOMS.md 4.4)."""
        n = max(self.accepted, default=0)
        if n == 0 or n not in self.epoch_keys:
            return None
        readers = set(self.roster.readers() if self.roster else [])
        return n if set(self.accepted[n]["wraps"]) == readers else None

    def rotate(self) -> int:
        """Make the next epoch for the roster's readers unless the current one covers them.
        On a 409 it reads epochs and roster again and makes one only if still due."""
        with self._lock:
            for attempt in range(_MAX_TRIES + 1):
                if self.roster is None:
                    self.refresh_roster()
                current = self.current_epoch()
                if current is not None:
                    return current
                if not self.is_active():
                    raise RoomError(0, "not_active")
                recipients = {d: self.roster.devices[d]["recv_pub"] for d in self.roster.readers()}
                n = max(self.epochs, default=0) + 1
                epoch, key = make_epoch(self.room, n, self.roster.n, self.device, self.sign_key, recipients)
                try:
                    self._call("POST", "/epochs", json_body=epoch)
                except RoomError as error:
                    if error.status != 409 or attempt >= _MAX_TRIES:
                        raise
                    self.refresh()
                    continue
                self.epochs[n] = self.accepted[n] = epoch
                self.epoch_keys[n] = key
                return n
            raise AssertionError("unreachable")

    # --- messages and blobs (ROOMS.md 4.5, 4.6) ---

    def post(self, plaintext: bytes, *, blob: bytes | None = None) -> int:
        """Seal and post `plaintext`, with `blob` as its file; rotates first when ROOMS.md 4.4 says so.

        A post the relay may have taken but did not answer stays in `state()` as
        `pending` and is sent again, with the same cid, before the next one.
        """
        with self._lock:
            self._flush_pending()
            self.refresh()
            epoch = self.rotate()
            key = self.epoch_keys[epoch]
            n = self.sent + 1
            blob_id = None
            if blob is not None:
                blob_id = random_id()
                self._call("PUT", f"/blobs/{blob_id}", data=seal_blob(self.room, blob_id, key, blob))
            sealed = seal_message(self.room, epoch, self.device, n, key, self.sign_key, plaintext, blob=blob_id)
            self.pending = {"cid": random_id(), **sealed}
            if blob_id is not None:
                self.blobs[blob_id] = epoch
            return self._flush_pending()

    def _flush_pending(self) -> int | None:
        if self.pending is None:
            return None
        for attempt in range(3):
            try:
                answer = self._call("POST", "/messages", json_body=self.pending)
                break
            except _NETWORK_ERRORS:
                if attempt == 2:
                    raise
        self.sent = max(self.sent, self.pending["n"])
        self.pending = None
        return answer["seq"]

    def sync(self) -> list[Message]:
        """Roster, epochs and every message after the last seq, each verified. Makes the epoch
        ROOMS.md 4.4 requires before it returns."""
        with self._lock:
            self.refresh()
            if self.is_active() and self.current_epoch() is None:
                self.rotate()
            out: list[Message] = []
            while True:
                answer = self._call("GET", f"/messages?after={self.last_seq}&limit=500")
                messages = answer.get("messages") if isinstance(answer, dict) else None
                watermark = answer.get("watermark") if isinstance(answer, dict) else None
                if not isinstance(messages, list) or not _is_int(watermark):
                    raise RoomError(0, "bad_answer")
                before = self.last_seq
                for message in messages:
                    self._take(message, watermark, out)
                if len(messages) < 500 or self.last_seq == before:
                    break
            return out

    def _take(self, message: Any, watermark: int, out: list[Message]) -> None:
        if not isinstance(message, dict) or not _is_int(message.get("seq")):
            return
        seq = message["seq"]
        self.last_seq = max(self.last_seq, seq)
        device, n, epoch = message.get("device"), message.get("n"), message.get("epoch")
        blob, at = message.get("blob"), message.get("at")

        def entry(status: str, plaintext: bytes | None = None, reason: str | None = None) -> Message:
            return Message(seq, device, epoch, n, plaintext, blob, at, status, reason)

        if not isinstance(device, str) or not _is_int(n) or not _is_int(epoch):
            out.append(entry("refused", reason="record"))
            return
        if is_replay(self.counters, device, n):
            out.append(entry("refused", reason="replay"))
            return

        def sign_pub(d: str) -> Any:
            found = self.roster.devices.get(d) if self.roster else None
            return found["sign_pub"] if found else None

        try:
            try:
                plaintext = open_message(self.room, message, self.accepted, self.epoch_keys, sign_pub)
            except Refused as error:
                if error.reason != "epoch":
                    raise
                self.refresh()
                plaintext = open_message(self.room, message, self.accepted, self.epoch_keys, sign_pub)
        except Refused as error:
            out.append(entry("refused", reason=error.reason))
            return
        gap = accept_counter(self.counters, watermark, {"device": device, "n": n, "seq": seq})
        if gap:
            out.append(Message(seq, device, None, gap["after_n"] + 1, None, None, None, gap["cause"]))
        if isinstance(blob, str):
            self.blobs[blob] = epoch
        out.append(entry("ok", plaintext))

    def blob(self, blob_id: str) -> bytes:
        """Fetch and open a blob a message named (from sync or post). Raises Refused."""
        epoch = self.blobs.get(blob_id)
        key = self.epoch_keys.get(epoch) if epoch is not None else None
        if key is None:
            raise Refused("epoch")
        return open_blob(self.room, blob_id, key, self._call("GET", f"/blobs/{blob_id}", binary=True))

    def ack(self, seq: int | None = None) -> None:
        self._call("POST", "/ack", json_body={"seq": self.last_seq if seq is None else seq})

    async def watch(self) -> AsyncIterator[int]:
        """The sequences /v1/rooms/ws announces for this room (ROOMS.md 3.5): hints to sync."""
        from websockets.asyncio.client import connect

        scheme, rest = self.base_url.split("://", 1)
        url = f"{'wss' if scheme == 'https' else 'ws'}://{rest}/v1/rooms/ws"
        async with connect(url) as socket:
            await socket.send(json.dumps({"tokens": [self.token]}))
            async for frame in socket:
                try:
                    hint = json.loads(frame)
                except ValueError:
                    continue
                if isinstance(hint, dict) and hint.get("room") == self.room and _is_int(hint.get("seq")):
                    yield hint["seq"]

    # --- an owner's calls (ROOMS.md 4.3): the roster record and the relay call together ---

    def invite(self, uses: int, expires_at: int, *, approval: bool = False, app_url: str = "") -> dict:
        """A join token and an `invite` record with a fresh invite key: {link, invite, invite_key_id}."""
        made = self._call("POST", "/invites", json_body={"uses": uses, "expires_at": expires_at})
        key = ec.generate_private_key(ec.SECP256R1())
        key_id = random_id()
        self.append({"kind": "invite", "invite": key_id, "invite_pub": public_jwk(key), "uses": uses,
                     "expires_at": expires_at, "approval": approval})
        pkcs8 = b64(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        host = urlsplit(self.base_url).netloc.lower()
        link = invite_link(relay_host=host, room=self.room, join_token=made["token"], invite_key=pkcs8, app_url=app_url)
        return {"link": link, "invite": made["invite"], "invite_key_id": key_id}

    def approve(self, device: str) -> int:
        """Approve a pending device and make the epoch that lets it read."""
        with self._lock:
            self.append({"kind": "approve", "device": device})
            self.refresh()
            return self.rotate()

    def remove(self, devices: str | list[str]) -> list[dict]:
        """The `remove` record, the relay's revocation of each, and the next epoch while this
        device still reads. Returns the relay calls that failed."""
        devices = [devices] if isinstance(devices, str) else list(devices)
        with self._lock:
            self.append({"kind": "remove", "devices": devices})
            failed = []
            for d in devices:
                try:
                    self._call("DELETE", f"/devices/{d}")
                except RoomError as error:
                    failed.append({"device": d, "status": error.status, "code": error.code})
            self.refresh()
            if self.is_active():
                self.rotate()
            return failed

    def info(self) -> dict:
        return self._call("GET")
