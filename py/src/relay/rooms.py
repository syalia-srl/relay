"""Roster helpers for rooms (ROOMS.md sections 2, 4.2, 4.3 and 5).

What a party that holds a credential needs to manage a room it can never read: a
P-256 signing key (the custodian's), signed roster records, a full replay of the
roster, and a client for the relay's owner routes. It holds no receiving key and
makes no epoch.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

SigningKey = ec.EllipticCurvePrivateKey

ID_LEN = 22
_B64 = re.compile(r"[A-Za-z0-9_-]*")
_KINDS = {"genesis", "invite", "join", "approve", "link", "remove", "promote", "demote", "close-invite"}

__all__ = [
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


def _sign(key: SigningKey, obj: Any) -> str:
    r, s = decode_dss_signature(key.sign(canonical(obj).encode(), ec.ECDSA(hashes.SHA256())))
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


def sign_entry(key: SigningKey, entry: dict, n: int, prev: str) -> dict:
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
    r.n, r.head = i + 1, record_hash(rec)


def _device(kind: str, role: str, sign_pub: dict, recv_pub: dict | None, member: str, status: str = "active") -> dict:
    return {
        "kind": kind,
        "role": role,
        "status": status,
        "member": member,
        "sign_pub": _reduce(sign_pub),
        "recv_pub": _reduce(recv_pub) if recv_pub else None,
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
