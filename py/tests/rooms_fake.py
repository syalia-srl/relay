"""An in-process relay mailbox that follows ROOMS.md section 3, over real HTTP on
127.0.0.1, ported from js/test-support/rooms_relay.js. Its `hostile` hooks let a
test make it lie: add a device, drop or forge roster records, replay messages, swap
blobs, and hold epoch posts to force a race.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

ID_RE = re.compile(r"[A-Za-z0-9_-]{22}")
B64_RE = re.compile(r"[A-Za-z0-9_-]*")
MAX_JSON = 1 << 20
CREDENTIAL = "operator-key-for-tests"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def new_id() -> str:
    return _b64(secrets.token_bytes(16))


def new_token() -> str:
    return _b64(secrets.token_bytes(32))


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 2**53 - 1


def _is_jwk(j: Any) -> bool:
    return isinstance(j, dict) and j.get("kty") == "EC" and j.get("crv") == "P-256" and isinstance(j.get("x"), str)


class HttpError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status, self.code = status, code


def fail(status: int, code: str):
    raise HttpError(status, code)


class Hostile:
    roster: Callable[[list, str], list] | None = None
    messages: Callable[[list, str], list] | None = None
    blob: Callable[[str, str, bytes], bytes] | None = None


class FakeRoomRelay:
    def __init__(self, quota: dict | None = None):
        self.quota = quota or {"max": 100, "stored_bytes": 1_000_000_000, "retention_days": 30, "blob_bytes": 1_000_000}
        self.rooms: dict[str, dict] = {}
        self.deleted: set[str] = set()
        self.tokens: dict[str, dict] = {}
        self.join_tokens: dict[str, dict] = {}
        self.log: list[str] = []
        self.hostile = Hostile()
        self.lock = threading.RLock()
        self.held: dict | None = None
        relay = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                relay.handle(self, self.rfile.read(length) if length else b"")

            do_GET = do_POST = do_PUT = do_DELETE = _serve

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def room(self, room_id: str) -> dict:
        return self.rooms[room_id]

    def hold_epochs(self, count: int) -> None:
        """Hold POST /epochs until `count` of them wait, then take them in arrival order."""
        self.held = {"count": count, "waiting": 0, "event": threading.Event()}

    def add_device(self, room_id: str) -> dict:
        """Hostile: a device in the relay's own view, with a token, as if it joined."""
        with self.lock:
            device, token = new_id(), new_token()
            self.rooms[room_id]["devices"][device] = {
                "kind": "device", "role": "member", "revoked": False, "last_ack_at": None, "ack": 0,
            }
            self.tokens[token] = {"room": room_id, "device": device}
            return {"device": device, "token": token}

    def post_message(self, room_id: str, message: dict) -> int:
        """Hostile: store a message as if a device posted it."""
        with self.lock:
            room = self.rooms[room_id]
            seq = room["next_seq"]
            room["next_seq"] += 1
            room["messages"].append({"seq": seq, "at": int(time.time()), **message})
            return seq

    # --- HTTP ---

    def handle(self, req: BaseHTTPRequestHandler, raw: bytes) -> None:
        url = urlsplit(req.path)
        self.log.append(f"{req.command} {url.path}")
        out: dict[str, str] = {}
        try:
            status, body = self.route(req.command, url, req.headers, raw, out)
        except HttpError as error:
            status, body = error.status, {"error": error.code}
        if isinstance(body, bytes):
            data, ctype = body, "application/octet-stream"
        elif body is None:
            data, ctype = b"", None
        else:
            data, ctype = json.dumps(body).encode(), "application/json"
        req.send_response(status)
        for k, v in out.items():
            req.send_header(k, v)
        if ctype:
            req.send_header("Content-Type", ctype)
        req.send_header("Content-Length", str(len(data)))
        req.end_headers()
        req.wfile.write(data)

    def bearer(self, headers: Any) -> str:
        auth = headers.get("Authorization") or ""
        if not auth.startswith("Bearer "):
            fail(401, "unauthorized")
        return auth[7:]

    def json(self, raw: bytes) -> dict:
        if len(raw) > MAX_JSON:
            fail(413, "too_large")
        try:
            body = json.loads(raw)
        except ValueError:
            fail(400, "bad_request")
        if not isinstance(body, dict):
            fail(400, "bad_request")
        return body

    def device(self, headers: Any, room_id: str, out: dict) -> tuple[dict, str, dict]:
        held = self.tokens.get(self.bearer(headers))
        if not held or held["room"] != room_id:
            if room_id in self.deleted:
                fail(410, "gone")
            fail(401, "unauthorized")
        room = self.rooms.get(room_id)
        if room is None:
            fail(410, "gone") if room_id in self.deleted else fail(404, "not_found")
        d = room["devices"].get(held["device"])
        if d is None or d["revoked"]:
            fail(401, "unauthorized")
        out["Relay-Room-Watermark"] = str(room["watermark"])
        return room, held["device"], d

    def route(self, method: str, url: Any, headers: Any, raw: bytes, out: dict) -> tuple[int, Any]:
        parts = [p for p in url.path.split("/") if p]
        if parts[:2] != ["v1", "rooms"]:
            fail(404, "not_found")
        rest = parts[2:]
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        if not rest and method == "POST":
            return self.create(headers, raw)
        room_id = rest[0]
        action = rest[1] if len(rest) > 1 else None
        if action == "join" and method == "POST":
            return self.join(headers, room_id, raw)
        if action == "epochs" and method == "POST":
            return self.post_epoch(headers, room_id, raw, out)
        with self.lock:
            return self.route_locked(method, rest, room_id, action, query, headers, raw, out)

    def route_locked(self, method, rest, room_id, action, query, headers, raw, out):  # noqa: PLR0911, PLR0912
        room, me, device = self.device(headers, room_id, out)
        owner = device["role"] == "owner"
        custodian = device["kind"] == "custodian"

        def require_owner() -> None:
            if not owner:
                fail(403, "forbidden")

        def no_custodian() -> None:
            if custodian:
                fail(403, "forbidden")

        if action is None and method == "GET":
            devices = [
                {"device": i, "kind": d["kind"], "role": d["role"], "last_ack_at": d["last_ack_at"]}
                for i, d in room["devices"].items()
                if not d["revoked"]
            ]
            return 200, {"room": room_id, "devices": devices, "limits": room["limits"], "stored_bytes": 0,
                         "read_only_since": None}
        if action is None and method == "DELETE":
            require_owner()
            del self.rooms[room_id]
            self.deleted.add(room_id)
            return 204, None
        if action == "invites" and method == "POST":
            require_owner()
            body = self.json(raw)
            now = int(time.time())
            if not _is_int(body.get("uses")) or not 1 <= body["uses"] <= 1000:
                fail(400, "bad_request")
            if not _is_int(body.get("expires_at")) or not now < body["expires_at"] <= now + 30 * 86400:
                fail(400, "bad_request")
            invite, token = new_id(), new_token()
            room["invites"][invite] = {"uses": body["uses"], "used": 0, "expires_at": body["expires_at"], "closed": False}
            self.join_tokens[token] = {"room": room_id, "invite": invite}
            return 201, {"invite": invite, "token": token}
        if action == "invites" and method == "DELETE":
            require_owner()
            invite = room["invites"].get(rest[2])
            if invite is None:
                fail(404, "not_found")
            invite["closed"] = True
            return 204, None
        if action == "roster" and method == "GET":
            after = int(query.get("after", 0))
            entries = [dict(r) for r in room["roster"] if r["n"] > after]
            if self.hostile.roster:
                entries = self.hostile.roster(entries, room_id)
            return 200, {"entries": entries}
        if action == "roster" and method == "POST":
            body = self.json(raw)
            if not isinstance(body.get("entry"), dict) or not isinstance(body.get("sig"), str) or not isinstance(
                body.get("prev"), str
            ):
                fail(400, "bad_request")
            if len(raw) > 65536:
                fail(413, "too_large")
            if body.get("n") != len(room["roster"]) + 1:
                fail(409, "conflict")
            room["roster"].append({**{k: body[k] for k in ("n", "entry", "sig", "prev")}, "signer": me})
            return 201, {"n": body["n"]}
        if action == "epochs" and method == "GET":
            after = int(query.get("after", 0))
            return 200, {"epochs": [dict(e) for e in room["epochs"] if e["n"] > after]}
        if action == "owners" and method == "POST":
            require_owner()
            body = self.json(raw)
            target = room["devices"].get(body.get("device"))
            if target is None or target["revoked"]:
                fail(404, "not_found")
            before = target["role"]
            target["role"] = "owner" if body.get("owner") else "member"
            if not self.owners_left(room):
                target["role"] = before
                fail(409, "conflict")
            return 204, None
        if action == "devices" and method == "DELETE":
            target_id = rest[2]
            if target_id != me:
                require_owner()
            target = room["devices"].get(target_id)
            if target is None or target["revoked"]:
                fail(404, "not_found")
            target["revoked"] = True
            if not self.owners_left(room):
                target["revoked"] = False
                fail(409, "conflict")
            return 204, None
        if action == "messages" and method == "GET":
            no_custodian()
            after = int(query.get("after", 0))
            limit = min(int(query.get("limit", 100)), 500)
            messages = [dict(m) for m in room["messages"] if m["seq"] > after]
            if self.hostile.messages:
                messages = self.hostile.messages(messages, room_id)
            return 200, {"messages": messages[:limit], "watermark": room["watermark"]}
        if action == "messages" and method == "POST":
            no_custodian()
            body = self.json(raw)
            if not all(isinstance(body.get(k), str) and B64_RE.fullmatch(body[k]) for k in ("cid", "iv", "ct", "sig")):
                fail(400, "bad_request")
            if not ID_RE.fullmatch(body["cid"]) or not _is_int(body.get("epoch")) or not _is_int(body.get("n")):
                fail(400, "bad_request")
            if "blob" in body and not (isinstance(body["blob"], str) and ID_RE.fullmatch(body["blob"])):
                fail(400, "bad_request")
            for m in room["messages"]:
                if m["device"] == me and m["cid"] == body["cid"]:
                    return 200, {"seq": m["seq"]}
            message = {k: body[k] for k in ("cid", "epoch", "n", "iv", "ct", "sig", "blob") if k in body}
            return 201, {"seq": self.post_message(room_id, {"device": me, **message})}
        if action == "blobs" and method == "PUT":
            no_custodian()
            blob_id = rest[2] if len(rest) > 2 else ""
            if not ID_RE.fullmatch(blob_id):
                fail(400, "bad_request")
            if len(raw) > room["limits"]["blob_bytes"]:
                fail(413, "too_large")
            if blob_id in room["blobs"]:
                fail(409, "conflict")
            room["blobs"][blob_id] = raw
            return 201, None
        if action == "blobs" and method == "GET":
            no_custodian()
            body = room["blobs"].get(rest[2])
            if body is None:
                fail(404, "not_found")
            if self.hostile.blob:
                body = self.hostile.blob(room_id, rest[2], body)
            return 200, body
        if action == "ack" and method == "POST":
            body = self.json(raw)
            if not _is_int(body.get("seq")):
                fail(400, "bad_request")
            device["ack"] = max(device["ack"], body["seq"])
            device["last_ack_at"] = int(time.time())
            return 204, None
        fail(404, "not_found")

    def post_epoch(self, headers, room_id, raw, out):
        with self.lock:
            _, me, device = self.device(headers, room_id, out)
            if device["kind"] == "custodian":
                fail(403, "forbidden")
            body = self.json(raw)
            if body.get("creator") != me:
                fail(403, "forbidden")
            if not _is_int(body.get("n")) or not _is_int(body.get("roster")) or not isinstance(body.get("wraps"), dict):
                fail(400, "bad_request")
            held = self.held
        if held is not None:
            with self.lock:
                held["waiting"] += 1
                if held["waiting"] >= held["count"]:
                    self.held = None
                    held["event"].set()
            held["event"].wait(5)
        with self.lock:
            room = self.rooms[room_id]
            if body["n"] != len(room["epochs"]) + 1:
                fail(409, "conflict")
            room["epochs"].append({k: body[k] for k in ("n", "roster", "creator", "wraps", "sig")})
            return 201, {"n": body["n"]}

    def owners_left(self, room: dict) -> bool:
        return any(not d["revoked"] and d["role"] == "owner" for d in room["devices"].values())

    def create(self, headers, raw):
        if self.bearer(headers) != CREDENTIAL:
            fail(401, "unauthorized")
        body = self.json(raw)
        if not all(_is_jwk(x) for x in (
            (body.get("owner") or {}).get("sign_pub"),
            (body.get("owner") or {}).get("recv_pub"),
            (body.get("custodian") or {}).get("sign_pub"),
        )):
            fail(400, "bad_request")
        limits = {"max_bytes": 2_000_000_000, "retention_days": 30, "blob_bytes": self.quota["blob_bytes"]}
        with self.lock:
            room_id, owner, custodian = new_id(), new_id(), new_id()
            owner_token, custodian_token = new_token(), new_token()
            dev = lambda kind: {"kind": kind, "role": "owner", "revoked": False, "last_ack_at": None, "ack": 0}  # noqa: E731
            self.rooms[room_id] = {
                "limits": limits,
                "devices": {owner: dev("device"), custodian: dev("custodian")},
                "invites": {},
                "roster": [],
                "epochs": [],
                "messages": [],
                "blobs": {},
                "next_seq": 1,
                "watermark": 1,
            }
            self.tokens[owner_token] = {"room": room_id, "device": owner}
            self.tokens[custodian_token] = {"room": room_id, "device": custodian}
        return 201, {
            "room": room_id,
            "device": owner,
            "token": owner_token,
            "custodian": {"device": custodian, "token": custodian_token},
            "limits": limits,
        }

    def join(self, headers, room_id, raw):
        with self.lock:
            held = self.join_tokens.get(self.bearer(headers))
            if not held or held["room"] != room_id:
                fail(401, "unauthorized")
            room = self.rooms.get(room_id)
            if room is None:
                fail(410, "gone") if room_id in self.deleted else fail(404, "not_found")
            invite = room["invites"][held["invite"]]
            if invite["closed"]:
                fail(401, "unauthorized")
            body = self.json(raw)
            if not _is_jwk(body.get("sign_pub")) or not _is_jwk(body.get("recv_pub")):
                fail(400, "bad_request")
            if invite["used"] >= invite["uses"] or invite["expires_at"] <= int(time.time()):
                fail(409, "conflict")
            invite["used"] += 1
            device, token = new_id(), new_token()
            room["devices"][device] = {"kind": "device", "role": "member", "revoked": False, "last_ack_at": None, "ack": 0}
            self.tokens[token] = {"room": room_id, "device": device}
            return 201, {"device": device, "token": token}
