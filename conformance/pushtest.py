"""Fakes for the push suite: a push gateway the relay calls, an FCM and OAuth
server the gateway calls, and the gateway binary itself.

Everything runs on loopback. The service account is generated per test: a
throwaway RSA key whose token_uri points at the fake, never a real credential.
"""

from __future__ import annotations

import base64
import json
import os
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from relaytest import sha256_hex

PROJECT = "example-project"
SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
GATEWAY_KEY = "gateway-key-0123456789"


@dataclass
class Seen:
    """One request a fake received."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    at: float

    def json(self):
        return json.loads(self.body)


# A handler answers (status, headers, body bytes) for one request.
Answer = tuple[int, dict[str, str], bytes]


def json_answer(status: int, body, headers: dict[str, str] | None = None) -> Answer:
    return status, {"Content-Type": "application/json", **(headers or {})}, json.dumps(body).encode()


class FakeServer:
    """A loopback HTTP server that records every request and answers with handle()."""

    def __init__(self, handle: Callable[[Seen], Answer]):
        self.handle = handle
        self.seen: list[Seen] = []
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _any(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                seen = Seen(self.command, self.path, {k.lower(): v for k, v in self.headers.items()}, body, time.monotonic())
                with outer.lock:
                    outer.seen.append(seen)
                status, headers, data = outer.handle(seen)
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_DELETE = _any

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def requests(self) -> list[Seen]:
        with self.lock:
            return list(self.seen)

    def wait(self, count: int, timeout: float = 10) -> list[Seen]:
        """Wait until at least count requests arrived, and return them all."""
        deadline = time.monotonic() + timeout
        while len(self.requests()) < count:
            if time.monotonic() > deadline:
                raise AssertionError(f"{len(self.requests())} request(s) arrived, want {count}")
            time.sleep(0.02)
        return self.requests()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class FakeGateway(FakeServer):
    """The push gateway the relay calls. answer(seen) scripts each reply; the
    default accepts every batch and marks nothing invalid."""

    def __init__(self, answer: Callable[[Seen], Answer] | None = None):
        super().__init__(answer or (lambda seen: json_answer(200, {"invalid": []})))

    def batches(self) -> list[list[str]]:
        return [seen.json()["tokens"] for seen in self.requests()]


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class FakeFCM(FakeServer):
    """FCM HTTP v1 and the OAuth token endpoint on one loopback server.

    POST /token checks the RS256 JWT bearer grant against the generated key and
    issues an access token. POST /v1/projects/<project>/messages:send checks
    that token and answers by the device token's prefix: "unregistered-" gives
    UNREGISTERED, "badarg-" INVALID_ARGUMENT, "fail-" a 503, anything else 200.
    """

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.access_tokens: list[str] = []
        self.jwt_errors: list[str] = []
        super().__init__(self._answer)

    def service_account(self) -> dict:
        pem = self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        return {
            "type": "service_account",
            "project_id": PROJECT,
            "private_key_id": "test-key-1",
            "private_key": pem,
            "client_email": "pushgw@example-project.example",
            "token_uri": self.url("/token"),
        }

    def sends(self) -> list[Seen]:
        return [s for s in self.requests() if s.path.endswith("/messages:send")]

    def grants(self) -> list[Seen]:
        return [s for s in self.requests() if s.path == "/token"]

    def _check_jwt(self, assertion: str) -> str | None:
        try:
            head, claims, sig = assertion.split(".")
            self.key.public_key().verify(unb64url(sig), f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
            header = json.loads(unb64url(head))
            body = json.loads(unb64url(claims))
        except Exception as e:  # noqa: BLE001 - any failure is a refused grant
            return f"bad jwt: {e!r}"
        now = time.time()
        if header.get("alg") != "RS256":
            return "alg"
        if body.get("iss") != "pushgw@example-project.example" or body.get("aud") != self.url("/token"):
            return "iss/aud"
        if body.get("scope") != SCOPE:
            return "scope"
        if not (body["iat"] <= now + 60 and body["exp"] > now and body["exp"] - body["iat"] <= 3600):
            return "times"
        return None

    def _answer(self, seen: Seen) -> Answer:
        if seen.path == "/token":
            from urllib.parse import parse_qs

            form = parse_qs(seen.body.decode())
            if form.get("grant_type") != ["urn:ietf:params:oauth:grant-type:jwt-bearer"]:
                self.jwt_errors.append("grant_type")
                return json_answer(400, {"error": "unsupported_grant_type"})
            problem = self._check_jwt(form.get("assertion", [""])[0])
            if problem:
                self.jwt_errors.append(problem)
                return json_answer(400, {"error": "invalid_grant"})
            token = "ya29.test-" + b64url(os.urandom(12))
            self.access_tokens.append(token)
            return json_answer(200, {"access_token": token, "expires_in": 3599, "token_type": "Bearer"})

        if seen.path != f"/v1/projects/{PROJECT}/messages:send":
            return json_answer(404, {"error": {"code": 404, "status": "NOT_FOUND"}})
        if seen.headers.get("authorization", "").removeprefix("Bearer ") not in self.access_tokens:
            return json_answer(401, {"error": {"code": 401, "status": "UNAUTHENTICATED"}})
        token = seen.json()["message"]["token"]
        if token.startswith("unregistered-"):
            return json_answer(404, fcm_error(404, "NOT_FOUND", "UNREGISTERED"))
        if token.startswith("badarg-"):
            return json_answer(400, fcm_error(400, "INVALID_ARGUMENT", "INVALID_ARGUMENT"))
        if token.startswith("fail-"):
            return json_answer(503, fcm_error(503, "UNAVAILABLE", "UNAVAILABLE"), {"Retry-After": "7"})
        return json_answer(200, {"name": f"projects/{PROJECT}/messages/{b64url(os.urandom(6))}"})


def fcm_error(code: int, status: str, error_code: str) -> dict:
    return {
        "error": {
            "code": code,
            "message": "test",
            "status": status,
            "details": [{"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": error_code}],
        }
    }


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def gateway_keys(*keys: tuple[str, str, int]) -> dict:
    """A PUSHGW_KEYS_PATH file from (id, key, per_minute) triples."""
    return {"keys": [{"id": i, "sha256": sha256_hex(k), "per_minute": n} for i, k, n in keys]}


@dataclass
class Gateway:
    """One pushgw process on its own port, against a FakeFCM."""

    root: Path
    fcm: FakeFCM
    keys: dict | None = field(default_factory=lambda: gateway_keys(("relay", GATEWAY_KEY, 1000)))
    proc: subprocess.Popen | None = None

    def __post_init__(self):
        self.root.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        self.keys_path = self.root / "pushgw-keys.json"
        if self.keys is not None:
            self.write_keys(self.keys)
        self.credentials_path = self.root / "service-account.json"
        self.credentials_path.write_text(json.dumps(self.fcm.service_account()))
        self.credentials_path.chmod(0o600)
        self.log_path = self.root / "pushgw.log"
        env = os.environ.copy()
        env.update(
            {
                "PUSHGW_ADDR": f"127.0.0.1:{self.port}",
                "PUSHGW_KEYS_PATH": str(self.keys_path),
                "PUSHGW_FCM_CREDENTIALS": str(self.credentials_path),
                "PUSHGW_FCM_ENDPOINT": self.fcm.url(""),
            }
        )
        binary = os.environ.get("PUSHGW_BIN")
        if not binary:
            raise RuntimeError("set PUSHGW_BIN to the push gateway binary under test")
        self.log = self.log_path.open("ab")
        self.proc = subprocess.Popen([binary], env=env, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"pushgw exited at once:\n{self.logs()}")
            with socket.socket() as probe:
                probe.settimeout(0.1)
                if probe.connect_ex(("127.0.0.1", self.port)) == 0:
                    return
            time.sleep(0.02)
        self.stop()
        raise RuntimeError(f"pushgw never listened:\n{self.logs()}")

    def write_keys(self, keys: dict) -> None:
        self.keys_path.write_text(json.dumps(keys))

    def reload(self) -> None:
        assert self.proc is not None
        before = self.logs().count("keys loaded")
        self.proc.send_signal(signal.SIGHUP)
        deadline = time.monotonic() + 5
        while self.logs().count("keys loaded") <= before:
            if time.monotonic() > deadline:
                raise AssertionError(f"pushgw never reloaded its keys:\n{self.logs()}")
            time.sleep(0.02)

    def url(self, path: str = "/v1/wake") -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def logs(self) -> str:
        try:
            return self.log_path.read_text(errors="replace")
        except FileNotFoundError:
            return ""

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        self.proc = None
        self.log.close()
