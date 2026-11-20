/**
 * An in-process relay mailbox that follows ROOMS.md section 3, over real HTTP on
 * 127.0.0.1, for the rooms tests (no Go binary serves rooms yet). Its `hostile`
 * hooks let a test make it lie: add a device, drop or forge roster records, replay
 * messages, swap blobs, and hold epoch posts to force a race.
 */

import { createServer } from "node:http";

const ID = () => b64(crypto.getRandomValues(new Uint8Array(16)));
const TOKEN = () => b64(crypto.getRandomValues(new Uint8Array(32)));
const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const B64_RE = /^[A-Za-z0-9_-]*$/;
const MAX_JSON = 1 << 20;

function b64(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

const isInt = (v) => Number.isSafeInteger(v) && v >= 0;

// --- room quota (PROTOCOL.md 2.2, ROOMS.md 3.1) ---

function quota(max, storedBytes, retentionDays, blobBytes) {
  if (![max, storedBytes, retentionDays, blobBytes].every(isInt) || max < 1 || retentionDays < 1) return null;
  return { max, stored_bytes: storedBytes, retention_days: retentionDays, blob_bytes: blobBytes };
}

export function roomQuotaOfKey(entry) {
  const r = entry.rooms;
  if (r === null || typeof r !== "object" || Array.isArray(r)) return null;
  return quota(r.max, r.stored_bytes, r.retention_days, r.blob_bytes);
}

export function roomQuotaOfToken(payload) {
  return quota(payload.rooms, payload.room_stored_bytes, payload.room_retention_days, payload.room_blob_bytes);
}

export function roomLimits(q, request) {
  for (const k of ["max_bytes", "retention_days"]) {
    if (k in request && (!isInt(request[k]) || request[k] < 1)) return null;
  }
  return {
    max_bytes: Math.min(request.max_bytes ?? 2_000_000_000, q.stored_bytes),
    retention_days: Math.min(request.retention_days ?? 30, q.retention_days),
    blob_bytes: q.blob_bytes,
  };
}

class HttpError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

const fail = (status, code) => {
  throw new HttpError(status, code);
};

const isJwk = (j) =>
  j && typeof j === "object" && j.kty === "EC" && j.crv === "P-256" && typeof j.x === "string" && typeof j.y === "string";

export class FakeRoomRelay {
  /** `credentials` maps a bearer credential to its keys.json-style entry with a `rooms` object. */
  constructor({ credentials = {} } = {}) {
    this.credentials = new Map(Object.entries(credentials));
    this.rooms = new Map();
    this.deleted = new Set();
    this.tokens = new Map(); // device token -> {room, device}
    this.joinTokens = new Map(); // join token -> {room, invite}
    this.used = new Map(); // credential -> rooms used
    this.log = [];
    this.hostile = {
      roster: null, // (entries, room) -> entries served by GET /roster
      messages: null, // (messages, room) -> messages served by GET /messages
      blob: null, // (room, blobId, body) -> body served by GET /blobs
    };
    this.held = null;
  }

  async start() {
    this.server = createServer((req, res) => this.handle(req, res));
    await new Promise((resolve) => this.server.listen(0, "127.0.0.1", resolve));
    this.url = `http://127.0.0.1:${this.server.address().port}`;
    return this;
  }

  async stop() {
    this.server.closeAllConnections();
    await new Promise((resolve) => this.server.close(resolve));
  }

  room(id) {
    return this.rooms.get(id);
  }

  /** Hold POST /epochs until `count` of them wait, then take them in arrival order. */
  holdEpochs(count) {
    this.held = { count, waiting: [] };
  }

  /** Hostile: add a device in the relay's own view, with a token, as if it joined. */
  addDevice(roomId, keys = {}) {
    const room = this.rooms.get(roomId);
    const device = ID();
    const token = TOKEN();
    room.devices.set(device, {
      kind: "device",
      role: "member",
      revoked: false,
      sign_pub: keys.signPub,
      recv_pub: keys.recvPub,
      last_ack_at: null,
      ack: 0,
    });
    this.tokens.set(token, { room: roomId, device });
    return { device, token };
  }

  async handle(req, res) {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks);
    const url = new URL(req.url, "http://relay.example");
    this.log.push(`${req.method} ${url.pathname}`);
    const headers = {};
    try {
      const { status, body } = await this.route(req.method, url, req.headers, raw, headers);
      if (body instanceof Uint8Array) {
        res.writeHead(status, { ...headers, "content-type": "application/octet-stream" });
        res.end(body);
      } else if (body === undefined) {
        res.writeHead(status, headers);
        res.end();
      } else {
        res.writeHead(status, { ...headers, "content-type": "application/json" });
        res.end(JSON.stringify(body));
      }
    } catch (error) {
      if (!(error instanceof HttpError)) throw error;
      res.writeHead(error.status, { ...headers, "content-type": "application/json" });
      res.end(JSON.stringify({ error: error.code }));
    }
  }

  bearer(headers) {
    const auth = headers.authorization ?? "";
    if (!auth.startsWith("Bearer ")) fail(401, "unauthorized");
    return auth.slice(7);
  }

  json(raw) {
    if (raw.length > MAX_JSON) fail(413, "too_large");
    try {
      const body = JSON.parse(raw.toString("utf8"));
      if (body === null || typeof body !== "object" || Array.isArray(body)) fail(400, "bad_request");
      return body;
    } catch (error) {
      if (error instanceof HttpError) throw error;
      fail(400, "bad_request");
    }
  }

  credential(headers) {
    const entry = this.credentials.get(this.bearer(headers));
    if (!entry) fail(401, "unauthorized");
    const q = roomQuotaOfKey(entry);
    if (!q) fail(403, "forbidden");
    return { id: entry.id, quota: q };
  }

  /** The device behind the token, checked against the room in the path. */
  device(headers, roomId, out) {
    const held = this.tokens.get(this.bearer(headers));
    if (!held || held.room !== roomId) {
      if (this.deleted.has(roomId)) fail(410, "gone");
      fail(401, "unauthorized");
    }
    const room = this.rooms.get(roomId);
    if (!room) fail(this.deleted.has(roomId) ? 410 : 404, this.deleted.has(roomId) ? "gone" : "not_found");
    const device = room.devices.get(held.device);
    if (!device || device.revoked) fail(401, "unauthorized");
    out["relay-room-watermark"] = String(room.watermark);
    return { room, id: held.device, device };
  }

  async route(method, url, headers, raw, out) {
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts[0] !== "v1" || parts[1] !== "rooms") fail(404, "not_found");
    const rest = parts.slice(2);
    const query = url.searchParams;

    if (rest.length === 0 && method === "POST") return this.create(headers, raw);
    if (rest.length === 1 && rest[0] === "quota" && method === "GET") {
      const { id, quota: q } = this.credential(headers);
      return {
        status: 200,
        body: {
          rooms: { max: q.max, used: this.used.get(id) ?? 0 },
          stored_bytes: { max: q.stored_bytes, used: 0 },
          retention_days: q.retention_days,
          blob_bytes: q.blob_bytes,
          read_only_since: null,
        },
      };
    }
    const roomId = rest[0];
    const action = rest[1];

    if (action === "join" && method === "POST") return this.join(headers, roomId, raw);

    const { room, id: me, device } = this.device(headers, roomId, out);
    const isOwner = device.role === "owner";
    const custodian = device.kind === "custodian";
    const requireOwner = () => isOwner || fail(403, "forbidden");
    const noCustodian = () => !custodian || fail(403, "forbidden");

    if (action === undefined && method === "GET") {
      const devices = [...room.devices]
        .filter(([, d]) => !d.revoked)
        .map(([id, d]) => ({ device: id, kind: d.kind, role: d.role, last_ack_at: d.last_ack_at }));
      return {
        status: 200,
        body: { room: roomId, devices, limits: room.limits, stored_bytes: room.storedBytes, read_only_since: null },
      };
    }
    if (action === undefined && method === "DELETE") {
      requireOwner();
      this.rooms.delete(roomId);
      this.deleted.add(roomId);
      this.used.set(room.credential, (this.used.get(room.credential) ?? 1) - 1);
      return { status: 204 };
    }
    if (action === "invites" && method === "POST") {
      requireOwner();
      const body = this.json(raw);
      const now = Math.floor(Date.now() / 1000);
      if (!isInt(body.uses) || body.uses < 1 || body.uses > 1000) fail(400, "bad_request");
      if (!isInt(body.expires_at) || body.expires_at <= now || body.expires_at > now + 30 * 86400) {
        fail(400, "bad_request");
      }
      const invite = ID();
      const token = TOKEN();
      room.invites.set(invite, { token, uses: body.uses, used: 0, expires_at: body.expires_at, closed: false });
      this.joinTokens.set(token, { room: roomId, invite });
      return { status: 201, body: { invite, token } };
    }
    if (action === "invites" && method === "DELETE") {
      requireOwner();
      const invite = room.invites.get(rest[2]);
      if (!invite) fail(404, "not_found");
      invite.closed = true;
      return { status: 204 };
    }
    if (action === "roster" && method === "GET") {
      const after = Number(query.get("after") ?? 0);
      let entries = room.roster.filter((r) => r.n > after);
      if (this.hostile.roster) entries = this.hostile.roster(entries, roomId);
      return { status: 200, body: { entries } };
    }
    if (action === "roster" && method === "POST") {
      const body = this.json(raw);
      if (typeof body.entry !== "object" || typeof body.sig !== "string" || typeof body.prev !== "string") {
        fail(400, "bad_request");
      }
      if (raw.length > 65536) fail(413, "too_large");
      if (body.n !== room.roster.length + 1) fail(409, "conflict");
      room.roster.push({ n: body.n, entry: body.entry, sig: body.sig, prev: body.prev, signer: me });
      return { status: 201, body: {} };
    }
    if (action === "epochs" && method === "GET") {
      const after = Number(query.get("after") ?? 0);
      return { status: 200, body: { epochs: room.epochs.filter((e) => e.n > after) } };
    }
    if (action === "epochs" && method === "POST") {
      noCustodian();
      const body = this.json(raw);
      if (body.creator !== me) fail(403, "forbidden");
      if (!isInt(body.n) || !isInt(body.roster) || typeof body.wraps !== "object" || typeof body.sig !== "string") {
        fail(400, "bad_request");
      }
      if (this.held) {
        const held = this.held;
        await new Promise((resolve) => {
          held.waiting.push(resolve);
          const release = () => {
            if (this.held === held) this.held = null;
            for (const wake of held.waiting.splice(0)) wake();
          };
          if (held.waiting.length >= held.count) release();
          else setTimeout(release, 5000).unref();
        });
      }
      if (body.n !== room.epochs.length + 1) fail(409, "conflict");
      room.epochs.push({ n: body.n, roster: body.roster, creator: body.creator, wraps: body.wraps, sig: body.sig });
      return { status: 201, body: {} };
    }
    if (action === "owners" && method === "POST") {
      requireOwner();
      const body = this.json(raw);
      const target = room.devices.get(body.device);
      if (!target || target.revoked) fail(404, "not_found");
      if (typeof body.owner !== "boolean") fail(400, "bad_request");
      const before = target.role;
      target.role = body.owner ? "owner" : "member";
      if (!this.ownersLeft(room)) {
        target.role = before;
        fail(409, "conflict");
      }
      return { status: 204 };
    }
    if (action === "devices" && method === "DELETE") {
      const targetId = rest[2];
      if (targetId !== me) requireOwner();
      const target = room.devices.get(targetId);
      if (!target || target.revoked) fail(404, "not_found");
      target.revoked = true;
      if (!this.ownersLeft(room)) {
        target.revoked = false;
        fail(409, "conflict");
      }
      return { status: 204 };
    }
    if (action === "messages" && method === "GET") {
      noCustodian();
      const after = Number(query.get("after") ?? 0);
      const limit = Math.min(Number(query.get("limit") ?? 100), 500);
      let messages = room.messages.filter((m) => m.seq > after);
      if (this.hostile.messages) messages = this.hostile.messages(messages, roomId);
      return { status: 200, body: { messages: messages.slice(0, limit), watermark: room.watermark } };
    }
    if (action === "messages" && method === "POST") {
      noCustodian();
      const body = this.json(raw);
      const fields = ["cid", "iv", "ct", "sig"];
      if (!fields.every((k) => typeof body[k] === "string" && B64_RE.test(body[k]))) fail(400, "bad_request");
      if (!ID_RE.test(body.cid) || !isInt(body.epoch) || !isInt(body.n)) fail(400, "bad_request");
      if (body.blob !== undefined && !ID_RE.test(body.blob)) fail(400, "bad_request");
      if (Buffer.from(body.ct, "base64url").length > 65536) fail(413, "too_large");
      const repeat = room.messages.find((m) => m.device === me && m.cid === body.cid);
      if (repeat) return { status: 200, body: { seq: repeat.seq } };
      const seq = room.nextSeq++;
      const message = { seq, device: me, cid: body.cid, epoch: body.epoch, n: body.n, iv: body.iv, ct: body.ct };
      message.sig = body.sig;
      if (body.blob !== undefined) message.blob = body.blob;
      message.at = Math.floor(Date.now() / 1000);
      room.messages.push(message);
      return { status: 201, body: { seq } };
    }
    if (action === "blobs" && method === "PUT") {
      noCustodian();
      const blobId = rest[2];
      if (!ID_RE.test(blobId ?? "")) fail(400, "bad_request");
      if (raw.length > room.limits.blob_bytes) fail(413, "too_large");
      if (room.blobs.has(blobId)) fail(409, "conflict");
      room.blobs.set(blobId, new Uint8Array(raw));
      return { status: 201, body: {} };
    }
    if (action === "blobs" && method === "GET") {
      noCustodian();
      let body = room.blobs.get(rest[2]);
      if (!body) fail(404, "not_found");
      if (this.hostile.blob) body = this.hostile.blob(roomId, rest[2], body);
      return { status: 200, body };
    }
    if (action === "ack" && method === "POST") {
      const body = this.json(raw);
      if (!isInt(body.seq)) fail(400, "bad_request");
      device.ack = Math.max(device.ack, body.seq);
      device.last_ack_at = Math.floor(Date.now() / 1000);
      return { status: 204 };
    }
    if (action === "push" && method === "PUT") {
      const body = this.json(raw);
      if (body.token !== null && typeof body.token !== "string") fail(400, "bad_request");
      device.push = body.token;
      return { status: 204 };
    }
    fail(404, "not_found");
  }

  ownersLeft(room) {
    return [...room.devices.values()].some((d) => !d.revoked && d.role === "owner");
  }

  create(headers, raw) {
    const { id, quota: q } = this.credential(headers);
    const body = this.json(raw);
    if (!isJwk(body.owner?.sign_pub) || !isJwk(body.owner?.recv_pub) || !isJwk(body.custodian?.sign_pub)) {
      fail(400, "bad_request");
    }
    const limits = roomLimits(q, body);
    if (!limits) fail(400, "bad_request");
    if ((this.used.get(id) ?? 0) >= q.max) fail(507, "full");
    this.used.set(id, (this.used.get(id) ?? 0) + 1);
    const roomId = ID();
    const owner = ID();
    const custodian = ID();
    const ownerToken = TOKEN();
    const custodianToken = TOKEN();
    const devices = new Map([
      [owner, { kind: "device", role: "owner", revoked: false, last_ack_at: null, ack: 0 }],
      [custodian, { kind: "custodian", role: "owner", revoked: false, last_ack_at: null, ack: 0 }],
    ]);
    this.rooms.set(roomId, {
      credential: id,
      limits,
      devices,
      invites: new Map(),
      roster: [],
      epochs: [],
      messages: [],
      blobs: new Map(),
      nextSeq: 1,
      watermark: 1,
      storedBytes: 0,
    });
    this.tokens.set(ownerToken, { room: roomId, device: owner });
    this.tokens.set(custodianToken, { room: roomId, device: custodian });
    return {
      status: 201,
      body: {
        room: roomId,
        device: owner,
        token: ownerToken,
        custodian: { device: custodian, token: custodianToken },
        limits,
      },
    };
  }

  join(headers, roomId, raw) {
    const held = this.joinTokens.get(this.bearer(headers));
    if (!held || held.room !== roomId) fail(401, "unauthorized");
    const room = this.rooms.get(roomId);
    if (!room) fail(this.deleted.has(roomId) ? 410 : 404, this.deleted.has(roomId) ? "gone" : "not_found");
    const invite = room.invites.get(held.invite);
    if (invite.closed) fail(401, "unauthorized");
    const body = this.json(raw);
    if (!isJwk(body.sign_pub) || !isJwk(body.recv_pub)) fail(400, "bad_request");
    if (invite.used >= invite.uses || invite.expires_at <= Math.floor(Date.now() / 1000)) fail(409, "conflict");
    invite.used += 1;
    const device = ID();
    const token = TOKEN();
    room.devices.set(device, { kind: "device", role: "member", revoked: false, last_ack_at: null, ack: 0 });
    this.tokens.set(token, { room: roomId, device });
    return { status: 201, body: { device, token } };
  }
}
