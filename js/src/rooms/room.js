/**
 * A room as one device sees it, over the relay's room routes (ROOMS.md 3.4): it
 * replays the roster, accepts and opens epochs, seals and opens messages and blobs,
 * keeps the per-sender counters, and makes the next epoch whenever the current one
 * does not match the roster's readers.
 */

import { Refused, makeEpoch, openBlob, openEpoch, openMessage, sealBlob, sealMessage, utf8 } from "./crypto.js";
import { accept, isReplay } from "./counters.js";
import { b64, canonical, randomId, sameJwk } from "./encoding.js";
import { importInviteKey, inviteLink, newInviteKey, parseInviteLink } from "./link.js";
import { acceptEpoch, joinBody, signEntry, verifyRoster } from "./roster.js";

const subtle = globalThis.crypto.subtle;
const SIG = { name: "ECDSA", hash: "SHA-256" };
const MAX_TRIES = 5;

/** An answer of the relay that is not a success: `status` and the `code` of its JSON error. */
export class RoomError extends Error {
  constructor(status, code) {
    super(`${status} ${code}`);
    this.name = "RoomError";
    this.status = status;
    this.code = code;
  }
}

/** One bearer token's calls to /v1/rooms. */
class Api {
  constructor(baseUrl, token, fetchImpl) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = token;
    this.fetch = fetchImpl ?? globalThis.fetch;
    this.watermark = null;
  }

  async call(method, path, { json, bytes, binary = false } = {}) {
    const headers = { authorization: `Bearer ${this.token}` };
    let body;
    if (json !== undefined) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(json);
    } else if (bytes !== undefined) {
      headers["content-type"] = "application/octet-stream";
      body = bytes;
    }
    const response = await this.fetch(`${this.baseUrl}/v1/rooms${path}`, { method, headers, body });
    const mark = response.headers.get("relay-room-watermark");
    if (mark !== null && /^[0-9]+$/.test(mark)) this.watermark = Number(mark);
    if (!response.ok) {
      let code = "unknown";
      try {
        code = (await response.json()).error ?? code;
      } catch {}
      throw new RoomError(response.status, code);
    }
    if (binary) return new Uint8Array(await response.arrayBuffer());
    if (response.status === 204) return null;
    const text = await response.text();
    return text ? JSON.parse(text) : null;
  }
}

/** Create a room with a credential (`POST /v1/rooms`). Returns the relay's answer. */
export async function createRoom({ baseUrl, credential, owner, custodian, maxBytes, retentionDays, fetch }) {
  const body = { owner: { sign_pub: owner.signPub, recv_pub: owner.recvPub }, custodian: { sign_pub: custodian } };
  if (maxBytes !== undefined) body.max_bytes = maxBytes;
  if (retentionDays !== undefined) body.retention_days = retentionDays;
  return new Api(baseUrl, credential, fetch).call("POST", "", { json: body });
}

function asBytes(value) {
  return typeof value === "string" ? utf8(value) : value;
}

export class Room {
  /**
   * `state` is what `state()` returned before: the device's own counter, the
   * sequence it read up to and the counters of the other devices. It holds no key.
   */
  constructor({ baseUrl, room, device, token, keys, fetch, state }) {
    this.baseUrl = baseUrl;
    this.id = room;
    this.device = device;
    this.keys = keys;
    this.api = new Api(baseUrl, token, fetch);
    this.records = [];
    this.roster = null;
    this.rosterError = null;
    this.epochs = new Map(); // n -> epoch as the relay holds it
    this.accepted = new Map(); // n -> accepted epoch
    this.epochKeys = new Map(); // n -> 32-byte key, for epochs wrapped for this device
    this.refusedEpochs = new Map(); // n -> reason
    this.sent = state?.sent ?? 0;
    this.lastSeq = state?.lastSeq ?? 0;
    this.counters = structuredClone(state?.counters ?? {});
    this.queue = Promise.resolve();
  }

  get token() {
    return this.api.token;
  }

  /** The watermark of the relay's last answer (ROOMS.md 3.3). */
  get watermark() {
    return this.api.watermark;
  }

  state() {
    return { sent: this.sent, lastSeq: this.lastSeq, counters: structuredClone(this.counters) };
  }

  // --- creating and joining (ROOMS.md 4.7, 4.8) ---

  /** Create a room with a credential the caller holds, then set it up. Returns `{room, created}`. */
  static async create({ baseUrl, credential, keys, custodianSignPub, maxBytes, retentionDays, fetch }) {
    const created = await createRoom({
      baseUrl,
      credential,
      owner: keys,
      custodian: custodianSignPub,
      maxBytes,
      retentionDays,
      fetch,
    });
    const room = await Room.setUp({ baseUrl, created, keys, custodianSignPub, fetch });
    return { room, created };
  }

  /** Post the genesis record and epoch 1 for a room whose `POST /v1/rooms` answer is `created`. */
  static async setUp({ baseUrl, created, keys, custodianSignPub, fetch }) {
    const room = new Room({ baseUrl, room: created.room, device: created.device, token: created.token, keys, fetch });
    const genesis = {
      kind: "genesis",
      by: created.device,
      room: created.room,
      creator: { device: created.device, sign_pub: keys.signPub, recv_pub: keys.recvPub },
      custodian: { device: created.custodian.device, sign_pub: custodianSignPub },
    };
    await room.append(genesis);
    await room.rotate();
    return room;
  }

  /**
   * Join with an invite link. `baseUrl` overrides the `https://<relay host>` the link
   * names; `now` is the join's `at` in Unix seconds.
   */
  static async join(link, keys, { baseUrl, fetch, now = Math.floor(Date.now() / 1000) } = {}) {
    const parsed = await parseInviteLink(link);
    if (!parsed) throw new RoomError(0, "bad_link");
    baseUrl ??= parsed.relay_base_url;
    const joined = await new Api(baseUrl, parsed.join_token, fetch).call("POST", `/${parsed.room}/join`, {
      json: { sign_pub: keys.signPub, recv_pub: keys.recvPub },
    });
    const room = new Room({ baseUrl, room: parsed.room, device: joined.device, token: joined.token, keys, fetch });
    await room.refreshRoster();
    const found = [...room.roster.invites].find(([, invite]) => sameJwk(invite.pub, parsed.invite_pub));
    if (!found) throw new RoomError(0, "invite_not_in_roster");
    const [inviteId, invite] = found;
    const inviteKey = await importInviteKey(parsed.invite_key);
    const entry = {
      kind: "join",
      by: joined.device,
      invite: inviteId,
      device: joined.device,
      at: now,
      sign_pub: keys.signPub,
      recv_pub: keys.recvPub,
    };
    const sig = await subtle.sign(SIG, inviteKey.privateKey, utf8(canonical(joinBody(entry))));
    entry.invite_sig = b64(sig);
    await room.append(entry);
    if (!invite.approval) {
      await room.refresh();
      await room.rotate();
    }
    return room;
  }

  // --- the roster ---

  async refreshRoster() {
    const { entries } = await this.api.call("GET", `/${this.id}/roster?after=${this.records.length}`);
    if (entries.length === 0 && this.roster) return;
    for (const { signer, ...record } of entries) this.records.push(record);
    const { roster, error } = await verifyRoster(this.records, { room: this.id, partial: true });
    this.roster = roster;
    this.rosterError = error;
  }

  /** Sign `entry` as the next record and post it, re-reading the roster on a 409. */
  async append(entry) {
    for (let attempt = 0; ; attempt++) {
      if (this.roster === null) await this.refreshRoster();
      if (this.rosterError) throw this.rosterError;
      const record = await signEntry(this.keys, entry, this.roster.n + 1, this.roster.head);
      try {
        await this.api.call("POST", `/${this.id}/roster`, { json: record });
      } catch (error) {
        if (!(error instanceof RoomError) || error.status !== 409 || attempt >= MAX_TRIES) throw error;
        await this.refreshRoster();
        continue;
      }
      await this.refreshRoster();
      return record;
    }
  }

  // --- epochs (ROOMS.md 4.4) ---

  /** Fetch new epochs; accept, open or refuse each. A refusal is final after one fresh roster. */
  async refreshEpochs() {
    const after = Math.max(0, ...this.epochs.keys());
    const { epochs } = await this.api.call("GET", `/${this.id}/epochs?after=${after}`);
    for (const epoch of epochs) this.epochs.set(epoch.n, epoch);
    let reread = false;
    for (const [n, epoch] of [...this.epochs].sort((a, b) => a[0] - b[0])) {
      if (this.accepted.has(n) || this.refusedEpochs.has(n)) continue;
      try {
        await acceptEpoch(this.roster, this.id, epoch, this.accepted.values());
      } catch (error) {
        if (!(error instanceof Refused)) throw error;
        if (!reread) {
          reread = true;
          await this.refreshRoster();
          try {
            await acceptEpoch(this.roster, this.id, epoch, this.accepted.values());
          } catch (again) {
            if (!(again instanceof Refused)) throw again;
            this.refusedEpochs.set(n, again.reason);
            continue;
          }
        } else {
          this.refusedEpochs.set(n, error.reason);
          continue;
        }
      }
      this.accepted.set(n, epoch);
      if (Object.hasOwn(epoch.wraps, this.device)) {
        try {
          this.epochKeys.set(n, await openEpoch({ room: this.id, epoch, device: this.device, keys: this.keys }));
        } catch (error) {
          if (!(error instanceof Refused)) throw error;
          this.refusedEpochs.set(n, error.reason);
        }
      }
    }
  }

  async refresh() {
    await this.refreshRoster();
    await this.refreshEpochs();
  }

  /** Whether this device is an active reader in its verified roster. */
  isActive() {
    return this.roster !== null && this.roster.readers().includes(this.device);
  }

  /**
   * The epoch to send under: the newest accepted epoch, when this device opened it
   * and its wraps are exactly the roster's readers now, so no device that left holds
   * its key and every reader can open it. Null when a new epoch is due: after a
   * join, an approval or a removal that no epoch has followed yet (ROOMS.md 4.4).
   */
  currentEpoch() {
    const n = Math.max(0, ...this.accepted.keys());
    if (n === 0 || !this.epochKeys.has(n)) return null;
    const readers = new Set(this.roster?.readers() ?? []);
    const wrapped = Object.keys(this.accepted.get(n).wraps);
    return wrapped.length === readers.size && wrapped.every((d) => readers.has(d)) ? n : null;
  }

  /**
   * Make the next epoch for the roster's readers unless the current one already
   * covers them. On a 409 it reads epochs and roster again and makes one only if
   * the new epoch does not cover what it needed. Returns the epoch to send under.
   */
  async rotate() {
    for (let attempt = 0; ; attempt++) {
      if (this.roster === null) await this.refreshRoster();
      const current = this.currentEpoch();
      if (current !== null) return current;
      if (!this.isActive()) throw new RoomError(0, "not_active");
      const recipients = {};
      for (const id of this.roster.readers()) recipients[id] = this.roster.device(id).recv_pub;
      const n = Math.max(0, ...this.epochs.keys()) + 1;
      const { epoch, key } = await makeEpoch({
        room: this.id,
        n,
        roster: this.roster.n,
        creator: this.device,
        keys: this.keys,
        recipients,
      });
      try {
        await this.api.call("POST", `/${this.id}/epochs`, { json: epoch });
      } catch (error) {
        if (!(error instanceof RoomError) || error.status !== 409 || attempt >= MAX_TRIES) throw error;
        await this.refresh();
        continue;
      }
      this.epochs.set(n, epoch);
      this.accepted.set(n, epoch);
      this.epochKeys.set(n, key);
      return n;
    }
  }

  // --- messages and blobs (ROOMS.md 4.5, 4.6) ---

  /**
   * Seal and post `plaintext` (bytes or a string), with `file` (bytes) as its blob
   * when given. It first reads roster and epochs and makes the next epoch when one
   * is due. Sends are taken one after another, each after the previous has its seq.
   */
  send(plaintext, { file } = {}) {
    const run = this.queue.then(() => this.sendNow(asBytes(plaintext), file));
    this.queue = run.catch(() => {});
    return run;
  }

  async sendNow(plaintext, file) {
    await this.refresh();
    const epoch = await this.rotate();
    const key = this.epochKeys.get(epoch);
    const n = this.sent + 1;
    const cid = randomId();
    let blob;
    if (file !== undefined) {
      blob = randomId();
      const body = await sealBlob({ room: this.id, blob, key, plaintext: asBytes(file) });
      await this.api.call("PUT", `/${this.id}/blobs/${blob}`, { bytes: body });
    }
    const sealed = await sealMessage({ room: this.id, epoch, device: this.device, n, key, keys: this.keys, plaintext, blob });
    const { seq } = await this.postMessage({ cid, ...sealed });
    this.sent = n;
    return { seq, cid, n, epoch, blob };
  }

  /** POST a message, retrying a failed connection with the same cid. */
  async postMessage(body) {
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.api.call("POST", `/${this.id}/messages`, { json: body });
      } catch (error) {
        if (error instanceof RoomError || attempt >= 2) throw error;
      }
    }
  }

  /**
   * Fetch what arrived since the last sync. Returns `{messages, dropped, refused,
   * gaps, watermark}`: opened messages with their plaintext, replays the counters
   * dropped, messages that failed a check with the reason, and the gaps the
   * counters show (`missing` when the relay owes them, `expired` when deleted).
   */
  async sync() {
    await this.refresh();
    const out = { messages: [], dropped: [], refused: [], gaps: [], watermark: null };
    while (true) {
      const answer = await this.api.call("GET", `/${this.id}/messages?after=${this.lastSeq}&limit=500`);
      out.watermark = answer.watermark;
      for (const message of answer.messages) await this.take(message, answer.watermark, out);
      if (answer.messages.length < 500) break;
    }
    return out;
  }

  async take(message, watermark, out) {
    this.lastSeq = Math.max(this.lastSeq, message.seq);
    if (isReplay(this.counters, message.device, message.n)) {
      out.dropped.push({ seq: message.seq, device: message.device, n: message.n });
      return;
    }
    const open = () =>
      openMessage({
        room: this.id,
        message,
        epochs: this.accepted,
        epochKeys: this.epochKeys,
        signPub: (device) => this.roster.device(device)?.sign_pub,
      });
    let plaintext;
    try {
      try {
        plaintext = await open();
      } catch (error) {
        if (!(error instanceof Refused) || error.reason !== "epoch") throw error;
        await this.refresh();
        plaintext = await open();
      }
    } catch (error) {
      if (!(error instanceof Refused)) throw error;
      out.refused.push({ seq: message.seq, device: message.device, n: message.n, reason: error.reason });
      return;
    }
    const gap = accept(this.counters, watermark, message);
    if (gap) out.gaps.push(gap);
    const { seq, device, n, epoch, blob, at } = message;
    out.messages.push({ seq, device, n, epoch, blob, at, plaintext, own: device === this.device });
  }

  /** Fetch and open the blob a message (as `sync` returned it) names. */
  async fetchFile(message) {
    const key = this.epochKeys.get(message.epoch);
    if (!key || message.blob === undefined) throw new Refused("epoch");
    const body = await this.api.call("GET", `/${this.id}/blobs/${message.blob}`, { binary: true });
    return openBlob({ room: this.id, blob: message.blob, key, body });
  }

  async ack(seq = this.lastSeq) {
    await this.api.call("POST", `/${this.id}/ack`, { json: { seq } });
  }

  async setPush(token) {
    await this.api.call("PUT", `/${this.id}/push`, { json: { token } });
  }

  async info() {
    return this.api.call("GET", `/${this.id}`);
  }

  async delete() {
    await this.api.call("DELETE", `/${this.id}`);
  }

  // --- membership (ROOMS.md 4.3): the roster record and the relay call together ---

  /**
   * Make an invite: a relay join token and an `invite` record with a fresh invite
   * key. Returns `{link, invite, inviteKeyId}`; keep both ids to close it.
   */
  async invite({ uses = 1, expiresAt, approval = false, appUrl = "" }) {
    const made = await this.api.call("POST", `/${this.id}/invites`, { json: { uses, expires_at: expiresAt } });
    const key = await newInviteKey();
    const inviteKeyId = randomId();
    await this.append({
      kind: "invite",
      by: this.device,
      invite: inviteKeyId,
      invite_pub: key.publicJwk,
      uses,
      expires_at: expiresAt,
      approval,
    });
    const relayHost = new URL(this.baseUrl).host;
    const link = inviteLink({ appUrl, relayHost, room: this.id, joinToken: made.token, inviteKey: key.pkcs8 });
    return { link, invite: made.invite, inviteKeyId };
  }

  async closeInvite({ inviteKeyId, invite }) {
    await this.append({ kind: "close-invite", by: this.device, invite: inviteKeyId });
    if (invite !== undefined) await this.api.call("DELETE", `/${this.id}/invites/${invite}`);
  }

  /** Approve a pending device and make the epoch that lets it read. */
  async approve(device) {
    await this.append({ kind: "approve", by: this.device, device });
    await this.refresh();
    return this.rotate();
  }

  /**
   * Remove devices: the `remove` record, the relay's revocation of each, and the
   * next epoch when this device still reads. Returns the relay calls that failed.
   */
  async remove(devices) {
    await this.append({ kind: "remove", by: this.device, devices });
    const failed = [];
    for (const device of devices) {
      try {
        await this.api.call("DELETE", `/${this.id}/devices/${device}`);
      } catch (error) {
        if (!(error instanceof RoomError)) throw error;
        failed.push({ device, status: error.status, code: error.code });
      }
    }
    await this.refresh();
    if (this.isActive()) await this.rotate();
    return failed;
  }

  async leave() {
    await this.append({ kind: "remove", by: this.device, devices: [this.device] });
    await this.api.call("DELETE", `/${this.id}/devices/${this.device}`);
  }

  async promote(device) {
    await this.append({ kind: "promote", by: this.device, device });
    await this.api.call("POST", `/${this.id}/owners`, { json: { device, owner: true } });
  }

  async demote(device) {
    await this.append({ kind: "demote", by: this.device, device });
    await this.api.call("POST", `/${this.id}/owners`, { json: { device, owner: false } });
  }
}
