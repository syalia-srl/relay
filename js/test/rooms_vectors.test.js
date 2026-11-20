/** Every vectors/rooms_*.json file, checked against the rooms module (ROOMS.md section 8). */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { fromHex, toHex } from "../src/bytes.js";
import { count } from "../src/rooms/counters.js";
import {
  Refused,
  blobAad,
  epochBody,
  keysFrom,
  messageAad,
  messageBody,
  openBlob,
  openEpoch,
  openMessage,
  sealBlob,
  sealMessage,
  verifyObject,
  wrapFor,
  wrapKey,
} from "../src/rooms/crypto.js";
import { canonical, reduceJwk } from "../src/rooms/encoding.js";
import { parseInviteLink } from "../src/rooms/link.js";
import { RosterInvalid, acceptEpoch, verifyRoster } from "../src/rooms/roster.js";
import { roomLimits, roomQuotaOfKey, roomQuotaOfToken } from "../test-support/rooms_relay.js";

const VECTORS = new URL("../../vectors/", import.meta.url);
const load = (name) => JSON.parse(readFileSync(new URL(name, VECTORS), "utf8"));
const subtle = globalThis.crypto.subtle;

async function ecdhPair(privateJwk) {
  const privateKey = await subtle.importKey("jwk", privateJwk, { name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ]);
  const publicKey = await subtle.importKey("jwk", reduceJwk(privateJwk), { name: "ECDH", namedCurve: "P-256" }, true, []);
  return { privateKey, publicKey };
}

async function rejects(promise, reason) {
  await assert.rejects(promise, (error) => error instanceof Refused && error.reason === reason);
}

test("rooms_encoding: canonical JSON", () => {
  for (const c of load("rooms_encoding.json").canonical) assert.equal(canonical(c.object), c.canonical);
});

test("rooms_encoding: signatures to accept and refuse", async () => {
  for (const c of load("rooms_encoding.json").signatures) {
    assert.equal(await verifyObject(c.public_jwk, c.object, c.sig), c.valid, c.name);
  }
});

test("rooms_encoding: JWK reduction", () => {
  const v = load("rooms_encoding.json").public_jwk;
  assert.deepEqual(reduceJwk(v.jwk), v.reduced);
});

test("rooms_roster: the valid roster replays to its state", async () => {
  const v = load("rooms_roster.json");
  const roster = await verifyRoster(v.valid.records, { room: v.room });
  assert.deepEqual(roster.state(), v.valid.state);
});

test("rooms_roster: refused rosters stop at the first invalid record", async () => {
  for (const c of load("rooms_roster.json").refused) {
    await assert.rejects(
      verifyRoster(c.records),
      (error) => error instanceof RosterInvalid && error.index === c.first_invalid && error.reason === c.reason,
      c.name,
    );
    const { roster, error } = await verifyRoster(c.records, { partial: true });
    assert.equal(error.index, c.first_invalid, c.name);
    assert.equal(roster.n, c.first_invalid, c.name);
  }
});

test("rooms_roster: another room's roster is refused at record 1", async () => {
  const v = load("rooms_roster.json");
  await rejects(verifyRoster(v.valid.records, { room: "AAAAAAAAAAAAAAAAAAAAAA" }), "room");
});

test("rooms_epoch: every intermediate value of each wrap", async () => {
  const v = load("rooms_epoch.json");
  const epochKey = fromHex(v.epoch_key);
  assert.equal(canonical(epochBody(v.room, v.epoch)), v.signed_canonical);
  for (const w of v.wraps) {
    const eph = await ecdhPair(w.eph_private_jwk);
    const receiving = await ecdhPair(w.recv_private_jwk);
    const keys = await keysFrom(null, receiving);
    const secret = await keys.derive(w.wrap.eph);
    assert.equal(toHex(secret), w.ecdh_secret);
    assert.equal(toHex(await wrapKey(secret, w.hkdf_info)), w.wrap_key);
    const made = await wrapFor({
      room: v.room,
      n: v.epoch.n,
      device: w.device,
      recvPub: reduceJwk(w.recv_private_jwk),
      epochKey,
      eph,
      iv: fromHex(w.iv),
    });
    assert.deepEqual(made, w.wrap);
    assert.deepEqual(v.epoch.wraps[w.device], w.wrap);
    const opened = await openEpoch({ room: v.room, epoch: v.epoch, device: w.device, keys });
    assert.equal(toHex(opened), v.epoch_key);
  }
});

test("rooms_epoch: the epoch is accepted, the refused ones are not", async () => {
  const v = load("rooms_epoch.json");
  const roster = await verifyRoster(v.roster, { room: v.room });
  await acceptEpoch(roster, v.room, v.epoch);
  await rejects(acceptEpoch(roster, "AAAAAAAAAAAAAAAAAAAAAA", v.epoch), "room");
  const verified = (n) => verifyRoster(v.full_roster.slice(0, n), { room: v.room });
  for (const c of v.accepted) await acceptEpoch(await verified(c.verified), v.room, c.epoch, c.before);
  for (const c of v.refused) {
    await rejects(acceptEpoch(await verified(c.verified), v.room, c.epoch, c.before), c.reason);
  }
});

async function messageContext() {
  const e = load("rooms_epoch.json");
  const v = load("rooms_message.json");
  const roster = await verifyRoster(e.roster, { room: e.room });
  await acceptEpoch(roster, e.room, e.epoch);
  return {
    v,
    epochs: new Map([[v.epoch, e.epoch]]),
    epochKeys: new Map([[v.epoch, fromHex(v.epoch_key)]]),
    signPub: (device) => roster.device(device)?.sign_pub,
  };
}

test("rooms_message: sealed messages open, and seal to the same bytes", async () => {
  const { v, epochs, epochKeys, signPub } = await messageContext();
  for (const c of v.cases) {
    const m = c.message;
    assert.equal(messageAad(v.room, m.epoch, m.device, m.n), c.additional_data);
    assert.equal(canonical(messageBody(v.room, m)), c.signed_canonical);
    assert.deepEqual(v.senders[m.device], signPub(m.device));
    const plaintext = await openMessage({ room: v.room, message: m, epochs, epochKeys, signPub });
    assert.equal(toHex(plaintext), c.plaintext);
    const iv = Uint8Array.from(atob(m.iv.replace(/-/g, "+").replace(/_/g, "/")), (ch) => ch.charCodeAt(0));
    const sealed = await sealMessage({
      room: v.room,
      epoch: m.epoch,
      device: m.device,
      n: m.n,
      key: fromHex(v.epoch_key),
      keys: { sign: async () => new Uint8Array(64) },
      plaintext: fromHex(c.plaintext),
      blob: m.blob,
      iv,
    });
    assert.equal(sealed.ct, m.ct);
  }
});

test("rooms_message: refused messages", async () => {
  const { v, epochs, epochKeys, signPub } = await messageContext();
  for (const c of v.refused) {
    await rejects(openMessage({ room: v.room, message: c.message, epochs, epochKeys, signPub }), c.reason);
  }
});

test("rooms_message: counters, replays and gaps", () => {
  for (const c of load("rooms_message.json").counters) {
    const { results, gaps, state } = count(c.state, c.watermark, c.messages);
    assert.deepEqual(results, c.results, c.name);
    assert.deepEqual(gaps, c.gaps, c.name);
    assert.deepEqual(state, c.state_after, c.name);
  }
});

test("rooms_blob: sealed blobs and bodies to refuse", async () => {
  const v = load("rooms_blob.json");
  const key = fromHex(v.epoch_key);
  const digest = async (bytes) => toHex(new Uint8Array(await subtle.digest("SHA-256", bytes)));
  for (const c of v.cases) {
    assert.equal(blobAad(v.room, c.blob), c.additional_data, c.name);
    const plaintext =
      typeof c.plaintext === "string"
        ? fromHex(c.plaintext)
        : Uint8Array.from({ length: c.plaintext.length }, (_, i) => i % 251);
    if (typeof c.plaintext !== "string") assert.equal(await digest(plaintext), c.plaintext.sha256);
    const sealed = await sealBlob({ room: v.room, blob: c.blob, key, plaintext, iv: fromHex(c.iv) });
    if (typeof c.body === "string") assert.equal(toHex(sealed), c.body, c.name);
    else assert.deepEqual({ sha256: await digest(sealed), length: sealed.length }, c.body, c.name);
    assert.deepEqual(await openBlob({ room: v.room, blob: c.blob, key, body: sealed }), plaintext, c.name);
  }
  for (const c of v.refused) {
    await rejects(openBlob({ room: v.room, blob: c.blob, key, body: fromHex(c.body) }), "decrypt");
  }
});

test("rooms_invite_link: links to accept and to refuse", async () => {
  for (const c of load("rooms_invite_link.json").cases) {
    const parsed = await parseInviteLink(c.text);
    if (!c.valid) {
      assert.equal(parsed, null, c.name);
      continue;
    }
    assert.ok(parsed, c.name);
    const { relay_base_url, ...parts } = parsed;
    assert.deepEqual(parts, c.parsed, c.name);
    assert.equal(relay_base_url, c.relay_base_url, c.name);
  }
});

test("rooms_quota: room quotas and room limits (the fake relay of the test suite)", () => {
  const v = load("rooms_quota.json");
  for (const c of v.credentials) {
    const quota = c.keys_entry ? roomQuotaOfKey(c.keys_entry) : roomQuotaOfToken(c.rt1_payload);
    assert.deepEqual(quota, c.room_quota, c.name);
  }
  for (const c of v.creates) {
    assert.deepEqual(roomLimits(c.room_quota ?? v.credentials[0].room_quota, c.request), c.limits, c.name);
  }
});
