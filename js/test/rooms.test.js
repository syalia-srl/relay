/** The Room client against the fake relay of ROOMS.md section 3: create, invite, join, talk. */

import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import * as relayPackage from "../src/index.js";
import { Room, RoomError, softwareDeviceKeys } from "../src/rooms/index.js";
import { inAWeek, roomWith, startRoomRelay, text } from "../test-support/rooms_helpers.js";

let relay;
before(async () => {
  relay = await startRoomRelay();
});
after(async () => {
  await relay.stop();
});

test("the package entry point exports the rooms module", () => {
  assert.equal(relayPackage.rooms.Room, Room);
  assert.equal(typeof relayPackage.rooms.softwareDeviceKeys, "function");
});

test("softwareDeviceKeys: P-256 public JWKs, 64-byte signatures, 32-byte secrets, nothing extractable", async () => {
  const keys = await softwareDeviceKeys();
  assert.deepEqual(Object.keys(keys.signPub).sort(), ["crv", "kty", "x", "y"]);
  assert.equal((await keys.sign(new Uint8Array([1, 2, 3]))).length, 64);
  const other = await softwareDeviceKeys();
  assert.deepEqual(await keys.derive(other.recvPub), await other.derive(keys.recvPub));
  assert.equal((await keys.derive(other.recvPub)).length, 32);
  assert.equal(Object.values(keys).some((v) => v instanceof CryptoKey && v.extractable), false);
});

test("an owner creates a room, a member joins by link, both read and write", async () => {
  const { a, members } = await roomWith(relay, 1);
  const [b] = members;
  await a.refresh();
  assert.equal(a.roster.n, 3); // genesis, invite, join
  assert.deepEqual(new Set(a.roster.readers()), new Set([a.device, b.device]));

  await a.send("hola");
  await b.send(new TextEncoder().encode("qué tal"));
  const atB = await b.sync();
  const atA = await a.sync();
  assert.deepEqual(atB.messages.map((m) => text(m.plaintext)), ["hola", "qué tal"]);
  assert.deepEqual(atA.messages.map((m) => [m.own, text(m.plaintext)]), [[true, "hola"], [false, "qué tal"]]);
  assert.deepEqual(atA.refused, []);
  assert.equal(atA.watermark, 1);
  // The joiner made epoch 2 for its own join, and nobody made a third.
  assert.equal(relay.room(a.id).epochs.length, 2);
});

test("a newcomer reads nothing from before it joined", async () => {
  const { a } = await roomWith(relay, 0);
  await a.send("before");
  const { link } = await a.invite({ uses: 1, expiresAt: inAWeek() });
  const c = await Room.join(link, await softwareDeviceKeys(), { baseUrl: relay.url });
  await a.send("after");
  const seen = await c.sync();
  assert.deepEqual(seen.messages.map((m) => text(m.plaintext)), ["after"]);
  // "before" is under epoch 1, which was never wrapped for the newcomer.
  assert.deepEqual(seen.refused.map((r) => r.reason), ["epoch"]);
});

test("a file travels as a blob bound to its message", async () => {
  const { a, members } = await roomWith(relay, 1);
  const file = crypto.getRandomValues(new Uint8Array(5000));
  const sent = await a.send('{"type":"file"}', { file });
  const { messages } = await members[0].sync();
  assert.equal(messages[0].blob, sent.blob);
  assert.deepEqual(await members[0].fetchFile(messages[0]), file);
});

test("an invite with approval admits a pending device that reads only once approved", async () => {
  const { a } = await roomWith(relay, 0);
  const { link } = await a.invite({ uses: 1, expiresAt: inAWeek(), approval: true });
  const b = await Room.join(link, await softwareDeviceKeys(), { baseUrl: relay.url });
  await b.refresh();
  assert.equal(b.roster.device(b.device).status, "pending");
  await assert.rejects(b.send("let me in"), (e) => e instanceof RoomError && e.code === "not_active");
  await a.send("not for b");
  await a.refresh();
  await a.approve(b.device);
  await a.send("now b reads");
  const seen = await b.sync();
  assert.deepEqual(seen.messages.map((m) => text(m.plaintext)), ["now b reads"]);
});

test("the counters survive a restart through state()", async () => {
  const { a, members } = await roomWith(relay, 1);
  await a.send("one");
  await members[0].sync();
  const again = new Room({
    baseUrl: relay.url,
    room: a.id,
    device: a.device,
    token: a.token,
    keys: a.keys,
    state: a.state(),
  });
  const sent = await again.send("two");
  assert.equal(sent.n, 2);
  const seen = await members[0].sync();
  assert.deepEqual(seen.messages.map((m) => [m.n, text(m.plaintext)]), [[2, "two"]]);
  assert.deepEqual(seen.dropped, []);
});

test("promote, demote, close an invite and leave", async () => {
  const { a, members } = await roomWith(relay, 1);
  const [b] = members;
  await a.promote(b.device);
  assert.equal(a.roster.device(b.device).role, "owner");
  assert.equal(relay.room(a.id).devices.get(b.device).role, "owner");
  await a.demote(b.device);
  assert.equal(a.roster.device(b.device).role, "member");
  const made = await a.invite({ uses: 3, expiresAt: inAWeek() });
  await a.closeInvite(made);
  assert.equal(a.roster.invites.get(made.inviteKeyId).closed, true);
  await assert.rejects(Room.join(made.link, await softwareDeviceKeys(), { baseUrl: relay.url }), (e) => e.status === 401);
  await b.leave();
  await a.refresh();
  assert.equal(a.roster.device(b.device).status, "removed");
  const sent = await a.send("b is gone");
  assert.equal(Object.hasOwn(relay.room(a.id).epochs.at(-1).wraps, b.device), false);
  assert.equal(sent.epoch, relay.room(a.id).epochs.length);
});
