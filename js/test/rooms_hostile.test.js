/**
 * A relay that lies (ROOMS.md 1 and 6): it adds a device, drops a roster record,
 * replays a message, swaps blobs and posts an epoch with a removed device's keys. Each
 * is refused or shown. And the epoch rules of
 * ROOMS.md 4.4: after a custodian's remove, a remaining member makes the next epoch
 * before it sends, and two members that race get one 201 and one 409.
 */

import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { Refused, Room, makeEpoch, sealMessage, signEntry, softwareDeviceKeys } from "../src/rooms/index.js";
import { custodianRemove, roomWith, startRoomRelay, text } from "../test-support/rooms_helpers.js";

let relay;
before(async () => {
  relay = await startRoomRelay();
});
after(async () => {
  await relay.stop();
});

const wrappedFor = (roomId, device) =>
  relay.room(roomId).epochs.filter((epoch) => Object.hasOwn(epoch.wraps, device)).map((epoch) => epoch.n);

test("hostile: a device the relay adds to its own view gets no key wrapped for it", async () => {
  const { a, members } = await roomWith(relay, 2);
  const [b, c] = members;
  const intruder = relay.addDevice(a.id, await softwareDeviceKeys());
  assert.ok((await a.info()).devices.some((d) => d.device === intruder.device), "the relay shows it");

  await a.remove([c.device]); // a change that makes a new epoch
  await a.send("after the removal");
  await b.send("b too");
  assert.deepEqual(wrappedFor(a.id, intruder.device), []);
  const newest = relay.room(a.id).epochs.at(-1);
  assert.deepEqual(new Set(Object.keys(newest.wraps)), new Set([a.device, b.device]));
});

test("hostile: a join the relay forges breaks the roster there, and its epoch is refused", async () => {
  const { a, members } = await roomWith(relay, 1);
  const [b] = members;
  const keys = await softwareDeviceKeys();
  const intruder = relay.addDevice(a.id, keys);
  await a.refresh();
  const inviteId = [...a.roster.invites.keys()][0];
  // The relay has no invite key, so it signs the join's invite_sig with a key of its own.
  const entry = {
    kind: "join",
    by: intruder.device,
    invite: inviteId,
    device: intruder.device,
    at: Math.floor(Date.now() / 1000),
    sign_pub: keys.signPub,
    recv_pub: keys.recvPub,
  };
  entry.invite_sig = (await signEntry(keys, entry, 0, "")).sig;
  const forged = await signEntry(keys, entry, a.roster.n + 1, a.roster.head);
  relay.room(a.id).roster.push({ ...forged, signer: intruder.device });
  // And an epoch it signs itself, wrapped for everyone and for itself.
  const recipients = { [a.device]: keys.recvPub, [b.device]: keys.recvPub, [intruder.device]: keys.recvPub };
  const n = relay.room(a.id).epochs.length + 1;
  const { epoch } = await makeEpoch({ room: a.id, n, roster: a.roster.n, creator: intruder.device, keys, recipients });
  relay.room(a.id).epochs.push(epoch);

  const sent = await a.send("still private");
  assert.equal(a.rosterError.reason, "invite_signature");
  assert.equal(a.rosterError.index, 3);
  assert.equal(a.roster.device(intruder.device), null);
  assert.equal(a.refusedEpochs.get(n), "creator");
  assert.notEqual(sent.epoch, n);
  assert.equal(Object.hasOwn(relay.room(a.id).epochs[sent.epoch - 1].wraps, intruder.device), false);
  const seen = await b.sync();
  assert.deepEqual(seen.messages.map((m) => text(m.plaintext)), ["still private"]);
  assert.equal(b.rosterError.reason, "invite_signature");
});

test("hostile: with a removed device's keys, the relay posts an epoch and a message under it; both are refused", async () => {
  const { a, members } = await roomWith(relay, 2);
  const [b, c] = members;
  await a.remove([c.device]);
  await a.send("after the removal");
  const seenBefore = await b.sync();
  assert.deepEqual(seenBefore.messages.map((m) => text(m.plaintext)), ["after the removal"]);
  const removedAt = b.roster.n;
  assert.ok(b.accepted.get(Math.max(...b.accepted.keys())).roster >= removedAt, "a member already rotated");

  // The relay holds c's keys: it signs an epoch that names the record before c's removal,
  // where c was still active, wraps it for everyone, and seals a message under it.
  const room = relay.room(a.id);
  const n = room.epochs.length + 1;
  const recipients = { [a.device]: a.keys.recvPub, [b.device]: b.keys.recvPub, [c.device]: c.keys.recvPub };
  const { epoch, key } = await makeEpoch({
    room: a.id,
    n,
    roster: removedAt - 1,
    creator: c.device,
    keys: c.keys,
    recipients,
  });
  room.epochs.push(epoch);
  const plaintext = new TextEncoder().encode("from the relay");
  const sealed = await sealMessage({ room: a.id, epoch: n, device: c.device, n: 1, key, keys: c.keys, plaintext });
  const seq = room.nextSeq++;
  room.messages.push({ seq, device: c.device, cid: "AAAAAAAAAAAAAAAAAAAAAA", ...sealed, at: Math.floor(Date.now() / 1000) });

  const seen = await b.sync();
  assert.equal(b.refusedEpochs.get(n), "roster_order");
  assert.equal(b.accepted.has(n), false);
  assert.deepEqual(seen.messages, []);
  assert.deepEqual(seen.refused.map((r) => [r.seq, r.device, r.reason]), [[seq, c.device, "epoch"]]);
  const sent = await b.send("still private");
  assert.notEqual(sent.epoch, n);
  assert.equal(Object.hasOwn(room.epochs[sent.epoch - 1].wraps, c.device), false);
});

test("hostile: a dropped roster record shows the roster as broken at that record", async () => {
  const { a } = await roomWith(relay, 1);
  relay.hostile.roster = (entries) => entries.filter((r) => r.n !== 2);
  try {
    const fresh = new Room({ baseUrl: relay.url, room: a.id, device: a.device, token: a.token, keys: a.keys });
    await fresh.refresh();
    assert.equal(fresh.rosterError.reason, "n");
    assert.equal(fresh.rosterError.index, 1);
    assert.equal(fresh.roster.n, 1);
  } finally {
    relay.hostile.roster = null;
  }
});

test("hostile: a replayed message is dropped by the counters, a forged one refused", async () => {
  const { a, members } = await roomWith(relay, 1);
  const [b] = members;
  await a.send("pay 10");
  relay.hostile.messages = (messages) => {
    const original = messages.find((m) => m.device === a.device);
    if (!original) return messages;
    const replay = { ...original, seq: 1000, cid: "AAAAAAAAAAAAAAAAAAAAAA" };
    const forged = { ...original, seq: 1001, n: 7, ct: original.ct.replace(/^./, (ch) => (ch === "A" ? "B" : "A")) };
    return [...messages, replay, forged];
  };
  try {
    const seen = await b.sync();
    assert.deepEqual(seen.messages.map((m) => text(m.plaintext)), ["pay 10"]);
    assert.deepEqual(seen.dropped, [{ seq: 1000, device: a.device, n: 1 }]);
    assert.deepEqual(seen.refused.map((r) => [r.seq, r.reason]), [[1001, "signature"]]);
  } finally {
    relay.hostile.messages = null;
  }
});

test("hostile: blobs the relay swaps fail to open", async () => {
  const { a, members } = await roomWith(relay, 1);
  const [b] = members;
  const one = await a.send("one", { file: new TextEncoder().encode("first file") });
  const two = await a.send("two", { file: new TextEncoder().encode("second file") });
  const blobs = relay.room(a.id).blobs;
  relay.hostile.blob = (_room, id, body) =>
    id === one.blob ? blobs.get(two.blob) : id === two.blob ? blobs.get(one.blob) : body;
  try {
    const { messages } = await b.sync();
    assert.equal(messages.length, 2);
    for (const message of messages) {
      await assert.rejects(b.fetchFile(message), (e) => e instanceof Refused && e.reason === "decrypt");
    }
  } finally {
    relay.hostile.blob = null;
  }
  const { messages } = await b.sync();
  assert.equal(messages.length, 0, "nothing new");
});

test("epochs: after a custodian's remove, a member makes the next epoch before it sends", async () => {
  const { a, members, custodian } = await roomWith(relay, 2);
  const [b, c] = members;
  await b.refresh();
  const before = relay.room(a.id).epochs.length;
  assert.ok(Object.hasOwn(relay.room(a.id).epochs.at(-1).wraps, c.device));

  await custodianRemove(relay, a.id, custodian, [c.device]);
  const sent = await b.send("c has left");
  const epochs = relay.room(a.id).epochs;
  assert.equal(epochs.length, before + 1);
  assert.equal(sent.epoch, before + 1);
  assert.equal(epochs.at(-1).creator, b.device);
  assert.deepEqual(new Set(Object.keys(epochs.at(-1).wraps)), new Set([a.device, b.device]));
  assert.equal(wrappedFor(a.id, c.device).includes(sent.epoch), false);
  const seen = await a.sync();
  assert.deepEqual(seen.messages.map((m) => text(m.plaintext)), ["c has left"]);
  await assert.rejects(c.sync(), (e) => e.status === 401);
});

test("epochs: two members that race after a remove get one 201 and one 409, and no third epoch", async () => {
  const { a, members, custodian } = await roomWith(relay, 2);
  const [b, c] = members;
  await a.refresh();
  await b.refresh();
  const before = relay.room(a.id).epochs.length;
  await custodianRemove(relay, a.id, custodian, [c.device]);

  const start = relay.log.length;
  relay.holdEpochs(2);
  const [fromA, fromB] = await Promise.all([a.send("from a"), b.send("from b")]);
  const posts = relay.log.slice(start).filter((line) => line === `POST /v1/rooms/${a.id}/epochs`);
  assert.equal(posts.length, 2, "both made an epoch");
  const epochs = relay.room(a.id).epochs;
  assert.equal(epochs.length, before + 1, "one 201, one 409, and the loser made no third");
  assert.equal(fromA.epoch, before + 1);
  assert.equal(fromB.epoch, before + 1);
  assert.equal(Object.hasOwn(epochs.at(-1).wraps, c.device), false);
  const atA = await a.sync();
  assert.deepEqual(atA.messages.map((m) => text(m.plaintext)).sort(), ["from a", "from b"]);
});
