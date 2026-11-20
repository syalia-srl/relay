/**
 * A custodian in Python (relay.rooms) removes a member of a room the JS client set up;
 * a remaining JS member makes the next epoch before its next send, and the removed
 * device gets no wrap (ROOMS.md 4.4).
 */

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

import { Room, softwareDeviceKeys } from "../src/rooms/index.js";
import { CREDENTIAL, inAWeek, startRoomRelay, text } from "../test-support/rooms_helpers.js";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const SCRIPT = fileURLToPath(new URL("../test-support/rooms_custodian.py", import.meta.url));
const UV = spawnSync("uv", ["--version"], { encoding: "utf8" }).status === 0;

/** Run the Python custodian; async, so the relay in this process can answer it meanwhile. */
function custodian(...args) {
  const child = spawn("uv", ["run", "--project", join(ROOT, "py"), "python", SCRIPT, ...args], { cwd: ROOT });
  let out = "";
  let errors = "";
  child.stdout.on("data", (chunk) => {
    out += chunk;
  });
  child.stderr.on("data", (chunk) => {
    errors += chunk;
  });
  return new Promise((resolve, reject) => {
    child.once("exit", (code) => (code === 0 ? resolve(JSON.parse(out)) : reject(new Error(errors))));
  });
}

let relay;
let dir;
before(async () => {
  relay = await startRoomRelay();
  dir = mkdtempSync(join(tmpdir(), "rooms-custodian-"));
});
after(async () => {
  await relay.stop();
  rmSync(dir, { recursive: true, force: true });
});

test("a Python custodian removes a member; a JS member rotates before it sends", { skip: !UV && "uv not found" }, async () => {
  const pem = join(dir, "custodian.pem");
  const custodianSignPub = await custodian("keygen", pem);
  const { room: a, created } = await Room.create({
    baseUrl: relay.url,
    credential: CREDENTIAL,
    keys: await softwareDeviceKeys(),
    custodianSignPub,
  });
  const members = [];
  for (let i = 0; i < 2; i++) {
    const { link } = await a.invite({ uses: 1, expiresAt: inAWeek() });
    members.push(await Room.join(link, await softwareDeviceKeys(), { baseUrl: relay.url }));
  }
  const [b, c] = members;
  await b.refresh();
  const before = relay.room(a.id).epochs.length;

  const readers = await custodian("remove", pem, relay.url, a.id, created.custodian.device, created.custodian.token, c.device);
  assert.deepEqual(readers, [a.device, b.device].sort());
  assert.equal(relay.room(a.id).epochs.length, before, "the custodian makes no epoch");

  const sent = await b.send("c has left");
  const newest = relay.room(a.id).epochs.at(-1);
  assert.equal(sent.epoch, before + 1);
  assert.equal(newest.creator, b.device);
  assert.equal(Object.hasOwn(newest.wraps, c.device), false);
  assert.deepEqual((await a.sync()).messages.map((m) => text(m.plaintext)), ["c has left"]);
});
