/**
 * The first part of issue #7's 3x3 matrix: a Python host with a JS guest, and a
 * JS host with a Python guest, through the same Go relay.
 */

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { Guest, Host, Relay, fileStore } from "../src/index.js";
import { GuestInbox, HostInbox, unpairAll, waitUntil } from "../test-support/inbox.js";
import { OPERATOR_KEY, startRelay } from "../test-support/relay.js";

const ROOT = fileURLToPath(new URL("../../", import.meta.url));
const SCRIPT = fileURLToPath(new URL("../test-support/python_partner.py", import.meta.url));
const UV = spawnSync("uv", ["--version"], { encoding: "utf8" }).status === 0;

/** One Python side, spoken to in JSON lines over stdin and stdout. */
function startPartner(...args) {
  const command = ["run", "--project", join(ROOT, "py"), "--group", "test", "python", SCRIPT];
  const child = spawn("uv", [...command, ...args], {
    cwd: ROOT,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const events = [];
  const waiters = [];
  let errors = "";
  createInterface({ input: child.stdout }).on("line", (line) => {
    events.push(JSON.parse(line));
    for (const wake of waiters.splice(0)) wake();
  });
  child.stderr.on("data", (chunk) => {
    errors += chunk;
  });
  const exited = new Promise((resolve) => child.once("exit", resolve));
  child.stdin.on("error", () => {});
  let stopping = null;
  return {
    send(command) {
      child.stdin.write(`${JSON.stringify(command)}\n`);
    },
    async next(name, timeout = 20_000) {
      const deadline = Date.now() + timeout;
      while (true) {
        const index = events.findIndex((event) => event.event === name);
        if (index >= 0) return events.splice(index, 1)[0];
        const failure = events.find((event) => event.event === "error");
        if (failure !== undefined) throw new Error(`${failure.message}\n${errors}`);
        if (Date.now() > deadline) throw new Error(`the Python partner never said ${name}\n${errors}`);
        await new Promise((resolve) => {
          waiters.push(resolve);
          setTimeout(resolve, 50);
        });
      }
    },
    async stop() {
      stopping ??= (async () => {
        child.stdin.write(`${JSON.stringify({ stop: true })}\n`);
        const timer = setTimeout(() => child.kill("SIGKILL"), 20_000);
        await exited;
        clearTimeout(timer);
      })();
      await stopping;
    },
  };
}

const encode = (base64) => new Uint8Array(Buffer.from(base64, "base64"));
const decode = (bytes) => Buffer.from(bytes).toString("base64");

test("a JS host with a Python guest", { skip: UV ? false : "uv is not installed" }, async () => {
  const directory = mkdtempSync(join(tmpdir(), "relay-js-cross-"));
  const relay = await startRelay(join(directory, "relay"));
  let partner;
  let host;
  try {
    host = await Host.open(fileStore(join(directory, "host")), {
      relays: [new Relay(relay.url, { key: OPERATOR_KEY })],
    });
    const pairing = await host.pair("python guest");
    partner = startPartner(
      "guest",
      "--state",
      join(directory, "python-guest"),
      "--payload",
      pairing.payload,
    );
    const { code } = await partner.next("code");
    const device = await host.pairing(pairing.device).confirm(code);
    await partner.next("bound");

    const received = new HostInbox(host);
    partner.send({ send: decode(new TextEncoder().encode("from python")) });
    await waitUntil(() => received.has(new TextEncoder().encode("from python")), 20_000);
    assert.deepEqual(received.messages[0][0], device.id);

    await device.send(new TextEncoder().encode("from javascript"));
    const answer = await partner.next("message");
    assert.equal(new TextDecoder().decode(encode(answer.data)), "from javascript");

    await partner.stop();
    await waitUntil(() => host.devices.length === 0, 20_000);
  } finally {
    if (partner !== undefined) await partner.stop().catch(() => {});
    if (host !== undefined) await host.close();
    await relay.stop();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a Python host with a JS guest", { skip: UV ? false : "uv is not installed" }, async () => {
  const directory = mkdtempSync(join(tmpdir(), "relay-js-cross-"));
  const relay = await startRelay(join(directory, "relay"));
  let partner;
  let guest;
  try {
    partner = startPartner(
      "host",
      "--state",
      join(directory, "python-host"),
      "--relay",
      relay.url,
      "--key",
      OPERATOR_KEY,
    );
    const { payload } = await partner.next("pairing");
    guest = await Guest.open(fileStore(join(directory, "guest")));
    const link = await guest.pair(payload);
    assert.match(link.code, /^\d{6}$/);
    partner.send({ code: link.code });
    const bound = await partner.next("bound");
    assert.equal(bound.name, "python");
    await link.bound();

    const replies = new GuestInbox(link);
    partner.send({ send: decode(new TextEncoder().encode("from python")) });
    await waitUntil(() => replies.has(new TextEncoder().encode("from python")), 20_000);

    await link.send(new TextEncoder().encode("from javascript"));
    const answer = await partner.next("message");
    assert.equal(new TextDecoder().decode(encode(answer.data)), "from javascript");

    await unpairAll(guest);
    await waitUntil(() => guest.hosts.length === 0);
  } finally {
    if (partner !== undefined) await partner.stop().catch(() => {});
    if (guest !== undefined) await guest.close();
    await relay.stop();
    rmSync(directory, { recursive: true, force: true });
  }
});
