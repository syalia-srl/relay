/** H1: the host may reach its relay by a URL different from the guests'. */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { Guest, Host, Relay, fileStore } from "../src/index.js";
import { HostileProxy } from "../test-support/hostile.js";
import { GuestInbox, HostInbox, unpairAll, waitUntil } from "../test-support/inbox.js";
import { OPERATOR_KEY, startRelay } from "../test-support/relay.js";

test("host URL policy follows PROTOCOL.md 2.3", () => {
  assert.throws(
    () => new Relay("wss://relay.example", { key: "key", hostUrl: "ws://relay.example" }),
    TypeError,
  );
  assert.throws(
    () => new Relay("wss://relay.example", { key: "key", hostUrl: "ws://203.0.113.7" }),
    TypeError,
  );
  assert.equal(
    new Relay("wss://relay.example", { key: "key", hostUrl: "ws://relay:8010" }).hostUrl,
    "ws://relay:8010",
  );
  assert.equal(
    new Relay("wss://relay.example", { key: "key", hostUrl: "ws://127.0.0.1:8010" }).hostUrl,
    "ws://127.0.0.1:8010",
  );
  assert.equal(new Relay("wss://relay.example", { key: "key" }).hostUrl, "wss://relay.example");
});

test("the host dials its own URL while guests receive the other one", async () => {
  const directory = mkdtempSync(join(tmpdir(), "relay-js-host-url-"));
  const relay = await startRelay(join(directory, "relay"));
  const proxy = new HostileProxy("127.0.0.1", relay.url, relay.loopbackHttp);
  await proxy.start();
  let host;
  let guest;
  try {
    host = await Host.open(fileStore(join(directory, "host")), {
      relays: [new Relay(relay.url, { key: OPERATOR_KEY, hostUrl: proxy.url })],
    });
    const pairing = await host.pair("pixel-7");
    assert.ok(proxy.httpRequests > 0, "the host did not create its channel through its host URL");
    await waitUntil(() => proxy.websockets > 0);

    const payload = JSON.parse(pairing.payload);
    assert.deepEqual(
      payload.relays.map((entry) => entry.url),
      [relay.url],
    );

    guest = await Guest.open(fileStore(join(directory, "guest")));
    const link = await guest.pair(pairing.payload);
    const device = await pairing.confirm(link.code);
    await link.bound();

    const received = new HostInbox(host);
    const replies = new GuestInbox(link);
    const encoder = new TextEncoder();
    await link.send(encoder.encode("ping"));
    await waitUntil(() => received.has(encoder.encode("ping")));
    await device.send(encoder.encode("pong"));
    await waitUntil(() => replies.has(encoder.encode("pong")));
  } finally {
    if (guest !== undefined) {
      try {
        await unpairAll(guest);
      } catch {
        // The relay may be gone first in a failed run.
      }
    }
    if (host !== undefined) await host.close();
    await proxy.stop();
    await relay.stop();
    rmSync(directory, { recursive: true, force: true });
  }
});
