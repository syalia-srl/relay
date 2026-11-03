/** A hostile relay between the library and the real relay binary. */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { equalBytes } from "../src/bytes.js";
import { Guest, Host, Relay, RelayError, fileStore } from "../src/index.js";
import { HostileProxy } from "../test-support/hostile.js";
import { GuestInbox, HostInbox, sendUntil, unpairAll, waitUntil } from "../test-support/inbox.js";
import { OPERATOR_KEY, startRelay } from "../test-support/relay.js";

const FAULTS = ["drop", "duplicate", "reorder", "delay", "relabel", "flip", "oversize"];

for (const action of FAULTS) {
  test(`hostile relay: ${action}`, async () => {
    const directory = mkdtempSync(join(tmpdir(), "relay-js-hostile-"));
    const relay = await startRelay(join(directory, "relay"));
    const proxy = new HostileProxy(relay.address, relay.url, relay.loopbackHttp);
    await proxy.start();
    let host;
    let guest;
    try {
      host = await Host.open(fileStore(join(directory, "host")), {
        relays: [new Relay(proxy.url, { key: OPERATOR_KEY })],
      });
      const pairing = await host.pair("pixel-7");
      guest = await Guest.open(fileStore(join(directory, "guest")));
      const link = await guest.pair(pairing.payload);
      const device = await pairing.confirm(link.code);
      await link.bound();

      const received = new HostInbox(host);
      const replies = new GuestInbox(link);
      const encoder = new TextEncoder();
      await link.send(encoder.encode("sync"));
      await waitUntil(() => received.has(encoder.encode("sync")));
      await device.send(encoder.encode("sync"));
      await waitUntil(() => replies.has(encoder.encode("sync")));

      if (action === "oversize") {
        // Only the host's socket gets the oversized frame: the guest sends next,
        // so the damaged down frame is the one the host reads.
        const sockets = proxy.websockets;
        proxy.arm("down", action);
        try {
          await link.send(encoder.encode("one"));
        } catch (error) {
          if (!(error instanceof RelayError)) throw error;
        }
        await waitUntil(() => proxy.websockets > sockets, 30_000);
      } else {
        proxy.arm("up", action);
        proxy.arm("down", action);
        for (const [send, message] of [
          [(value) => link.send(value), encoder.encode("one")],
          [(value) => device.send(value), encoder.encode("two")],
        ]) {
          try {
            await send(message);
          } catch (error) {
            if (!(error instanceof RelayError)) throw error;
          }
        }
      }
      await sendUntil(
        (message) => link.send(message),
        encoder.encode("after"),
        () => received.has(encoder.encode("after")),
        30_000,
      );
      await sendUntil(
        (message) => device.send(message),
        encoder.encode("after"),
        () => replies.has(encoder.encode("after")),
        30_000,
      );

      const sent = ["sync", "one", "two", "after"].map((text) => encoder.encode(text));
      const same = (message) => sent.some((candidate) => equalBytes(candidate, message));
      assert.ok(
        received.messages.every(([, message]) => same(message)),
        "a changed message reached the host",
      );
      assert.ok(
        replies.messages.every((message) => same(message)),
        "a changed message reached the guest",
      );
      assert.ok(received.has(encoder.encode("after")) && replies.has(encoder.encode("after")));
    } finally {
      if (guest !== undefined) {
        try {
          await unpairAll(guest);
        } catch {
          // A hostile relay may keep `closed` from arriving; the guest stops anyway.
        }
      }
      if (host !== undefined) await host.close();
      await proxy.stop();
      await relay.stop();
      rmSync(directory, { recursive: true, force: true });
    }
  });
}
