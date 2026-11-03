/** A host and a guest through the real relay binary. */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { Guest, Host, PairingFailed, Relay, Revoked, WrongCode, fileStore } from "../src/index.js";
import { GuestInbox, HostInbox, sendUntil, unpairAll, waitUntil } from "../test-support/inbox.js";
import { OPERATOR_KEY, startRelay } from "../test-support/relay.js";

function workspace() {
  return mkdtempSync(join(tmpdir(), "relay-js-"));
}

async function pair(relay, directory) {
  const host = await Host.open(fileStore(join(directory, "host")), {
    relays: [new Relay(relay.url, { key: OPERATOR_KEY })],
  });
  const pairing = await host.pair("pixel-7");
  const guest = await Guest.open(fileStore(join(directory, "guest")));
  const link = await guest.pair(pairing.payload);
  assert.match(link.code, /^\d{6}$/);
  // A web application confirms in a later request, finding the pairing by id.
  const device = await host.pairing(pairing.device).confirm(link.code);
  await link.bound();
  return { host, guest, device, link };
}

test("pair and send both ways", async () => {
  const directory = workspace();
  const relay = await startRelay(join(directory, "relay"));
  try {
    const { host, guest, device, link } = await pair(relay, directory);
    const encoder = new TextEncoder();
    // The host's inbox exists from open, so a message that arrives before the
    // application iterates is not lost.
    await link.send(encoder.encode("early"));
    await new Promise((resolve) => setTimeout(resolve, 200));
    const received = new HostInbox(host);
    const replies = new GuestInbox(link);
    try {
      await waitUntil(() => device.connected);
      await waitUntil(() => received.has(encoder.encode("early")));
      await link.send(encoder.encode("ping"));
      await waitUntil(() => received.has(encoder.encode("ping")));
      await device.send(encoder.encode("pong"));
      await waitUntil(() => replies.has(encoder.encode("pong")));

      const big = Uint8Array.from({ length: 200_000 }, (_, index) => index % 251);
      await link.send(big);
      await waitUntil(() => received.has(big), 20_000);
      await device.send(big);
      await waitUntil(() => replies.has(big), 20_000);

      assert.equal(statSync(join(directory, "host")).mode & 0o777, 0o600);
      assert.equal(statSync(join(directory, "guest")).mode & 0o777, 0o600);
    } finally {
      await unpairAll(guest);
      await host.close();
    }
  } finally {
    await relay.stop();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("restart both sides from their stores", async () => {
  const directory = workspace();
  const relay = await startRelay(join(directory, "relay"));
  try {
    let { host, guest, link } = await pair(relay, directory);
    let received = new HostInbox(host);
    await link.send(new TextEncoder().encode("before"));
    await waitUntil(() => received.has(new TextEncoder().encode("before")));
    await host.close();
    await guest.close();

    host = await Host.open(fileStore(join(directory, "host")), {
      relays: [new Relay(relay.url, { key: OPERATOR_KEY })],
    });
    guest = await Guest.open(fileStore(join(directory, "guest")));
    try {
      assert.deepEqual(
        host.devices.map((device) => device.name),
        ["pixel-7"],
      );
      assert.equal(guest.hosts.length, 1);
      link = guest.hosts[0];
      await link.bound();

      received = new HostInbox(host);
      const replies = new GuestInbox(link);
      await link.send(new TextEncoder().encode("after"));
      await waitUntil(() => received.has(new TextEncoder().encode("after")), 20_000);
      await host.devices[0].send(new TextEncoder().encode("back"));
      await waitUntil(() => replies.has(new TextEncoder().encode("back")), 20_000);
    } finally {
      await unpairAll(guest);
      await host.close();
    }
  } finally {
    await relay.stop();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("revoke", async () => {
  const directory = workspace();
  const relay = await startRelay(join(directory, "relay"));
  try {
    const { host, guest, device, link } = await pair(relay, directory);
    try {
      const messages = link[Symbol.asyncIterator]();
      await host.revoke(device);
      await assert.rejects(messages.next(), Revoked);
      assert.deepEqual(host.devices, []);
      assert.deepEqual(guest.hosts, []);
    } finally {
      await host.close();
    }
  } finally {
    await relay.stop();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("unpair forgets both sides", async () => {
  const directory = workspace();
  const relay = await startRelay(join(directory, "relay"));
  try {
    let { host, guest } = await pair(relay, directory);
    await unpairAll(guest);
    await waitUntil(() => host.devices.length === 0);
    await host.close();

    host = await Host.open(fileStore(join(directory, "host")), {
      relays: [new Relay(relay.url, { key: OPERATOR_KEY })],
    });
    guest = await Guest.open(fileStore(join(directory, "guest")));
    try {
      assert.deepEqual(host.devices, []);
      assert.deepEqual(guest.hosts, []);
    } finally {
      await host.close();
    }
  } finally {
    await relay.stop();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("wrong codes", async () => {
  const directory = workspace();
  const relay = await startRelay(join(directory, "relay"));
  try {
    const host = await Host.open(fileStore(join(directory, "host")), {
      relays: [new Relay(relay.url, { key: OPERATOR_KEY })],
    });
    const pairing = await host.pair("pixel-7");
    const guest = await Guest.open(fileStore(join(directory, "guest")));
    try {
      const link = await guest.pair(pairing.payload);
      const wrong = link.code === "000000" ? "111111" : "000000";
      await assert.rejects(pairing.confirm("١٢٣٤٥٦"), (error) => {
        assert.ok(error instanceof WrongCode);
        assert.equal(error.triesLeft, 2);
        return true;
      });
      await assert.rejects(pairing.confirm(wrong), WrongCode);
      await assert.rejects(pairing.confirm(wrong), PairingFailed);
      assert.throws(() => host.pairing(pairing.device), PairingFailed);
    } finally {
      await guest.close();
      await host.close();
    }
  } finally {
    await relay.stop();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("a second concurrent confirm is refused", async () => {
  const directory = workspace();
  const relay = await startRelay(join(directory, "relay"));
  try {
    const host = await Host.open(fileStore(join(directory, "host")), {
      relays: [new Relay(relay.url, { key: OPERATOR_KEY })],
    });
    const pairing = await host.pair("pixel-7");
    const guest = await Guest.open(fileStore(join(directory, "guest")));
    try {
      const link = await guest.pair(pairing.payload);
      const first = pairing.confirm(link.code);
      await assert.rejects(pairing.confirm(link.code), PairingFailed);
      const device = await first;
      await link.bound();
      assert.equal(device.connected, true);
    } finally {
      await unpairAll(guest);
      await guest.close();
      await host.close();
    }
  } finally {
    await relay.stop();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("device.send gives up when its signal aborts", async () => {
  const directory = workspace();
  const relay = await startRelay(join(directory, "relay"));
  try {
    const { host, guest, device } = await pair(relay, directory);
    try {
      await relay.stop();
      await waitUntil(() => !device.connected, 20_000);
      await assert.rejects(
        device.send(new TextEncoder().encode("nobody there"), { signal: AbortSignal.timeout(100) }),
        (error) => error.name === "TimeoutError",
      );
    } finally {
      await guest.close();
      await host.close();
    }
  } finally {
    await relay.stop();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("moves to the second relay", async () => {
  const directory = workspace();
  const first = await startRelay(join(directory, "first"));
  const second = await startRelay(join(directory, "second"));
  try {
    const host = await Host.open(fileStore(join(directory, "host")), {
      relays: [
        new Relay(first.url, { key: OPERATOR_KEY }),
        new Relay(second.url, { key: OPERATOR_KEY }),
      ],
    });
    const pairing = await host.pair("pixel-7");
    const guest = await Guest.open(fileStore(join(directory, "guest")));
    const link = await guest.pair(pairing.payload);
    const device = await pairing.confirm(link.code);
    await link.bound();
    const received = new HostInbox(host);
    const replies = new GuestInbox(link);
    try {
      await link.send(new TextEncoder().encode("on the first"));
      await waitUntil(() => received.has(new TextEncoder().encode("on the first")));

      await first.stop();
      await sendUntil(
        (message) => link.send(message),
        new TextEncoder().encode("on the second"),
        () => received.has(new TextEncoder().encode("on the second")),
        30_000,
      );
      await device.send(new TextEncoder().encode("back again"));
      await waitUntil(() => replies.has(new TextEncoder().encode("back again")), 20_000);
    } finally {
      await unpairAll(guest);
      await host.close();
    }
  } finally {
    await first.stop();
    await second.stop();
    rmSync(directory, { recursive: true, force: true });
  }
});
