/** A real Go relay, started the way the conformance suite starts it. */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync, writeFileSync } from "node:fs";
import net from "node:net";
import { networkInterfaces } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { urlAllowed } from "../../src/relays.js";

export const OPERATOR_KEY = "operator-key-0123456789";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));

function keysFile() {
  return {
    relay_id: "relay.test",
    issuers: {},
    keys: [
      {
        id: "operator",
        sha256: createHash("sha256").update(OPERATOR_KEY).digest("hex"),
        channels: 1000,
        creates_per_minute: 1000,
        bytes_per_day: 100_000_000,
      },
    ],
  };
}

/** A private address this machine owns, which the URL policy of §8.1 accepts. */
export function privateAddress() {
  const configured = process.env.RELAY_TEST_ADDR;
  if (configured !== undefined) return configured;
  for (const addresses of Object.values(networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (address.family === "IPv4" && urlAllowed(`ws://${address.address}`)) return address.address;
    }
  }
  throw new Error("no private IPv4 address to serve the relay on; set RELAY_TEST_ADDR");
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, "0.0.0.0", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function listening(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host: "127.0.0.1" });
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => resolve(false));
  });
}

export function relayBinary() {
  return process.env.RELAY_BIN ?? join(ROOT, "server", "relay");
}

/** One relay process with its own port, state file and keys file. */
export async function startRelay(root) {
  mkdirSync(root, { recursive: true });
  const address = privateAddress();
  const port = await freePort();
  const statePath = join(root, "channels.json");
  const keysPath = join(root, "keys.json");
  const logPath = join(root, "relay.log");
  writeFileSync(keysPath, JSON.stringify(keysFile()));
  const log = openSync(logPath, "a");
  const process_ = spawn(relayBinary(), [], {
    env: {
      ...process.env,
      RELAY_ADDR: `0.0.0.0:${port}`,
      RELAY_STATE_PATH: statePath,
      RELAY_KEYS_PATH: keysPath,
      RELAY_V0: "off",
    },
    stdio: ["ignore", log, log],
  });
  closeSync(log);
  const relay = {
    address,
    port,
    url: `ws://${address}:${port}`,
    loopbackHttp: `http://127.0.0.1:${port}`,
    logs: () => {
      try {
        return readFileSync(logPath, "utf8");
      } catch {
        return "";
      }
    },
    stop: async () => {
      if (process_.exitCode !== null) return;
      const exited = new Promise((resolve) => process_.once("exit", resolve));
      process_.kill("SIGTERM");
      const timer = setTimeout(() => process_.kill("SIGKILL"), 10_000);
      await exited;
      clearTimeout(timer);
    },
  };
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (process_.exitCode !== null) {
      throw new Error(`the relay exited at once:\n${relay.logs()}`);
    }
    if (await listening(port)) return relay;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  await relay.stop();
  throw new Error(`the relay never listened:\n${relay.logs()}`);
}
