/**
 * The JavaScript side of the cross-language matrix, driven over stdin and
 * stdout. One JSON object per line each way; the Go test is the other side.
 */

import { createInterface } from "node:readline";

import { Guest, Host, Relay, fileStore } from "../src/index.js";

function emit(event, fields = {}) {
  console.log(JSON.stringify({ event, ...fields }));
}

async function* commands() {
  const lines = createInterface({ input: process.stdin });
  for await (const line of lines) {
    if (line.trim() !== "") yield JSON.parse(line);
  }
}

function parseArguments(argv) {
  const arguments_ = { mode: null, state: null, relay: null, key: null, payload: null };
  for (let index = 0; index < argv.length; index++) {
    const item = argv[index];
    if (item.startsWith("--")) {
      arguments_[item.slice(2)] = argv[++index];
    } else {
      arguments_.mode = item;
    }
  }
  return arguments_;
}

async function hostMode(arguments_) {
  const host = await Host.open(fileStore(arguments_.state), {
    relays: [new Relay(arguments_.relay, { key: arguments_.key })],
  });
  const pairing = await host.pair("javascript");
  emit("pairing", { payload: pairing.payload, device: pairing.device });
  let device = null;

  const collecting = (async () => {
    try {
      for await (const [, message] of host) {
        emit("message", { data: Buffer.from(message).toString("base64") });
      }
    } catch (error) {
      emit("error", { message: String(error) });
    }
  })();
  try {
    for await (const command of commands()) {
      if ("code" in command) {
        try {
          device = await host.pairing(pairing.device).confirm(command.code);
          emit("bound", { id: device.id, name: device.name });
        } catch (error) {
          emit("error", { message: `${error.name}: ${error.message}` });
          return;
        }
      } else if ("send" in command) {
        await device.send(Buffer.from(command.send, "base64"));
        emit("sent");
      } else if (command.stop) {
        return;
      }
    }
  } finally {
    await host.close();
    await collecting;
    emit("closed");
  }
}

async function guestMode(arguments_) {
  const guest = await Guest.open(fileStore(arguments_.state));
  const link = await guest.pair(arguments_.payload);
  emit("code", { code: link.code });
  await link.bound();
  emit("bound");

  const collecting = (async () => {
    try {
      for await (const message of link) {
        emit("message", { data: Buffer.from(message).toString("base64") });
      }
    } catch (error) {
      emit("error", { message: String(error) });
    }
  })();
  try {
    for await (const command of commands()) {
      if ("send" in command) {
        await link.send(Buffer.from(command.send, "base64"));
        emit("sent");
      } else if (command.stop) {
        return;
      }
    }
  } finally {
    await link.unpair();
    await guest.close();
    await collecting;
    emit("closed");
  }
}

const arguments_ = parseArguments(process.argv.slice(2));
if (arguments_.mode === "host") {
  await hostMode(arguments_);
} else {
  await guestMode(arguments_);
}
