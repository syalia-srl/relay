/** Small helpers the end-to-end and hostile-relay tests share. */

import { equalBytes } from "../src/bytes.js";
import { RelayError } from "../src/errors.js";

/** Collects what `for await (const [device, message] of host)` yields. */
export class HostInbox {
  constructor(host) {
    this.messages = [];
    this.error = null;
    this._collect(host);
  }

  async _collect(host) {
    try {
      for await (const [device, message] of host) this.messages.push([device.id, message]);
    } catch (error) {
      this.error = error;
    }
  }

  has(message) {
    return this.messages.some(([, received]) => equalBytes(received, message));
  }
}

/** Collects what `for await (const message of link)` yields. */
export class GuestInbox {
  constructor(link) {
    this.messages = [];
    this.error = null;
    this._collect(link);
  }

  async _collect(link) {
    try {
      for await (const message of link) this.messages.push(message);
    } catch (error) {
      this.error = error;
    }
  }

  has(message) {
    return this.messages.some((received) => equalBytes(received, message));
  }
}

/** Poll until `predicate` holds, so a test reads like the Python suite's. */
export async function waitUntil(predicate, timeout = 10_000) {
  const deadline = Date.now() + timeout;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("the condition never held");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/** Retry a send while the library reconnects, until the peer has it. */
export async function sendUntil(send, message, delivered, timeout = 20_000) {
  const deadline = Date.now() + timeout;
  while (!delivered()) {
    if (Date.now() > deadline) throw new Error("the message never arrived");
    try {
      await send(message);
    } catch (error) {
      if (!(error instanceof RelayError)) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

export async function unpairAll(guest) {
  for (const link of guest.hosts) await link.unpair();
}
