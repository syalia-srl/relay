/**
 * The relay side of L1: URL policy, the HTTP API, the socket and backoff
 * (PROTOCOL.md §§2.3, 2.4 and 8).
 */

import { Mutex, Queue } from "./async.js";
import { concat, utf8 } from "./bytes.js";
import { ChannelGone, ProtocolViolation, RelayError, SocketClosed } from "./errors.js";
import { isB64Url, parse } from "./strictjson.js";

const HTTP_TIMEOUT = 10_000;

/** PROTOCOL.md §8.1: the relay URLs a guest and a host may exchange. */
export function urlAllowed(url) {
  if (typeof url !== "string" || [...url].length > 2048) return false;
  let parts;
  try {
    parts = new URL(url);
  } catch {
    return false;
  }
  if (parts.username !== "" || parts.password !== "") return false;
  if (parts.search !== "" || parts.hash !== "") return false;
  if (parts.port !== "" && (Number(parts.port) < 1 || Number(parts.port) > 65535)) return false;
  if (parts.protocol === "wss:") return true;
  if (parts.protocol !== "ws:") return false;
  const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(url)[1];
  const rawHost = authority.startsWith("[")
    ? authority.slice(0, authority.indexOf("]") + 1)
    : authority.replace(/:\d*$/, "");
  // §8.1 wants a literal address. WHATWG URL would also accept legacy forms
  // such as ws://10.1, which mean the same address but are not literals.
  if (rawHost.toLowerCase() !== parts.hostname) return false;
  const host = parts.hostname;
  if (host.startsWith("[")) {
    // fc00::/7 is the only IPv6 a plain-text relay may have; a zone id or a
    // mapped IPv4 address never parses to it (PROTOCOL.md §8.1).
    const first = host.slice(1, -1).split(":")[0] || "0";
    return /^[0-9a-f]+$/.test(first) && ((Number.parseInt(first, 16) >> 8) & 0xfe) === 0xfc;
  }
  const quad = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (quad === null) return false;
  const [first, second] = quad.slice(1).map(Number);
  return first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168);
}

/** A relay the host application uses, with the project key that creates channels. */
export class Relay {
  /**
   * @param {string} url The guests' URL of the relay.
   * @param {{ key: string }} options The project key that creates channels.
   */
  constructor(url, { key }) {
    if (!urlAllowed(url)) {
      throw new TypeError(`relay URL fails the policy of PROTOCOL.md §8.1: ${url}`);
    }
    this.url = url;
    this.key = key;
  }
}

/** One relay, its channel and the guest token, as section 4 defines it. */
export class RelayEntry {
  constructor(url, channel, token) {
    this.url = url;
    this.channel = channel;
    this.token = token;
  }

  static fromJson(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
    const { url, channel, token } = value;
    if (typeof url !== "string" || !isB64Url(channel, 22) || !isB64Url(token, 43)) return null;
    return new RelayEntry(url, channel, token);
  }

  toJson() {
    return { url: this.url, channel: this.channel, token: this.token };
  }
}

/** The three strings POST /v1/channels answers with. */
export class Credentials {
  constructor(channel, hostToken, guestToken) {
    this.channel = channel;
    this.hostToken = hostToken;
    this.guestToken = guestToken;
  }
}

export function wsUrl(base, channel) {
  return `${base.replace(/\/$/, "")}/v1/ws/${channel}`;
}

function httpBase(base) {
  const parts = new URL(base);
  const scheme = parts.protocol === "wss:" ? "https" : "http";
  return `${scheme}://${parts.host}${parts.pathname.replace(/\/$/, "")}`;
}

/** POST /v1/channels with the relay's project key (PROTOCOL.md §2.3). */
export async function createChannel(relay) {
  const response = await request("POST", `${httpBase(relay.url)}/v1/channels`, relay.key);
  if (response.status !== 201) {
    throw new RelayError(`creating a channel failed with HTTP ${response.status}`);
  }
  let value;
  try {
    value = parse(await response.text());
  } catch {
    throw new RelayError("the relay answered invalid JSON");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new RelayError("the relay answered invalid JSON");
  }
  const { channel, host_token: hostToken, guest_token: guestToken } = value;
  if (!isB64Url(channel, 22) || !isB64Url(hostToken, 43) || !isB64Url(guestToken, 43)) {
    throw new RelayError("the relay answered invalid credentials");
  }
  return new Credentials(channel, hostToken, guestToken);
}

/** Delete a channel. False means the relay no longer had it. */
export async function deleteChannel(url, channel, hostToken) {
  const response = await request("DELETE", `${httpBase(url)}/v1/channels/${channel}`, hostToken);
  if (response.status === 204) return true;
  if (response.status === 404) return false;
  throw new RelayError(`deleting a channel failed with HTTP ${response.status}`);
}

async function request(method, url, bearer) {
  try {
    return await fetch(url, {
      method,
      headers: { Authorization: `Bearer ${bearer}` },
      signal: AbortSignal.timeout(HTTP_TIMEOUT),
    });
  } catch (error) {
    throw new RelayError(`the relay answered nothing: ${error.message}`);
  }
}

/** One authenticated L0 socket, carrying L1 frames. */
export class Socket {
  #url;
  #token;
  #websocket = null;
  #closed = null;
  #messages = new Queue();
  #sendLock = new Mutex();
  #opened = Promise.withResolvers();

  constructor(base, channel, token) {
    this.#url = wsUrl(base, channel);
    this.#token = token;
  }

  /** Connect, send `auth` and wait for `ready`. */
  async open() {
    let websocket;
    try {
      websocket = new WebSocket(this.#url);
    } catch (error) {
      throw new RelayError(`cannot use the relay: ${error.message}`);
    }
    websocket.binaryType = "arraybuffer";
    this.#websocket = websocket;
    websocket.addEventListener("open", () => this.#opened.resolve(), { once: true });
    websocket.addEventListener("message", (event) => this.#receive(event.data));
    websocket.addEventListener("close", (event) => this.#shut(event.code || 1006));
    // The error event carries no details; the close that follows does.
    websocket.addEventListener("error", () => {});
    try {
      await this.#opened.promise;
    } catch (error) {
      await this.close();
      throw error;
    }
    await this.#sendText(JSON.stringify({ auth: this.#token }));
    while (true) {
      const raw = await this.#next();
      if (raw[0] !== 0x00) throw new ProtocolViolation("the relay sent a frame before ready");
      if (systemEvent(raw) === "ready") return;
    }
  }

  /** The next L1 frame; presence events are skipped. `undefined` on timeout. */
  async recv(timeout = Infinity) {
    const deadline = timeout === Infinity ? Infinity : Date.now() + timeout;
    while (true) {
      const raw = await this.#next(deadline === Infinity ? Infinity : Math.max(0, deadline - Date.now()));
      if (raw === undefined) return undefined;
      if (raw[0] === 0x00) continue;
      if (raw[0] === 0x01) return raw.slice(1);
      throw new ProtocolViolation("the relay sent an unknown frame");
    }
  }

  async sendAll(frames) {
    await this.#sendLock.run(async () => {
      for (const item of frames) await this.#sendBinary(concat(Uint8Array.of(0x01), item));
    });
  }

  async close() {
    const websocket = this.#websocket;
    this.#shut(1006);
    if (websocket === null) return;
    try {
      websocket.close();
    } catch {
      // Closing a socket the relay already dropped is not a failure.
    }
  }

  async #next(timeout = Infinity) {
    const item = await this.#messages.next(timeout);
    if (item === undefined) return undefined;
    if (item.done) throw new SocketClosed(this.#closed ?? 1006);
    if (item.value.closed !== undefined) throw new SocketClosed(item.value.closed);
    if (item.value.text !== undefined) throw new ProtocolViolation("the relay sent a text frame");
    return item.value.binary;
  }

  async #sendBinary(bytes) {
    if (this.#closed !== null) throw new SocketClosed(1006);
    try {
      this.#websocket.send(bytes);
    } catch {
      throw new SocketClosed(1006);
    }
  }

  async #sendText(text) {
    if (this.#closed !== null) throw new SocketClosed(1006);
    try {
      this.#websocket.send(text);
    } catch {
      throw new SocketClosed(1006);
    }
  }

  #receive(data) {
    if (typeof data === "string") {
      this.#messages.tryPush({ text: data });
      return;
    }
    // binaryType is "arraybuffer", so this is an ArrayBuffer.
    this.#messages.tryPush({ binary: new Uint8Array(data) });
  }

  #shut(code) {
    if (this.#closed !== null) return;
    this.#closed = code;
    // A socket closed while it is still opening must fail the open, not leave
    // the caller waiting for an event the browser will not send.
    this.#opened.reject(new SocketClosed(code));
    this.#messages.tryPush({ closed: code });
  }
}

function systemEvent(frame) {
  try {
    const value = JSON.parse(new TextDecoder().decode(frame.slice(1)));
    return typeof value?.event === "string" ? value.event : null;
  } catch {
    return null;
  }
}

/** Section 8.2: 1 second, doubling, at most 60, back to 1 after a success. */
export class Backoff {
  #delay = 1000;

  next() {
    const delay = this.#delay;
    this.#delay = Math.min(2 * this.#delay, 60_000);
    return delay;
  }

  reset() {
    this.#delay = 1000;
  }
}

/** How long a relay over its daily byte quota stays unusable. */
export function secondsUntilUtcMidnight(now = new Date()) {
  const tomorrow = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return (tomorrow - now.getTime()) / 1000;
}
