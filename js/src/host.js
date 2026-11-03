/** The host role: pairing, bound devices, channels and revocation. */

import { Condition, Mutex, Queue, TimeoutError, sleep, withTimeout } from "./async.js";
import { equalBytes, equalInConstantTime, fromHex, randomBytes, randomHex, toHex } from "./bytes.js";
import { encodeControl, parseControl } from "./control.js";
import {
  ChannelGone,
  PairingFailed,
  ProtocolViolation,
  RelayError,
  SocketClosed,
  TagFailure,
  WrongCode,
} from "./errors.js";
import {
  ABORT,
  ACCEPT,
  CONNECT,
  KIND_APPLICATION,
  KIND_CONTROL,
  MAX_TRANSPORT,
  MIN_TRANSPORT,
  PAIR,
  TRANSPORT,
  frame,
  pairingCode,
  prologue,
} from "./frames.js";
import { MemoryKey } from "./keys.js";
import { HandshakeState } from "./noise.js";
import { Payload } from "./payload.js";
import {
  Backoff,
  RelayEntry,
  Socket,
  createChannel,
  deleteChannel,
  secondsUntilUtcMidnight,
  urlAllowed,
} from "./relays.js";
import { Session } from "./session.js";
import { STATE_VERSION } from "./store.js";
import { isHex64 } from "./strictjson.js";

const PAIRING_LIFETIME = 300;
const CONFIRMATION_LIFETIME = 600_000;
const MAX_PENDING = 4;
const MAX_UNMATCHED_CODES = 3;
const SOCKET_TIMEOUT = 10_000;

class Candidate {
  constructor(guest, session, code) {
    this.guest = guest;
    this.session = session;
    this.code = code;
  }
}

class Channel {
  constructor({ id, url, hostToken, guestToken, dev, pairing }) {
    this.id = id;
    this.url = url;
    this.hostToken = hostToken;
    this.guestToken = guestToken;
    this.dev = dev;
    this.pairing = pairing;
    this.guest = null;
    this.session = null;
    this.candidate = null;
    this.socket = null;
    this.stopped = false;
    this.stop = new AbortController();
  }
}

/** A bound guest. `id` and `name` are the host's, `connected` is live. */
export class Device {
  constructor(host, id, name, guest) {
    this._host = host;
    this._id = id;
    this._name = name;
    this._guest = guest;
    this._channels = new Map();
    this._current = null;
    this._condition = new Condition();
  }

  get id() {
    return this._id;
  }

  get name() {
    return this._name;
  }

  get connected() {
    return this._current !== null && this._current.session !== null;
  }

  /**
   * Send one message, waiting until the device is connected. `{ signal }` gives
   * up waiting.
   *
   * @param {Uint8Array} message
   * @param {{ signal?: AbortSignal }} [options]
   */
  async send(message, { signal } = {}) {
    await this._host._send(this, message, signal);
  }

  async _wait(signal) {
    const wake = () => this._condition.notifyAll();
    const aborted = () => signal !== undefined && signal.aborted;
    if (signal !== undefined) signal.addEventListener("abort", wake, { once: true });
    try {
      await this._condition.waitFor(
        () =>
          this.connected ||
          this._host._closed ||
          this._host._devices.get(this._id) !== this ||
          aborted(),
      );
    } finally {
      if (signal !== undefined) signal.removeEventListener("abort", wake);
    }
    signal?.throwIfAborted();
  }
}

/** One open pairing: the payload to show, and the code a person types. */
export class Pairing {
  constructor(host, dev, name, psk, expires) {
    this._host = host;
    this._dev = dev;
    this._name = name;
    this._psk = psk;
    this._expires = expires;
    this._payload = "";
    this._channels = [];
    this._pending = new Map();
    this._unmatched = 0;
    this._confirming = false;
    this._bound = false;
    this._boundKey = null;
    this._expiryTimer = null;
    this._deadlineTimer = null;
  }

  /** The device id this pairing binds, to find it again with `host.pairing`. */
  get device() {
    return this._dev;
  }

  /** The JSON of section 4, for a QR or copied text. */
  get payload() {
    return this._payload;
  }

  /**
   * Bind the pending key whose code the person typed (PROTOCOL.md §5.5).
   *
   * @param {string} code
   * @returns {Promise<Device>}
   */
  async confirm(code) {
    return this._host._confirm(this, code);
  }
}

/** The long-lived side: one static key, many bound devices. */
export class Host {
  constructor(store, privateKey, relays) {
    this._store = store;
    this._privateKey = privateKey;
    this._static = null;
    this._relays = relays;
    this._devices = new Map();
    this._pairings = new Map();
    this._faulty = new Set();
    this._paused = new Map();
    // Messages wait here until the application iterates; a full inbox makes the
    // channel readers wait, which pushes back on the relay.
    this._inbox = new Queue(64);
    this._saveLock = new Mutex();
    this._closed = false;
  }

  /**
   * Open the host whose state the store holds, drawing its static key on the
   * first run.
   *
   * @param {{ load: () => Promise<object | null>, save: (state: object) => Promise<void> }} store
   * @param {{ relays: import("./relays.js").Relay[] }} options
   * @returns {Promise<Host>}
   */
  static async open(store, { relays }) {
    if (!Array.isArray(relays) || relays.length === 0) {
      throw new TypeError("a host needs at least one relay");
    }
    const state = await store.load();
    if (state !== null && state.v !== STATE_VERSION) {
      throw new RelayError("the state file has an unknown version");
    }
    if (state !== null && !isHex64(state.static)) {
      throw new RelayError("the state file is damaged");
    }
    const host = new Host(store, state === null ? randomBytes(32) : fromHex(state.static), relays);
    host._static = await MemoryKey.fromPrivate(host._privateKey);
    if (state !== null) host._load(state);
    else await host._save();
    for (const device of host._devices.values()) {
      for (const channel of device._channels.values()) host._start(channel);
    }
    return host;
  }

  /** The bound devices. */
  get devices() {
    return [...this._devices.values()];
  }

  /** The open pairing for `device`, so another request can confirm it. */
  pairing(device) {
    const pairing = this._pairings.get(device);
    if (pairing === undefined || pairing._bound) throw new PairingFailed("the pairing has ended");
    return pairing;
  }

  /**
   * Open one pairing on every usable relay and build its payload (§5.2).
   *
   * @param {string} name
   * @returns {Promise<Pairing>}
   */
  async pair(name) {
    const dev = randomHex(8);
    const psk = randomBytes(32);
    const pairing = new Pairing(this, dev, name, psk, Math.floor(Date.now() / 1000) + PAIRING_LIFETIME);
    pairing._channels = await this._createChannels(dev, true);
    if (pairing._channels.length === 0) throw new RelayError("no relay created a pairing channel");
    this._pairings.set(dev, pairing);
    for (const channel of pairing._channels) this._start(channel);
    pairing._payload = new Payload({
      dev,
      hostPublic: this._static.publicKey,
      psk,
      expires: pairing._expires,
      relays: pairing._channels.map(
        (channel) => new RelayEntry(channel.url, channel.id, channel.guestToken),
      ),
    }).encode();
    pairing._expiryTimer = setTimeout(() => {
      this._expire(pairing).catch(() => {});
    }, Math.max(0, pairing._expires * 1000 - Date.now()));
    return pairing;
  }

  /**
   * Send `revoked`, then delete the device's channels (PROTOCOL.md §10.5).
   *
   * @param {Device} device
   */
  async revoke(device) {
    if (this._devices.get(device.id) !== device) return;
    const channel = device._current;
    if (channel !== null && channel.session !== null && channel.socket !== null) {
      try {
        await channel.session.send(channel.socket, KIND_CONTROL, encodeControl("revoked"));
      } catch (error) {
        if (!(error instanceof SocketClosed)) throw error;
      }
    }
    await this._removeDevice(device.id);
  }

  /** Stop every socket. Bound devices and their channels stay in the store. */
  async close() {
    if (this._closed) return;
    this._closed = true;
    const ephemeral = [];
    for (const pairing of this._pairings.values()) {
        this._cancel(pairing);
      ephemeral.push(...pairing._channels);
    }
    this._pairings.clear();
    for (const channel of ephemeral) await this._stopChannel(channel);
    await this._deleteChannels(ephemeral);
    for (const device of this._devices.values()) {
      device._condition.notifyAll();
      for (const channel of device._channels.values()) await this._stopChannel(channel);
    }
    this._inbox.close();
  }

  /** Messages from every bound device, as `[device, message]` pairs. */
  [Symbol.asyncIterator]() {
    return this._inbox;
  }

  // -- pairing ----------------------------------------------------------

  async _confirm(pairing, code) {
    if (this._pairings.get(pairing._dev) !== pairing || pairing._bound) {
      throw new PairingFailed("the pairing has ended");
    }
    if (pairing._confirming) throw new PairingFailed("this pairing is already being confirmed");
    // Typed text may hold anything; only the six ASCII digits can match a code.
    const typed = typeof code === "string" ? code.trim() : "";
    const matches = [...pairing._pending.entries()]
      .filter(([, value]) => equalInConstantTime(value, typed))
      .map(([guest]) => guest);
    if (matches.length !== 1) {
      if (matches.length === 0) {
        pairing._unmatched += 1;
        if (pairing._unmatched < MAX_UNMATCHED_CODES) {
          throw new WrongCode(MAX_UNMATCHED_CODES - pairing._unmatched);
        }
      }
      await this._endPairing(pairing);
      if (matches.length > 0) throw new PairingFailed("two pending keys have that code");
      throw new PairingFailed("too many wrong codes");
    }

    const guest = fromHex(matches[0]);
    pairing._confirming = true;
    let channels;
    try {
      channels = await this._createChannels(pairing._dev, false, guest);
    } finally {
      pairing._confirming = false;
    }
    if (this._pairings.get(pairing._dev) !== pairing) {
      await this._deleteChannels(channels);
      throw new PairingFailed("the pairing has ended");
    }
    if (channels.length === 0) {
      await this._endPairing(pairing);
      throw new PairingFailed("no relay created a device channel");
    }

    const device = new Device(this, pairing._dev, pairing._name, guest);
    device._channels = new Map(channels.map((channel) => [channel.id, channel]));
    this._devices.set(pairing._dev, device);
    pairing._bound = true;
    pairing._boundKey = guest;
    pairing._pending.clear();
    pairing._psk = null;
    if (pairing._expiryTimer !== null) clearTimeout(pairing._expiryTimer);
    pairing._expiryTimer = null;

    // PROTOCOL.md §5.5: forget the other pending keys and their sessions.
    for (const channel of pairing._channels) {
      channel.candidate = null;
      if (channel.guest === null || !equalBytes(channel.guest, guest)) {
        await this._abortChannel(channel);
      }
    }
    await this._save();
    for (const channel of channels) this._start(channel);
    pairing._deadlineTimer = setTimeout(() => {
      this._deadline(pairing).catch(() => {});
    }, CONFIRMATION_LIFETIME);

    for (const channel of pairing._channels) {
      if (channel.guest !== null && equalBytes(channel.guest, guest) && channel.session !== null) {
        await this._sendRelays(pairing, channel);
        break;
      }
    }
    return device;
  }

  async _expire(pairing) {
    if (this._pairings.get(pairing._dev) === pairing && !pairing._bound) {
      await this._endPairing(pairing);
    }
  }

  async _deadline(pairing) {
    if (this._pairings.get(pairing._dev) === pairing) {
      // PROTOCOL.md §5.5: the guest never reached its device channels.
      await this._endPairing(pairing);
    }
  }

  async _endPairing(pairing) {
    if (this._pairings.get(pairing._dev) !== pairing) return;
    this._pairings.delete(pairing._dev);
    this._cancel(pairing);
    const channels = [...pairing._channels];
    if (pairing._bound) {
      const device = this._devices.get(pairing._dev);
      if (device !== undefined) {
        this._devices.delete(pairing._dev);
        device._current = null;
        device._condition.notifyAll();
        channels.push(...device._channels.values());
        await this._save();
      }
    }
    await this._stopChannels(channels);
    await this._deleteChannels(channels);
  }

  /** The guest reached a device channel: the pairing channels can go. */
  async _finishPairing(pairing) {
    if (this._pairings.get(pairing._dev) !== pairing) return;
    this._pairings.delete(pairing._dev);
    this._cancel(pairing);
    await this._stopChannels(pairing._channels);
    await this._deleteChannels(pairing._channels);
  }

  _cancel(pairing) {
    if (pairing._expiryTimer !== null) clearTimeout(pairing._expiryTimer);
    if (pairing._deadlineTimer !== null) clearTimeout(pairing._deadlineTimer);
    pairing._expiryTimer = null;
    pairing._deadlineTimer = null;
  }

  async _removeDevice(dev) {
    const device = this._devices.get(dev);
    if (device === undefined) return;
    this._devices.delete(dev);
    device._current = null;
    device._condition.notifyAll();
    const channels = [...device._channels.values()];
    const pairing = this._pairings.get(dev);
    if (pairing !== undefined) {
      this._pairings.delete(dev);
        this._cancel(pairing);
      channels.push(...pairing._channels);
    }
    await this._save();
    await this._stopChannels(channels);
    await this._deleteChannels(channels);
  }

  // -- channels ---------------------------------------------------------

  _usable() {
    const now = Date.now();
    return this._relays.filter(
      (relay) => !this._faulty.has(relay.url) && (this._paused.get(relay.url) ?? 0) <= now,
    );
  }

  async _createChannels(dev, pairing, guest = null) {
    const relays = this._usable();
    const results = await Promise.allSettled(relays.map((relay) => createChannel(relay)));
    const held = new Set(this._allChannels().map((channel) => channel.id));
    const channels = [];
    for (const [index, result] of results.entries()) {
      if (result.status === "rejected") continue;
      const credentials = result.value;
      // PROTOCOL.md §3.1: a channel id the host already holds, on any relay, is
      // a failed creation.
      if (held.has(credentials.channel)) continue;
      held.add(credentials.channel);
      const channel = new Channel({
        id: credentials.channel,
        url: relays[index].url,
        hostToken: credentials.hostToken,
        guestToken: credentials.guestToken,
        dev,
        pairing,
      });
      channel.guest = guest;
      channels.push(channel);
    }
    return channels;
  }

  _start(channel) {
    this._runChannel(channel);
  }

  _allChannels() {
    const channels = [...this._pairings.values()].flatMap((pairing) => pairing._channels);
    for (const device of this._devices.values()) channels.push(...device._channels.values());
    return channels;
  }

  async _stopChannel(channel) {
    channel.stopped = true;
    channel.stop.abort();
    const socket = channel.socket;
    channel.socket = null;
    if (socket !== null) await socket.close();
  }

  async _stopChannels(channels) {
    for (const channel of channels) await this._stopChannel(channel);
  }

  async _deleteChannels(channels) {
    await Promise.allSettled(
      channels.map((channel) => deleteChannel(channel.url, channel.id, channel.hostToken)),
    );
  }

  /** PROTOCOL.md §8.4: the relay no longer has it, so stop using it. */
  async _forgetChannel(channel) {
    channel.stopped = true;
    if (this._closed) return;
    if (channel.pairing) {
      const pairing = this._pairings.get(channel.dev);
      if (pairing !== undefined) {
        pairing._channels = pairing._channels.filter((item) => item !== channel);
      }
    } else {
      const device = this._devices.get(channel.dev);
      if (device !== undefined) {
        device._channels.delete(channel.id);
        await this._save();
      }
    }
  }

  _pause(url) {
    this._paused.set(url, Date.now() + secondsUntilUtcMidnight() * 1000);
  }

  async _fault(channel) {
    this._faulty.add(channel.url);
    for (const other of this._allChannels()) {
      if (other.url === channel.url && other !== channel) await this._stopChannel(other);
    }
  }

  // -- sockets ----------------------------------------------------------

  async _runChannel(channel) {
    const backoff = new Backoff();
    while (!channel.stopped && !this._closed) {
      if (this._faulty.has(channel.url)) return;
      const paused = (this._paused.get(channel.url) ?? 0) - Date.now();
      if (paused > 0) {
        await sleep(paused, channel.stop.signal);
        continue;
      }
      const socket = new Socket(channel.url, channel.id, channel.hostToken);
      channel.socket = socket;
      try {
        await withTimeout(socket.open(), SOCKET_TIMEOUT);
      } catch (error) {
        channel.socket = null;
        await socket.close();
        if (error instanceof ChannelGone) {
          await this._forgetChannel(channel);
          return;
        }
        if (error instanceof TimeoutError) {
          await sleep(backoff.next(), channel.stop.signal);
          continue;
        }
        if (error instanceof SocketClosed) {
          if (error.code === 4400 || error.code === 4413) {
            await this._fault(channel);
            return;
          }
          if (error.code === 4429) {
            this._pause(channel.url);
            continue;
          }
          await sleep(backoff.next(), channel.stop.signal);
          continue;
        }
        if (!(error instanceof RelayError)) throw error;
        await sleep(backoff.next(), channel.stop.signal);
        continue;
      }
      backoff.reset();
      try {
        while (!channel.stopped && !this._closed) {
          await this._handle(channel, socket, await socket.recv());
        }
      } catch (error) {
        if (error instanceof ChannelGone) {
          await this._forgetChannel(channel);
          return;
        }
        if (error instanceof SocketClosed) {
          if (error.code === 4400 || error.code === 4413) {
            await this._fault(channel);
            return;
          }
          if (error.code === 4429) this._pause(channel.url);
        } else if (!(error instanceof RelayError)) {
          throw error;
        }
      } finally {
        channel.socket = null;
        this._dropSession(channel);
        await socket.close();
      }
      if (channel.stopped || this._closed) return;
      await sleep(backoff.next(), channel.stop.signal);
    }
  }

  _dropSession(channel) {
    channel.session = null;
    channel.candidate = null;
    const device = this._devices.get(channel.dev);
    if (device !== undefined && device._current === channel) {
      device._current = null;
      device._condition.notifyAll();
    }
  }

  // -- inbound frames ---------------------------------------------------

  async _handle(channel, socket, data) {
    if (data.length === 0) {
      await this._abort(channel, socket, false);
      return;
    }
    const body = data.slice(1);
    switch (data[0]) {
      case PAIR:
        await this._onPair(channel, socket, body);
        return;
      case CONNECT:
        await this._onConnect(channel, socket, body);
        return;
      case TRANSPORT:
        await this._onTransport(channel, socket, body);
        return;
      case ABORT:
        channel.candidate = null;
        this._dropSession(channel);
        return;
      default:
        // ACCEPT, or an unknown type: the host never receives either.
        await this._abort(channel, socket, false);
    }
  }

  async _onPair(channel, socket, body) {
    const pairing = this._pairings.get(channel.dev);
    if (
      !channel.pairing ||
      pairing === undefined ||
      pairing._bound ||
      Date.now() > pairing._expires * 1000 ||
      body.length !== 96 ||
      pairing._pending.size >= MAX_PENDING
    ) {
      await this._abort(channel, socket, true);
      return;
    }
    let handshake;
    try {
      handshake = await HandshakeState.create({
        pattern: "IKpsk1",
        initiator: false,
        prologue: prologue(channel.dev, channel.id),
        staticKey: this._static,
        psk: pairing._psk,
      });
      await handshake.readMessage(body);
    } catch (error) {
      if (!(error instanceof ProtocolViolation)) throw error;
      await this._abort(channel, socket, true);
      return;
    }
    const guest = handshake.remoteStatic;
    if (pairing._pending.has(toHex(guest))) {
      await this._abort(channel, socket, true);
      return;
    }
    const answer = await handshake.writeMessage();
    channel.candidate = new Candidate(
      guest,
      await Session.responder(handshake),
      await pairingCode(handshake.handshakeHash),
    );
    await socket.sendAll([frame(ACCEPT, answer)]);
  }

  async _onConnect(channel, socket, body) {
    if (body.length !== 48) {
      await this._abort(channel, socket, true);
      return;
    }
    let keys;
    if (channel.pairing) {
      const pairing = this._pairings.get(channel.dev);
      if (pairing === undefined) {
        await this._abort(channel, socket, true);
        return;
      }
      keys = pairing._bound
        ? [pairing._boundKey]
        : [...pairing._pending.keys()].map((guest) => fromHex(guest));
    } else {
      const device = this._devices.get(channel.dev);
      keys = device === undefined ? [] : [device._guest];
    }
    for (const key of keys) {
      let handshake;
      let answer;
      try {
        handshake = await HandshakeState.create({
          pattern: "KK",
          initiator: false,
          prologue: prologue(channel.dev, channel.id),
          staticKey: this._static,
          remoteStatic: key,
        });
        await handshake.readMessage(body);
        answer = await handshake.writeMessage();
      } catch (error) {
        if (error instanceof ProtocolViolation) continue;
        throw error;
      }
      channel.candidate = new Candidate(key, await Session.responder(handshake), null);
      await socket.sendAll([frame(ACCEPT, answer)]);
      return;
    }
    await this._abort(channel, socket, true);
  }

  async _onTransport(channel, socket, body) {
    if (body.length < MIN_TRANSPORT || body.length > MAX_TRANSPORT) {
      await this._abort(channel, socket, false);
      return;
    }
    const candidate = channel.candidate;
    if (candidate !== null) {
      let decrypted;
      try {
        decrypted = await candidate.session.decrypt(body);
      } catch (error) {
        if (error instanceof TagFailure) decrypted = null;
        else if (error instanceof ProtocolViolation) {
          await this._abort(channel, socket, false);
          return;
        } else throw error;
      }
      if (decrypted !== null) {
        await this._promote(channel, socket, candidate, ...decrypted);
        return;
      }
    }
    if (channel.session === null) {
      await this._abort(channel, socket, false);
      return;
    }
    let decrypted;
    try {
      decrypted = await channel.session.decrypt(body);
    } catch (error) {
      if (!(error instanceof ProtocolViolation)) throw error;
      await this._abort(channel, socket, false);
      return;
    }
    // PROTOCOL.md §6.3: the current session decrypted it, so the candidate goes.
    channel.candidate = null;
    const [kind, message] = decrypted;
    if (message !== null) await this._process(channel, socket, channel.session, kind, message);
  }

  async _promote(channel, socket, candidate, kind, message) {
    // PROTOCOL.md §6.1: a promoted candidate's first frame is a ping.
    if (message === null || kind !== KIND_CONTROL) {
      await this._abort(channel, socket, false);
      return;
    }
    let control;
    try {
      control = parseControl(message, "host");
    } catch (error) {
      if (!(error instanceof ProtocolViolation)) throw error;
      await this._abort(channel, socket, false);
      return;
    }
    if (control === null || control.op !== "ping") {
      await this._abort(channel, socket, false);
      return;
    }

    channel.candidate = null;
    channel.session = candidate.session;
    channel.guest = candidate.guest;
    if (channel.pairing) {
      const pairing = this._pairings.get(channel.dev);
      if (pairing === undefined) {
        await this._abort(channel, socket, false);
        return;
      }
      const guest = toHex(candidate.guest);
      if (!pairing._bound) {
        if (!pairing._pending.has(guest)) {
          // PROTOCOL.md §5.3: one pairing holds at most four pending keys.
          if (pairing._pending.size >= MAX_PENDING || candidate.code === null) {
            await this._abort(channel, socket, false);
            return;
          }
          pairing._pending.set(guest, candidate.code);
        }
      } else if (pairing._boundKey !== null && equalBytes(candidate.guest, pairing._boundKey)) {
        // PROTOCOL.md §5.5: the guest may have missed the list on the socket it
        // had at confirmation, so every promotion carries it.
        await this._sendRelays(pairing, channel);
      }
    }
    await channel.session.send(socket, KIND_CONTROL, encodeControl("pong"));
    if (!channel.pairing) await this._promotedDevice(channel);
  }

  async _promotedDevice(channel) {
    const device = this._devices.get(channel.dev);
    if (device === undefined) return;
    device._current = channel;
    device._condition.notifyAll();
    const pairing = this._pairings.get(channel.dev);
    if (pairing !== undefined && pairing._bound) await this._finishPairing(pairing);
  }

  async _process(channel, socket, session, kind, message) {
    if (kind === KIND_APPLICATION) {
      if (channel.pairing) {
        await this._abort(channel, socket, false);
        return;
      }
      await this._deliver(channel.dev, message);
      return;
    }
    let control;
    try {
      control = parseControl(message, "host");
    } catch (error) {
      if (!(error instanceof ProtocolViolation)) throw error;
      await this._abort(channel, socket, false);
      return;
    }
    if (control === null) return;
    if (control.op === "ping") {
      await session.send(socket, KIND_CONTROL, encodeControl("pong"));
    } else if (control.op === "close") {
      await session.send(socket, KIND_CONTROL, encodeControl("closed"));
      if (channel.pairing) {
        const pairing = this._pairings.get(channel.dev);
        if (pairing !== undefined) await this._endPairing(pairing);
      } else {
        await this._removeDevice(channel.dev);
      }
    }
  }

  async _abort(channel, socket, keepCurrent) {
    channel.candidate = null;
    if (!keepCurrent) this._dropSession(channel);
    try {
      await socket.sendAll([frame(ABORT, new Uint8Array(0))]);
    } catch (error) {
      if (!(error instanceof SocketClosed)) throw error;
    }
  }

  async _abortChannel(channel) {
    channel.candidate = null;
    if (channel.session !== null && channel.socket !== null) {
      try {
        await channel.socket.sendAll([frame(ABORT, new Uint8Array(0))]);
      } catch (error) {
        if (!(error instanceof SocketClosed)) throw error;
      }
    }
    this._dropSession(channel);
  }

  async _sendRelays(pairing, channel) {
    const device = this._devices.get(pairing._dev);
    if (device === undefined || channel.session === null || channel.socket === null) return;
    const entries = [...device._channels.values()].map(
      (item) => new RelayEntry(item.url, item.id, item.guestToken),
    );
    try {
      await channel.session.send(channel.socket, KIND_CONTROL, encodeControl("relays", entries));
    } catch (error) {
      if (!(error instanceof SocketClosed)) throw error;
    }
  }

  async _deliver(dev, message) {
    const device = this._devices.get(dev);
    if (device === undefined) return;
    await this._inbox.push([device, message]);
  }

  async _send(device, message, signal) {
    if (!(message instanceof Uint8Array)) throw new TypeError("a message is Uint8Array");
    while (true) {
      signal?.throwIfAborted();
      if (this._closed) throw new RelayError("the host is closed");
      if (this._devices.get(device.id) !== device) throw new RelayError("the device is not bound");
      if (device._channels.size === 0) throw new RelayError("the device has no channel left");
      const channel = device._current;
      if (channel !== null && channel.session !== null && channel.socket !== null) {
        try {
          await channel.session.send(channel.socket, KIND_APPLICATION, message);
          return;
        } catch (error) {
          if (!(error instanceof SocketClosed)) throw error;
        }
      }
      await device._wait(signal);
    }
  }

  // -- state ------------------------------------------------------------

  async _save() {
    await this._saveLock.run(() =>
      this._store.save({
        v: STATE_VERSION,
        static: toHex(this._privateKey),
        devices: this.devices.map((device) => ({
          id: device.id,
          name: device.name,
          guest: toHex(device._guest),
          channels: [...device._channels.values()].map((channel) => ({
            url: channel.url,
            channel: channel.id,
            host_token: channel.hostToken,
            guest_token: channel.guestToken,
          })),
        })),
      }),
    );
  }

  _load(state) {
    if (!Array.isArray(state.devices)) {
      throw new RelayError("the state file has no device list");
    }
    try {
      for (const item of state.devices) {
        if (!isHex64(item.guest) || typeof item.id !== "string" || typeof item.name !== "string") {
          throw new RelayError("the state file is damaged");
        }
        const device = new Device(this, item.id, item.name, fromHex(item.guest));
        for (const stored of item.channels) {
          if (!urlAllowed(stored.url)) continue;
          const channel = new Channel({
            id: stored.channel,
            url: stored.url,
            hostToken: stored.host_token,
            guestToken: stored.guest_token,
            dev: device.id,
            pairing: false,
          });
          channel.guest = device._guest;
          device._channels.set(channel.id, channel);
        }
        this._devices.set(device.id, device);
      }
    } catch (error) {
      if (error instanceof RelayError) throw error;
      throw new RelayError("the state file is damaged");
    }
  }
}
