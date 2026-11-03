/** The guest role: first contact, relay choice and device connections. */

import { Condition, Mutex, Queue, TimeoutError, sleep, withTimeout } from "./async.js";
import { fromHex, randomBytes, toHex } from "./bytes.js";
import { encodeControl, parseControl } from "./control.js";
import {
  ChannelGone,
  PairingFailed,
  ProtocolViolation,
  RelayError,
  Revoked,
  SocketClosed,
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
import { parsePayload } from "./payload.js";
import {
  Backoff,
  RelayEntry,
  Socket,
  secondsUntilUtcMidnight,
  urlAllowed,
} from "./relays.js";
import { Session } from "./session.js";
import { STATE_VERSION } from "./store.js";
import { isHex64 } from "./strictjson.js";

const CONNECT_TIMEOUT = 1500;
const UPGRADE_INTERVAL = 60_000;
const GONE_ROUNDS = 3;
const UNPAIR_TIMEOUT = 10_000;

/** This session is over; go back to step 1 of PROTOCOL.md §8.2. */
class Reconnect extends Error {}

/** The link reached a final state. */
class Done extends Error {}

/** A host this guest paired with. Its iterator throws `Revoked` when revoked. */
export class PairedHost {
  constructor(guest, dev, hostPublic, relays, staticKey, privateKey, expires) {
    this._guest = guest;
    this._dev = dev;
    this._hostPublic = hostPublic;
    this._relays = relays;
    this._static = staticKey;
    this._privateKey = privateKey;
    this._expires = expires;
    this._psk = null;
    this._state = expires === null ? "bound" : "pairing";
    this._error = null;
    this._code = "";
    this._pendingCode = null;
    this._ready = false;
    this._session = null;
    this._socket = null;
    this._connecting = null;
    this._unpairing = false;
    this._stopped = false;
    this._paused = new Map();
    this._inbox = new Queue(64);
    this._condition = new Condition();
    this._expiryTimer = null;
    this._stopSignal = new AbortController();
  }

  /** The six digits the person types into the host, once the host has the key. */
  get code() {
    return this._code;
  }

  /** Return once the device channels carry a session. */
  async bound() {
    await this._condition.waitFor(
      () => (this._ready && this._state === "bound") || this._terminal(),
    );
    this._raiseTerminal();
    if (this._state === "closed") throw new RelayError("the host no longer has this guest");
  }

  /**
   * Send one message to the host, waiting until the device channels carry a
   * session.
   *
   * @param {Uint8Array} message
   */
  async send(message) {
    if (!(message instanceof Uint8Array)) throw new TypeError("a message is Uint8Array");
    while (true) {
      await this._condition.waitFor(
        () => (this._ready && this._state === "bound") || this._terminal(),
      );
      this._raiseTerminal();
      if (this._state === "closed") throw new RelayError("the host no longer has this guest");
      const session = this._session;
      const socket = this._socket;
      if (session === null || socket === null) continue;
      try {
        await session.send(socket, KIND_APPLICATION, message);
        return;
      } catch (error) {
        if (!(error instanceof SocketClosed)) throw error;
        this._ready = false;
      }
    }
  }

  /** Send `close` and wait for `closed`, then forget this host. */
  async unpair() {
    await this._unpair();
  }

  /** Messages from the host; throws `Revoked` when the host revoked this guest. */
  async *[Symbol.asyncIterator]() {
    while (true) {
      if (this._terminal() && this._inbox.size === 0) {
        this._raiseTerminal();
        return;
      }
      const item = await this._inbox.next();
      if (item.done) {
        this._raiseTerminal();
        return;
      }
      yield item.value;
    }
  }

  _terminal() {
    return this._state === "closed" || this._state === "revoked" || this._state === "failed";
  }

  _raiseTerminal() {
    if (this._state === "revoked") throw new Revoked("the host revoked this guest");
    if (this._error !== null) throw this._error;
  }

  async _notify() {
    if (this._terminal()) this._inbox.close();
    this._condition.notifyAll();
  }

  _wake() {
    if (this._terminal()) this._inbox.close();
  }

  _start() {
    this._run();
    if (this._expires !== null) {
      this._expiryTimer = setTimeout(
        () => {
          this._expire().catch(() => {});
        },
        Math.max(0, this._expires * 1000 - Date.now() + 60_000),
      );
    }
  }

  _cancelDeadline() {
    if (this._expiryTimer !== null) clearTimeout(this._expiryTimer);
    this._expiryTimer = null;
  }

  // -- the relay loop ---------------------------------------------------

  async _run() {
    const backoff = new Backoff();
    let goneRounds = 0;
    while (!this._terminal() && !this._stopped) {
      let established = false;
      let allGone = true;
      for (let position = 0; position < this._relays.length; position++) {
        if (this._terminal() || this._stopped) return;
        const entry = this._relays[position];
        if ((this._paused.get(entry.url) ?? 0) > Date.now()) {
          allGone = false;
          continue;
        }
        let socket;
        let session;
        try {
          [socket, session] = await this._connect(entry);
        } catch (error) {
          if (error instanceof ChannelGone) continue;
          if (error instanceof SocketClosed) {
            if (error.code === 4429) {
              this._paused.set(entry.url, Date.now() + secondsUntilUtcMidnight() * 1000);
            }
            allGone = false;
            continue;
          }
          // Any other failure, a bug included, costs this attempt only.
          allGone = false;
          continue;
        }
        established = true;
        backoff.reset();
        try {
          await this._serve(socket, session, position);
        } catch (error) {
          // Reconnect, a closed socket or any other failure: back to step 1 of §8.2.
          if (error instanceof Done) return;
        } finally {
          this._ready = false;
          this._pendingCode = null;
          this._session = null;
          this._socket = null;
          await socket.close();
        }
        break;
      }
      if (this._terminal() || this._stopped) return;
      if (established) {
        goneRounds = 0;
        continue;
      }
      if (allGone && this._relays.length > 0) {
        goneRounds += 1;
        if (goneRounds >= GONE_ROUNDS) {
          await this._gone();
          return;
        }
      } else {
        goneRounds = 0;
      }
      await sleep(backoff.next(), this._stopSignal.signal);
    }
  }

  /** Open one socket and get to `accept` within 1.5 s (PROTOCOL.md §8.2). */
  async _connect(entry) {
    const socket = new Socket(entry.url, entry.channel, entry.token);
    this._connecting = socket;
    try {
      const handshake = await withTimeout(this._handshake(socket, entry), CONNECT_TIMEOUT);
      if (this._state === "pairing") {
        this._pendingCode = await pairingCode(handshake.handshakeHash);
      }
      const session = await Session.initiator(handshake);
      // PROTOCOL.md §6.1: the guest's first transport frame is a ping.
      await session.send(socket, KIND_CONTROL, encodeControl("ping"));
      return [socket, session];
    } catch (error) {
      await socket.close();
      throw error;
    } finally {
      if (this._connecting === socket) this._connecting = null;
    }
  }

  async _handshake(socket, entry) {
    await socket.open();
    const connecting = this._state === "pending" || this._state === "bound";
    const handshake = await HandshakeState.create({
      pattern: connecting ? "KK" : "IKpsk1",
      initiator: true,
      prologue: prologue(this._dev, entry.channel),
      staticKey: this._static,
      remoteStatic: this._hostPublic,
      psk: connecting ? null : this._psk,
    });
    const message = await handshake.writeMessage();
    await socket.sendAll([frame(connecting ? CONNECT : PAIR, message)]);
    const answer = await socket.recv();
    if (answer.length !== 49 || answer[0] !== ACCEPT) {
      throw new ProtocolViolation("expected an accept frame");
    }
    await handshake.readMessage(answer.slice(1));
    return handshake;
  }

  async _serve(socket, session, position) {
    let currentSocket = socket;
    let currentSession = session;
    let currentPosition = position;
    this._socket = currentSocket;
    this._session = currentSession;
    let deadline = Date.now() + UPGRADE_INTERVAL;
    while (!this._terminal() && !this._stopped) {
      let incoming;
      if (currentPosition > 0) {
        incoming = await currentSocket.recv(Math.max(100, deadline - Date.now()));
        if (incoming === undefined) {
          deadline = Date.now() + UPGRADE_INTERVAL;
          const moved = await this._earlier(currentPosition);
          if (moved === null) continue;
          const [newSocket, newSession, newPosition] = moved;
          this._ready = false;
          const previous = currentSocket;
          currentSocket = newSocket;
          currentSession = newSession;
          currentPosition = newPosition;
          this._socket = currentSocket;
          this._session = currentSession;
          await previous.close();
          continue;
        }
      } else {
        incoming = await currentSocket.recv();
      }
      await this._receive(currentSocket, currentSession, incoming);
    }
  }

  /** PROTOCOL.md §8.2 step 2: move up when an earlier relay gets to `accept`. */
  async _earlier(position) {
    for (let earlier = 0; earlier < position; earlier++) {
      const entry = this._relays[earlier];
      if ((this._paused.get(entry.url) ?? 0) > Date.now()) continue;
      try {
        const [socket, session] = await this._connect(entry);
        return [socket, session, earlier];
      } catch (error) {
        if (
          error instanceof SocketClosed ||
          error instanceof RelayError ||
          error instanceof TimeoutError
        ) {
          continue;
        }
        throw error;
      }
    }
    return null;
  }

  async _receive(socket, session, incoming) {
    if (incoming.length === 0) throw new Reconnect();
    const body = incoming.slice(1);
    if (incoming[0] === ABORT && incoming.length === 1) throw new Reconnect();
    if (incoming[0] !== TRANSPORT) {
      await this._abort(socket);
      throw new Reconnect();
    }
    if (body.length < MIN_TRANSPORT || body.length > MAX_TRANSPORT) {
      await this._abort(socket);
      throw new Reconnect();
    }
    let decrypted;
    try {
      decrypted = await session.decrypt(body);
    } catch (error) {
      if (!(error instanceof ProtocolViolation)) throw error;
      await this._abort(socket);
      throw new Reconnect();
    }
    const [kind, message] = decrypted;
    if (message !== null) await this._process(socket, session, kind, message);
  }

  async _process(socket, session, kind, message) {
    if (kind === KIND_APPLICATION) {
      // PROTOCOL.md §5.4: a pending guest has no access of any kind.
      if (this._state !== "bound") {
        await this._abort(socket);
        throw new Reconnect();
      }
      await this._inbox.push(message);
      return;
    }
    let control;
    try {
      control = parseControl(message, "guest");
    } catch (error) {
      if (!(error instanceof ProtocolViolation)) throw error;
      await this._abort(socket);
      throw new Reconnect();
    }
    if (control === null) return;
    switch (control.op) {
      case "ping":
        await session.send(socket, KIND_CONTROL, encodeControl("pong"));
        return;
      case "pong":
        await this._onPong(socket, session);
        return;
      case "relays":
        this._relays = [...control.relays];
        this._state = "bound";
        this._psk = null;
        this._ready = false;
        await this._guest._persist(this);
        await this._notify();
        // PROTOCOL.md §8.3: replace the list and start over at step 1.
        throw new Reconnect();
      case "closed":
        this._state = "closed";
        await this._guest._forget(this);
        await this._notify();
        throw new Done();
      case "revoked":
        this._state = "revoked";
        await this._guest._forget(this);
        await this._notify();
        throw new Done();
    }
  }

  async _onPong(socket, session) {
    this._ready = true;
    if (this._state === "pairing") {
      // The host sends `pong` only after promoting the key (PROTOCOL.md §5.3).
      this._code = this._pendingCode ?? "";
      this._pendingCode = null;
      this._state = "pending";
      this._cancelDeadline();
    }
    if (this._unpairing) await session.send(socket, KIND_CONTROL, encodeControl("close"));
    await this._notify();
  }

  async _expire() {
    if (!this._terminal()) await this._fail(new PairingFailed("the pairing payload expired"));
  }

  async _gone() {
    // PROTOCOL.md §8.4: every relay lost the channel, three rounds in a row.
    if (this._state === "bound") {
      this._state = "revoked";
      await this._guest._forget(this);
    } else {
      await this._fail(new PairingFailed("every relay lost the channel"));
      return;
    }
    await this._notify();
  }

  async _fail(error) {
    if (this._terminal()) return;
    this._error = error;
    this._state = "failed";
    await this._guest._forget(this);
    await this._stop();
    await this._notify();
  }

  async _unpair() {
    if (this._state === "pairing") {
      // No key is pending at the host yet, so there is nothing to close.
      this._state = "closed";
      this._wake();
      this._cancelDeadline();
      await this._stop();
      await this._guest._forget(this);
      return;
    }
    this._unpairing = !this._terminal();
    const session = this._session;
    const socket = this._socket;
    const paired = this._state === "pending" || this._state === "bound";
    if (this._terminal()) {
      this._cancelDeadline();
      await this._guest._forget(this);
      return;
    }
    if (paired && session !== null && socket !== null && this._ready) {
      try {
        await session.send(socket, KIND_CONTROL, encodeControl("close"));
      } catch (error) {
        if (!(error instanceof SocketClosed)) throw error;
      }
    }
    try {
      await withTimeout(
        this._condition.waitFor(
          () => this._state === "closed" || this._state === "revoked" || this._state === "failed",
        ),
        UNPAIR_TIMEOUT,
      );
    } catch (error) {
      if (!(error instanceof TimeoutError)) throw error;
      // PROTOCOL.md §9.1 keeps the key until `closed`; a guest whose host is
      // unreachable still has to be able to unpair, so it forgets locally.
      this._state = "closed";
      this._wake();
      await this._stop();
    }
    this._cancelDeadline();
    await this._guest._forget(this);
  }

  async _abort(socket) {
    try {
      await socket.sendAll([frame(ABORT, new Uint8Array(0))]);
    } catch (error) {
      if (!(error instanceof SocketClosed)) throw error;
    }
  }

  async _stop() {
    this._stopped = true;
    this._stopSignal.abort();
    this._cancelDeadline();
    const sockets = [this._socket, this._connecting];
    this._socket = null;
    this._connecting = null;
    for (const socket of sockets) if (socket !== null) await socket.close();
  }
}

/** The side that pairs with a host, then carries messages to it. */
export class Guest {
  constructor(store, key) {
    this._store = store;
    this._key = key;
    this._hosts = new Map();
    this._saveLock = new Mutex();
  }

  /**
   * Open the guest whose state the store holds. `key` is any object with
   * `publicKey` and `dh()`, to keep the private half outside the page.
   *
   * @param {{ load: () => Promise<object | null>, save: (state: object) => Promise<void> }} store
   * @param {{ key?: {
   *   publicKey: Uint8Array,
   *   dh: (peerPublic: Uint8Array) => Promise<Uint8Array>,
   * } | null }} [options]
   * @returns {Promise<Guest>}
   */
  static async open(store, { key = null } = {}) {
    const guest = new Guest(store, key);
    const state = await store.load();
    if (state === null) return guest;
    if (state.v !== STATE_VERSION) throw new RelayError("the state file has an unknown version");
    if (!Array.isArray(state.hosts)) throw new RelayError("the state file has no host list");
    try {
      for (const item of state.hosts) {
        if (!isHex64(item.host) || typeof item.dev !== "string") {
          throw new RelayError("the state file is damaged");
        }
        const relays = item.relays.map((stored) => {
          const entry = RelayEntry.fromJson(stored);
          if (entry === null || !urlAllowed(entry.url)) {
            throw new RelayError("the state file has a bad relay entry");
          }
          return entry;
        });
        const privateHex = item.static ?? null;
        let staticKey;
        if (key !== null) {
          if (privateHex !== null) throw new RelayError("this state already holds a guest key");
          staticKey = key;
        } else {
          if (privateHex === null) {
            throw new RelayError("this state was paired with a native key; pass it to open");
          }
          if (!isHex64(privateHex)) throw new RelayError("the state file is damaged");
          staticKey = await MemoryKey.fromPrivate(fromHex(privateHex));
        }
        const link = new PairedHost(
          guest,
          item.dev,
          fromHex(item.host),
          relays,
          staticKey,
          privateHex === null ? null : fromHex(privateHex),
          null,
        );
        guest._hosts.set(link._dev, link);
      }
    } catch (error) {
      if (error instanceof RelayError) throw error;
      throw new RelayError("the state file is damaged");
    }
    for (const link of guest._hosts.values()) link._start();
    return guest;
  }

  /** The paired hosts, each the same object `pair` returned. */
  get hosts() {
    return [...this._hosts.values()];
  }

  /**
   * First contact with a host, from the payload it showed.
   *
   * @param {string} payload
   * @returns {Promise<PairedHost>}
   */
  async pair(payload) {
    const parsed = parsePayload(payload);
    if (this._key !== null && this._hosts.size > 0) {
      // PROTOCOL.md §3: one gs serves one pairing, and a native key cannot mint
      // another, so a second pairing needs its own Guest.
      throw new RelayError("this guest key is already paired; a fresh key pairs again");
    }
    const privateKey = this._key === null ? randomBytes(32) : null;
    const staticKey = this._key ?? (await MemoryKey.fromPrivate(privateKey));
    const link = new PairedHost(
      this,
      parsed.dev,
      parsed.hostPublic,
      [...parsed.relays],
      staticKey,
      privateKey,
      parsed.expires,
    );
    link._psk = parsed.psk;
    this._hosts.set(link._dev, link);
    link._start();
    await link._condition.waitFor(() => link._code !== "" || link._terminal());
    if (link._terminal()) {
      link._raiseTerminal();
      throw new PairingFailed("the pairing ended before the host showed a code");
    }
    return link;
  }

  /** Stop every connection. Paired hosts stay in the store. */
  async close() {
    for (const link of this._hosts.values()) await link._stop();
  }

  async _forget(link) {
    if (this._hosts.get(link._dev) === link) {
      this._hosts.delete(link._dev);
      await this._save();
    }
  }

  async _persist(link) {
    if (this._hosts.get(link._dev) === link) await this._save();
  }

  async _save() {
    await this._saveLock.run(() =>
      this._store.save({
        v: STATE_VERSION,
        hosts: this.hosts
          // A pairing that a restart interrupts starts over from a new payload.
          .filter((link) => link._state === "bound")
          .map((link) => ({
            dev: link._dev,
            host: toHex(link._hostPublic),
            relays: link._relays.map((entry) => entry.toJson()),
            ...(link._privateKey === null ? {} : { static: toHex(link._privateKey) }),
          })),
      }),
    );
  }
}
