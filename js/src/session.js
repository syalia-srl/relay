/** One established L1 session: transport frames, fragments and rekey. */

import { Mutex } from "./async.js";
import { concat } from "./bytes.js";
import { ProtocolViolation } from "./errors.js";
import {
  FragmentAssembler,
  KIND_APPLICATION,
  KIND_CONTROL,
  MAX_PAYLOAD,
  MAX_TRANSPORT,
  MIN_TRANSPORT,
  TRANSPORT,
  frame,
} from "./frames.js";

/** The transport state of one side of one connection. */
export class Session {
  #send;
  #receive;
  #fragments = new FragmentAssembler();
  // A whole message's fragments must reach the socket together, and their
  // nonces in order, whichever task sends them (PROTOCOL.md §7.2).
  #lock = new Mutex();

  constructor(send, receive) {
    this.#send = send;
    this.#receive = receive;
  }

  static async initiator(handshake) {
    const [first, second] = await handshake.split();
    return new Session(first, second);
  }

  static async responder(handshake) {
    const [first, second] = await handshake.split();
    // PROTOCOL.md §6.2: c1 carries guest-to-host frames and c2 host-to-guest.
    return new Session(second, first);
  }

  /** The L1 transport frames for one application or control message. */
  async frames(kind, message) {
    if (kind !== KIND_APPLICATION && kind !== KIND_CONTROL) {
      throw new ProtocolViolation("unknown message kind");
    }
    const parts = [];
    for (let index = 0; index < message.length; index += MAX_PAYLOAD) {
      parts.push(message.slice(index, index + MAX_PAYLOAD));
    }
    if (parts.length === 0) parts.push(message);
    const frames = [];
    for (const [index, part] of parts.entries()) {
      const plaintext = concat(Uint8Array.of(kind, index < parts.length - 1 ? 1 : 0), part);
      frames.push(frame(TRANSPORT, await this.#send.encrypt(new Uint8Array(0), plaintext)));
    }
    return frames;
  }

  async send(socket, kind, message) {
    await this.#lock.run(async () => socket.sendAll(await this.frames(kind, message)));
  }

  /** Decrypt one transport frame; a null message means more fragments follow. */
  async decrypt(body) {
    if (body.length < MIN_TRANSPORT || body.length > MAX_TRANSPORT) {
      throw new ProtocolViolation("a transport frame has the wrong length");
    }
    const plaintext = await this.#receive.decrypt(new Uint8Array(0), body);
    const [kind, flags] = plaintext;
    if (kind !== KIND_APPLICATION && kind !== KIND_CONTROL) {
      throw new ProtocolViolation("unknown message kind");
    }
    if ((flags & ~0x01) !== 0) throw new ProtocolViolation("unknown transport flags");
    return [kind, this.#fragments.push(kind, (flags & 0x01) !== 0, plaintext.slice(2))];
  }
}
