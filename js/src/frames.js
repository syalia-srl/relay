/**
 * L1 frame types, the prologue, the pairing code and fragment reassembly
 * (PROTOCOL.md §§3.1, 3.2, 5.6, 7.1 and 7.2).
 */

import { concat, utf8 } from "./bytes.js";
import { ProtocolViolation } from "./errors.js";

export const PAIR = 0x01;
export const CONNECT = 0x02;
export const ACCEPT = 0x03;
export const TRANSPORT = 0x04;
export const ABORT = 0x05;

export const KIND_APPLICATION = 0x00;
export const KIND_CONTROL = 0x01;

export const MAX_PAYLOAD = 65_517;
export const MAX_MESSAGE = 16_777_216;
export const MIN_TRANSPORT = 18;
export const MAX_TRANSPORT = 65_535;

/** PROTOCOL.md §3.1: bind a handshake to one device and one channel. */
export function prologue(dev, channel) {
  const device = utf8(dev);
  const identifier = utf8(channel);
  const length = new Uint8Array(2);
  const view = new DataView(length.buffer);
  view.setUint16(0, device.length);
  const channelLength = new Uint8Array(2);
  new DataView(channelLength.buffer).setUint16(0, identifier.length);
  return concat(utf8("relay-channel/3"), length, device, channelLength, identifier);
}

/** PROTOCOL.md §5.6: the six digits the person types into the host. */
export async function pairingCode(handshakeHash) {
  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      concat(utf8("relay-channel/3 pairing code"), handshakeHash),
    ),
  );
  const value = new DataView(digest.buffer).getUint32(0);
  return String(value % 1_000_000).padStart(6, "0");
}

export function frame(frameType, body) {
  return concat(Uint8Array.of(frameType), body);
}

/** Reassembles one direction's message, refusing interleaved fragments. */
export class FragmentAssembler {
  #kind = null;
  #parts = [];
  #size = 0;

  /** The whole message, or null when more fragments follow. */
  push(kind, more, payload) {
    if (this.#kind === null) this.#kind = kind;
    else if (kind !== this.#kind) throw new ProtocolViolation("a fragment changed kind");
    this.#size += payload.length;
    // PROTOCOL.md §7.2: the payloads of one message add up to at most 16 MiB.
    if (this.#size > MAX_MESSAGE) throw new ProtocolViolation("a message is larger than 16 MiB");
    this.#parts.push(payload);
    if (more) return null;
    const message = concat(...this.#parts);
    this.#kind = null;
    this.#parts = [];
    this.#size = 0;
    return message;
  }
}
