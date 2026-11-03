/** Control messages of PROTOCOL.md §9.1. */

import { fromUtf8 } from "./bytes.js";
import { ProtocolViolation } from "./errors.js";
import { RelayEntry, urlAllowed } from "./relays.js";
import { parse } from "./strictjson.js";

// The side entitled to send each op; null means either side.
const SENDERS = {
  relays: "host",
  close: "guest",
  closed: "host",
  revoked: "host",
  ping: null,
  pong: null,
};

/**
 * Apply, ignore (null) or abort (throw) one control message. The receiver is
 * "host" or "guest".
 */
export function parseControl(bytes, receiver) {
  let value;
  try {
    value = parse(fromUtf8(bytes));
  } catch {
    throw new ProtocolViolation("the control message is not JSON");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ProtocolViolation("the control message is not an object");
  }
  const op = value.op;
  if (typeof op !== "string") throw new ProtocolViolation("the control message has no op");
  if (!Object.prototype.hasOwnProperty.call(SENDERS, op)) return null;
  const sender = SENDERS[op];
  if (sender !== null && sender === receiver) {
    throw new ProtocolViolation(`${op} came from the wrong side`);
  }
  if (op !== "relays") return { op, relays: [] };
  const raw = value.relays;
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > 16) {
    throw new ProtocolViolation("invalid relay list");
  }
  const entries = raw.map((item) => {
    const entry = RelayEntry.fromJson(item);
    if (entry === null) throw new ProtocolViolation("invalid relay entry");
    return entry;
  });
  const kept = entries.filter((entry) => urlAllowed(entry.url));
  // PROTOCOL.md §8.3: filter the list as a whole and ignore it if nothing is left.
  return kept.length === 0 ? null : { op, relays: kept };
}

export function encodeControl(op, relays = null) {
  const value = { op };
  if (relays !== null) value.relays = relays.map((entry) => entry.toJson());
  return new TextEncoder().encode(JSON.stringify(value));
}
