/** The pairing payload of PROTOCOL.md §4. */

import { fromHex, toHex } from "./bytes.js";
import { PayloadInvalid } from "./errors.js";
import { RelayEntry, urlAllowed } from "./relays.js";
import { isHex64, isInteger, parse } from "./strictjson.js";

const DEVICE = /^[A-Za-z0-9_-]{1,64}$/;

/** Everything a guest needs for the first contact, kept out of the relay. */
export class Payload {
  constructor({ dev, hostPublic, psk, expires, relays }) {
    this.dev = dev;
    this.hostPublic = hostPublic;
    this.psk = psk;
    this.expires = expires;
    this.relays = relays;
  }

  encode() {
    return JSON.stringify({
      v: 3,
      hs: toHex(this.hostPublic),
      psk: toHex(this.psk),
      dev: this.dev,
      exp: this.expires,
      relays: this.relays.map((entry) => entry.toJson()),
    });
  }
}

/** Check a payload as a guest and keep the relays that pass section 8.1. */
export function parsePayload(text, now = Math.floor(Date.now() / 1000)) {
  let value;
  try {
    value = parse(text);
  } catch {
    throw new PayloadInvalid("the payload is not JSON");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new PayloadInvalid("the payload is not an object");
  }
  if (!isInteger(value.v) || value.v !== 3) throw new PayloadInvalid("unknown payload version");
  if (!isHex64(value.hs)) throw new PayloadInvalid("invalid host public key");
  if (!isHex64(value.psk)) throw new PayloadInvalid("invalid pairing secret");
  if (typeof value.dev !== "string" || !DEVICE.test(value.dev)) {
    throw new PayloadInvalid("invalid device id");
  }
  if (!isInteger(value.exp)) throw new PayloadInvalid("invalid expiry");
  // PROTOCOL.md §4: a guest SHOULD refuse a payload past exp by more than 60 s.
  if (now > value.exp + 60) throw new PayloadInvalid("the pairing payload has expired");
  if (value.name != null && (typeof value.name !== "string" || [...value.name].length > 100)) {
    throw new PayloadInvalid("invalid name");
  }
  if (value.url != null && (typeof value.url !== "string" || [...value.url].length > 2048)) {
    throw new PayloadInvalid("invalid url");
  }
  if (!Array.isArray(value.relays) || value.relays.length < 1 || value.relays.length > 16) {
    throw new PayloadInvalid("invalid relay list");
  }
  const entries = value.relays.map((raw) => {
    const entry = RelayEntry.fromJson(raw);
    if (entry === null) throw new PayloadInvalid("invalid relay entry");
    return entry;
  });
  const kept = entries.filter((entry) => urlAllowed(entry.url));
  if (kept.length === 0) throw new PayloadInvalid("no relay passes the URL policy");
  return new Payload({
    dev: value.dev,
    hostPublic: fromHex(value.hs),
    psk: fromHex(value.psk),
    expires: value.exp,
    relays: kept,
  });
}
