/**
 * The cryptography of the room protocol (ROOMS.md sections 2, 4.4 to 4.6), ported from
 * vault's crypto.js. Only WebCrypto: ECDSA and ECDH on P-256, HKDF-SHA-256 and
 * AES-256-GCM. A device's private keys stay behind the key interface (C3):
 *
 *   { signPub, recvPub, async sign(bytes) -> Uint8Array(64), async derive(peerJwk) -> Uint8Array(32) }
 */

import { b64, canonical, isJwk, reduceJwk, unb64 } from "./encoding.js";

const subtle = globalThis.crypto.subtle;
const UTF8 = new TextEncoder();

const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
const ECDH = { name: "ECDH", namedCurve: "P-256" };
const SIG = { name: "ECDSA", hash: "SHA-256" };

/** Something a client refuses: a record, an epoch, a message or a blob. `reason` names the check. */
export class Refused extends Error {
  constructor(reason, message) {
    super(message ?? reason);
    this.name = "Refused";
    this.reason = reason;
  }
}

export function utf8(text) {
  return UTF8.encode(text);
}

/**
 * A device's keys in WebCrypto, with private halves that cannot be exported
 * (extractable: false). For tests and the browser; a phone fills the same
 * interface from its own key store.
 */
export async function softwareDeviceKeys() {
  const signing = await subtle.generateKey(ECDSA, false, ["sign", "verify"]);
  const receiving = await subtle.generateKey(ECDH, false, ["deriveBits"]);
  return keysFrom(signing, receiving);
}

/** The key interface over two WebCrypto key pairs (or a receiving key alone). */
export async function keysFrom(signing, receiving) {
  return {
    signPub: signing ? reduceJwk(await subtle.exportKey("jwk", signing.publicKey)) : null,
    recvPub: receiving ? reduceJwk(await subtle.exportKey("jwk", receiving.publicKey)) : null,
    async sign(bytes) {
      return new Uint8Array(await subtle.sign(SIG, signing.privateKey, bytes));
    },
    async derive(peerJwk) {
      return deriveBits(receiving.privateKey, peerJwk);
    },
  };
}

async function deriveBits(privateKey, peerJwk) {
  if (!isJwk(peerJwk)) throw new Refused("record", "not a P-256 JWK");
  const pub = await subtle.importKey("jwk", reduceJwk(peerJwk), ECDH, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: pub }, privateKey, 256));
}

/** The base64url signature of `keys` over the canonical JSON of `object`. */
export async function signObject(keys, object) {
  const sig = await keys.sign(utf8(canonical(object)));
  if (!(sig instanceof Uint8Array) || sig.length !== 64) throw new TypeError("sign() must return 64 bytes r||s");
  return b64(sig);
}

/** Whether `sig` is a 64-byte r||s signature by `jwk` over the canonical JSON of `object`. */
export async function verifyObject(jwk, object, sig) {
  try {
    if (!isJwk(jwk)) return false;
    const raw = unb64(sig);
    if (raw.length !== 64) return false;
    const key = await subtle.importKey("jwk", reduceJwk(jwk), ECDSA, false, ["verify"]);
    return await subtle.verify(SIG, key, raw, utf8(canonical(object)));
  } catch {
    return false;
  }
}

export async function sha256(bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

// --- epochs and wraps (ROOMS.md 4.4) ---

export function wrapInfo(room, n, device) {
  return `relay-wrap-1|${room}|${n}|${device}`;
}

export async function wrapKey(secret, info) {
  const ikm = await subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: utf8(info) },
    ikm,
    256,
  );
  return new Uint8Array(bits);
}

async function aes(key, usage) {
  return subtle.importKey("raw", key, "AES-GCM", false, [usage]);
}

async function encrypt(key, iv, plaintext, additionalData) {
  const params = additionalData ? { name: "AES-GCM", iv, additionalData } : { name: "AES-GCM", iv };
  return new Uint8Array(await subtle.encrypt(params, await aes(key, "encrypt"), plaintext));
}

async function decrypt(key, iv, ciphertext, additionalData) {
  const params = additionalData ? { name: "AES-GCM", iv, additionalData } : { name: "AES-GCM", iv };
  try {
    return new Uint8Array(await subtle.decrypt(params, await aes(key, "decrypt"), ciphertext));
  } catch {
    throw new Refused("decrypt");
  }
}

/**
 * Wrap `epochKey` for one device's receiving key. `eph` (a WebCrypto ECDH key
 * pair) and `iv` are drawn fresh unless given, as the vectors give them.
 */
export async function wrapFor({ room, n, device, recvPub, epochKey, eph, iv }) {
  eph ??= await subtle.generateKey(ECDH, false, ["deriveBits"]);
  iv ??= crypto.getRandomValues(new Uint8Array(12));
  const secret = await deriveBits(eph.privateKey, recvPub);
  const key = await wrapKey(secret, wrapInfo(room, n, device));
  return {
    eph: reduceJwk(await subtle.exportKey("jwk", eph.publicKey)),
    iv: b64(iv),
    ct: b64(await encrypt(key, iv, epochKey)),
  };
}

export function epochBody(room, epoch) {
  return { v: "relay-epoch-1", room, n: epoch.n, roster: epoch.roster, creator: epoch.creator, wraps: epoch.wraps };
}

/**
 * A new epoch: a fresh 32-byte key wrapped for each of `recipients` ({device: recvPub}),
 * signed by `keys`. `roster` is the length of the creator's verified roster. Returns the
 * body of POST /epochs and the key.
 */
export async function makeEpoch({ room, n, roster, creator, keys, recipients, epochKey }) {
  epochKey ??= crypto.getRandomValues(new Uint8Array(32));
  const wraps = {};
  for (const [device, recvPub] of Object.entries(recipients)) {
    wraps[device] = await wrapFor({ room, n, device, recvPub, epochKey });
  }
  const epoch = { n, roster, creator, wraps };
  epoch.sig = await signObject(keys, epochBody(room, epoch));
  return { epoch, key: epochKey };
}

/** Open this device's wrap of an epoch with `keys.derive`. Throws Refused. */
export async function openEpoch({ room, epoch, device, keys }) {
  const wrap = epoch.wraps?.[device];
  if (!wrap) throw new Refused("not_wrapped");
  let secret;
  try {
    secret = await keys.derive(reduceJwk(wrap.eph));
  } catch {
    throw new Refused("decrypt");
  }
  const key = await wrapKey(secret, wrapInfo(room, epoch.n, device));
  const raw = await decrypt(key, unb64(wrap.iv), unb64(wrap.ct));
  if (raw.length !== 32) throw new Refused("decrypt");
  return raw;
}

// --- messages (ROOMS.md 4.5) ---

export function messageAad(room, epoch, device, n) {
  return `relay-msg-1|${room}|${epoch}|${device}|${n}`;
}

export function messageBody(room, message) {
  const body = {
    v: "relay-msg-1",
    room,
    device: message.device,
    epoch: message.epoch,
    n: message.n,
    iv: message.iv,
    ct: message.ct,
  };
  if (message.blob !== undefined) body.blob = message.blob;
  return body;
}

/** Seal `plaintext` (bytes) as message `n` of `device` under `epoch`. Returns the signed fields. */
export async function sealMessage({ room, epoch, device, n, key, keys, plaintext, blob, iv }) {
  iv ??= crypto.getRandomValues(new Uint8Array(12));
  const ct = await encrypt(key, iv, plaintext, utf8(messageAad(room, epoch, device, n)));
  const message = { epoch, n, iv: b64(iv), ct: b64(ct) };
  if (blob !== undefined) message.blob = blob;
  message.sig = await signObject(keys, messageBody(room, { ...message, device }));
  return message;
}

/**
 * Open a message as GET /messages returns it. `epochs` maps an epoch number to the
 * accepted epoch, `epochKeys` to its key, `signPub(device)` gives a sender's key
 * from the verified roster. Throws Refused with the vectors' reasons.
 */
export async function openMessage({ room, message, epochs, epochKeys, signPub }) {
  const epoch = epochs.get(message.epoch);
  const key = epochKeys.get(message.epoch);
  if (!epoch || !key) throw new Refused("epoch");
  if (!Object.hasOwn(epoch.wraps, message.device)) throw new Refused("not_wrapped");
  if (!(await verifyObject(signPub(message.device), messageBody(room, message), message.sig))) {
    throw new Refused("signature");
  }
  let iv, ct;
  try {
    iv = unb64(message.iv);
    ct = unb64(message.ct);
  } catch {
    throw new Refused("decrypt");
  }
  return decrypt(key, iv, ct, utf8(messageAad(room, message.epoch, message.device, message.n)));
}

// --- blobs (ROOMS.md 4.6) ---

export function blobAad(room, blob) {
  return `relay-blob-1|${room}|${blob}`;
}

/** The body to PUT: a 12-byte IV, then the AES-256-GCM ciphertext and tag. */
export async function sealBlob({ room, blob, key, plaintext, iv }) {
  iv ??= crypto.getRandomValues(new Uint8Array(12));
  const ct = await encrypt(key, iv, plaintext, utf8(blobAad(room, blob)));
  const body = new Uint8Array(12 + ct.length);
  body.set(iv);
  body.set(ct, 12);
  return body;
}

export async function openBlob({ room, blob, key, body }) {
  if (body.length < 28) throw new Refused("decrypt");
  return decrypt(key, body.subarray(0, 12), body.subarray(12), utf8(blobAad(room, blob)));
}
