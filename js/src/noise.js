/**
 * A minimal Noise Protocol Framework (revision 34) for the channel protocol.
 *
 * Only the suite 25519_AESGCM_SHA256 and the two patterns PROTOCOL.md uses are
 * implemented: IKpsk1 for pairing and KK for every later connection. This is the
 * same shape as `vectors/tools/noise_ref.py`, which generates the vectors.
 */

import { concat, randomBytes, utf8 } from "./bytes.js";
import { TagFailure, ProtocolViolation } from "./errors.js";
import { publicFromPrivate, x25519 } from "./keys.js";

const HASHLEN = 32;
const DHLEN = 32;
export const REKEY_EVERY = 2 ** 20;

const MAX_NONCE = 2n ** 64n - 1n;

const PATTERNS = {
  IKpsk1: {
    preInitiator: [],
    preResponder: ["s"],
    messages: [
      ["e", "es", "s", "ss", "psk"],
      ["e", "ee", "se"],
    ],
    psk: true,
  },
  KK: {
    preInitiator: ["s"],
    preResponder: ["s"],
    messages: [
      ["e", "es", "ss"],
      ["e", "ee", "se"],
    ],
    psk: false,
  },
};

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

async function hmac(key, ...parts) {
  const imported = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, concat(...parts)));
}

async function hkdf(chainingKey, ikm, outputs) {
  const temp = await hmac(chainingKey, ikm);
  const out = [];
  let previous = new Uint8Array(0);
  for (let index = 1; index <= outputs; index++) {
    previous = await hmac(temp, previous, Uint8Array.of(index));
    out.push(previous);
  }
  return out;
}

function nonceBytes(nonce) {
  const bytes = new Uint8Array(12);
  new DataView(bytes.buffer).setBigUint64(4, nonce);
  return bytes;
}

async function importAesGcm(key) {
  return crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** Noise's Rekey() for AES-GCM. */
export async function rekey(key) {
  const cryptoKey = await importAesGcm(key);
  const out = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonceBytes(MAX_NONCE), additionalData: new Uint8Array(0) },
      cryptoKey,
      new Uint8Array(32),
    ),
  );
  return out.slice(0, 32);
}

/** A Noise cipher state: an optional key and a 64-bit message counter. */
export class CipherState {
  #key;
  #nonce;
  #cryptoKey = null;

  constructor(key = null, nonce = 0n) {
    this.#key = key;
    this.#nonce = nonce;
  }

  get key() {
    return this.#key;
  }

  get nonce() {
    return this.#nonce;
  }

  async encrypt(associatedData, plaintext) {
    if (this.#key === null) return plaintext;
    // PROTOCOL.md §7.3: a session whose nonce would reach 2^64 - 1 is closed.
    if (this.#nonce === MAX_NONCE) throw new ProtocolViolation("the transport nonce is exhausted");
    const cryptoKey = await this.#import();
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonceBytes(this.#nonce), additionalData: associatedData },
        cryptoKey,
        plaintext,
      ),
    );
    await this.#advance();
    return ciphertext;
  }

  async decrypt(associatedData, ciphertext) {
    if (this.#key === null) return ciphertext;
    if (this.#nonce === MAX_NONCE) throw new ProtocolViolation("the transport nonce is exhausted");
    const cryptoKey = await this.#import();
    let plaintext;
    try {
      plaintext = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: nonceBytes(this.#nonce), additionalData: associatedData },
          cryptoKey,
          ciphertext,
        ),
      );
    } catch {
      // A failed tag leaves the counter alone, so a candidate and the current
      // session can each try the same frame (PROTOCOL.md §6.3).
      throw new TagFailure("a transport message does not decrypt");
    }
    await this.#advance();
    return plaintext;
  }

  async #advance() {
    this.#nonce += 1n;
    // PROTOCOL.md §7.3: both ends rekey after the frame whose nonce is 2^20 - 1.
    if (this.#nonce % BigInt(REKEY_EVERY) === 0n) {
      this.#key = await rekey(this.#key);
      this.#cryptoKey = null;
    }
  }

  async #import() {
    this.#cryptoKey ??= importAesGcm(this.#key);
    return this.#cryptoKey;
  }
}

/** One side of an IKpsk1 or KK handshake. */
export class HandshakeState {
  #initiator;
  #staticKey;
  #remoteStatic;
  #psk;
  #fixedEphemeral;
  #ephemeral = null;
  #remoteEphemeral = null;
  #index = 0;
  #h;
  #ck;
  #cipher = new CipherState();
  #pskMode;
  #messages;

  static async create({
    pattern,
    initiator,
    prologue,
    staticKey,
    remoteStatic = null,
    psk = null,
    ephemeral = null,
  }) {
    const known = PATTERNS[pattern];
    if (known === undefined) throw new Error(`unsupported Noise pattern ${pattern}`);
    if (known.psk && psk === null) throw new Error("IKpsk1 needs a psk");
    const state = new HandshakeState();
    state.#initiator = initiator;
    state.#staticKey = staticKey;
    state.#remoteStatic = remoteStatic;
    state.#psk = psk;
    state.#fixedEphemeral = ephemeral;
    state.#pskMode = known.psk;
    state.#messages = known.messages;
    const name = utf8(`Noise_${pattern}_25519_AESGCM_SHA256`);
    state.#h = name.length <= HASHLEN ? pad(name) : await sha256(name);
    state.#ck = state.#h;
    await state.#mixHash(prologue);
    for (const _ of known.preInitiator) await state.#mixHash(initiator ? staticKey.publicKey : remoteStatic);
    for (const _ of known.preResponder) await state.#mixHash(initiator ? remoteStatic : staticKey.publicKey);
    return state;
  }

  get handshakeHash() {
    return this.#h;
  }

  get remoteStatic() {
    return this.#remoteStatic;
  }

  finished() {
    return this.#index === this.#messages.length;
  }

  async #mixHash(data) {
    if (data === null) throw new Error("a pre-message static key is missing");
    this.#h = await sha256(concat(this.#h, data));
  }

  async #mixKey(ikm) {
    const [chainingKey, key] = await hkdf(this.#ck, ikm, 2);
    this.#ck = chainingKey;
    this.#cipher = new CipherState(key);
  }

  async #mixKeyAndHash(ikm) {
    const [ck, tempH, key] = await hkdf(this.#ck, ikm, 3);
    this.#ck = ck;
    await this.#mixHash(tempH);
    this.#cipher = new CipherState(key);
  }

  async #encryptAndHash(plaintext) {
    const ciphertext = await this.#cipher.encrypt(this.#h, plaintext);
    await this.#mixHash(ciphertext);
    return ciphertext;
  }

  async #decryptAndHash(ciphertext) {
    const plaintext = await this.#cipher.decrypt(this.#h, ciphertext);
    await this.#mixHash(ciphertext);
    return plaintext;
  }

  async #dh(token) {
    // "xy": x belongs to the initiator, y to the responder.
    const [x, y] = token;
    const mine = this.#initiator ? x : y;
    const theirs = this.#initiator ? y : x;
    const remote = theirs === "e" ? this.#remoteEphemeral : this.#remoteStatic;
    if (remote === null) throw new ProtocolViolation(`${token} has no remote key`);
    if (mine === "e" && this.#ephemeral !== null) return x25519(this.#ephemeral, remote);
    return this.#staticKey.dh(remote);
  }

  async writeMessage(payload = new Uint8Array(0)) {
    if (this.finished()) throw new ProtocolViolation("the handshake is already finished");
    let out = new Uint8Array(0);
    for (const token of this.#messages[this.#index]) {
      if (token === "e") {
        this.#ephemeral = this.#fixedEphemeral ?? randomBytes(DHLEN);
        const publicKey = await publicFromPrivate(this.#ephemeral);
        out = concat(out, publicKey);
        await this.#mixHash(publicKey);
        if (this.#pskMode) await this.#mixKey(publicKey);
      } else if (token === "s") {
        out = concat(out, await this.#encryptAndHash(this.#staticKey.publicKey));
      } else if (token === "psk") {
        await this.#mixKeyAndHash(this.#psk);
      } else {
        await this.#mixKey(await this.#dh(token));
      }
    }
    out = concat(out, await this.#encryptAndHash(payload));
    this.#index += 1;
    return out;
  }

  async readMessage(message) {
    if (this.finished()) throw new ProtocolViolation("the handshake is already finished");
    for (const token of this.#messages[this.#index]) {
      if (token === "e") {
        if (message.length < DHLEN) throw new ProtocolViolation("a handshake message is too short");
        this.#remoteEphemeral = message.slice(0, DHLEN);
        message = message.slice(DHLEN);
        await this.#mixHash(this.#remoteEphemeral);
        if (this.#pskMode) await this.#mixKey(this.#remoteEphemeral);
      } else if (token === "s") {
        const size = this.#cipher.key === null ? DHLEN : DHLEN + 16;
        if (message.length < size) throw new ProtocolViolation("a handshake message is too short");
        this.#remoteStatic = await this.#decryptAndHash(message.slice(0, size));
        message = message.slice(size);
      } else if (token === "psk") {
        await this.#mixKeyAndHash(this.#psk);
      } else {
        await this.#mixKey(await this.#dh(token));
      }
    }
    const payload = await this.#decryptAndHash(message);
    this.#index += 1;
    return payload;
  }

  async split() {
    if (!this.finished()) throw new ProtocolViolation("the handshake is not finished");
    const [first, second] = await hkdf(this.#ck, new Uint8Array(0), 2);
    return [new CipherState(first), new CipherState(second)];
  }
}

function pad(name) {
  const out = new Uint8Array(HASHLEN);
  out.set(name);
  return out;
}
