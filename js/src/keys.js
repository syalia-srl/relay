/**
 * Static X25519 keys.
 *
 * A role holds its own static key behind the {@link StaticKey} shape and the
 * peer's as 32 public bytes. Keeping the private half behind that interface is
 * what lets a guest run its key in native code: the library only ever asks for a
 * Diffie-Hellman result.
 */

import { randomBytes } from "./bytes.js";
import { ProtocolViolation } from "./errors.js";

const KEY_SIZE = 32;

/** The X25519 base point: DH with it turns a private key into its public key. */
const BASE_POINT = new Uint8Array(KEY_SIZE);
BASE_POINT[0] = 9;

const PKCS8 = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * @typedef {object} StaticKey
 * @property {Uint8Array} publicKey The 32-byte public key.
 * @property {(peerPublic: Uint8Array) => Promise<Uint8Array>} dh The shared secret with `peerPublic`.
 */

/**
 * The raw X25519 shared secret for one pair of keys.
 *
 * WebCrypto reports a low-order public key (or a wrong-sized one) as a failed
 * operation; PROTOCOL.md §9.2 turns that into an abort, never another error.
 */
export async function x25519(privateKey, publicKey) {
  try {
    // Node 22 accepts a raw private key only without usages, so wrap it in PKCS8.
    const priv = await crypto.subtle.importKey("pkcs8", concatPkcs8(privateKey), "X25519", false, [
      "deriveBits",
    ]);
    const pub = await crypto.subtle.importKey("raw", publicKey, "X25519", false, []);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: pub }, priv, 256));
  } catch {
    throw new ProtocolViolation("a remote X25519 key is invalid");
  }
}

function concatPkcs8(privateKey) {
  const wrapped = new Uint8Array(PKCS8.length + privateKey.length);
  wrapped.set(PKCS8);
  wrapped.set(privateKey, PKCS8.length);
  return wrapped;
}

export async function publicFromPrivate(privateKey) {
  return x25519(privateKey, BASE_POINT);
}

/** A {@link StaticKey} whose private half lives in process memory. */
export class MemoryKey {
  #privateKey;
  #publicKey;

  constructor(privateKey, publicKey) {
    this.#privateKey = privateKey;
    this.#publicKey = publicKey;
  }

  static async generate() {
    return MemoryKey.fromPrivate(randomBytes(KEY_SIZE));
  }

  static async fromPrivate(privateKey) {
    if (privateKey.length !== KEY_SIZE) throw new Error("an X25519 private key is 32 bytes");
    return new MemoryKey(privateKey, await publicFromPrivate(privateKey));
  }

  get publicKey() {
    return this.#publicKey;
  }

  async dh(peerPublic) {
    return x25519(this.#privateKey, peerPublic);
  }
}
