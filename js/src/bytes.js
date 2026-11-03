/** Byte helpers shared by the protocol modules. */

const HEX = "0123456789abcdef";
const UTF8 = new TextEncoder();
const UTF8_FATAL = new TextDecoder("utf-8", { fatal: true });

export function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** 32 random bytes as 64 lowercase hex characters, the form device ids take. */
export function randomHex(length) {
  let text = "";
  for (const byte of randomBytes(length)) text += HEX[byte >> 4] + HEX[byte & 0x0f];
  return text;
}

export function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((size, item) => size + item.length, 0));
  let offset = 0;
  for (const item of arrays) {
    out.set(item, offset);
    offset += item.length;
  }
  return out;
}

export function toHex(bytes) {
  let text = "";
  for (const byte of bytes) text += HEX[byte >> 4] + HEX[byte & 0x0f];
  return text;
}

export function fromHex(text) {
  const out = new Uint8Array(text.length / 2);
  for (let index = 0; index < out.length; index++) {
    out[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

export function utf8(text) {
  return UTF8.encode(text);
}

/** Throws TypeError on bytes that are not UTF-8, as Python's decode does. */
export function fromUtf8(bytes) {
  return UTF8_FATAL.decode(bytes);
}

/**
 * Compare two byte arrays by value, for guest keys that came from different
 * handshakes.
 */
export function equalBytes(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

/**
 * Compare two strings without letting their first difference show in the time
 * taken: the typed pairing code is a secret until it is checked (§5.5).
 */
export function equalInConstantTime(left, right) {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index++) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}
