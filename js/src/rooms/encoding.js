/** The encodings of ROOMS.md section 2: base64url, canonical JSON, JWKs and ids. */

export const ID_LENGTH = 22;
export const TOKEN_LENGTH = 43;

const B64URL = /^[A-Za-z0-9_-]*$/;

export function b64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let text = "";
  for (let i = 0; i < u8.length; i += 0x8000) text += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Unpadded base64url with canonical trailing bits; throws TypeError on anything else. */
export function unb64(text) {
  if (typeof text !== "string" || !B64URL.test(text) || text.length % 4 === 1) {
    throw new TypeError("not base64url");
  }
  const raw = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  if (b64(out) !== text) throw new TypeError("base64url with non-canonical trailing bits");
  return out;
}

export function isB64(value, length) {
  if (typeof value !== "string" || value.length !== length) return false;
  try {
    unb64(value);
    return true;
  } catch {
    return false;
  }
}

/** A client or relay id: 16 bytes in base64url, 22 characters. */
export function isId(value) {
  return isB64(value, ID_LENGTH);
}

/** An integer in the range of PROTOCOL.md section 1. */
export function isInt(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

/** 16 random bytes in base64url: a message cid, a blob id, an invite key id. */
export function randomId() {
  return b64(crypto.getRandomValues(new Uint8Array(16)));
}

/** Sorted keys, no whitespace, strings as JSON.stringify writes them. Refuses non-integers. */
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new TypeError("signed objects hold only integers");
  }
  if (value === undefined || typeof value === "function" || typeof value === "bigint") {
    throw new TypeError("not a JSON value");
  }
  return JSON.stringify(value);
}

/** A P-256 public JWK reduced to kty, crv, x and y. */
export function reduceJwk(jwk) {
  return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
}

export function isJwk(jwk) {
  return (
    jwk !== null &&
    typeof jwk === "object" &&
    jwk.kty === "EC" &&
    jwk.crv === "P-256" &&
    isB64(jwk.x, 43) &&
    isB64(jwk.y, 43)
  );
}

export function sameJwk(left, right) {
  return isJwk(left) && isJwk(right) && left.x === right.x && left.y === right.y;
}
