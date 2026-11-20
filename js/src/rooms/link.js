/** Invite links (ROOMS.md 5): `<app url>#v1.<relay host>.<room id>.<join token>.<invite key>`. */

import { TOKEN_LENGTH, b64, isB64, isId, reduceJwk, unb64 } from "./encoding.js";

const subtle = globalThis.crypto.subtle;
const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
const LABEL = "[a-z0-9]([a-z0-9-]*[a-z0-9])?";
const HOST = new RegExp(`^${LABEL}(\\.${LABEL})*(:[1-9][0-9]{0,4})?$`);

/** The invite key from its PKCS#8 bytes, as a signing CryptoKey and its public JWK. */
export async function importInviteKey(pkcs8) {
  const der = typeof pkcs8 === "string" ? unb64(pkcs8) : pkcs8;
  const privateKey = await subtle.importKey("pkcs8", der, ECDSA, true, ["sign"]);
  const jwk = await subtle.exportKey("jwk", privateKey);
  return { privateKey, publicJwk: reduceJwk(jwk), der };
}

/** A fresh invite key pair: the PKCS#8 for the link and the public JWK for the roster. */
export async function newInviteKey() {
  const pair = await subtle.generateKey(ECDSA, true, ["sign", "verify"]);
  const pkcs8 = b64(await subtle.exportKey("pkcs8", pair.privateKey));
  return { pkcs8, publicJwk: reduceJwk(await subtle.exportKey("jwk", pair.publicKey)), privateKey: pair.privateKey };
}

/** Whether the RFC 5915 ECPrivateKey inside `der` carries the public key `jwk`. */
function holdsPublicKey(der, jwk) {
  const point = new Uint8Array(68);
  point.set([0x03, 0x42, 0x00, 0x04]);
  point.set(unb64(jwk.x), 4);
  point.set(unb64(jwk.y), 36);
  outer: for (let i = 0; i + point.length <= der.length; i++) {
    for (let j = 0; j < point.length; j++) if (der[i + j] !== point[j]) continue outer;
    return true;
  }
  return false;
}

/**
 * Parse an invite link, or its fragment alone. Returns `{relay_host, room,
 * join_token, invite_key, invite_pub, relay_base_url}`, or null for a link a reader
 * refuses.
 */
export async function parseInviteLink(text) {
  if (typeof text !== "string") return null;
  const hash = text.indexOf("#");
  const parts = (hash >= 0 ? text.slice(hash + 1) : text).split(".");
  if (parts.length < 5 || parts[0] !== "v1") return null;
  const [room, token, key] = parts.slice(-3);
  const host = parts.slice(1, -3).join(".");
  if (host.length > 260 || !HOST.test(host)) return null;
  if (host.includes(":") && Number(host.slice(host.lastIndexOf(":") + 1)) > 65535) return null;
  if (!isId(room) || !isB64(token, TOKEN_LENGTH)) return null;
  let invite;
  try {
    invite = await importInviteKey(key);
  } catch {
    return null;
  }
  if (!holdsPublicKey(invite.der, invite.publicJwk)) return null;
  return {
    relay_host: host,
    room,
    join_token: token,
    invite_key: key,
    invite_pub: invite.publicJwk,
    relay_base_url: `https://${host}`,
  };
}

/** An invite link for `appUrl` (any URL of the application, or "" for the fragment alone). */
export function inviteLink({ appUrl = "", relayHost, room, joinToken, inviteKey }) {
  const base = appUrl.split("#")[0];
  return `${base}#v1.${relayHost.toLowerCase()}.${room}.${joinToken}.${inviteKey}`;
}
