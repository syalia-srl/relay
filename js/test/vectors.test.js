/** Every test vector in vectors/ and the cacophony subset (PROTOCOL.md §12). */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { concat, fromHex, toHex, utf8 } from "../src/bytes.js";
import { parseControl } from "../src/control.js";
import { PayloadInvalid, ProtocolViolation } from "../src/errors.js";
import { ACCEPT, KIND_APPLICATION, PAIR, frame, pairingCode, prologue } from "../src/frames.js";
import { MemoryKey } from "../src/keys.js";
import { CipherState, HandshakeState, REKEY_EVERY, rekey } from "../src/noise.js";
import { parsePayload } from "../src/payload.js";
import { urlAllowed } from "../src/relays.js";
import { Session } from "../src/session.js";

const VECTORS = new URL("../../vectors/", import.meta.url);

function load(name) {
  return JSON.parse(readFileSync(new URL(name, VECTORS), "utf8"));
}

async function staticKey(vector, role) {
  return MemoryKey.fromPrivate(fromHex(vector[`${role}_static_private`]));
}

async function handshake(vector, role, initiator, pattern, psk) {
  const remoteStatic = fromHex(role === "host" ? vector.guest_static_public : vector.host_static_public);
  return HandshakeState.create({
    pattern,
    initiator,
    prologue: fromHex(vector.prologue),
    staticKey: await staticKey(vector, role),
    remoteStatic,
    psk,
    ephemeral: fromHex(vector[`${role}_ephemeral_private`]),
  });
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function checkFrame(frameBytes, expected) {
  const whole = concat(Uint8Array.of(0x01), frameBytes);
  if (typeof expected === "string") {
    assert.equal(toHex(whole), expected);
  } else {
    assert.equal(toHex(await sha256(whole)), expected.sha256);
    assert.equal(whole.length, expected.length);
  }
}

async function checkHandshake(vector, pattern, first, psk) {
  const guest = await handshake(vector, "guest", true, pattern, psk);
  const host = await handshake(vector, "host", false, pattern, psk);

  const message1 = await guest.writeMessage();
  assert.equal(toHex(message1), vector.message1);
  assert.equal(toHex(concat(Uint8Array.of(0x01), frame(first, message1))), vector.frame1);
  await host.readMessage(message1);
  assert.equal(toHex(host.remoteStatic), vector.guest_static_public);

  const message2 = await host.writeMessage();
  assert.equal(toHex(message2), vector.message2);
  assert.equal(toHex(concat(Uint8Array.of(0x01), frame(ACCEPT, message2))), vector.frame2);
  await guest.readMessage(message2);
  assert.equal(toHex(guest.handshakeHash), vector.handshake_hash);
  assert.equal(toHex(host.handshakeHash), vector.handshake_hash);
  if (pattern === "IKpsk1") assert.equal(await pairingCode(guest.handshakeHash), vector.pairing_code);

  const guestSession = await Session.initiator(guest);
  const hostSession = await Session.responder(host);
  const detail = vector.fragmented_message;
  const big = detail ? Uint8Array.from({ length: detail.length }, (_, index) => index % 251) : new Uint8Array(0);
  const fragmentPositions = detail ? detail.frames : [];
  let bigFrames = [];
  for (const [index, item] of vector.transport.entries()) {
    const sender = item.sender === "guest" ? guestSession : hostSession;
    const receiver = item.sender === "guest" ? hostSession : guestSession;
    let frameBytes;
    let expected;
    if (fragmentPositions.includes(index)) {
      if (bigFrames.length === 0) bigFrames = await sender.frames(KIND_APPLICATION, big);
      frameBytes = bigFrames[fragmentPositions.indexOf(index)];
      await checkFrame(frameBytes, item.frame);
      expected = [KIND_APPLICATION, index === fragmentPositions.at(-1) ? big : null];
    } else {
      const plaintext = fromHex(item.plaintext);
      const frames = await sender.frames(plaintext[0], plaintext.slice(2));
      assert.equal(frames.length, 1);
      assert.equal(toHex(concat(Uint8Array.of(0x01), frames[0])), item.frame);
      frameBytes = frames[0];
      expected = [plaintext[0], plaintext.slice(2)];
    }
    assert.deepEqual(await receiver.decrypt(frameBytes.slice(1)), expected);
  }
}

test("the pairing vector", async () => {
  const vector = load("pairing.json").cases[0];
  await checkHandshake(vector, "IKpsk1", PAIR, fromHex(vector.psk));
});

test("the pairing vector's refused first messages", async () => {
  const vector = load("pairing.json").cases[0];
  for (const refused of load("pairing.json").refused) {
    const host = await HandshakeState.create({
      pattern: "IKpsk1",
      initiator: false,
      prologue: prologue("dev_01", refused.channel),
      staticKey: await staticKey(vector, "host"),
      psk: fromHex(vector.psk),
    });
    await assert.rejects(host.readMessage(fromHex(refused.message1)), ProtocolViolation, refused.name);
  }
});

test("the connect vector", async () => {
  await checkHandshake(load("connect.json").cases[0], "KK", 0x02, null);
});

test("the connect vector's refused first message", async () => {
  const vector = load("connect.json");
  const host = await HandshakeState.create({
    pattern: "KK",
    initiator: false,
    prologue: prologue("dev_01", vector.cases[0].channel),
    staticKey: await staticKey(vector.cases[0], "host"),
    remoteStatic: fromHex(vector.cases[0].guest_static_public),
  });
  await assert.rejects(host.readMessage(fromHex(vector.refused[0].message1)), ProtocolViolation);
});

test("the rekey vectors", async () => {
  for (const vector of load("rekey.json").cases) {
    const cipher = new CipherState(fromHex(vector.key), BigInt(vector.nonce_before));
    const before = await cipher.encrypt(new Uint8Array(0), fromHex(vector.plaintext_before));
    assert.equal(toHex(before), vector.ciphertext_before);
    assert.equal(toHex(cipher.key), vector.rekeyed);
    assert.equal(toHex(await rekey(fromHex(vector.key))), vector.rekeyed);
    assert.equal(cipher.nonce, BigInt(REKEY_EVERY));
    const after = await cipher.encrypt(new Uint8Array(0), fromHex(vector.plaintext_after));
    assert.equal(toHex(after), vector.ciphertext_after);
    assert.equal(cipher.nonce, BigInt(REKEY_EVERY + 1));
  }
});

test("the prologue vectors", () => {
  for (const vector of load("prologue.json").cases) {
    assert.equal(toHex(prologue(vector.dev, vector.channel)), vector.prologue);
  }
});

test("the pairing code vectors", async () => {
  for (const vector of load("pairing_code.json").cases) {
    assert.equal(await pairingCode(fromHex(vector.h)), vector.code);
  }
});

test("the URL policy vectors", () => {
  for (const vector of load("url_policy.json").cases) {
    assert.equal(urlAllowed(vector.url), vector.allowed, vector.url);
  }
});

test("the pairing payload vectors", () => {
  for (const vector of load("pairing_payload.json").cases) {
    if (!vector.valid) {
      assert.throws(() => parsePayload(vector.text, vector.now), PayloadInvalid, vector.name);
      continue;
    }
    const payload = parsePayload(vector.text, vector.now);
    const original = JSON.parse(vector.text).relays;
    const kept = payload.relays.map((entry) => [entry.url, entry.channel, entry.token]);
    const expected = vector.relays_kept.map((index) => [
      original[index].url,
      original[index].channel,
      original[index].token,
    ]);
    assert.deepEqual(kept, expected, vector.name);
  }
});

test("the control vectors", () => {
  for (const vector of load("control.json").cases) {
    const bytes = utf8(vector.text);
    if (vector.result === "apply") {
      assert.notEqual(parseControl(bytes, vector.receiver), null, vector.text);
    } else if (vector.result === "ignore") {
      assert.equal(parseControl(bytes, vector.receiver), null, vector.text);
    } else {
      assert.throws(() => parseControl(bytes, vector.receiver), ProtocolViolation, vector.text);
    }
  }
});

const PATTERNS = {
  "Noise_IKpsk1_25519_AESGCM_SHA256": "IKpsk1",
  "Noise_KK_25519_AESGCM_SHA256": "KK",
};

test("the cacophony vectors", async () => {
  const vectors = load("tools/cacophony_subset.json").vectors.filter(
    (vector) => vector.protocol_name in PATTERNS,
  );
  assert.deepEqual(vectors.map((vector) => vector.protocol_name).sort(), Object.keys(PATTERNS).sort());
  for (const vector of vectors) await checkCacophony(vector, PATTERNS[vector.protocol_name]);
});

async function checkCacophony(vector, pattern) {
  const key = (name) => (name in vector ? fromHex(vector[name]) : null);
  const initiator = await HandshakeState.create({
    pattern,
    initiator: true,
    prologue: key("init_prologue") ?? new Uint8Array(0),
    staticKey: await MemoryKey.fromPrivate(key("init_static")),
    remoteStatic: key("init_remote_static"),
    psk: vector.init_psks ? fromHex(vector.init_psks[0]) : null,
    ephemeral: key("init_ephemeral"),
  });
  const responder = await HandshakeState.create({
    pattern,
    initiator: false,
    prologue: key("resp_prologue") ?? new Uint8Array(0),
    staticKey: await MemoryKey.fromPrivate(key("resp_static")),
    remoteStatic: key("resp_remote_static"),
    psk: vector.resp_psks ? fromHex(vector.resp_psks[0]) : null,
    ephemeral: key("resp_ephemeral"),
  });
  let sessions = null;
  for (const [index, message] of vector.messages.entries()) {
    const payload = fromHex(message.payload);
    const expected = fromHex(message.ciphertext);
    const initiatorSends = index % 2 === 0;
    if (sessions === null) {
      const sender = initiatorSends ? initiator : responder;
      const receiver = initiatorSends ? responder : initiator;
      const ciphertext = await sender.writeMessage(payload);
      assert.equal(toHex(ciphertext), toHex(expected), `handshake message ${index}`);
      assert.equal(toHex(await receiver.readMessage(ciphertext)), toHex(payload));
      if (initiator.finished()) {
        assert.equal(toHex(initiator.handshakeHash), vector.handshake_hash);
        assert.equal(toHex(responder.handshakeHash), vector.handshake_hash);
        sessions = [...(await initiator.split()), ...(await responder.split())];
      }
    } else {
      const [i1, i2, r1, r2] = sessions;
      const sender = initiatorSends ? i1 : r2;
      const receiver = initiatorSends ? r1 : i2;
      const ciphertext = await sender.encrypt(new Uint8Array(0), payload);
      assert.equal(toHex(ciphertext), toHex(expected), `transport message ${index}`);
      assert.equal(toHex(await receiver.decrypt(new Uint8Array(0), ciphertext)), toHex(payload));
    }
  }
}

test("a low-order ephemeral key is a protocol violation", async () => {
  // A relay that sends an all-zero key must not raise anything but the error
  // the host and guest socket loops catch (PROTOCOL.md §9.2), and must fail at
  // the key itself rather than at the tag that follows from it.
  const host = await MemoryKey.generate();
  const guest = await MemoryKey.generate();
  const responder = await HandshakeState.create({
    pattern: "KK",
    initiator: false,
    prologue: new Uint8Array(0),
    staticKey: host,
    remoteStatic: guest.publicKey,
  });
  await assert.rejects(responder.readMessage(new Uint8Array(48)), (error) => {
    assert.ok(error instanceof ProtocolViolation);
    assert.match(error.message, /X25519/);
    return true;
  });
});
