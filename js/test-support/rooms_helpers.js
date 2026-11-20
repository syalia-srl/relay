/** Shared set-up for the rooms tests: a fake relay with a credential, and a custodian. */

import { Room, softwareDeviceKeys } from "../src/rooms/index.js";
import { signEntry, verifyRoster } from "../src/rooms/roster.js";
import { FakeRoomRelay } from "./rooms_relay.js";

export const CREDENTIAL = "operator-key-for-tests";

export async function startRoomRelay() {
  return new FakeRoomRelay({
    credentials: {
      [CREDENTIAL]: {
        id: "install",
        rooms: { max: 10, stored_bytes: 1_000_000_000, retention_days: 30, blob_bytes: 1_000_000 },
      },
    },
  }).start();
}

export const inAWeek = () => Math.floor(Date.now() / 1000) + 7 * 86400;

/** A room with an owner `a`, the custodian's keys and token, and members joined by link. */
export async function roomWith(relay, memberCount = 0, { approval = false } = {}) {
  const custodianKeys = await softwareDeviceKeys();
  const ownerKeys = await softwareDeviceKeys();
  const { room: a, created } = await Room.create({
    baseUrl: relay.url,
    credential: CREDENTIAL,
    keys: ownerKeys,
    custodianSignPub: custodianKeys.signPub,
  });
  const members = [];
  for (let i = 0; i < memberCount; i++) {
    const { link } = await a.invite({ uses: 1, expiresAt: inAWeek(), approval, appUrl: "https://app.example/j" });
    members.push(await Room.join(link, await softwareDeviceKeys(), { baseUrl: relay.url }));
  }
  const custodian = { keys: custodianKeys, device: created.custodian.device, token: created.custodian.token };
  return { a, members, custodian, created };
}

/** The custodian removes `devices` through the relay routes alone, as a server would. */
export async function custodianRemove(relay, roomId, custodian, devices) {
  const auth = { authorization: `Bearer ${custodian.token}`, "content-type": "application/json" };
  const { entries } = await (await fetch(`${relay.url}/v1/rooms/${roomId}/roster`, { headers: auth })).json();
  const roster = await verifyRoster(entries.map(({ signer, ...r }) => r), { room: roomId });
  const record = await signEntry(
    custodian.keys,
    { kind: "remove", by: custodian.device, devices },
    roster.n + 1,
    roster.head,
  );
  const posted = await fetch(`${relay.url}/v1/rooms/${roomId}/roster`, {
    method: "POST",
    headers: auth,
    body: JSON.stringify(record),
  });
  if (posted.status !== 201) throw new Error(`roster ${posted.status}`);
  for (const device of devices) {
    const gone = await fetch(`${relay.url}/v1/rooms/${roomId}/devices/${device}`, { method: "DELETE", headers: auth });
    if (gone.status !== 204) throw new Error(`delete ${gone.status}`);
  }
}

export const text = (bytes) => new TextDecoder().decode(bytes);
