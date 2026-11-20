/** The signed roster (ROOMS.md 4.2): replay, checks and the records a client signs. */

import { Refused, epochBody, sha256, signObject, utf8, verifyObject } from "./crypto.js";
import { b64, canonical, isId, isInt, isJwk, reduceJwk } from "./encoding.js";

/** A roster refused at record `index` (0-based); the records before it stand. */
export class RosterInvalid extends Refused {
  constructor(reason, index) {
    super(reason, `roster record ${index + 1}: ${reason}`);
    this.name = "RosterInvalid";
    this.index = index;
  }
}

const KINDS = new Set(["genesis", "invite", "join", "approve", "link", "remove", "promote", "demote", "close-invite"]);

export function entryBody(entry, n, prev) {
  return { v: "relay-roster-1", n, prev, entry };
}

export function joinBody(entry) {
  const { invite, device, sign_pub, recv_pub, at } = entry;
  return { v: "relay-join-1", invite, device, sign_pub, recv_pub, at };
}

export function linkBody(member, device) {
  return { v: "relay-link-1", member, device };
}

/** The hash of a record: base64url SHA-256 of the canonical signed object, no signature. */
export async function recordHash(record) {
  return b64(await sha256(utf8(canonical(entryBody(record.entry, record.n, record.prev)))));
}

/** The body of POST /roster: `entry` as record `n` after the record whose hash is `prev`. */
export async function signEntry(keys, entry, n, prev) {
  return { n, entry, sig: await signObject(keys, entryBody(entry, n, prev)), prev };
}

/**
 * The state a replay yields. Devices hold their keys, kind, role, status and person
 * (`member`), and the span of records during which they were active.
 */
export class Roster {
  constructor() {
    this.room = "";
    this.n = 0;
    this.head = "";
    this.devices = new Map();
    this.invites = new Map();
  }

  device(id) {
    return this.devices.get(id) ?? null;
  }

  active(id) {
    const device = this.devices.get(id);
    return device && device.status === "active" ? device : null;
  }

  /** The ids of active devices of kind `device`: who an epoch is wrapped for. */
  readers() {
    return [...this.devices].filter(([, d]) => d.status === "active" && d.kind === "device").map(([id]) => id);
  }

  /** The state in the shape of vectors/rooms_roster.json. */
  state() {
    const devices = {};
    for (const [id, d] of this.devices) {
      devices[id] = { kind: d.kind, role: d.role, status: d.status, member: d.member };
    }
    const invites = {};
    for (const [id, v] of this.invites) {
      invites[id] = { uses: v.uses, used: v.used, expires_at: v.expires_at, approval: v.approval, closed: v.closed };
    }
    return { room: this.room, n: this.n, head: this.head, devices, invites };
  }
}

/**
 * Replay `records` in order. Throws RosterInvalid at the first record that is not
 * valid; with `{partial: true}` returns `{roster, error}` with the prefix that stands.
 */
export async function verifyRoster(records, { room, partial = false } = {}) {
  const roster = new Roster();
  let error = null;
  for (let index = 0; index < records.length; index++) {
    try {
      await applyRecord(roster, index, records[index]);
      if (index === 0 && room !== undefined && roster.room !== room) throw new Refused("room");
    } catch (failure) {
      error = new RosterInvalid(failure instanceof Refused ? failure.reason : "record", index);
      if (index === 0) roster.devices.clear();
      break;
    }
  }
  if (partial) return { roster, error };
  if (error) throw error;
  return roster;
}

async function applyRecord(roster, index, record) {
  if (record === null || typeof record !== "object" || !["n", "entry", "sig", "prev"].every((k) => k in record)) {
    throw new Refused("record");
  }
  if (!isInt(record.n) || record.n !== index + 1) throw new Refused("n");
  if (record.prev !== (index ? roster.head : "")) throw new Refused("chain");
  const entry = record.entry;
  if (entry === null || typeof entry !== "object" || typeof entry.kind !== "string" || !isId(entry.by)) {
    throw new Refused("record");
  }
  const { kind, by } = entry;
  if (!KINDS.has(kind)) throw new Refused("kind");
  if ((index === 0) !== (kind === "genesis")) throw new Refused("genesis");
  let signerPub;
  if (kind === "genesis") {
    if (!isId(entry.creator.device) || by !== entry.creator.device) throw new Refused("signer");
    signerPub = entry.creator.sign_pub;
  } else if (kind === "join") {
    if (!isId(entry.device) || by !== entry.device) throw new Refused("signer");
    signerPub = entry.sign_pub;
  } else {
    const signer = roster.active(by);
    if (!signer) throw new Refused("signer");
    signerPub = signer.sign_pub;
  }
  if (!isJwk(signerPub) || !(await verifyObject(signerPub, entryBody(entry, record.n, record.prev), record.sig))) {
    throw new Refused("signature");
  }
  await APPLY[kind](roster, entry, record.n);
  roster.n = index + 1;
  roster.head = await recordHash(record);
}

function newDevice(kind, role, signPub, recvPub, member, at, status = "active", invite = null) {
  return {
    kind,
    role,
    status,
    member,
    sign_pub: reduceJwk(signPub),
    recv_pub: recvPub ? reduceJwk(recvPub) : null,
    invite,
    activeFrom: status === "active" ? at : null,
    removedAt: null,
  };
}

function owner(roster, by) {
  if (roster.devices.get(by).role !== "owner") throw new Refused("not_owner");
}

function ownersLeft(roster) {
  for (const d of roster.devices.values()) if (d.status === "active" && d.role === "owner") return;
  throw new Refused("last_owner");
}

const APPLY = {
  genesis(roster, e, at) {
    const c = e.creator;
    const k = e.custodian;
    if (!isId(e.room) || !isId(k.device) || !isJwk(c.recv_pub) || !isJwk(k.sign_pub)) throw new Refused("record");
    if (c.device === k.device) throw new Refused("device");
    roster.room = e.room;
    roster.devices.set(c.device, newDevice("device", "owner", c.sign_pub, c.recv_pub, c.device, at));
    roster.devices.set(k.device, newDevice("custodian", "owner", k.sign_pub, null, k.device, at));
  },

  invite(roster, e) {
    owner(roster, e.by);
    if (
      !isId(e.invite) ||
      !isJwk(e.invite_pub) ||
      !isInt(e.uses) ||
      e.uses < 1 ||
      !isInt(e.expires_at) ||
      typeof e.approval !== "boolean" ||
      roster.invites.has(e.invite)
    ) {
      throw new Refused("record");
    }
    roster.invites.set(e.invite, {
      pub: reduceJwk(e.invite_pub),
      uses: e.uses,
      used: 0,
      expires_at: e.expires_at,
      approval: e.approval,
      closed: false,
    });
  },

  async join(roster, e, at) {
    if (!isJwk(e.recv_pub) || !isId(e.invite) || !isInt(e.at) || typeof e.invite_sig !== "string") {
      throw new Refused("record");
    }
    if (roster.devices.has(e.device)) throw new Refused("device");
    const invite = roster.invites.get(e.invite);
    if (!invite) throw new Refused("invite_unknown");
    if (!(await verifyObject(invite.pub, joinBody(e), e.invite_sig))) throw new Refused("invite_signature");
    if (invite.closed) throw new Refused("invite_closed");
    if (invite.used >= invite.uses) throw new Refused("invite_used");
    if (e.at >= invite.expires_at) throw new Refused("invite_expired");
    invite.used += 1;
    const status = invite.approval ? "pending" : "active";
    roster.devices.set(
      e.device,
      newDevice("device", "member", e.sign_pub, e.recv_pub, e.device, at, status, e.invite),
    );
  },

  approve(roster, e, at) {
    owner(roster, e.by);
    const d = roster.devices.get(e.device);
    if (!d || d.status !== "pending") throw new Refused("state");
    d.status = "active";
    d.activeFrom = at;
  },

  async link(roster, e) {
    const a = roster.devices.get(e.by);
    const id = e.device;
    const b = roster.active(id);
    const linked = [...roster.devices].some(([other, d]) => other !== id && d.member === id);
    if (a.kind !== "device" || !b || b.kind !== "device" || id === e.by || b.member !== id || linked) {
      throw new Refused("state");
    }
    if (!(await verifyObject(b.sign_pub, linkBody(a.member, id), e.device_sig))) throw new Refused("link_signature");
    b.member = a.member;
    if (a.role === "owner") b.role = "owner";
  },

  remove(roster, e, at) {
    const targets = e.devices;
    if (!Array.isArray(targets) || targets.length === 0 || new Set(targets).size !== targets.length) {
      throw new Refused("record");
    }
    const by = roster.devices.get(e.by);
    for (const t of targets) {
      const d = roster.devices.get(t);
      if (!d || d.status === "removed") throw new Refused("state");
      if (by.role !== "owner" && d.member !== by.member) throw new Refused("not_owner");
    }
    for (const t of targets) {
      const d = roster.devices.get(t);
      d.status = "removed";
      d.removedAt = at;
    }
    ownersLeft(roster);
  },

  promote(roster, e) {
    setRole(roster, e, "owner", "member");
  },

  demote(roster, e) {
    setRole(roster, e, "member", "owner");
  },

  "close-invite"(roster, e) {
    owner(roster, e.by);
    const invite = roster.invites.get(e.invite);
    if (!invite) throw new Refused("invite_unknown");
    if (invite.closed) throw new Refused("state");
    invite.closed = true;
  },
};

function setRole(roster, e, to, from) {
  owner(roster, e.by);
  const d = roster.active(e.device);
  if (!d || d.role !== from) throw new Refused("state");
  d.role = to;
  ownersLeft(roster);
}

/** Whether a device was active at roster record `at` (after replaying records 1..at). */
function activeAt(device, at) {
  return device.activeFrom !== null && device.activeFrom <= at && (device.removedAt === null || at < device.removedAt);
}

/**
 * Check an epoch against a verified roster (ROOMS.md 4.4). The epoch names the record
 * `roster` its creator had verified; the creator and every device in `wraps` must be
 * active devices of kind `device` at that record, and `roster` never decreases as `n`
 * grows over the epochs accepted `before` (an iterable of epochs). Throws Refused.
 */
export async function acceptEpoch(roster, room, epoch, before = []) {
  if (roster.room !== room) throw new Refused("room");
  if (!isInt(epoch?.n) || epoch.n < 1 || epoch.wraps === null || typeof epoch.wraps !== "object") {
    throw new Refused("record");
  }
  const at = epoch.roster;
  if (!isInt(at) || at < 1 || at > roster.n) throw new Refused("roster");
  const creator = roster.device(epoch.creator);
  if (!creator || creator.kind !== "device" || !activeAt(creator, at) || !Object.hasOwn(epoch.wraps, epoch.creator)) {
    throw new Refused("creator");
  }
  if (!(await verifyObject(creator.sign_pub, epochBody(room, epoch), epoch.sig))) throw new Refused("signature");
  for (const id of Object.keys(epoch.wraps)) {
    const d = roster.device(id);
    if (!d || d.kind !== "device" || !activeAt(d, at)) throw new Refused("unknown_device");
  }
  for (const earlier of before) {
    if (earlier.n < epoch.n && earlier.roster > at) throw new Refused("roster_order");
  }
}
