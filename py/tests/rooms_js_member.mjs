// A JS room member (js/src/rooms, the R3 `Room`) driven over stdin by the Python
// cross-language test: one JSON command per line, one JSON answer per line.
//   {"id": "a", "op": "create", "baseUrl", "credential", "custodianSignPub"}
//   {"id": "b", "op": "join", "link", "baseUrl"}
//   {"id": "a", "op": "invite"}            -> {"link"}
//   {"id": "a", "op": "send", "text", "file"?}   -> {"seq", "epoch", "blob"}
//   {"id": "a", "op": "sync"}              -> {"messages": [{seq, device, n, epoch, text, blob, file?}], "refused", "gaps"}
//   {"id": "a", "op": "remove", "devices"} -> {"failed"}
import { createInterface } from "node:readline";

import { Room, softwareDeviceKeys } from "../../js/src/rooms/index.js";

const rooms = new Map();
const text = (bytes) => new TextDecoder().decode(bytes);
const bytes = (s) => new TextEncoder().encode(s);
const inAWeek = () => Math.floor(Date.now() / 1000) + 7 * 86400;

async function run(cmd) {
  const room = rooms.get(cmd.id);
  switch (cmd.op) {
    case "create": {
      const { room: r, created } = await Room.create({
        baseUrl: cmd.baseUrl,
        credential: cmd.credential,
        keys: await softwareDeviceKeys(),
        custodianSignPub: cmd.custodianSignPub,
      });
      rooms.set(cmd.id, r);
      return { room: r.id, device: r.device, token: r.token, custodian: created.custodian };
    }
    case "join": {
      const r = await Room.join(cmd.link, await softwareDeviceKeys(), { baseUrl: cmd.baseUrl });
      rooms.set(cmd.id, r);
      return { room: r.id, device: r.device, token: r.token };
    }
    case "invite":
      return { link: (await room.invite({ uses: 1, expiresAt: inAWeek(), appUrl: "https://app.example/j" })).link };
    case "send": {
      const sent = await room.send(bytes(cmd.text), cmd.file === undefined ? {} : { file: bytes(cmd.file) });
      return { seq: sent.seq, epoch: sent.epoch, blob: sent.blob ?? null };
    }
    case "sync": {
      const seen = await room.sync();
      const messages = [];
      for (const m of seen.messages) {
        const out = { seq: m.seq, device: m.device, n: m.n, epoch: m.epoch, text: text(m.plaintext), blob: m.blob ?? null };
        if (m.blob !== undefined) out.file = text(await room.fetchFile(m));
        messages.push(out);
      }
      return { messages, refused: seen.refused, gaps: seen.gaps, dropped: seen.dropped };
    }
    case "remove":
      return { failed: await room.remove(cmd.devices) };
    default:
      throw new Error(`unknown op ${cmd.op}`);
  }
}

const lines = createInterface({ input: process.stdin });
for await (const line of lines) {
  let answer;
  try {
    answer = { ok: true, result: await run(JSON.parse(line)) };
  } catch (error) {
    answer = { ok: false, error: String(error?.stack ?? error), status: error?.status ?? null };
  }
  process.stdout.write(JSON.stringify(answer) + "\n");
}
