// An echo host and a guest that pair through a relay and exchange one message.
//
//   RELAY_URL=ws://10.255.0.1:8010 RELAY_KEY=<project key> \
//       node js/examples/echo.mjs

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Guest, Host, Relay, fileStore } from "@syalia/relay";

const relay = process.env.RELAY_URL ?? "ws://10.255.0.1:8010";
const key = process.env.RELAY_KEY ?? "example-key";
const directory = await mkdtemp(join(tmpdir(), "relay-example-"));

const host = await Host.open(fileStore(join(directory, "host")), {
  relays: [new Relay(relay, { key })],
});
const guest = await Guest.open(fileStore(join(directory, "guest")));

const pairing = await host.pair("echo");
const link = await guest.pair(pairing.payload);
// A person reads link.code on the guest and types it into the host.
await pairing.confirm(link.code);
await link.bound();

const echo = (async () => {
  for await (const [sender, message] of host) await sender.send(message);
})();

const replies = link[Symbol.asyncIterator]();
await link.send(new TextEncoder().encode("hello from the guest"));
const { value } = await replies.next();
console.log(`guest received: ${new TextDecoder().decode(value)}`);

await link.unpair();
await guest.close();
await host.close();
await rm(directory, { recursive: true, force: true });
