/** The two stores API.md ships, and the state format they carry. */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { RelayError } from "../src/errors.js";
import { fileStore, webStore } from "../src/store.js";

test("webStore keeps state in localStorage", async () => {
  const data = new Map();
  globalThis.localStorage = {
    getItem: (name) => data.get(name) ?? null,
    setItem: (name, value) => data.set(name, String(value)),
  };
  try {
    const store = webStore("relay-guest");
    assert.equal(await store.load(), null);
    await store.save({ v: 1, hosts: [] });
    assert.deepEqual(await store.load(), { v: 1, hosts: [] });

    data.set("relay-guest", "not JSON");
    await assert.rejects(store.load(), RelayError);
  } finally {
    delete globalThis.localStorage;
  }
});

test("fileStore replaces its file atomically at mode 0600", async () => {
  const directory = mkdtempSync(join(tmpdir(), "relay-js-store-"));
  try {
    const path = join(directory, "state", "host");
    const store = fileStore(path);
    assert.equal(await store.load(), null);
    await store.save({ v: 1, static: "00" });
    assert.deepEqual(await store.load(), { v: 1, static: "00" });
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(statSync(join(directory, "state")).mode & 0o777, 0o700);

    await store.save({ v: 1, static: "11" });
    assert.deepEqual(await store.load(), { v: 1, static: "11" });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
