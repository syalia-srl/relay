/**
 * The two stores API.md ships: a JSON file for Node, replaced atomically at mode
 * 0600 (PROTOCOL.md §10.2), and `localStorage` for browsers. Node's modules are
 * imported inside the calls so a browser bundle never loads them.
 */

import { RelayError } from "./errors.js";

/**
 * @typedef {object} Store
 * @property {() => Promise<object | null>} load The state, or null on the first run.
 * @property {(state: object) => Promise<void>} save Replace the state.
 */

/** The state format both roles write through a store. */
export const STATE_VERSION = 1;

/**
 * @param {string} path The JSON file to keep the state in.
 * @returns {Store} A store that replaces its file atomically, at mode 0600.
 */
export function fileStore(path) {
  return {
    async load() {
      const { readFile } = await import("node:fs/promises");
      let text;
      try {
        text = await readFile(path, "utf8");
      } catch (error) {
        if (error.code === "ENOENT") return null;
        throw new RelayError(`cannot read the state file: ${error.message}`);
      }
      try {
        return JSON.parse(text);
      } catch {
        throw new RelayError("the state file is not JSON");
      }
    },

    async save(state) {
      const { mkdir, open, rename, unlink } = await import("node:fs/promises");
      const { basename, dirname, join } = await import("node:path");
      const directory = dirname(path);
      let temporary = null;
      try {
        await mkdir(directory, { recursive: true });
        temporary = join(
          directory,
          `.${basename(path)}.${crypto.randomUUID()}.tmp`,
        );
        const handle = await open(temporary, "wx", 0o600);
        try {
          await handle.writeFile(JSON.stringify(state));
          await handle.sync();
        } finally {
          await handle.close();
        }
        await rename(temporary, path);
        temporary = null;
        const directoryHandle = await open(directory, "r");
        try {
          await directoryHandle.sync();
        } finally {
          await directoryHandle.close();
        }
      } catch (error) {
        if (temporary !== null) await unlink(temporary).catch(() => {});
        throw new RelayError(`cannot write the state file: ${error.message}`);
      }
    },
  };
}

/**
 * @param {string} name The `localStorage` key to keep the state under.
 * @returns {Store} A store backed by `localStorage`.
 */
export function webStore(name) {
  return {
    async load() {
      const text = globalThis.localStorage.getItem(name);
      if (text === null) return null;
      try {
        return JSON.parse(text);
      } catch {
        throw new RelayError("the state is not JSON");
      }
    },

    async save(state) {
      globalThis.localStorage.setItem(name, JSON.stringify(state));
    },
  };
}
