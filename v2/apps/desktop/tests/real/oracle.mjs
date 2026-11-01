/**
 * An independent client of the same daemon, used to check what the app did without trusting the app's own screens.
 *
 * The oracle is NOT the shim: it has its own login (the broker allows several), its own token, and it talks the socket protocol
 * directly. A test uses it to assert that a value the UI claimed to save is in the vault, to kill the app's login from outside
 * (`vault.lock` revokes every session token), and to play the part of an agent: a process with no token whose working directory
 * decides which node it may write to (the broker identifies the peer process, not the caller's claim).
 */
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { call } from "./shim/transport.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

export class Oracle {
  #token = null;

  constructor(socketPath, passphrase) {
    this.socketPath = socketPath;
    this.passphrase = passphrase;
  }

  /** One op with this oracle's token. */
  call(op, params = {}) {
    return call(this.socketPath, op, this.#token, params);
  }

  /** Log in with the passphrase (and a second-factor code when the gate asks for one). */
  async login(secondFactor) {
    this.#token = null;
    let value;
    try {
      value = await call(this.socketPath, "vault.unlock", null, { passphrase: this.passphrase });
    } catch (e) {
      if (e?.code !== "two_factor_required" || !secondFactor) throw e;
      value = await call(this.socketPath, "vault.gate_verify", null, { code: typeof secondFactor === "function" ? await secondFactor() : secondFactor });
    }
    this.#token = value.token;
    return this;
  }

  /** Revoke every session token, the app's included (ADR-056). */
  async lockVault() {
    const r = await this.call("vault.lock");
    this.#token = null;
    return r;
  }

  /**
   * The names in a node, with the stored values, by an independent route. An entry with several fields has no one value (ADR-078:
   * `entry.reveal` answers `value` only for a one-field entry), so it appears as the array of its `{label, value}` pairs instead.
   * @returns {Promise<Record<string, string | {label: string, value: string}[]>>}
   */
  async entries(node) {
    const list = await this.call("entry.list", { node });
    const out = {};
    for (let i = 0; i < list.ids.length; i++) {
      const r = await this.call("entry.reveal", { node, entry: list.ids[i] });
      out[list.names[i]] = r.value !== undefined ? r.value : r.fields.map((f) => ({ label: f.label, value: f.value }));
    }
    return out;
  }

  /**
   * One entry's fields, in stored order, with their values, by an independent route.
   * @returns {Promise<{id: string, label: string, value: string, type: string, masked: boolean}[]>}
   */
  async fieldsOf(node, name) {
    return (await this.call("entry.reveal", { node, entry: await this.entryId(node, name) })).fields;
  }

  /** What `entry.get` answers for one entry: field ids, labels, types and masking, never a value. */
  async entryMeta(node, name) {
    return this.call("entry.get", { node, entry: await this.entryId(node, name) });
  }

  /** Replace a node's note by an independent route (what `credmgr notes set` does): read the generation, write against it. */
  async setNote(node, markdown) {
    const { generation } = await this.call("notes.read", { node });
    return this.call("notes.write", { node, markdown, generation });
  }

  /** The ids of the nodes this login may list. */
  async nodeIds() {
    return (await this.call("node.list")).nodes;
  }

  /** What is waiting in a node's locked-write tray. */
  async pending(node) {
    return (await this.call("vault.pending_list", { node })).pending;
  }

  /** The id the broker gave the entry called `name` in `node`. */
  async entryId(node, name) {
    const list = await this.call("entry.list", { node });
    const i = list.names.indexOf(name);
    if (i < 0) throw new Error(`no entry called ${name} in ${node}`);
    return list.ids[i];
  }

  /**
   * A tokenless request from a process whose working directory is `cwd` — what an agent in a project folder is. Runs a child Node
   * process so the broker sees a real peer with that cwd.
   */
  static agent(socketPath, cwd, op, params = {}) {
    const r = spawnSync(process.execPath, [join(HERE, "agent-client.mjs"), socketPath, op, JSON.stringify(params)], { cwd, encoding: "utf8", env: { PATH: "/usr/bin:/bin" } });
    if (r.status !== 0 && !r.stdout) throw new Error(`agent client failed: ${r.stderr}`);
    return JSON.parse(r.stdout);
  }
}
