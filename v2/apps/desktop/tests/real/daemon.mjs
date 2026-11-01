/**
 * A real `credmgrd` on a throwaway vault.
 *
 *   const d = await Daemon.start();         // mkdtemp root, fresh vault dir, daemon listening on <root>/v/run/broker.sock
 *   await d.restart();                      // SIGTERM, wait, start again on the SAME vault (the data must survive)
 *   await d.dispose();                      // stop, delete the root
 *
 * Isolation is the point of this file. The daemon resolves its vault from `CREDMGR_VAULT_DIR` (and its software-counter state from
 * `CREDMGR_STATE_DIR`); both are set to directories under a fresh `cmreal-*` temp root, and `HOME` is too, so even a daemon that
 * ignored the overrides would default to a path inside the throwaway home. The parent environment is NOT inherited: no
 * `CREDMGR_*` variable, no token, nothing of the developer's vault can reach the child. {@link Daemon.openPaths} lists the files
 * and sockets the live process really holds so a test can prove the daemon never touched anything outside its root.
 *
 * Nothing here opens a TCP port: the daemon's only listener is the Unix socket.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const V2_ROOT = resolve(HERE, "../../../..");

/** A Unix socket path must stay under ~104 bytes on macOS. */
const MAX_SOCKET_BYTES = 100;
const ROOT_PREFIX = "cmreal-";

/** Where `cargo build -p credmgr-brokerd --bin credmgrd` puts the binary (honours CARGO_TARGET_DIR, like cargo). */
export function daemonBinary() {
  if (process.env.CREDMGRD_BIN) return resolve(process.env.CREDMGRD_BIN);
  const target = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : join(V2_ROOT, "target");
  return join(target, process.env.CREDMGR_REAL_PROFILE ?? "debug", "credmgrd");
}

function pickBase() {
  for (const base of [os.tmpdir(), "/tmp"]) {
    const probe = join(base, `${ROOT_PREFIX}XXXXXX`, "v", "run", "broker.sock");
    if (Buffer.byteLength(probe) <= MAX_SOCKET_BYTES) return base;
  }
  throw new Error("no temp directory short enough for a Unix socket path");
}

/** Whether something accepts connections on `socketPath`. */
function canConnect(socketPath) {
  return new Promise((resolveOk) => {
    const s = net.createConnection({ path: socketPath });
    s.once("connect", () => {
      s.destroy();
      resolveOk(true);
    });
    s.once("error", () => resolveOk(false));
  });
}

export class Daemon {
  /** @type {import("node:child_process").ChildProcess | null} */
  proc = null;
  starts = 0;

  constructor(root) {
    this.root = root;
    this.vaultDir = join(root, "v");
    this.stateDir = join(root, "s");
    this.homeDir = join(root, "h");
    this.workDir = join(root, "work");
    this.socketPath = join(this.vaultDir, "run", "broker.sock");
    this.logPath = join(root, "credmgrd.log");
    this.binary = daemonBinary();
  }

  static async start() {
    const base = pickBase();
    const root = mkdtempSync(join(base, ROOT_PREFIX));
    const d = new Daemon(root);
    for (const dir of [d.vaultDir, d.stateDir, d.homeDir, d.workDir]) mkdirSync(dir, { recursive: true });
    await d.#spawn();
    return d;
  }

  /** The environment the child gets: built from scratch, never inherited. */
  #env() {
    return {
      PATH: "/usr/bin:/bin",
      HOME: this.homeDir,
      CREDMGR_VAULT_DIR: this.vaultDir,
      CREDMGR_STATE_DIR: this.stateDir,
      TMPDIR: join(this.root, "tmp"),
    };
  }

  async #spawn() {
    if (!existsSync(this.binary)) throw new Error(`credmgrd is not built at ${this.binary}: run "npm run test:real" (it builds it) or "cargo build -p credmgr-brokerd --bin credmgrd"`);
    mkdirSync(join(this.root, "tmp"), { recursive: true });
    const log = openSync(this.logPath, "a");
    const proc = spawn(this.binary, [], { env: this.#env(), cwd: this.root, stdio: ["ignore", log, log], detached: false });
    this.proc = proc;
    this.starts += 1;
    let exited = null;
    proc.once("exit", (code, signal) => {
      exited = { code, signal };
    });
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      if (exited) throw new Error(`credmgrd exited at start (${JSON.stringify(exited)}): ${this.logTail()}`);
      if (await canConnect(this.socketPath)) return;
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error(`credmgrd did not start listening on ${this.socketPath} within 15 s: ${this.logTail()}`);
  }

  get pid() {
    return this.proc?.pid ?? null;
  }

  logTail(lines = 12) {
    try {
      return readFileSync(this.logPath, "utf8").trim().split("\n").slice(-lines).join(" | ");
    } catch {
      return "(no log)";
    }
  }

  /** SIGTERM and wait for exit (SIGKILL after 5 s). Leaves the vault exactly as it is. */
  async stop() {
    const proc = this.proc;
    if (!proc || proc.exitCode !== null || proc.signalCode !== null) {
      this.proc = null;
      return;
    }
    await new Promise((resolveExit) => {
      const t = setTimeout(() => proc.kill("SIGKILL"), 5_000);
      proc.once("exit", () => {
        clearTimeout(t);
        resolveExit();
      });
      proc.kill("SIGTERM");
    });
    this.proc = null;
  }

  /** A crash, not a shutdown: SIGKILL, no chance to clean up. */
  async kill() {
    const proc = this.proc;
    if (!proc || proc.exitCode !== null || proc.signalCode !== null) return;
    await new Promise((resolveExit) => {
      proc.once("exit", resolveExit);
      proc.kill("SIGKILL");
    });
    this.proc = null;
  }

  /** Stop and start again on the same vault and the same socket path. */
  async restart({ crash = false } = {}) {
    if (crash) await this.kill();
    else await this.stop();
    await this.#spawn();
  }

  /** Stop the daemon and delete the throwaway root (unless CREDMGR_REAL_KEEP=1, for post-mortems). */
  async dispose() {
    await this.stop();
    if (process.env.CREDMGR_REAL_KEEP === "1") return;
    // Refuse to delete anything that is not a root this module made.
    const underTemp = this.root.startsWith(os.tmpdir() + sep) || this.root.startsWith("/tmp/");
    if (!basename(this.root).startsWith(ROOT_PREFIX) || !underTemp) {
      throw new Error(`refusing to delete ${this.root}: not a ${ROOT_PREFIX}* temp root`);
    }
    rmSync(this.root, { recursive: true, force: true });
  }

  /**
   * Every file, directory and socket the running daemon holds open, from `lsof` (the kernel's answer, not the daemon's).
   * Each entry is `{ type, name }`.
   */
  openPaths() {
    if (!this.pid) return [];
    const r = spawnSync("/usr/sbin/lsof", ["-nP", "-F", "tn", "-p", String(this.pid)], { encoding: "utf8" });
    if (r.status !== 0 && !r.stdout) throw new Error(`lsof failed: ${r.stderr}`);
    const out = [];
    let type = "";
    for (const line of r.stdout.split("\n")) {
      if (line.startsWith("t")) type = line.slice(1);
      else if (line.startsWith("n")) out.push({ type, name: line.slice(1) });
    }
    return out;
  }

  /** TCP/UDP sockets the daemon holds (must be none: its only listener is the Unix socket). */
  networkSockets() {
    return this.openPaths().filter((p) => p.type === "IPv4" || p.type === "IPv6");
  }

  /** Every file under the vault directory (relative paths), for "no plaintext on disk" scans. */
  vaultFiles() {
    const out = [];
    const walk = (dir) => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name);
        const st = statSync(p);
        if (st.isDirectory()) walk(p);
        else if (st.isFile()) out.push(p);
      }
    };
    for (const dir of [this.vaultDir, this.stateDir]) if (existsSync(dir)) walk(dir);
    return out;
  }
}
