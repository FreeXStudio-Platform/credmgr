/**
 * The real-broker harness: `test` with an `app` fixture whose backend is a REAL `credmgrd` on a throwaway vault.
 *
 *   test("...", async ({ app }) => {
 *     await app.open();                                   // the BUILT app (build/), production CSP, shell replaced by the shim
 *     await expect(app.screen("S17 First run")).toBeVisible();
 *     ...
 *     await app.restartDaemon();                          // SIGTERM + start again on the same vault
 *   });
 *
 * What is real: the bundle (`build/`, the release build: no demo vault, no `window.__cm`), the production Content-Security-Policy
 * (read from tauri.conf.json), `src/lib/bridge.ts`, the model and the screens, the wire protocol, `credmgrd`, the vault on disk.
 * What is replaced: the Tauri shell, by the shim (tests/real/shim): `window.__TAURI_INTERNALS__.invoke` runs the shell's command
 * layer in Node and talks to the daemon over its Unix socket. The shim holds the login token, as the shell does; the page never
 * sees it (checked at the end of every test).
 *
 * Every test also ends by asserting what the other e2e suites assert: 0 CSP violations, 0 console errors, 0 uncaught page errors,
 * 0 failed or 404 requests, 0 requests that leave the app's origin (they are aborted) — plus the real-broker invariants: the
 * shim threw nothing of its own, the daemon holds no TCP socket and no file outside its throwaway root, and no login token is
 * anywhere the page can read.
 *
 * No server process serves the bundle and no TCP port is opened by this suite: files are answered from disk by `page.route`.
 */
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { dirname, extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test as base, type Locator, type Page, type TestInfo } from "@playwright/test";

import { productionCsp } from "../../scripts/verify-csp.mjs";
import { Daemon } from "./daemon.mjs";
import { Oracle } from "./oracle.mjs";
import { pageShimSource } from "./shim/page.mjs";
import { Shim } from "./shim/shim.mjs";
import { randomTotpSeed } from "./totp.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
export const APP_ROOT = resolve(HERE, "../..");
const BUILD_DIR = join(APP_ROOT, "build");
/** Fully intercepted, never resolved. */
export const ORIGIN = "https://tauri.localhost";

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".woff2": "font/woff2",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
};

function newestMtime(path: string, skip: (p: string) => boolean = () => false): number {
  if (!existsSync(path)) return 0;
  const st = statSync(path);
  if (!st.isDirectory()) return st.mtimeMs;
  let newest = 0;
  for (const name of readdirSync(path)) {
    const p = join(path, name);
    if (skip(p)) continue;
    newest = Math.max(newest, newestMtime(p, skip));
  }
  return newest;
}

let freshnessChecked = false;
/**
 * A green run must be a run of THIS source. If build/ is older than the front-end sources, or credmgrd older than the Rust
 * sources, the suite refuses to run rather than pass against a stale artefact: `npm run test:real` rebuilds both first.
 */
export function assertFresh(): void {
  if (freshnessChecked || process.env.CREDMGR_REAL_SKIP_STALE_CHECK === "1") return;
  const bundle = join(BUILD_DIR, "index.html");
  if (!existsSync(bundle)) throw new Error(`${bundle} is missing: run "npm run test:real" (it builds the app first) or "npm run build"`);
  const frontSources = Math.max(
    newestMtime(join(APP_ROOT, "src")),
    newestMtime(join(APP_ROOT, "index.html")),
    newestMtime(join(APP_ROOT, "vite.config.ts")),
    newestMtime(join(APP_ROOT, "scripts/dc")),
    newestMtime(join(APP_ROOT, "src-tauri/tauri.conf.json")),
  );
  if (statSync(bundle).mtimeMs < frontSources) throw new Error("build/ is older than the front-end sources: run \"npm run build\" (or \"npm run test:real\", which does) so the suite tests this code");
  const binary = new Daemon(".").binary;
  if (!existsSync(binary)) throw new Error(`${binary} is missing: run "npm run test:real" (it builds credmgrd first)`);
  const v2 = resolve(APP_ROOT, "../..");
  const rustSources = Math.max(
    newestMtime(join(v2, "crates"), (p) => p.includes(`${sep}target${sep}`)),
    newestMtime(join(v2, "Cargo.toml")),
    newestMtime(join(v2, "Cargo.lock")),
  );
  if (statSync(binary).mtimeMs < rustSources) throw new Error("credmgrd is older than the Rust sources: run \"cargo build -p credmgr-brokerd --bin credmgrd\" (or \"npm run test:real\", which does)");
  freshnessChecked = true;
}

/** A test passphrase and value factory: generated per run, obviously not credentials of anything. */
export function fixtureSecret(label: string): string {
  return `real-e2e ${label} ${Math.random().toString(36).slice(2, 10)}`;
}

/** A TOTP seed for a fixture entry: random per call, 32 base32 characters, never a literal in a spec. */
export function fixtureTotpSeed(): string {
  return randomTotpSeed();
}

export interface OpenOptions {
  /** Rewrite what the bundle serves (path, bytes -> bytes). For canaries only: a mutated control or an injected inline script. */
  transform?: (path: string, body: Buffer) => Buffer;
}

export class RealApp {
  readonly violations: string[] = [];
  readonly consoleErrors: string[] = [];
  readonly pageErrors: string[] = [];
  readonly failedRequests: string[] = [];
  readonly external: string[] = [];
  readonly notFound: string[] = [];
  /** Anything the shim itself threw that was not a bridge error: a bug in the harness, never a legitimate answer. */
  readonly shimFaults: string[] = [];
  private readonly allowedConsole: RegExp[] = [];

  daemon!: Daemon;
  shim!: Shim;
  oracle!: Oracle;

  constructor(readonly page: Page, readonly passphrase: string) {}

  private transform: OpenOptions["transform"];

  async start(): Promise<void> {
    assertFresh();
    this.daemon = await Daemon.start();
    this.shim = new Shim({ socketPath: this.daemon.socketPath });
    this.oracle = new Oracle(this.daemon.socketPath, this.passphrase);
    const conf = JSON.parse(readFileSync(join(APP_ROOT, "src-tauri/tauri.conf.json"), "utf8"));

    await this.page.exposeFunction("__realInvoke", async (cmd: string, args: unknown) => {
      try {
        return { ok: true, value: await this.shim.invoke(cmd, args) };
      } catch (e: any) {
        if (typeof e === "string") return { ok: false, error: e };
        if (e && typeof e === "object" && typeof e.source === "string" && typeof e.code === "string") return { ok: false, error: e };
        this.shimFaults.push(`${cmd}: ${String(e?.stack ?? e)}`);
        return { ok: false, error: { source: "bridge", code: "internal", message: `shim fault: ${String(e?.message ?? e)}` } };
      }
    });
    await this.page.exposeFunction("__reportCsp", (v: string) => this.violations.push(v));
    await this.page.addInitScript(() => {
      document.addEventListener("securitypolicyviolation", (e) => (window as any).__reportCsp(`${e.violatedDirective} ${e.blockedURI} ${(e.sample || "").slice(0, 80)}`));
    });
    await this.page.addInitScript({ content: pageShimSource({ version: conf.version, homeDir: this.daemon.homeDir }) });

    const csp = productionCsp();
    await this.page.route("**/*", (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== ORIGIN) {
        this.external.push(url.href);
        return route.abort();
      }
      const path = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
      const file = join(BUILD_DIR, path);
      if (!file.startsWith(BUILD_DIR) || !existsSync(file)) {
        this.notFound.push(path);
        return route.fulfill({ status: 404, body: "not found" });
      }
      const headers: Record<string, string> = { "content-type": MIME[extname(file)] || "application/octet-stream" };
      if (path.endsWith(".html")) headers["content-security-policy"] = csp;
      const bytes = readFileSync(file);
      return route.fulfill({ status: 200, headers, body: this.transform ? this.transform(path, bytes) : bytes });
    });
    this.page.on("console", (m) => {
      if (m.type() === "error") this.consoleErrors.push(m.text().slice(0, 300));
    });
    this.page.on("pageerror", (e) => this.pageErrors.push(String(e.message || e).slice(0, 300)));
    this.page.on("requestfailed", (r) => {
      if (r.url().startsWith(ORIGIN)) this.failedRequests.push(`${r.url()} ${r.failure()?.errorText || ""}`);
    });
  }

  /** Load the built app. */
  async open(options: OpenOptions = {}): Promise<void> {
    this.transform = options.transform;
    await this.page.goto(`${ORIGIN}/index.html`, { waitUntil: "load" });
  }

  /** `[data-screen-label="…"]`, the design's own name for each screen. */
  screen(label: string): Locator {
    return this.page.locator(`[data-screen-label="${label}"]`).first();
  }

  /** Take (and forget) the CSP violations and off-origin requests seen so far. For the canaries only. */
  takeViolations(): { violations: string[]; external: string[] } {
    return { violations: this.violations.splice(0), external: this.external.splice(0) };
  }

  /** A provoked console error is allowed to match; any other still fails the test. */
  expectConsoleError(re: RegExp): void {
    this.allowedConsole.push(re);
  }

  /** The commands the app invoked, oldest first (all, or only `cmd`). Arguments are copies. */
  calls(cmd?: string): Array<{ cmd: string; args: Record<string, any> }> {
    return this.shim.calls.filter((c: any) => !cmd || c.cmd === cmd);
  }

  /**
   * The broker's answer to the `nth` (default: last) call of `cmd`, once it has COMPLETED. A frame is logged when it is sent and an
   * answer when it returns, so a test that reads the answer straight after a click can win a race with the broker; this waits.
   */
  async answerOf(cmd: string, nth = -1): Promise<{ cmd: string; result?: any; error?: any }> {
    const find = () => {
      const all = this.shim.answers.filter((a: any) => a.cmd === cmd);
      return nth < 0 ? all.at(nth) : all[nth];
    };
    await expect.poll(() => find() !== undefined, { message: `no completed answer for ${cmd}`, timeout: 15_000 }).toBe(true);
    return find();
  }

  /** The shell-plugin commands the page made (`plugin:app|version`, `plugin:path|resolve_directory`, event listen/unlisten), oldest first. */
  pluginCalls(): Promise<Array<{ cmd: string; args: Record<string, any> }>> {
    return this.page.evaluate(() => (window as any).__REAL__.pluginCalls());
  }

  /** The broker frames the shim sent (`op` and `params`), oldest first (all, or only `op`). */
  frames(op?: string): Array<{ op: string; params: Record<string, any> }> {
    return this.shim.wire.filter((w: any) => !op || w.op === op);
  }

  /** The commands, as bare names, in order. */
  commands(): string[] {
    return this.shim.calls.map((c: any) => c.cmd);
  }

  async restartDaemon(options: { crash?: boolean } = {}): Promise<void> {
    await this.daemon.restart(options);
  }

  /** Everything the page keeps in local and session storage, as one string. */
  storageDump(): Promise<string> {
    return this.page.evaluate(() => {
      const out: string[] = [];
      for (const s of [localStorage, sessionStorage]) for (let i = 0; i < s.length; i++) out.push(`${s.key(i)}=${s.getItem(s.key(i) as string)}`);
      return out.join("\n");
    });
  }

  /** The page's whole DOM plus its storage: the places a secret must not be left. */
  async pageDump(): Promise<string> {
    return (await this.page.content()) + (await this.storageDump());
  }

  /** The invariants every test ends with. */
  async assertClean(): Promise<void> {
    const unexpected = this.consoleErrors.filter((m) => !this.allowedConsole.some((re) => re.test(m)));
    expect(this.violations, "CSP violations").toEqual([]);
    expect(unexpected, "console errors").toEqual([]);
    expect(this.pageErrors, "uncaught page errors").toEqual([]);
    expect(this.failedRequests, "failed requests").toEqual([]);
    expect(this.external, "requests that left the app origin").toEqual([]);
    expect(this.notFound, "same-origin 404s").toEqual([]);
    expect(this.shimFaults, "the shim itself threw (a harness bug, not a broker answer)").toEqual([]);

    // The login token is the shell's alone: not in the DOM, not in storage. The token SHAPE is looked for whether or not the shim
    // still holds a login: a test that ends locked (or after a session ended) must not have left one behind on the page either.
    if (!this.page.isClosed()) {
      const token = this.shim.session.token();
      const dump = await this.pageDump();
      if (token) expect(dump.includes(token), "the session token is readable by the page").toBe(false);
      expect(/cmt_[0-9a-f]{8,}/i.test(dump), "something shaped like a session token is in the page").toBe(false);
    }
    // The daemon: one Unix socket, no TCP, nothing outside its throwaway root.
    if (this.daemon.pid) {
      expect(this.daemon.networkSockets(), "the daemon holds a network socket").toEqual([]);
      expect(heldOutsideRoot(this.daemon), "the daemon holds files outside its throwaway root").toEqual([]);
    }
  }
}

const withoutPrivate = (p: string): string => p.replace(/^\/private/, "");

/**
 * Whether a path is somewhere a user's data could live: the system's own libraries and devices are not, and neither is the daemon's
 * own executable, wherever it was built (CREDMGRD_BIN, CARGO_TARGET_DIR, the release profile) - the file `lsof` lists for a running
 * program is the program itself.
 */
export function isUserPath(name: string, binary: string): boolean {
  if (/^\/(usr|System|Library\/Apple|private\/var\/db|dev|opt\/homebrew\/Cellar|private\/etc|etc)\b/.test(name)) return false;
  let own = binary;
  try {
    own = realpathSync(binary);
  } catch {
    // the binary is gone: compare by the path we were given
  }
  return withoutPrivate(name) !== withoutPrivate(own) && withoutPrivate(name) !== withoutPrivate(binary);
}

/**
 * The files, directories and sockets a daemon holds open (from `lsof`) that could be a user's data and are not inside its own
 * throwaway root. Must always be empty. Only the daemon's own executable is exempted, by exact path.
 */
export function heldOutsideRoot(daemon: Daemon): Array<{ type: string; name: string }> {
  return daemon
    .openPaths()
    .filter((p: { type: string; name: string }) => (p.type === "REG" || p.type === "DIR" || p.type === "unix") && p.name.startsWith("/") && isUserPath(p.name, daemon.binary) && !isUnderRoot(p.name, daemon.root));
}

function isUnderRoot(name: string, root: string): boolean {
  const real = (p: string) => p.replace(/^\/private/, "");
  return real(name).startsWith(real(root));
}

export const test = base.extend<{ app: RealApp }>({
  app: async ({ page }, use, testInfo: TestInfo) => {
    const app = new RealApp(page, fixtureSecret("passphrase"));
    await app.start();
    let failed = false;
    try {
      await use(app);
      await app.assertClean();
    } catch (e) {
      failed = true;
      throw e;
    } finally {
      if (failed || testInfo.status !== testInfo.expectedStatus) {
        await testInfo.attach("credmgrd.log", { body: app.daemon.logTail(60), contentType: "text/plain" }).catch(() => {});
        await testInfo.attach("commands.json", { body: JSON.stringify(app.commands(), null, 1), contentType: "application/json" }).catch(() => {});
        await testInfo.attach("timings.json", { body: JSON.stringify(app.shim.timings), contentType: "application/json" }).catch(() => {});
      }
      await app.daemon.dispose();
    }
  },
});

export { expect };
export type { Locator, Page };
