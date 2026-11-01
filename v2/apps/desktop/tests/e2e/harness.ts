/**
 * The e2e harness: `test` with an `app` fixture.
 *
 *   test("...", async ({ app }) => {
 *     const broker = await app.open({ broker: { locked: true } });   // fixture broker; `broker: false` = no Tauri shell at all
 *     await expect(app.screen("S16 Lock screen")).toBeVisible();
 *     ...
 *   });
 *
 * It serves build-test/ (the test build: the production bundle plus the `window.__cm` handle) exactly as Tauri would, with the
 * production Content-Security-Policy read from src-tauri/tauri.conf.json on the HTML, and records everything that should never
 * happen: a policy violation, a console error, an uncaught page error, a failed or same-origin 404 request, a request that
 * leaves the app's origin (it is aborted).  When the test ends the fixture asserts all of those are empty, so EVERY spec is
 * also a CSP spec.  A spec that provokes one on purpose says so (`expectConsoleError`, `takeViolations`).
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test as base, type Locator, type Page } from "@playwright/test";

import { productionCsp } from "../../scripts/verify-csp.mjs";
import { installBroker, type Broker, type BrokerOptions, type Scripted } from "../fixtures/broker/index";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");
const BUILD_DIR = join(ROOT, "build-test");
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

export interface OpenOptions {
  /** The fixture broker's starting state, or `false` for a page with no Tauri shell (the app then runs on its demo data). */
  broker?: BrokerOptions | false;
  /** Scripted answers installed before the app starts, so they apply to its very first calls (e.g. the boot status). */
  script?: Record<string, Scripted[]>;
  /** Rewrite the served index.html (used by the canary that injects inline code). */
  htmlTransform?: (html: string) => string;
}

export class App {
  readonly violations: string[] = [];
  readonly consoleErrors: string[] = [];
  readonly pageErrors: string[] = [];
  readonly failedRequests: string[] = [];
  readonly external: string[] = [];
  readonly notFound: string[] = [];
  broker: Broker | null = null;
  private readonly allowedConsole: RegExp[] = [];

  constructor(readonly page: Page) {}

  /** `[data-screen-label="…"]`, the design's own name for each screen. */
  screen(label: string): Locator {
    return this.page.locator(`[data-screen-label="${label}"]`).first();
  }

  /** This test provokes a console error on purpose: ignore ones that match, still fail on any other. */
  expectConsoleError(re: RegExp): void {
    this.allowedConsole.push(re);
  }

  /** Take (and forget) the CSP violations seen so far.  For the canary only. */
  takeViolations(): string[] {
    return this.violations.splice(0);
  }

  async open(options: OpenOptions = {}): Promise<Broker | null> {
    const { page } = this;
    if (!existsSync(join(BUILD_DIR, "index.html"))) {
      throw new Error(`${BUILD_DIR}/index.html is missing - run "npm run build:test" first (npm run test:e2e does)`);
    }
    const csp = productionCsp();

    await page.exposeFunction("__reportCsp", (v: string) => this.violations.push(v));
    await page.addInitScript(() => {
      document.addEventListener("securitypolicyviolation", (e) => (window as any).__reportCsp(`${e.violatedDirective} ${e.blockedURI} ${(e.sample || "").slice(0, 80)}`));
    });
    if (options.broker !== false) {
      this.broker = await installBroker(page, options.broker ?? {});
      for (const [cmd, responses] of Object.entries(options.script ?? {})) {
        await page.addInitScript(([c, r]) => (window as any).__BROKER__.script(c, r), [cmd, responses] as const);
      }
    }

    await page.route("**/*", (route) => {
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
      let body = readFileSync(file);
      const headers: Record<string, string> = { "content-type": MIME[extname(file)] || "application/octet-stream" };
      if (path.endsWith(".html")) {
        headers["content-security-policy"] = csp;
        if (options.htmlTransform) body = Buffer.from(options.htmlTransform(body.toString("utf8")));
      }
      return route.fulfill({ status: 200, headers, body });
    });

    page.on("console", (m) => {
      if (m.type() === "error") this.consoleErrors.push(m.text().slice(0, 300));
    });
    page.on("pageerror", (e) => this.pageErrors.push(String(e.message || e).slice(0, 300)));
    page.on("requestfailed", (r) => {
      if (r.url().startsWith(ORIGIN)) this.failedRequests.push(`${r.url()} ${r.failure()?.errorText || ""}`);
    });

    await page.goto(`${ORIGIN}/index.html`, { waitUntil: "load" });
    return this.broker;
  }

  /** The invariants every spec ends with. */
  assertClean(): void {
    const unexpected = this.consoleErrors.filter((m) => !this.allowedConsole.some((re) => re.test(m)));
    expect(this.violations, "CSP violations").toEqual([]);
    expect(unexpected, "console errors").toEqual([]);
    expect(this.pageErrors, "uncaught page errors").toEqual([]);
    expect(this.failedRequests, "failed requests").toEqual([]);
    expect(this.external, "requests that left the app origin").toEqual([]);
    expect(this.notFound, "same-origin 404s").toEqual([]);
  }

  /** Everything the page keeps in local and session storage, as one string (to prove a value is not in it). */
  storageDump(): Promise<string> {
    return this.page.evaluate(() => {
      const out: string[] = [];
      for (const s of [localStorage, sessionStorage]) for (let i = 0; i < s.length; i++) out.push(`${s.key(i)}=${s.getItem(s.key(i) as string)}`);
      return out.join("\n");
    });
  }

  /** The model's current view as JSON (test builds only: `window.__cm` is the logic class). */
  viewJson(): Promise<string> {
    return this.page.evaluate(() => JSON.stringify((window as any).__cm.vault));
  }

  /** How many revealed values the model holds right now (never their content). */
  secretCount(): Promise<number> {
    return this.page.evaluate(() => (window as any).__cm.model.secretCount);
  }
}

export const test = base.extend<{ app: App }>({
  app: async ({ page }, use) => {
    const app = new App(page);
    await use(app);
    app.assertClean();
  },
});

export { expect };
export type { Locator, Page };
