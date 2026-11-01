#!/usr/bin/env node
/**
 * verify-csp.mjs - the headless Content-Security-Policy gate.
 *
 *   node scripts/verify-csp.mjs [--dir build] [--engine webkit|chromium|all] [--no-drive] [--shots <dir>]
 *
 * It loads the BUILT front end the way Tauri serves it - every request is answered from the build directory by
 * a route handler, and the HTML carries the production policy read from src-tauri/tauri.conf.json - then fails on:
 *   - any `securitypolicyviolation` event (script, style, font, image, connect, frame, ...);
 *   - any console error, uncaught page error, failed or non-2xx same-origin request;
 *   - any request that leaves the app's origin (it is aborted, and counted);
 *   - the first screen not rendering, or the three font families not being usable.
 * Then it drives the UI (unlock, every dialog / overlay / settings section reachable by clicking) and asserts the
 * same again, so a violation that only happens when a screen is opened is still caught.
 *
 * A gate that has never failed proves nothing: three canaries re-run the page with an injected inline <style>,
 * an injected inline <script> and an injected remote stylesheet and REQUIRE the gate to see each of them.
 *
 * WebKit is the gate (same engine family as the WKWebView Tauri uses on macOS); Chromium is the second opinion.
 * The fakes are installed with addInitScript, which runs outside the page's CSP and so cannot weaken the policy under test.
 * The release build has no demo vault and no data of its own, so the drive below runs with the FIXTURE broker standing in for
 * the Tauri shell (tests/fixtures/broker) and an open vault behind it, exactly as the e2e specs do; the screens that depend on
 * what the broker says (first run, the Lock screen, a broker that is not there) are loaded again, once each, and must render clean.
 * A page with NO shell at all must show the broker-unreachable screen and nothing else: a release build never shows example data.
 */
import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { brokerScript, FIXTURE_PASSPHRASE } from "../tests/fixtures/broker/script.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const ORIGIN = "https://tauri.localhost"; // fully intercepted, never resolved

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".woff2": "font/woff2",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
};

/** The production CSP, as the header string Tauri would send. */
export function productionCsp() {
  const conf = JSON.parse(readFileSync(join(ROOT, "src-tauri", "tauri.conf.json"), "utf8"));
  const csp = conf.app?.security?.csp;
  if (!csp || typeof csp !== "object") throw new Error("tauri.conf.json: app.security.csp must be an object of directives");
  return Object.entries(csp)
    .map(([d, v]) => `${d} ${Array.isArray(v) ? v.join(" ") : v}`)
    .join("; ");
}

/**
 * Open the built app under the production CSP in `browserType` and report what happened.
 * @param {{ browserType: any, buildDir: string, csp?: string, htmlTransform?: (html: string) => string,
 *           drive?: boolean, shots?: string, init?: string[], inspect?: (page: any) => Promise<unknown> }} o
 */
export async function runOnce(o) {
  const csp = o.csp ?? productionCsp();
  const browser = await o.browserType.launch();
  const result = { violations: [], consoleErrors: [], pageErrors: [], failedRequests: [], external: [], notFound: [], steps: [], firstScreen: null, fonts: null, webCrypto: null };
  try {
    // `shots` mode is for a human to look at the screens: Playwright's screenshot helper injects a <style> element, which
    // the policy under test would (correctly) refuse and report.  So screenshots run with the policy NOT enforced and
    // the run is not a gate result.  Without --shots the policy is enforced and nothing is injected.
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, bypassCSP: !!o.shots });
    const page = await context.newPage();

    // Violations are reported to Node as they happen, so a reload or navigation cannot lose them.
    await page.exposeFunction("__reportCsp", (v) => result.violations.push(v));
    await page.addInitScript(() => {
      document.addEventListener("securitypolicyviolation", (e) => window.__reportCsp(`${e.violatedDirective} ${e.blockedURI} ${(e.sample || "").slice(0, 80)}`));
    });
    for (const script of o.init || []) await page.addInitScript({ content: script });

    await page.route("**/*", (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== ORIGIN) {
        result.external.push(url.href);
        return route.abort();
      }
      const path = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
      const file = join(o.buildDir, path);
      if (!file.startsWith(o.buildDir) || !existsSync(file)) {
        result.notFound.push(path);
        return route.fulfill({ status: 404, body: "not found" });
      }
      let body = readFileSync(file);
      const headers = { "content-type": MIME[extname(file)] || "application/octet-stream" };
      if (path.endsWith(".html")) {
        headers["content-security-policy"] = csp;
        if (o.htmlTransform) body = Buffer.from(o.htmlTransform(body.toString("utf8")));
      }
      return route.fulfill({ status: 200, headers, body });
    });

    page.on("console", (m) => {
      if (m.type() === "error") result.consoleErrors.push(m.text().slice(0, 300));
    });
    page.on("pageerror", (e) => result.pageErrors.push(String(e.message || e).slice(0, 300)));
    page.on("requestfailed", (r) => {
      if (!r.url().startsWith(ORIGIN)) return; // already counted as external
      result.failedRequests.push(`${r.url()} ${r.failure()?.errorText || ""}`);
    });

    await page.goto(`${ORIGIN}/index.html`, { waitUntil: "load" });
    await page.waitForSelector("[data-screen-label]", { timeout: 15000 }).catch(() => {});
    await page.waitForTimeout(400);

    result.firstScreen = await page.evaluate(() => {
      const host = document.querySelector("#dc-root > .sc-host");
      const label = document.querySelector("[data-screen-label]");
      return { hostRendered: !!host && host.children.length > 0, label: label ? label.getAttribute("data-screen-label") : null, elements: document.querySelectorAll("#dc-root *").length, errorPanel: !!document.querySelector("[data-error-boundary]") };
    });
    // The supporter extras are checked with Web Crypto (AES-GCM, PBKDF2): it exists only in a secure context.  The Tauri origin has to be one,
    // so this says so at start-up in both engines instead of leaving the code prompt to fail with a message about the code.
    result.webCrypto = await page.evaluate(() => ({ secureContext: window.isSecureContext, subtle: !!(globalThis.crypto && globalThis.crypto.subtle && typeof globalThis.crypto.subtle.deriveKey === "function") }));
    result.fonts = await page.evaluate(async () => {
      // Faces are loaded lazily (only when text uses them), so ask for every one: this proves all ten woff2 files are
      // reachable under `font-src 'self'`, not just the ones the first screen happens to draw.
      const wanted = [
        ...[400, 500, 600, 700].map((w) => `${w} 16px "Inter"`),
        ...[600, 700].map((w) => `${w} 16px "Inter Tight"`),
        ...[400, 500, 600, 700].map((w) => `${w} 16px "JetBrains Mono"`),
      ];
      await Promise.all(wanted.map((f) => document.fonts.load(f)));
      await document.fonts.ready;
      return {
        inter: document.fonts.check('16px "Inter"'),
        interTight: document.fonts.check('600 16px "Inter Tight"'),
        mono: document.fonts.check('16px "JetBrains Mono"'),
        loaded: [...document.fonts].filter((f) => f.status === "loaded").length,
        total: document.fonts.size,
      };
    });
    if (o.shots) {
      mkdirSync(o.shots, { recursive: true });
      await page.screenshot({ path: join(o.shots, "first-screen.png"), caret: "initial" });
    }

    if (o.drive) await drive(page, result, o.shots);
    if (o.inspect) result.inspected = await o.inspect(page);

  } finally {
    await browser.close();
  }
  return result;
}

/** Click through the app on the fixture broker's open vault.  Every step is recorded; a step that cannot find its control is a finding, not a skip. */
async function drive(page, result, shots) {
  let seen = 0;
  const step = async (name, fn) => {
    try {
      await fn();
      await page.waitForTimeout(120);
      const total = result.violations.length;
      result.steps.push(`ok   ${name}${total > seen ? `  (+${total - seen} CSP violation${total - seen === 1 ? "" : "s"})` : ""}`);
      seen = total;
    } catch (e) {
      result.steps.push(`FAIL ${name}: ${String(e.message || e).split("\n")[0].slice(0, 160)}`);
      result.pageErrors.push(`drive step failed: ${name}`);
    }
  };
  const shot = async (n) => {
    if (shots) await page.screenshot({ path: join(shots, `${n}.png`), caret: "initial" }); // caret:"initial": the default injects a <style> that the CSP under test would (correctly) refuse
  };
  const hasLabel = (label) => page.locator(`[data-screen-label="${label}"]`).first();
  const closeAll = async () => {
    await page.keyboard.press("Escape");
    await page.waitForTimeout(80);
  };

  // lock screen -> unlock (only if the vault started locked; the fixture broker wants its own passphrase)
  const locked = (await hasLabel("S16 Lock screen").count()) > 0;
  if (locked) {
    await step("lock screen: unlock", async () => {
      await page.locator('input[type="password"]').fill(FIXTURE_PASSPHRASE);
      await page.getByRole("button", { name: "Unlock", exact: true }).click();
      await hasLabel("S1 Main").waitFor({ timeout: 5000 });
    });
  }
  await step("main screen rendered", async () => {
    await hasLabel("S1 Main").waitFor({ timeout: 5000 });
    await page.locator("canvas").first().waitFor({ timeout: 5000 });
  });
  await shot("main");

  // header controls and the vault menu
  await step("hover a rail row", async () => {
    await page.locator(".cm-rail .k-tree-row").first().hover();
  });
  await step("help dialog", async () => {
    await page.getByRole("button", { name: "help", exact: true }).click();
    await hasLabel("S21 Help").waitFor({ timeout: 3000 });
    await shot("help");
    await closeAll();
  });
  await step("settings overlay + every section", async () => {
    await page.getByRole("button", { name: "settings", exact: true }).click();
    await hasLabel("S12 Settings").waitFor({ timeout: 3000 });
    const nav = page.locator(".cm-settings > div:first-child > button");
    const names = (await nav.allTextContents()).map((t) => t.trim());
    if (names.length < 6) throw new Error(`settings nav has ${names.length} sections`);
    for (const name of names) {
      // a section button can replace the overlay (e.g. a shortcut to Operations), so reopen it when needed
      if ((await page.locator(".cm-settings").count()) === 0) {
        await page.getByRole("button", { name: "settings", exact: true }).click();
        await hasLabel("S12 Settings").waitFor({ timeout: 3000 });
      }
      await page.locator(".cm-settings > div:first-child > button", { hasText: name }).first().click();
      await page.waitForTimeout(60);
      await shot(`settings-${name.replace(/\W+/g, "-").toLowerCase()}`);
    }
    await closeAll();
  });
  const openFromMenu = async (item, label, after) => {
    if ((await page.locator(".cm-vaultmenu").count()) === 0) await page.getByRole("button", { name: "vault menu" }).click();
    await page.locator(".cm-vaultmenu button", { hasText: item }).first().click();
    if (label) await hasLabel(label).waitFor({ timeout: 3000 });
    if (label) await shot(label.replace(/\W+/g, "-").toLowerCase());
    if (after) await after();
  };
  for (const [item, label] of [
    ["About CredMgr", "S18 About"],
    ["Operations", "S14 Operations"],
    ["Pending writes", "S20 Pending tray"],
    ["Games", "S19 CredGames"],
    ["Help", "S21 Help"],
    ["Orphaned", "S10 Orphaned"],
  ]) {
    await step(`vault menu: ${item}`, () => openFromMenu(item, label, closeAll));
  }
  await step("add entry dialog (N); typing keeps focus (D7)", async () => {
    await page.locator("body").click({ position: { x: 5, y: 5 } });
    await page.keyboard.press("n");
    try {
      await hasLabel("S6 Add entry").waitFor({ timeout: 3000 });
      await shot("add-entry");
      // The upstream host never passed the previous logic state, so the design re-ran "focus the first control" 30 ms
      // after every re-render while a dialog was open and typing in the second field lost focus (PROVENANCE.md, D7).
      const name = page.locator('input[placeholder="vps-root"]').first();
      await page.waitForTimeout(120);
      await name.click();
      await page.keyboard.type("abc", { delay: 120 });
      await page.waitForTimeout(150);
      const typed = await name.inputValue();
      if (typed !== "abc") throw new Error(`typing lost focus: the name field holds "${typed}"`);
    } finally {
      await closeAll(); // never leave the dialog open for the next step
    }
  });
  await step("tree view (T) and back", async () => {
    await page.keyboard.press("t");
    await hasLabel("S2 Worktree view").waitFor({ timeout: 3000 });
    await page.keyboard.press("t");
  });
  await step("lock from the vault menu, then unlock with the passphrase", async () => {
    await openFromMenu("Lock vault", "S16 Lock screen");
    await page.locator('input[type="password"]').fill(FIXTURE_PASSPHRASE);
    await page.getByRole("button", { name: "Unlock", exact: true }).click();
    await hasLabel("S1 Main").waitFor({ timeout: 5000 });
  });
}

/**
 * Screens that exist only when a broker answers, loaded with the fixture broker in place of the shell.  Each must be the first
 * screen, render, and trip nothing: 0 violations, 0 console errors, 0 external requests.
 */
export const BROKER_SCENARIOS = [
  ["first run (no vault yet)", { initialized: false }, "S17 First run"],
  ["Lock screen (a vault exists, locked)", { locked: true }, "S16 Lock screen"],
  ["broker not reachable", { locked: true, unreachable: true }, "S16 Broker unreachable"],
  // No shell at all (a release build opened in a plain browser): no example vault, just the broker-unreachable screen.
  ["no Tauri shell at all", null, "S16 Broker unreachable"],
];

const fmt = (list) => (list.length ? list.slice(0, 8).map((x) => "      " + x).join("\n") : "      (none)");

/** @returns {string[]} the findings (empty = clean) */
export function findings(r) {
  const out = [];
  if (r.violations.length) out.push(`CSP violations (${r.violations.length}):\n${fmt(r.violations)}`);
  if (r.consoleErrors.length) out.push(`console errors (${r.consoleErrors.length}):\n${fmt(r.consoleErrors)}`);
  if (r.pageErrors.length) out.push(`page errors (${r.pageErrors.length}):\n${fmt(r.pageErrors)}`);
  if (r.failedRequests.length) out.push(`failed requests (${r.failedRequests.length}):\n${fmt(r.failedRequests)}`);
  if (r.external.length) out.push(`requests that left the app origin (${r.external.length}):\n${fmt(r.external)}`);
  if (r.notFound.length) out.push(`same-origin 404s (${r.notFound.length}):\n${fmt(r.notFound)}`);
  if (r.firstScreen?.errorPanel) out.push("the error boundary is showing (\"Something went wrong\"): the app crashed while rendering");
  if (!r.firstScreen?.hostRendered || !r.firstScreen?.label) out.push(`first screen did not render: ${JSON.stringify(r.firstScreen)}`);
  if (!r.fonts?.inter || !r.fonts?.interTight || !r.fonts?.mono || r.fonts.loaded !== 10 || r.fonts.total !== 10) out.push(`fonts not usable (expected all 10 faces loaded): ${JSON.stringify(r.fonts)}`);
  if (!r.webCrypto?.subtle || !r.webCrypto?.secureContext) out.push(`crypto.subtle is not available (secure context: ${r.webCrypto?.secureContext}, crypto.subtle: ${r.webCrypto?.subtle}): the supporter code cannot be checked in this window`);
  const failedSteps = r.steps.filter((s) => s.startsWith("FAIL"));
  if (failedSteps.length) out.push(`drive steps failed:\n${fmt(failedSteps)}`);
  return out;
}

async function main() {
  const argv = process.argv.slice(2);
  const arg = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
  const buildDir = resolve(ROOT, arg("--dir", "build"));
  const engines = arg("--engine", "all");
  const drive = !argv.includes("--no-drive");
  const shots = argv.includes("--shots") ? resolve(arg("--shots")) : undefined;
  if (!existsSync(join(buildDir, "index.html"))) {
    console.error(`verify-csp: ${buildDir}/index.html does not exist - run "npm run build" first`);
    return 2;
  }

  const pw = await import("playwright");
  const all = [
    ["webkit", pw.webkit],
    ["chromium", pw.chromium],
  ].filter(([n]) => engines === "all" || engines === n);

  const csp = productionCsp();
  console.log(`verify-csp: policy: ${csp}`);
  let bad = 0;

  for (const [name, browserType] of all) {
    if (shots) console.log("verify-csp: --shots given: the policy is NOT enforced in this run (screenshots inject a <style>); this is not a gate result");
    const r = await runOnce({ browserType, buildDir, drive, shots: shots && join(shots, name), init: [brokerScript({ locked: false })] });
    const f = findings(r);
    console.log(`\n[${name}] first screen: ${r.firstScreen?.label} (${r.firstScreen?.elements} elements); fonts ${r.fonts?.loaded}/${r.fonts?.total} loaded; ${r.steps.length} drive steps`);
    for (const s of r.steps) console.log("    " + s);
    if (f.length) {
      bad++;
      console.log(`[${name}] FAILED\n` + f.map((x) => "  - " + x).join("\n"));
    } else console.log(`[${name}] clean: 0 CSP violations, 0 console errors, 0 page errors, 0 failed or external requests`);

    for (const [label, options, screen] of BROKER_SCENARIOS) {
      const b = await runOnce({ browserType, buildDir, drive: false, init: options === null ? [] : [brokerScript(options)] });
      const bf = findings(b);
      if (b.firstScreen?.label !== screen) bf.push(`expected the first screen to be "${screen}", got "${b.firstScreen?.label}"`);
      console.log(`[${name}] ${label}: ${bf.length ? "FAILED\n" + bf.map((x) => "  - " + x).join("\n") : `${screen}, clean`}`);
      if (bf.length) bad++;
    }

    // Canaries: the gate must see each of these.  (Only on the plain page - the drive adds nothing to them.)
    const canaries = [
      ["inline <style>", (h) => h.replace("</head>", "<style>body{margin:0}</style></head>"), /style-src/],
      ["inline <script>", (h) => h.replace("</head>", "<script>window.__x=1</script></head>"), /script-src/],
      ["remote stylesheet", (h) => h.replace("</head>", '<link rel="stylesheet" href="https://example.invalid/x.css"></head>'), null],
    ];
    for (const [label, htmlTransform, directive] of canaries) {
      const c = await runOnce({ browserType, buildDir, htmlTransform, drive: false });
      const seen = directive ? c.violations.some((v) => directive.test(v)) : c.external.length > 0 || c.violations.length > 0;
      console.log(`[${name}] canary ${label}: ${seen ? "detected (good)" : "NOT DETECTED - the gate is blind to this"}`);
      if (!seen) bad++;
    }
    // The Web Crypto check must be able to fail: a page with no crypto.subtle is reported.
    const nc = await runOnce({ browserType, buildDir, drive: false, init: ["Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });"] });
    const ncSeen = findings(nc).some((x) => /crypto\.subtle is not available/.test(x));
    console.log(`[${name}] canary no crypto.subtle: ${ncSeen ? "detected (good)" : "NOT DETECTED - the gate is blind to this"}`);
    if (!ncSeen) bad++;
  }
  console.log(bad ? `\nverify-csp: FAILED (${bad})` : "\nverify-csp: PASS");
  return bad ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(await main());
