#!/usr/bin/env node
/**
 * verify-design-audit.mjs - runs the design team's own in-page audit (audit-probe.js) against the BUILT app.
 *
 *   node scripts/verify-design-audit.mjs [--engine chromium|webkit|all] [--root <dir>]
 *
 * The design side ships a small dev tool that drives the app through its states and checks each one for: buttons and
 * inputs with no handler (dead), controls with no accessible name (nolab), clipped text inside dialogs (ovf), controls
 * squashed vertically by their parent (squash) and text under WCAG AA contrast (low; AAA when the contrast mode is high).
 * Their handover note records 0 / 0 / 0 / 0 / 0 for the unmodified design.  This gate re-runs the same probe on the
 * wired app, in every state of scripts/states.mjs, under the production CSP, with the FIXTURE broker
 * (tests/fixtures/broker) answering in place of the Tauri shell, and fails on any finding - so a change to src/design/ or
 * to what the wiring puts on a screen cannot quietly regress what the design team already proved.
 *
 * THE INPUT IS COMMITTED, AND THE GATE NEVER SKIPS (in the private repository; in the PUBLIC tree the probe is absent by licence and the
 * gate says "NOT RUN" unless DESIGN_EXPORT_DIR names it: see resolveProbe).  The probe is design-upstream/<snapshot>/audit-probe.js (brought in by
 * scripts/dc/import.mjs, sanitized, with its sha256 before and after recorded in design-upstream/PROVENANCE.md).  Before it
 * runs, its digest is checked against the one PROVENANCE.md records, so a probe edited or swapped in place is refused.  A
 * missing probe, a missing PROVENANCE row, a digest that does not match or a missing build-test/ is an ERROR (exit 2), never
 * a skip: the earlier version read the probe from an export outside the repository and exited 0 when there was none, so on a
 * fresh clone and in every session without that export the design gate silently never ran, and "green" meant nothing.
 *
 * It is installed with addInitScript, which runs outside the page's CSP and therefore cannot weaken the policy under
 * test; the app itself runs with the production policy.  The graph <canvas> is not DOM and is not covered by the probe.
 *
 * Exit codes: 0 every finding section empty in every state (and the canary seen); 1 a finding, or the probe cannot be
 * trusted; 2 an input is missing or does not match its record.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { brokerScript } from "../tests/fixtures/broker/script.mjs";
import { BASE, ORIGIN, SEED_AND_CLOCK, STATES, serve } from "./states.mjs";
import { productionCsp } from "./verify-csp.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");

/** The committed snapshot directories, oldest first (`design-upstream/2026-10-02` and so on). */
export function snapshotDirs(root) {
  const base = join(root, "design-upstream");
  if (!existsSync(base)) return [];
  return readdirSync(base, { withFileTypes: true })
    .filter((d) => d.isDirectory() && /^\d{4}-\d{2}-\d{2}$/.test(d.name))
    .map((d) => join(base, d.name))
    .sort();
}

/**
 * The sha256 PROVENANCE.md records for the COMMITTED audit-probe.js: the sanitized digest when the importer changed anything, else
 * the raw one (a row that says "byte-identical to the raw download").  `null` when there is no such row, or it does not say committed.
 */
export function recordedProbeSha(provenance) {
  const row = provenance.split("\n").find((l) => /^\|\s*\d+\s*\|\s*`audit-probe\.js`\s*\|/.test(l));
  if (!row || !/\*\*committed\*\*/.test(row)) return null;
  const sanitized = /sanitized\s*->\s*`([0-9a-f]{64})`/.exec(row);
  if (sanitized) return sanitized[1];
  if (!/byte-identical to the raw download/.test(row)) return null;
  const cells = row.split("|").map((c) => c.trim());
  const raw = /`([0-9a-f]{64})`/.exec(cells[4] || "");
  return raw ? raw[1] : null;
}

/** Prove the probe at `path` is the one PROVENANCE.md records.  Never returns "skip". */
function checkProbeAt(path, root, what) {
  if (!existsSync(path)) return { ok: false, why: `${path} is missing: ${what}` };
  const provPath = join(root, "design-upstream", "PROVENANCE.md");
  if (!existsSync(provPath)) return { ok: false, why: `${provPath} is missing: it records the digest the probe is checked against` };
  const want = recordedProbeSha(readFileSync(provPath, "utf8"));
  if (!want) return { ok: false, why: `${provPath} has no row marking audit-probe.js as committed with a sha256: record it with scripts/dc/import.mjs` };
  const source = readFileSync(path, "utf8");
  const have = createHash("sha256").update(readFileSync(path)).digest("hex");
  if (have !== want) return { ok: false, why: `${path} has sha256 ${have}, but design-upstream/PROVENANCE.md records ${want}: the probe was changed or replaced; re-import it` };
  return { ok: true, source, path, sha: have };
}

/**
 * Find the committed probe and prove it is the one on record.  Returns `{ ok: true, source, path, sha }` or `{ ok: false, why }`; it
 * never returns "skip".  `root` is the app directory (v2/apps/desktop).
 */
export function loadCommittedProbe(root) {
  const dirs = snapshotDirs(root);
  if (!dirs.length) return { ok: false, why: `no design snapshot under ${join(root, "design-upstream")} (expected design-upstream/<date>/audit-probe.js, committed by scripts/dc/import.mjs)` };
  const dir = dirs[dirs.length - 1]; // the newest snapshot is the one the app is derived from
  return checkProbeAt(join(dir, "audit-probe.js"), root, "the audit probe is a COMMITTED file (run scripts/dc/import.mjs against the design export to bring it in); this gate does not skip");
}

/**
 * Is this the PUBLIC tree?  The export generates a `.public-export` marker at the repository root (tools/public-export).  The design
 * team's audit-probe.js is not licensed for redistribution, so the public tree does not carry it; the private repository has no marker
 * and keeps the strict rule above (a missing probe is an error).
 */
export function isPublicTree(root) {
  return existsSync(join(root, "..", "..", "..", ".public-export"));
}

/**
 * The probe to run.  Private repository: the committed one, strictly.  Public tree: the committed one if somebody put it there,
 * else the one in `$DESIGN_EXPORT_DIR` (the design project's export; same digest check), else `{ ok: false, devOnly: true }`: this is
 * a development-only gate there, and it says so instead of failing.  A DESIGN_EXPORT_DIR that is set but wrong is still an error.
 */
export function resolveProbe(root, { env = process.env, publicTree = isPublicTree(root) } = {}) {
  const committed = loadCommittedProbe(root);
  if (committed.ok || !publicTree) return committed;
  const dir = env.DESIGN_EXPORT_DIR;
  if (dir) return checkProbeAt(join(resolve(dir), "audit-probe.js"), root, "DESIGN_EXPORT_DIR must name the directory holding the design team's audit-probe.js");
  return { ok: false, devOnly: true, why: "the design team's audit-probe.js is not part of the public tree (it is not licensed for redistribution), so `npm run test:design` is a development-only gate here. To run it, set DESIGN_EXPORT_DIR to the design export directory that holds audit-probe.js (its sha256 is checked against design-upstream/PROVENANCE.md)." };
}

/** Sections that must be empty.  `small` (text under 10.5px) is design information, reported but not a failure. */
const MUST_BE_EMPTY = ["dead", "nolab", "ovf", "squash", "low"];

export async function runAudit({ browserType, probeSource, buildDir }) {
  const browser = await browserType.launch();
  const errors = [];
  let audit = [];
  let canary = null;
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "dark", reducedMotion: "reduce" });
    const page = await context.newPage();
    await page.addInitScript({ content: SEED_AND_CLOCK });
    await page.addInitScript({ content: brokerScript({ locked: false }) }); // an open vault: the app boots straight into it
    await page.addInitScript({ content: probeSource });
    page.on("pageerror", (e) => errors.push(`page error: ${e.message}`));
    page.on("console", (m) => m.type() === "error" && errors.push(`console: ${m.text().slice(0, 200)}`));
    const files = (url) => {
      const p = url.pathname === "/" ? "/index.html" : decodeURIComponent(url.pathname);
      const f = join(buildDir, p);
      return f.startsWith(buildDir) && existsSync(f) ? f : null;
    };
    const external = await serve(page, { files, csp: productionCsp() });
    await page.goto(`${ORIGIN}/index.html`, { waitUntil: "load" });
    await page.waitForFunction(
      () => !!window.__cm && !!window.__probe && window.__cm.state.screen === "app" && window.__cm.model.status === "unlocked" && document.querySelector('[data-screen-label="S1 Main"]'),
      null,
      { timeout: 20000 },
    );
    await page.waitForTimeout(600);

    for (const [name, patch] of STATES) {
      const state = { ...BASE, ...patch };
      if (state.__fr) {
        state.fr = await page.evaluate((n) => ({ ...window.__cm.state.fr, step: n }), state.__fr);
        delete state.__fr;
      }
      await page.evaluate((s) => window.__cm.setState(s), state);
      await page.waitForTimeout(200);
      await page.evaluate((n) => {
        try {
          window.__probe(n);
        } catch (e) {
          window.__audit.push({ l: n, err: String(e) });
        }
      }, name);
    }
    // A gate that has never failed proves nothing: inject a button with no handler, a button with no accessible name
    // and a low-contrast span (all through the DOM and CSSOM, which the CSP allows) and REQUIRE the probe to see them.
    canary = await page.evaluate(() => {
      const root = document.querySelector("#dc-root");
      const dead = document.createElement("button");
      dead.textContent = "canary-dead";
      const unnamed = document.createElement("button");
      unnamed.textContent = " ";
      const faint = document.createElement("span");
      faint.textContent = "canary-low-contrast";
      faint.style.background = "#808080";
      faint.style.color = "#888888";
      root.append(dead, unnamed, faint);
      const R = window.__probe("canary");
      dead.remove();
      unnamed.remove();
      faint.remove();
      window.__audit.pop();
      return { dead: R.dead.length, nolab: R.nolab.length, low: R.low.length };
    });
    audit = await page.evaluate(() => window.__audit);
    if (external.length) errors.push(`requests left the origin: ${external.slice(0, 3).join(", ")}`);
  } finally {
    await browser.close();
  }
  return { audit, errors, canary };
}

/** Aggregate the per-state results the way the design's own __show() does: one line per distinct finding, with the states it appears in. */
export function summarize(audit) {
  const out = { states: audit.length, errs: [], sections: {} };
  for (const sec of [...MUST_BE_EMPTY, "small"]) {
    const map = new Map();
    for (const R of audit) {
      if (R.err) continue;
      if (sec === "small") {
        for (const [k, n] of Object.entries(R.small || {})) map.set(k, (map.get(k) || 0) + n);
        continue;
      }
      for (const x of R[sec] || []) {
        const key = sec === "low" ? x.replace(/^[0-9.]+ /, "") : x;
        const states = map.get(key) || [];
        if (!states.includes(R.l)) states.push(R.l);
        map.set(key, states);
      }
    }
    out.sections[sec] = [...map.entries()].map(([k, v]) => `${k}  <- ${Array.isArray(v) ? v.join(",") : v}`);
  }
  out.errs = audit.filter((R) => R.err).map((R) => `${R.l}: ${R.err}`);
  return out;
}

async function main() {
  const argv = process.argv.slice(2);
  const root = resolve(argv.includes("--root") ? argv[argv.indexOf("--root") + 1] : ROOT);
  const probe = resolveProbe(root);
  if (!probe.ok && probe.devOnly) {
    console.log(`verify-design-audit: NOT RUN - ${probe.why}`);
    return 0;
  }
  if (!probe.ok) {
    console.error(`verify-design-audit: FAILED - ${probe.why}`);
    return 2;
  }
  console.log(`verify-design-audit: probe ${relative(root, probe.path)} (sha256 ${probe.sha.slice(0, 12)}…, matches design-upstream/PROVENANCE.md)`);
  const buildDir = resolve(root, "build-test");
  if (!existsSync(join(buildDir, "index.html"))) {
    console.error('verify-design-audit: FAILED - build-test/ is missing; run "npm run build:test" first (npm run test:design does)');
    return 2;
  }
  const engine = argv.includes("--engine") ? argv[argv.indexOf("--engine") + 1] : "chromium";
  const pw = await import("playwright");
  const engines = [["chromium", pw.chromium], ["webkit", pw.webkit]].filter(([n]) => engine === "all" || engine === n);
  if (!engines.length) {
    console.error(`verify-design-audit: unknown engine "${engine}"`);
    return 2;
  }
  const probeSource = probe.source;
  let bad = 0;
  for (const [name, browserType] of engines) {
    const { audit, errors, canary } = await runAudit({ browserType, probeSource, buildDir });
    const s = summarize(audit);
    console.log(`\n[${name}] probed ${s.states} states`);
    for (const e of errors) console.log(`   error: ${e}`);
    for (const e of s.errs) console.log(`   probe error: ${e}`);
    for (const sec of MUST_BE_EMPTY) {
      const lines = s.sections[sec];
      console.log(`   ${sec.padEnd(7)} ${lines.length}`);
      for (const l of lines.slice(0, 12)) console.log(`      ${l}`);
    }
    console.log(`   small   ${s.sections.small.length} (text under 10.5px; design information, not a failure)`);
    const canaryOk = !!canary && canary.dead >= 1 && canary.nolab >= 1 && canary.low >= 1;
    console.log(`   canary  ${canaryOk ? "detected (good): a dead button, an unnamed button and a low-contrast span" : `NOT detected (${JSON.stringify(canary)}) - the probe cannot be trusted`}`);
    const failed = !canaryOk || errors.length || s.errs.length || s.states !== STATES.length || MUST_BE_EMPTY.some((sec) => s.sections[sec].length);
    if (failed) bad++;
    else console.log(`[${name}] OK: 0 dead, 0 unlabelled, 0 clipped, 0 squashed, 0 low-contrast across ${s.states} states`);
  }
  console.log(bad ? "\nverify-design-audit: FAILED" : "\nverify-design-audit: PASS");
  return bad ? 1 : 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(await main());
