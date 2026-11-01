#!/usr/bin/env node
/**
 * verify-build.mjs - the static gate on a built front end.  Runs at the end of `npm run build`; no browser needed.
 *
 *   node scripts/dc/verify-build.mjs <build-dir> [--test-build]
 *
 * The production Content-Security-Policy (src-tauri/tauri.conf.json) is `script-src 'self'; style-src 'self'` with no
 * 'unsafe-eval', no 'unsafe-inline' and no remote origin.  Tauri adds hashes for inline code it finds in HTML at
 * bundle time, which would silently widen that policy - so the build must contain no inline code at all.  This
 * script fails the build if it does, and if the JavaScript or CSS contains anything that needs eval, the network
 * or the upstream design runtime.  Exit code is 0 only when every check passes; nothing here is a warning.
 *
 * `--test-build` (the build-test/ output used by the e2e specs and the design audit) additionally permits the window.__cm
 * debug handle and the demo vault; the release build must contain neither, nor the fixture broker, nor a mock of anything
 * (scripts/dc/release-bans.mjs: the specific strings, the words that must never appear, and - checked at build time by
 * scripts/dc/vite-plugin-dc.mjs - the modules).  Every build, release or test, must also contain the typed client's wire
 * (REQUIRED_WIRE): a bundle with no broker client in it would pass every ban.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";

import { RELEASE_BANNED_TEXT, RELEASE_BANS, REQUIRED_WIRE } from "./release-bans.mjs";

const argv = process.argv.slice(2);
const dir = resolve(argv.find((a) => !a.startsWith("--")) || "build");
const testBuild = argv.includes("--test-build");

const failures = [];
const fail = (where, what) => failures.push(`${where}: ${what}`);

function walk(d) {
  const out = [];
  for (const name of readdirSync(d).sort()) {
    const p = join(d, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

if (!existsSync(join(dir, "index.html"))) {
  console.error(`verify-build: ${dir}/index.html does not exist - run the build first`);
  process.exit(2);
}
const files = walk(dir);
const rel = (p) => relative(dir, p).split(sep).join("/"); // posix-style on every OS: the checks below match "assets/..."

// ── index.html: no inline code, no remote resource ──
{
  const html = readFileSync(join(dir, "index.html"), "utf8");
  for (const m of html.matchAll(/<script\b([^>]*)>/gi)) if (!/\bsrc\s*=/.test(m[1])) fail("index.html", `inline <script> (${m[0].slice(0, 60)})`);
  if (/<style\b/i.test(html)) fail("index.html", "inline <style> element");
  if (/\sstyle\s*=/i.test(html)) fail("index.html", "style= attribute");
  if (/\son[a-z]+\s*=/i.test(html)) fail("index.html", "inline event-handler attribute");
  if (/<base\b/i.test(html)) fail("index.html", "<base> element");
  for (const m of html.matchAll(/\b(?:src|href)\s*=\s*"([^"]*)"/gi)) {
    if (!m[1].startsWith("/") || m[1].startsWith("//")) fail("index.html", `resource that is not same-origin: ${m[1]}`);
  }
}

// ── JavaScript ──
// The demo vault (src/vault/demo-source.ts) exists in the TEST build only, where two of its display strings look like URLs
// (never loaded).  A release build has no demo vault at all, so nothing is allow-listed there.
const DEMO_URL_STRINGS = testBuild ? ["https://grafana.example.test:3000", "https://hooks.example.test/monit/demo"] : [];
const URL_ALLOWLIST = [
  /^http:\/\/www\.w3\.org\/(?:2000\/svg|1999\/xlink|1998\/Math\/MathML|XML\/1998\/namespace)$/,
  /^https:\/\/react\.dev\/errors\/?$/,
];
const usedDemo = new Set();
const JS_BANS = [
  [/\bnew\s+Function\s*\(/, "new Function("],
  [/(^|[^A-Za-z0-9_$.])eval\s*\(/, "eval("],
  [/(^|[^A-Za-z0-9_$.])Function\s*\(\s*["'`]/, "Function(\"...\")"],
  [/set(?:Timeout|Interval)\(\s*["'`]/, "setTimeout/setInterval with a string"],
  [/unpkg|jsdelivr|cdnjs|googleapis|gstatic/i, "CDN host"],
  [/@babel|babel-standalone/, "Babel"],
  [/__dcUpdate|__dcBoot|__dcRegistry|sc-streaming|data-dc-editor/, "upstream design runtime marker"],
  [/localhost:14(?:20|21)/, "dev-server address"],
  [/\binsertRule\s*\(/, "insertRule( (runtime stylesheet)"],
  [/parent\.postMessage|postMessage\([^)]*,\s*["']\*["']\)/, "postMessage to a parent frame"],
];
const jsFiles = files.filter((p) => /\.(?:m?js)$/.test(p));
for (const f of jsFiles) {
  const text = readFileSync(f, "utf8");
  for (const [re, label] of JS_BANS) if (re.test(text)) fail(rel(f), `contains ${label}`);
  if (!testBuild && /window\.__cm\b/.test(text)) fail(rel(f), "contains the window.__cm debug handle (release builds must not)");
  // The demo vault and the fixture broker are development and test aids: a release build carries neither (scripts/dc/release-bans.mjs).
  if (!testBuild) for (const { needle, what } of RELEASE_BANS) if (text.includes(needle)) fail(rel(f), `contains "${needle}": ${what} must not be part of a release build`);
  // ...and the class of them: no mock of anything, no fixture, no example-vault wording, whatever it is called (a renamed needle still trips these)
  if (!testBuild) for (const { pattern, what } of RELEASE_BANNED_TEXT) { const m = pattern.exec(text); if (m) fail(rel(f), `contains ${JSON.stringify(m[0])}: ${what} must not be part of a release build`); }
  for (const m of text.matchAll(/https?:\/\/[^\s"'`)\\<>]+/g)) {
    const u = m[0];
    if (URL_ALLOWLIST.some((re) => re.test(u))) continue;
    const demo = DEMO_URL_STRINGS.find((s) => u === s);
    if (demo) {
      usedDemo.add(demo);
      continue;
    }
    fail(rel(f), `URL string ${u.slice(0, 80)}`);
  }
}
// ── the broker client is in the bundle: every build talks to the broker through the typed client ──
{
  const all = jsFiles.map((f) => readFileSync(f, "utf8")).join("\n");
  for (const wire of REQUIRED_WIRE) if (!all.includes(`"${wire}"`) && !all.includes(`\`${wire}\``) && !all.includes(`'${wire}'`)) fail("assets", `the bundle never names the broker command ${wire}: the typed client (src/lib/bridge.ts) is not in it`);
}
for (const s of DEMO_URL_STRINGS) if (!usedDemo.has(s)) console.log(`verify-build: note: allowlisted demo URL no longer present (remove it from DEMO_URL_STRINGS): ${s}`);

// ── CSS ──
for (const f of files.filter((p) => p.endsWith(".css"))) {
  const text = readFileSync(f, "utf8");
  if (/url\(\s*["']?data:/i.test(text)) fail(rel(f), "url(data:...) - fonts and images must be real files");
  if (/@import/i.test(text)) fail(rel(f), "@import");
  for (const m of text.matchAll(/url\(\s*["']?([^"')]+)/gi)) {
    if (!m[1].startsWith("/") || m[1].startsWith("//")) fail(rel(f), `url() that is not a same-origin path: ${m[1]}`);
  }
  if (/https?:\/\//.test(text)) fail(rel(f), "absolute URL");
}

// ── assets that must exist ──
const FONTS = [
  "inter-latin-400",
  "inter-latin-500",
  "inter-latin-600",
  "inter-latin-700",
  "inter-tight-latin-600",
  "inter-tight-latin-700",
  "jetbrains-mono-latin-400",
  "jetbrains-mono-latin-500",
  "jetbrains-mono-latin-600",
  "jetbrains-mono-latin-700",
];
for (const name of FONTS) {
  if (!files.some((p) => rel(p).startsWith(`assets/${name}-`) && p.endsWith(".woff2"))) fail("assets", `missing font ${name}.woff2`);
}
if (files.some((p) => p.endsWith(".map"))) fail("assets", "source map shipped");

if (failures.length) {
  console.error(`verify-build: FAILED (${failures.length})`);
  for (const f of failures) console.error("  - " + f);
  process.exit(1);
}
const kb = (n) => (n / 1024).toFixed(0) + " kB";
const size = files.reduce((n, p) => n + statSync(p).size, 0);
console.log(
  `verify-build: ok - ${rel(dir) || dir}: ${files.length} files, ${kb(size)}; no inline code, no eval, no Babel, no remote URL, ${FONTS.length} fonts present, the broker client present${testBuild ? " (test build)" : "; no demo vault, no fixture broker, no mock of anything"}`,
);
