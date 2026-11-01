#!/usr/bin/env node
/**
 * npm run test:real - the UI end-to-end suite over the REAL broker.
 *
 *   npm run test:real                         everything, on WebKit (the gate) and Chromium
 *   npm run test:real -- --project=webkit     any Playwright arguments go straight through
 *   npm run test:real -- -g "second factor"
 *
 * It rebuilds what the suite tests, then runs it, and stops at the first step that fails:
 *
 *   1. cargo build -p credmgr-brokerd --bin credmgrd --locked     the daemon, from THIS source
 *   2. npm run build                                              the release front end (build/), then its release-bans check
 *   3. node --test tests/real/drift-guard.test.mjs               the shim's command table against commands.rs, ops.rs, bridge.ts, and
 *              tests/real/preview.test.mjs                        the shim's port of the local fields_preview against the cases the Rust pins
 *   4. playwright test -c tests/real/playwright.config.ts         the journeys, each on its own daemon and its own throwaway vault
 *
 * A green run therefore means: THIS credmgrd, THIS build/, a shim that matches the Tauri shell, and journeys that passed.
 * (The harness also refuses to run if build/ or credmgrd is older than its sources, so the suite cannot be pointed at a stale
 * artefact by running Playwright by hand.)
 *
 * Needs the Bash sandbox OFF when run from an agent session: it builds with cargo and npm, binds a Unix socket and launches browsers.
 * Requirements: the Rust toolchain pinned in v2/rust-toolchain.toml, Node 22.12+, `npm ci` done, `npx playwright install webkit chromium`.
 * Never touches ~/.credmgr, the live vault, or any real vault path: every daemon is started on a fresh temp root (tests/real/daemon.mjs).
 *
 * Environment: CREDMGR_REAL_WORKERS (default 2), CREDMGR_REAL_KEEP=1 (keep the temp roots, for a post-mortem),
 *              CREDMGR_REAL_SKIP_BUILD=1 (reuse build/ and credmgrd as they are - for iterating on the specs only; the staleness
 *              check in the harness still applies), CARGO / CARGO_TARGET_DIR as usual.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";

import { daemonBinary } from "../tests/real/daemon.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const APP = resolve(HERE, "..");
const V2 = resolve(APP, "../..");

const say = (line) => process.stdout.write(`${line}\n`);

function step(title, command, args, options = {}) {
  say(`\n== ${title}`);
  say(`   $ ${[command, ...args].join(" ")}`);
  const r = spawnSync(command, args, { stdio: "inherit", ...options });
  if (r.error) {
    say(`\nreal-e2e: could not run ${command}: ${r.error.message}`);
    process.exit(1);
  }
  if (r.status !== 0) {
    say(`\nreal-e2e: FAILED at "${title}" (exit ${r.status ?? r.signal})`);
    process.exit(r.status ?? 1);
  }
  return r;
}

function cargoBinary() {
  if (process.env.CARGO) return process.env.CARGO;
  const home = join(os.homedir(), ".cargo", "bin", "cargo");
  return existsSync(home) ? home : "cargo";
}

const skipBuild = process.env.CREDMGR_REAL_SKIP_BUILD === "1";
const passthrough = process.argv.slice(2);

say("CredMgr real-broker UI suite");
say(`   app   ${APP}`);
say(`   v2    ${V2}`);

if (skipBuild) {
  say("\n== build skipped (CREDMGR_REAL_SKIP_BUILD=1): using build/ and credmgrd as they are");
} else {
  step("1/4 build credmgrd from this source", cargoBinary(), ["build", "-p", "credmgr-brokerd", "--bin", "credmgrd", "--locked"], {
    cwd: V2,
    env: { ...process.env, CARGO_INCREMENTAL: "0" },
  });
  step("2/4 build the release front end (build/)", "npm", ["run", "build"], { cwd: APP });
}

// What is about to be tested, in one place, so a log says which artefacts a green run was green FOR.
const binary = daemonBinary();
if (!existsSync(binary)) {
  say(`\nreal-e2e: ${binary} does not exist`);
  process.exit(1);
}
const version = spawnSync(binary, ["--version"], { encoding: "utf8" });
say(`\n== under test`);
say(`   daemon  ${binary}`);
say(`           ${(version.stdout || version.stderr || "").trim()} (built ${new Date(statSync(binary).mtimeMs).toISOString()})`);
const assets = join(APP, "build", "assets");
const bundle = existsSync(assets) ? readdirSync(assets).find((f) => /^index-.*\.js$/.test(f)) : null;
if (!bundle) {
  say("\nreal-e2e: build/assets/index-*.js is missing");
  process.exit(1);
}
const bytes = readFileSync(join(assets, bundle));
say(`   bundle  build/assets/${bundle} (${bytes.length} bytes, sha256 ${createHash("sha256").update(bytes).digest("hex").slice(0, 16)}...)`);
say(`   shell   src-tauri/tauri.conf.json csp -> production policy; Tauri shell replaced by tests/real/shim (Node, over the Unix socket)`);

step("3/4 drift guard: the shim's command table against the Tauri shell, and its preview port against the Rust cases", process.execPath, ["--test", "tests/real/drift-guard.test.mjs", "tests/real/preview.test.mjs"], { cwd: APP });

step("4/4 journeys", join(APP, "node_modules", ".bin", "playwright"), ["test", "-c", "tests/real/playwright.config.ts", ...passthrough], {
  cwd: APP,
  env: { ...process.env, CREDMGRD_BIN: binary },
});

say("\nreal-e2e: OK - the journeys passed against this credmgrd and this build/.");
