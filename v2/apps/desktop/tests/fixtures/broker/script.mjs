/**
 * The fixture broker as one injectable script.  Plain ESM so that both the Playwright specs (tests/fixtures/broker/index.ts) and
 * the CSP gate (scripts/verify-csp.mjs) can build it; nothing here touches Playwright.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** Concatenated in this order: core defines the namespace the rest register on, install builds the first vault. */
export const FILES = ["core.js", "seed.js", "fields.js", "session.js", "read.js", "write.js", "admin.js", "install.js"];

/** Test values, invented for this fixture.  Not credentials of anything. */
export const FIXTURE_PASSPHRASE = "fixture-passphrase";
export const FIXTURE_GATE_CODE = "424242";
/** What first run's `vault_init_begin` hands out (session.js), what `vault_gate_recover` wants, and what confirms an enrolment. */
export const FIXTURE_INIT_RECOVERY_CODE = "FIXT-URE0-CODE-0001";
export const FIXTURE_ROOT_RECOVERY_CODE = "FIXT-ROOT-RECO-VERY-0001";
export const FIXTURE_ENROL_CODE = "654321";

/** The source of the fake, as one script (see index.ts BrokerOptions for the options). */
export function brokerScript(options = {}) {
  const opts = { passphrase: FIXTURE_PASSPHRASE, gateCode: FIXTURE_GATE_CODE, ...options };
  const body = FILES.map((f) => readFileSync(join(HERE, f), "utf8")).join("\n");
  return `window.__BROKER_OPTIONS__ = ${JSON.stringify(opts)};\n${body}`;
}
