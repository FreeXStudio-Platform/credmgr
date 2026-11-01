/**
 * Strings a RELEASE bundle must not contain, with what each one stands for.  Pure data, shared by scripts/dc/verify-build.mjs (which
 * fails the build on any of them) and tests/unit/release-build.test.ts (which proves each one really is in the code it names, so
 * this list cannot rot into checking for something that no longer exists).
 *
 * Each is a string literal in the source, so it survives minification.  `where` is the file(s) that must still contain it.
 */
export const RELEASE_BANS = [
  { needle: "credmgr-demo-vault-marker", what: "the demo vault (src/vault/demo-source.ts)", where: ["src/vault/demo-source.ts"] },
  { needle: "fail2ban-alerts", what: "demo vault data (an entry name only the demo vault has)", where: ["src/vault/demo-source.ts"] },
  { needle: "vault-backups-eu", what: "demo vault data (a bucket name only the demo vault has)", where: ["src/vault/demo-source.ts"] },
  { needle: "example.test", what: "demo vault hosts", where: ["src/vault/demo-source.ts"] },
  { needle: "__brokerFixture", what: "the fixture broker (tests/fixtures/broker)", where: ["tests/fixtures/broker/core.js"] },
  { needle: "__BROKER__", what: "the fixture broker's control surface", where: ["tests/fixtures/broker/install.js"] },
  { needle: "__BROKER_OPTIONS__", what: "the fixture broker's options", where: ["tests/fixtures/broker/script.mjs"] },
  { needle: "fixture-passphrase", what: "the fixture broker's passphrase", where: ["tests/fixtures/broker/script.mjs"] },
  { needle: "fixture-value-", what: "the fixture broker's entry values", where: ["tests/fixtures/broker/seed.js"] },
  { needle: "FIXT-ROOT-RECO", what: "the fixture broker's recovery code", where: ["tests/fixtures/broker/script.mjs"] },
  { needle: "usageSet", what: "the test-only handle that drives the milestone ask (src/design/logic/extras.js, behind the build-time test constant)", where: ["src/design/logic/extras.js"] },
  { needle: "__cm", what: "the test-only state handle window.__cm and its paint counter (T8; src/design/logic/core.js and graph.js, behind the build-time test constant)", where: ["src/design/logic/core.js"] },
  { needle: "credmgr_dev", what: "the design file's debug switch (devOn: ?dev=1 or localStorage credmgr_dev). The app has none; a design drop that brings it back must not ship", where: [] },
  { needle: "packLoad", what: "the test-only handle that opens the extras pack without storing a key (src/design/logic/extras.js)", where: ["src/design/logic/extras.js"] },
];

/**
 * The same ban, one level up: MODULES a release bundle must not contain.  A string needle can be defeated by a rename; a module
 * that was never bundled cannot leak a string.  `scripts/dc/vite-plugin-dc.mjs` checks every chunk's module list in a release build
 * (`generateBundle`) and fails the build on a match, so "the shipped app does not import the demo vault or the fixture broker" is
 * enforced where the imports are resolved, not just where their strings might show.  Matched against the module's absolute id.
 * (A module that is imported but wholly tree-shaken is not in the list: that is how the demo vault leaves a release bundle, and it is
 * measured, not assumed - tests/unit/release-build.test.ts builds both ways and looks.)
 */
export const RELEASE_BANNED_MODULES = [
  { pattern: /[\\/]src[\\/]vault[\\/]demo-source\.[cm]?[jt]s$/, what: "the in-memory demo vault" },
  { pattern: /[\\/]tests[\\/]fixtures[\\/]/, what: "the fixture broker" },
  { pattern: /[\\/]design-upstream[\\/]/, what: "the upstream design snapshot (a mock runtime's data)" },
];

/** The reason a module id may not be in a release bundle, or `null`. */
export function bannedModule(id) {
  const hit = RELEASE_BANNED_MODULES.find(({ pattern }) => pattern.test(id));
  return hit ? hit.what : null;
}

/**
 * Words a release bundle must not contain at all, with a sample that trips each one.  They are the vocabulary of the things the
 * release does not have: a mock or fixture of anything, the example vault's model kind (`"demo"` as a string), and the "browser preview"
 * wording the example vault's screens used.  The needles above name specific strings; these catch the class.  They hold today because
 * the code that says them is behind a build-time constant that folds to `false` in a release build (settings.js / write.js `DEMO_BUILD`).
 */
export const RELEASE_BANNED_TEXT = [
  { pattern: /mock/i, what: "a mock (data, badge or runtime)", sample: "var x = 'mock data';" },
  { pattern: /fixture/i, what: "a test fixture", sample: "var x = 'fixture-value-1';" },
  { pattern: /[`"']demo[`"']/, what: "the example vault's model kind", sample: "if (m.kind === `demo`) {}" },
  { pattern: /browser preview|preview has no broker/i, what: "the example vault's 'browser preview' wording", sample: "notify('This browser preview has no broker.')" },
];

/**
 * What a bundle that talks to the broker MUST contain: the command names the typed client (src/lib/bridge.ts) sends.  Checked in every build,
 * so the same gate that says what is absent also says the real thing is there - a bundle with no client at all would pass every ban.
 */
export const REQUIRED_WIRE = ["graph_snapshot", "entry_list", "entry_create_batch", "vault_gate_enroll_begin", "node_seal"];
