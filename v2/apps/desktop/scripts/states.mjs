/**
 * states.mjs - the screens the headless gates walk, as state patches for the logic class (`window.__cm.setState`, test builds).
 *
 * Shared by `scripts/verify-design-audit.mjs` (the design team's audit probe, run against the built app with the fixture
 * broker answering) and `tests/unit/logic.test.ts` (every name the template reads exists in `renderVals()` in each state).
 * `tests/e2e/screens.spec.ts` walks the same list and fails on any state that lands on the error screen.
 *
 * The ids are the FIXTURE broker's (tests/fixtures/broker/seed.js): atlas, beacon, cobalt (a locked node), staging, entry
 * e-a1 (a login), e-a3 (a TOTP entry).  The app reads its data from the broker; a state patch names one of those ids and the
 * model's view (what the broker said) fills in the rest.
 *
 * Also here, because the audit and the specs need the same thing and it must not drift: the page origin the gates serve the
 * build from, the seeded random/clock script, and the tiny file server.
 */
import { readFileSync } from "node:fs";
import { extname } from "node:path";

import { TEST_PACK } from "../tests/fixtures/extras/seal-test-pack.mjs";

export const ORIGIN = "https://tauri.localhost";

const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".woff2": "font/woff2" };

/** The "settled app" state every other state is a patch on (the design team's own base, audit-probe.js `window.__B`). */
export const BASE = {
  screen: "app", vaultLocked: false, overlay: null, dialog: null, view: "graph", openEntry: null, donateToastOpen: false, donateView: "main",
  ctx: null, vaultMenu: false, searchOpen: false, searchQ: "", railOpen: false, inspOpen: false, hover: null, selected: "atlas",
  aboutTab: "main", setSection: "security", theme: "dark", contrastMode: "standard", gameScreen: "menu",
};

/** The second-factor dialog's working state for the gates (dummy QR path and obviously fake codes: nothing here is a secret). */
const GATE_QR = { d: "M4,4h3v1h-3zM4,5h1v1h-1zM6,5h1v1h-1zM4,6h3v1h-3zM9,4h2v1h-2zM8,6h1v1h-1z", size: 15 };
const GATE = { step: "qr", replacing: false, reason: null, qr: GATE_QR, secret: "FIXT URE0 SECR ET00 0000 0000 0000 0000", totp: "", codes: [], codesSaved: false, busy: false };
const GATE_CODES = Array.from({ length: 10 }, (_, i) => `FIXT-GATE-RC${String(i + 1).padStart(2, "0")}-0000-0000`);

/** The field dialog's working state for the gates (the fixture's multi-field entry e-a2, "pg-main"; nothing here is a secret). */
const FIELD_FORM = { mode: "add", node: "atlas", entry: "e-a2", entryName: "pg-main", field: null, label: "", origLabel: "", value: "", type: "auto", origType: "auto", masked: "auto", origMasked: "auto", index: 0, busy: false };
const FIELD_EDIT = { ...FIELD_FORM, mode: "edit", field: "f_00a20004", label: "password", origLabel: "password", index: 3 };

/** The cosmetic choices at their defaults (src/design/logic/extras.js cosmDef); a state patches a few of them. */
const COSM = { mark: "keep", glyph: "classic", halo: false, ring: false, shape: "circle", global: "bone", link: "default", dots: "spectrum", backdrop: "plain", badge: "none", icon: "keep", flourish: "off", trail: "standard" };

export const SETTINGS_SECTIONS = ["security", "appearance", "backup", "mode", "games", "nodes", "grants", "agents", "maintenance", "audit", "advanced"];

export const STATES = [
  ["graph", {}],
  ["tree", { view: "tree" }],
  ["entry", { openEntry: "e-a1" }],
  ["entry-totp", { openEntry: "e-a3" }],
  ["entry-multi", { openEntry: "e-a2" }],
  ["entry-multi-menu", { openEntry: "e-a2", fieldMenu: "e-a2:f_00a20004" }],
  ["field-add", { openEntry: "e-a2", dialog: "field", fieldForm: { ...FIELD_FORM, label: "replica", value: "fixture-value-replica" } }],
  ["field-edit", { openEntry: "e-a2", dialog: "field", fieldForm: { ...FIELD_EDIT, type: "password", masked: "hidden" } }],
  ["field-remove", { openEntry: "e-a2", dialog: "field", fieldForm: { ...FIELD_EDIT, mode: "remove" } }],
  ["entry-locked", { openEntry: "e-a1", vaultLocked: true }],
  ["node-locked (cobalt)", { selected: "cobalt" }],
  ["orphan", { selected: "__orphan" }],
  ["global", { selected: "global" }],
  ["rail", { railOpen: true }],
  ["insp", { inspOpen: true }],
  ["vaultmenu", { vaultMenu: true }],
  ["search", { searchOpen: true, searchQ: "stripe" }],
  ["search-none", { searchOpen: true, searchQ: "zzzz-no-match" }],
  ["ctx", { ctx: { node: "atlas", x: 200, y: 200 } }],
  ["locked", { vaultLocked: true }],
  ["add-single", { dialog: "addEntry" }],
  ["add-bulk", { dialog: "addEntry", addMode: "bulk", bulkText: "host: a.example\nuser: root\n///\napi key: sk-test-123" }],
  ["add-multi", { dialog: "addEntry", addName: "box", singleFields: [{ label: "host", value: "a.example.test" }, { label: "password", value: "fixture-value-pw" }] }],
  ["add-note", { dialog: "addEntry", entryTypeOverride: "note", singleFields: [{ label: "note", value: "fixture note" }] }],
  ["add-split", { dialog: "addEntry", addMode: "bulk", splitSegs: true, bulkText: "host: a.example\nuser: root\n///\napi key: sk-test-123\n///\nplain text with no label" }],
  ["add-locked", { dialog: "addEntry", vaultLocked: true }],
  ["addNode", { dialog: "addNode", newNodeName: "x" }],
  ["seal", { dialog: "seal", sealTarget: "beacon" }],
  ["grant", { dialog: "grant" }],
  ["about", { dialog: "about" }],
  ["about-donate", { dialog: "about", aboutTab: "donate" }],
  ["about-privacy", { dialog: "about", aboutTab: "privacy" }],
  ["about-licences", { dialog: "about", aboutTab: "licenses" }],
  ["help", { dialog: "help" }],
  ["pending", { dialog: "pending" }],
  ["touch", { dialog: "touch", touch: { title: "t", body: "b" } }],
  ["gate-loading", { overlay: "settings", dialog: "gateEnrol", gateFlow: { ...GATE, step: "loading", qr: null, secret: "" } }],
  ["gate-qr", { overlay: "settings", dialog: "gateEnrol", gateFlow: { ...GATE, totp: "123" } }],
  ["gate-replace", { overlay: "settings", dialog: "gateEnrol", gateFlow: { ...GATE, replacing: true } }],
  ["gate-codes", { overlay: "settings", dialog: "gateEnrol", gateFlow: { ...GATE, step: "codes", qr: null, secret: "", codes: GATE_CODES } }],
  ["gate-error", { overlay: "settings", dialog: "gateEnrol", gateFlow: { ...GATE, step: "error", qr: null, secret: "", reason: "internal" } }],
  ["gate-error-fresh", { overlay: "settings", dialog: "gateEnrol", gateFlow: { ...GATE, step: "error", replacing: true, qr: null, secret: "", reason: "two_factor_required" } }],
  ["ops", { overlay: "ops" }],
  ["games", { overlay: "games", gameScreen: "menu" }],
  ["games-library", { overlay: "games", gameScreen: "library" }],
  // the 2026-10-18 drop: the milestone reminder in each of its views, the unlock flourish, the supporter extras open (the data tables of the test pack), the header stamp
  ["donate-toast", { donateToastOpen: true, donateMs: "50 entries" }],
  ["donate-toast-guide", { donateToastOpen: true, donateView: "guide", donateMs: "150 entries" }],
  ["donate-toast-code", { donateToastOpen: true, donateView: "code", donateCode: "x", donateCodeErr: true }],
  ["donate-toast-optout", { donateToastOpen: true, donateView: "optout", donateMs: "300 entries" }],
  ["flourish", { flourishOn: true }],
  ["stamp", { pack: TEST_PACK, cosm: { ...COSM, badge: "stamp", shape: "hexagon", global: "sig", backdrop: "rings", link: "ash", dots: "warm" } }],
  ["extras-open", { overlay: "settings", setSection: "appearance", pack: TEST_PACK, cosm: { ...COSM, badge: "ring", shape: "octagon", global: "tint", backdrop: "dots", flourish: "on", trail: "comet" } }],
  ["extras-open-light", { theme: "light", overlay: "settings", setSection: "appearance", pack: TEST_PACK, cosm: { ...COSM, badge: "stamp", shape: "square", global: "ash", backdrop: "lines" } }],
  // the 2026-10-25 drop: Undo and Generate in the field dialog, the second-factor dialog, the locked-approval panel, the node dialog's privateNames choice
  ["entry-undo", { openEntry: "e-a2", undo: { node: "atlas", entry: "e-a2", audit: "a_000000000001", text: "remove field" } }],
  ["entry-undone", { openEntry: "e-a2", undoDone: { entry: "e-a2", text: "Restored: 5 fields (undone remove field)" } }],
  ["field-add-generated", { openEntry: "e-a2", dialog: "field", fieldForm: { ...FIELD_FORM, label: "api token", value: "fixture-generated-0123456789abcdef", gen: true, genBits: 142, gl: "34" } }],
  ["tf", { openEntry: "e-a2", dialog: "tf", tf: { node: "atlas", code: "12", err: "", busy: false } }],
  ["tf-error", { openEntry: "e-a2", dialog: "tf", tf: { node: "atlas", code: "", err: "That code was not accepted.", busy: false } }],
  ["lock-approval", { screen: "lock", lockStep: 3, aprOpen: true, aprReq: "rq_fixture0001", aprCode: "12" }],
  ["lock-approval-error", { screen: "lock", lockStep: 3, aprOpen: true, aprReq: "rq_fixture0001", aprErr: "Wrong passphrase." }],
  ["lock-approval-result", { screen: "lock", lockStep: 3, aprResult: "approved with the passphrase · the vault is still locked" }],
  ["addNode-pn", { dialog: "addNode", newNodeName: "x", addNodeAdv: { subShare: true, twofa: true, childRead: false, agentAccess: "read-write", pn: true } }],
  ["lock1", { screen: "lock", lockStep: 1 }],
  ["lock2", { screen: "lock", lockStep: 2 }],
  ["lock3", { screen: "lock", lockStep: 3 }],
  ["lock4", { screen: "lock", lockStep: 4 }],
  ["brokerdown", { screen: "brokerdown" }],
  ["bootfailed", { screen: "bootfailed" }],
  ...SETTINGS_SECTIONS.map((k) => [`settings-${k}`, { overlay: "settings", setSection: k }]),
  ...[1, 2, 3, 4, 5].map((n) => [`firstrun-${n}`, { screen: "firstrun", __fr: n }]),
  ["dark-high", { contrastMode: "high" }],
  ["light", { theme: "light" }],
  ["light-high", { theme: "light", contrastMode: "high" }],
];

/** Seeded `Math.random` and a frozen clock, so two runs of a gate draw the same picture. */
export const SEED_AND_CLOCK = `
(() => {
  let s = 123456789;
  Math.random = () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296);
  const FIXED = Date.UTC(2026, 9, 2, 9, 0, 0);
  const RealDate = Date;
  class FixedDate extends RealDate {
    constructor(...a) { if (a.length) super(...a); else super(FIXED); }
    static now() { return FIXED; }
  }
  window.Date = FixedDate;
})();`;

/**
 * Answer every request of `page` from `files(url)` (a path or null), the way Tauri serves the build: the HTML carries `csp`;
 * anything that leaves ORIGIN is refused and reported.  Resolves to the array the refusals are appended to.
 */
export function serve(page, { files, csp }) {
  const external = [];
  return page
    .route("**/*", (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== ORIGIN) {
        external.push(url.href);
        return route.abort();
      }
      const hit = files(url);
      if (!hit) return route.fulfill({ status: 404, body: "not found" });
      const headers = { "content-type": MIME[extname(hit)] || "application/octet-stream" };
      if (csp && hit.endsWith(".html")) headers["content-security-policy"] = csp;
      return route.fulfill({ status: 200, headers, body: readFileSync(hit) });
    })
    .then(() => external);
}
