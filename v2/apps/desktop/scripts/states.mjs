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

const AGENT_TOKENS = {
  max: 32, defaultExpiresIn: 86400, maxExpiresIn: 604800,
  tokens: [
    { id: "a_00000000f1c00001", label: "claude on atlas", node: "atlas", capabilities: ["list", "read", "reveal"], effectiveCapabilities: ["list", "read", "reveal"], createdAt: 4102358400, expiresAt: 4102444800, lastUsedAt: 4102362000, rotatedAt: null },
    { id: "a_00000000f1c00002", label: "ci on beacon", node: "beacon", capabilities: ["list", "read", "update"], effectiveCapabilities: ["list", "read"], createdAt: 4102358400, expiresAt: 4102963200, lastUsedAt: null, rotatedAt: null },
  ],
};
const AGENTS_FOUND = {
  binary: "/opt/homebrew/bin/credmgr", binaryFound: true, claudeCodeCommand: "claude mcp add --scope user credmgr -- /opt/homebrew/bin/credmgr mcp",
  clients: [
    { client: "claude-code", label: "Claude Code", path: "~/.claude.json", state: "ready", detail: null, writable: false, container: "mcpServers" },
    { client: "claude-desktop", label: "Claude Desktop", path: "~/Library/Application Support/Claude/claude_desktop_config.json", state: "connected", detail: null, writable: true, container: "mcpServers" },
    { client: "cursor", label: "Cursor", path: "~/.cursor/mcp.json", state: "ready", detail: null, writable: true, container: "mcpServers" },
    { client: "vscode", label: "VS Code (Copilot)", path: "~/Library/Application Support/Code/User/mcp.json", state: "not_found", detail: null, writable: true, container: "servers" },
    { client: "windsurf", label: "Windsurf", path: "~/.codeium/windsurf/mcp_config.json", state: "unreadable", detail: "the file is not valid JSON; it was left alone", writable: true, container: "mcpServers" },
  ],
};
const AGENT_PLAN = {
  client: "cursor", label: "Cursor", action: "connect", path: "~/.cursor/mcp.json", exists: true, unchanged: false,
  diff: [{ kind: " ", text: "  \"mcpServers\": {" }, { kind: "+", text: "    \"credmgr\": {" }, { kind: "+", text: "      \"command\": \"/opt/homebrew/bin/credmgr\"," }, { kind: "+", text: "      \"args\": [\"mcp\"]" }, { kind: "+", text: "    }" }, { kind: " ", text: "  }" }],
  backupName: "mcp.json.credmgr-backup-<time>", token: "tok-cursor-connect-ready",
};

export const SETTINGS_SECTIONS = ["security", "appearance", "backup", "mode", "games", "nodes", "grants", "agents", "maintenance", "audit", "report", "advanced"];

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
  ["alias", { openEntry: "e-a1", dialog: "alias", aliasForm: { node: "atlas", entry: "e-a1", entryName: "stripe-live", text: "live-payments\nPayments Key", orig: [], busy: false } }],
  ["entry-history", { openEntry: "e-a1", entryTab: { key: "atlas\u0000e-a1", tab: "history" }, historyView: { key: "atlas\u0000e-a1", loading: false, err: null, data: { node: "atlas", entry: "e-a1", truncated: false, exists: true, name: "stripe-live", ref: 1, modified: 1760000000, rotatedAt: null, expiresAt: 1790000000,
    records: [{ id: "aud-1", timestamp: 1760000000, actor: "human", action: "entry.create", decision: "allow", generation: null }, { id: "aud-2", timestamp: 1760000600, actor: "ses_fixture_agent", action: "entry.reveal", decision: "deny", generation: null }] } } }],
  ["entry-history-failed", { openEntry: "e-a1", entryTab: { key: "atlas\u0000e-a1", tab: "history" }, historyView: { key: "atlas\u0000e-a1", loading: false, err: "internal", data: null } }],
  ["expiry", { openEntry: "e-a1", dialog: "expiry", expiryForm: { node: "atlas", entry: "e-a1", entryName: "stripe-live", date: "2030-06-01", orig: null, busy: false } }],
  ["rotate", { openEntry: "e-a2", dialog: "rotate", rotateForm: { node: "atlas", entry: "e-a2", entryName: "pg-main", field: "f_00a20004", fields: [{ id: "f_00a20004", label: "password", masked: true }, { id: "f_00a20001", label: "host", masked: false }], value: "", gen: false, genBits: 0, gl: "24", gs: true, gp: false, busy: false } }],
  ["rotate-generated", { openEntry: "e-a1", dialog: "rotate", rotateForm: { node: "atlas", entry: "e-a1", entryName: "stripe-live", field: "f_00000000", fields: [{ id: "f_00000000", label: "field 1", masked: true }], value: "fixture-generated-state", gen: true, genBits: 150, gl: "24", gs: true, gp: false, busy: false } }],
  ["remove-entry", { openEntry: "e-a1", dialog: "removeEntry", removeForm: { node: "atlas", entry: "e-a1", entryName: "stripe-live", busy: false } }],
  ["removed-undo", { removedUndo: { node: "atlas", entry: "e-gone", name: "old-key", busy: false, clash: true } }],
  ["expiry-change", { openEntry: "e-a1", dialog: "expiry", expiryForm: { node: "atlas", entry: "e-a1", entryName: "stripe-live", date: "2030-06-01", orig: 1790000000, busy: false } }],
  ["import-env", { dialog: "importEnv", importForm: { node: "atlas", text: "NAME=value", fileName: "", stage: "input", pairs: [], skippedEmpty: [], plan: null, onConflict: "refuse", busy: false } }],
  ["import-env-preview", { dialog: "importEnv", importForm: { node: "atlas", text: "", fileName: "", stage: "preview", pairs: [{ name: "FIX_ONE", value: "x" }, { name: "stripe-live", value: "y" }], skippedEmpty: ["FIX_EMPTY"], onConflict: "refuse", busy: false,
    plan: { items: [{ name: "FIX_ONE", status: "new", similar: [{ id: "e-a1", name: "stripe-live", reason: "one-edit" }] }, { name: "stripe-live", status: "exists" }], counts: { new: 1, exists: 1, duplicate: 0, empty: 0, invalid: 0 } } } }],
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
  // ADR-150: the confirm dialog (passphrase only; with Touch ID offered; a wrong passphrase said), and the Settings rows with the Pro options.
  ["confirm", { dialog: "confirm", confirm: { ask: { command: "entry_reveal", operation: "entry.reveal", mode: "window", windowSeconds: 300 }, busy: false, error: "", touch: null } }],
  ["confirm-touch", { dialog: "confirm", confirm: { ask: { command: "entry_reveal", operation: "entry.reveal", mode: "everyTime", windowSeconds: 0 }, busy: false, error: "", touch: "Touch ID" } }],
  ["confirm-error", { overlay: "settings", dialog: "confirm", confirm: { ask: { command: "node_policy", operation: "node.policy", mode: "window", windowSeconds: 300 }, busy: false, error: "Wrong passphrase.", touch: null } }],
  ["settings-confirm-on", { overlay: "settings", setSection: "security", mode: "pro", rc: { mode: "window", windowSeconds: 300, scope: "high" } }],
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
  ["node-filter", { nodeFilter: "stag" }],
  ["node-filter-none", { nodeFilter: "zzz" }],
  ["node-find", { selected: "atlas", nodeFind: { node: "atlas", q: "pay", rows: [{ id: "e-a1", name: "stripe-live", alias: "live-payments" }], err: null } }],
  ["node-find-none", { selected: "atlas", nodeFind: { node: "atlas", q: "zzz", rows: [], err: null } }],
  ["search-ref", { searchOpen: true, searchQ: "#2", searchHits: { q: "#2", rows: [], ref: { node: "atlas", entry: "e-a1", name: "stripe-live", ref: 2 } } }],
  ["audit-report", { overlay: "settings", setSection: "report", auditReport: { range: "30", fromDay: "2026-10-01", toDay: "2026-10-31", node: "", busy: false, err: "", report: {
    from: 1760000000, to: 1762592000, node: null, records: 3, decisions: { allow: 2, deny: 1, other: 0 },
    byAction: [{ action: "entry.list", count: 2, allow: 2, deny: 0 }, { action: "entry.reveal", count: 1, allow: 0, deny: 1 }],
    byActor: [{ actor: "human", count: 2, allow: 2, deny: 0 }, { actor: "ses_fixture_agent", count: 1, allow: 0, deny: 1 }],
    byNode: [{ node: "atlas", count: 3, allow: 2, deny: 1 }],
    denials: { total: 1, reasons: [{ action: "entry.reveal", reason: "node_access_denied", count: 1 }], recent: [{ id: "aud-3", timestamp: 1760000600, actor: "ses_fixture_agent", action: "entry.reveal", node: "atlas", reason: "node_access_denied" }] },
    presence: { uses: 1, byOp: [{ op: "entry.move", count: 1 }], refused: 0 }, chain: { months: ["2026-10"], verified: true } } } }],
  ["audit-report-dates-error", { overlay: "settings", setSection: "report", auditReport: { range: "dates", fromDay: "2026-10-31", toDay: "2026-10-01", node: "atlas", busy: false, err: "The end date is before the start date.", report: null } }],
  // ADR-163: "Forgot passphrase?" — the recovery-code form, the same form once the broker asked for the second factor (with a refusal), the new code shown once
  ["lock5", { screen: "lock", lockStep: 5 }],
  ["lock5-factor", { screen: "lock", lockStep: 5, forgotCode: "x", forgotPass: "abcd", forgotRepeat: "abcd", forgotNeedFactor: true, fieldErrors: { forgot: "That code was not accepted." } }],
  ["lock6", { screen: "lock", lockStep: 6, forgotNewCode: "FIXT-NEWC-ODE0-0001" }],
  ["brokerdown", { screen: "brokerdown" }],
  ["restore", { overlay: "settings", setSection: "backup", dialog: "restoreBackup", restoreForm: { archive: "/backups/credmgr-backup-1760000001.enc", target: "", passphrase: "", busy: false, done: null } }],
  ["restore-refused", { overlay: "settings", setSection: "backup", dialog: "restoreBackup", restoreForm: { archive: "/backups/credmgr-backup-1760000001.enc", target: "", passphrase: "", busy: false, done: null }, fieldErrors: { "restore.save": "CredMgr's broker is running, and a restore never runs beside it. Nothing was read or written." } }],
  ["restore-brokerdown", { screen: "brokerdown", dialog: "restoreBackup", restoreForm: { archive: "/backups/a.enc", target: "/restored", passphrase: "", busy: false, done: null } }],
  ["restore-done", { screen: "brokerdown", dialog: "restoreBackup", restoreForm: { archive: "/backups/a.enc", target: "/restored", passphrase: "", busy: false, done: { target: "/restored", stateDir: "/state", files: 12, bytes: 4096, counter: "keptExisting", complete: false } } }],
  ["bootfailed", { screen: "bootfailed" }],
  ...SETTINGS_SECTIONS.map((k) => [`settings-${k}`, { overlay: "settings", setSection: k }]),
  // ADR-143: the Agents section with what the shell found, and the change dialog drawn from a plan.
  ["settings-agents-found", { overlay: "settings", setSection: "agents", agents: AGENTS_FOUND }],
  ["agent-dialog", { overlay: "settings", setSection: "agents", agents: AGENTS_FOUND, dialog: "agent", agentDlg: { client: "cursor", action: "connect", busy: false, plan: AGENT_PLAN } }],
  ["agent-dialog-nothing", { overlay: "settings", setSection: "agents", agents: AGENTS_FOUND, dialog: "agent", agentDlg: { client: "claude-desktop", action: "connect", busy: false, plan: { ...AGENT_PLAN, client: "claude-desktop", label: "Claude Desktop", unchanged: true, diff: [], backupName: null } } }],
  // ADR-164: the Agent tokens list, the Issue dialog's form, and the token shown once (an invented value, not a credential).
  ["agent-tokens-list", { overlay: "settings", setSection: "agents", agents: AGENTS_FOUND, atList: AGENT_TOKENS }],
  ["agent-token-form", { overlay: "settings", setSection: "agents", agents: AGENTS_FOUND, atList: AGENT_TOKENS, dialog: "agentToken", atForm: { node: "atlas", label: "claude on atlas", caps: { list: true, read: true, reveal: true, create: false, update: false }, expires: 28800, busy: false, err: null } }],
  ["agent-token-issued", { overlay: "settings", setSection: "agents", agents: AGENTS_FOUND, atList: AGENT_TOKENS, dialog: "agentToken", atForm: { node: "atlas", label: "claude on atlas", caps: { list: true, read: true }, expires: 28800, busy: false, err: null }, atIssued: { id: "a_00000000f1c00001", label: "claude on atlas", node: "atlas", capabilities: ["list", "read", "reveal"], expiresAt: 4102444800, copied: true, clearAfter: 30, revoked: false } }],
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
