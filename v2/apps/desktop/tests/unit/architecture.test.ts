// The rules that keep the layers honest, as tests, so a wiring package cannot break them quietly:
//   - the logic reads data only through the model (nothing imports the demo data; only the model layer knows it exists)
//   - the only module that calls the Tauri shell's invoke() is src/lib/bridge.ts
//   - the frozen interface the four wiring packages build against is really there
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { classifyError, createModel, VaultModel } from "../../src/vault/index";
import * as vaultIndex from "../../src/vault/index";
import * as admin from "../../src/vault/actions/admin";
import * as read from "../../src/vault/actions/read";
import * as session from "../../src/vault/actions/session";
import * as write from "../../src/vault/actions/write";
import { defaultPrefs, loadPrefs, savePrefs } from "../../src/vault/prefs";

const SRC = resolve(__dirname, "../../src");

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}
const files = (pred: (rel: string) => boolean) => walk(SRC).filter((p) => pred(relative(SRC, p).split("\\").join("/")));
const text = (p: string) => readFileSync(p, "utf8");

describe("layering", () => {
  it("no screen or logic file imports the demo data or any vault source", () => {
    for (const f of files((r) => r.startsWith("design/"))) {
      const t = text(f);
      expect(t, relative(SRC, f)).not.toMatch(/mock-vault|createMockVault|demo-source|DemoSource|bridge-source|BridgeSource/);
    }
  });

  it("the logic reaches the vault layer only through its index (never a source, never the bridge)", () => {
    for (const f of files((r) => r.startsWith("design/logic/"))) {
      for (const m of text(f).matchAll(/from\s+["']([^"']+)["']/g)) {
        const spec = m[1];
        if (spec.includes("vault/")) expect(spec, relative(SRC, f)).toMatch(/vault\/index$/);
        expect(spec, relative(SRC, f)).not.toMatch(/lib\/bridge|@tauri-apps/);
      }
    }
  });

  it("invoke() is called from src/lib/bridge.ts and nowhere else", () => {
    for (const f of files((r) => /\.(ts|js|mjs)$/.test(r) && r !== "lib/bridge.ts")) {
      const t = text(f);
      expect(t, relative(SRC, f)).not.toMatch(/@tauri-apps\/api\/core/);
      expect(t, relative(SRC, f)).not.toMatch(/(^|[^A-Za-z0-9_$.])invoke\s*\(/);
      expect(t, relative(SRC, f)).not.toMatch(/__TAURI_INTERNALS__\s*\.\s*invoke/);
    }
  });

  it("every import of the Tauri JavaScript API is on an explicit allow-list: the typed client, and the one event listener", () => {
    const found = new Map<string, Set<string>>();
    for (const f of files((r) => /\.(ts|tsx|js|mjs|html)$/.test(r))) {
      const mods = tauriModules(text(f));
      if (mods.length) found.set(relative(SRC, f).split("\\").join("/"), new Set(mods));
    }
    const seen = Object.fromEntries([...found].map(([f, m]) => [f, [...m].sort()]));
    // Nothing outside the list, and nothing on the list that is no longer there (a stale entry is a door nobody walks through, kept open).
    expect(seen).toEqual(Object.fromEntries(Object.entries(TAURI_IMPORTS).map(([f, m]) => [f, [...m].sort()])));
    // The page's own entry file may not reach for the shell either (it is not under src/).
    expect(tauriModules(readFileSync(resolve(SRC, "../index.html"), "utf8"))).toEqual([]);
    // Tauri's global API object is the same door by another name.
    for (const f of files((r) => /\.(ts|tsx|js|mjs|html)$/.test(r))) expect(code(text(f)), relative(SRC, f)).not.toMatch(/\bwindow\s*\.\s*__TAURI__\b|\bwithGlobalTauri\b/);
    // The check can fail: it sees every spelling of an import.
    for (const bad of ['import { x } from "@tauri-apps/api/app";', "import y from '@tauri-apps/api/path'", 'const m = await import("@tauri-apps/plugin-fs");', 'require("@tauri-apps/api/window")', 'import "@tauri-apps/api/dpi"']) {
      expect(tauriModules(bad).length, bad).toBe(1);
    }
    expect(tauriModules('// from "@tauri-apps/api/core"\n/* @tauri-apps/api/event */ const a = 1;')).toEqual([]); // a comment is not an import
  });

  it("the shell facts the page asks for (version, home directory) are typed in src/lib/bridge.ts, so no action module imports them itself", () => {
    const bridge = text(resolve(SRC, "lib/bridge.ts"));
    expect(bridge).toMatch(/export const getVersion\s*=\s*\(\)\s*:\s*Promise<string>/);
    expect(bridge).toMatch(/export const homeDir\s*=\s*\(\)\s*:\s*Promise<string>/);
    for (const f of files((r) => r.startsWith("vault/actions/"))) expect(text(f), relative(SRC, f)).not.toMatch(/@tauri-apps/);
  });

  it("no screen, logic or vault file says 'mock' or 'not built' anywhere, not even in a comment: there is no mock badge and no mock data path left to describe", () => {
    const seen: string[] = [];
    for (const f of files((r) => /\.(ts|tsx|js|mjs|html|css)$/.test(r))) {
      const t = text(f);
      seen.push(relative(SRC, f));
      expect(t, relative(SRC, f)).not.toMatch(/mock/i);
      expect(t, relative(SRC, f)).not.toMatch(/not built/i);
    }
    expect(seen.length).toBeGreaterThan(40); // it looked at the whole tree
    // the check can fail
    expect("<span class=\"k-chip\">mock</span>").toMatch(/mock/i);
    expect("// MOCK: not built").toMatch(/not built/i);
  });

  it("the demo-only branches of the logic read a build-time constant, so a release bundle drops them with the words they show", () => {
    for (const name of ["settings.js", "write.js", "fields.js"]) {
      const t = code(text(resolve(SRC, "design/logic", name)));
      expect(t, name).toMatch(/const DEMO_BUILD = import\.meta\.env\.DEV \|\| import\.meta\.env\.MODE === 'test';/);
      // every test of the model's kind for 'demo' (or for "not the real broker") is behind it
      for (const m of t.matchAll(/this\.model\.kind\s*(?:===\s*'demo'|!==\s*'bridge')/g)) {
        expect(t.slice(Math.max(0, (m.index ?? 0) - 12), m.index), `${name}: ${m[0]}`).toMatch(/DEMO_BUILD&&$/);
      }
    }
  });

  it("no source file writes a secret-bearing value to storage or the console", () => {
    for (const f of files((r) => r.startsWith("vault/") || r.startsWith("design/logic/"))) {
      const t = text(f);
      expect(t, relative(SRC, f)).not.toMatch(/console\.(log|info|debug|warn)\s*\(/);
    }
  });

  it("the page never writes to the clipboard: no source file, outside comments, touches the browser's clipboard API", () => {
    for (const f of files((r) => /\.(ts|js|mjs|html)$/.test(r))) {
      expect(code(text(f)), relative(SRC, f)).not.toMatch(CLIPBOARD_API);
    }
    // the check can fail: it sees every way of writing there is
    for (const bad of ["navigator.clipboard.writeText(x)", "navigator['clipboard']", "document.execCommand('copy')", "e.clipboardData.setData('text/plain', v)", "await navigator . clipboard . write([])"]) {
      expect(bad, bad).toMatch(CLIPBOARD_API);
    }
  });

  it("every caller of model.reveal(), readTotp() and revealUnmasked() in the logic uses the answer: a value the model dropped is never shown as revealed", () => {
    const seen = { reveal: 0, totp: 0, unmasked: 0 };
    for (const f of files((r) => r.startsWith("design/logic/"))) {
      for (const line of code(text(f)).split("\n")) {
        if (/\bmodel\.reveal\s*\(/.test(line)) {
          seen.reveal++;
          expect(line, `${relative(SRC, f)}: ${line.trim().slice(0, 80)}`).toMatch(/\b\w+\s*=\s*await\s+this\.model\.reveal\s*\(/);
        }
        if (/\breadTotp\s*\(/.test(line) && !/^\s*import\b/.test(line)) {
          seen.totp++;
          expect(line, `${relative(SRC, f)}: ${line.trim().slice(0, 80)}`).toMatch(/\b\w+\s*=\s*await\s+readTotp\s*\(/);
        }
        if (/\brevealUnmasked\s*\(/.test(line) && !/^\s*import\b/.test(line)) {
          seen.unmasked++;
          expect(line, `${relative(SRC, f)}: ${line.trim().slice(0, 80)}`).toMatch(/\b\w+\s*=\s*await\s+revealUnmasked\s*\(/);
        }
      }
    }
    // it looked at something
    expect(seen.reveal).toBeGreaterThan(0);
    expect(seen.totp).toBeGreaterThan(0);
    expect(seen.unmasked).toBeGreaterThan(0);
    // the check can fail
    expect("await this.model.reveal(node,en.id,i,ms);").not.toMatch(/\b\w+\s*=\s*await\s+this\.model\.reveal\s*\(/);
    expect("await revealUnmasked(this.model,node,en.id,ids,ms);").not.toMatch(/\b\w+\s*=\s*await\s+revealUnmasked\s*\(/);
  });

  it("no logic file shows or stores a field's value except through the model's private store: a value is never read off the view, a notice or a label", () => {
    for (const f of files((r) => r.startsWith("design/logic/"))) {
      const t = code(text(f));
      // a field's value comes back from the model's private store only
      for (const m of t.matchAll(/\.fields\s*(?:\[[^\]]*\])?\s*\.\s*value\b/g)) {
        throw new Error(`${relative(SRC, f)}: reads a field's .value off the view near "${t.slice(Math.max(0, (m.index ?? 0) - 20), (m.index ?? 0) + 30)}"`);
      }
    }
    // notices built in the field and entry logic do not name a field's label or carry a value
    const fields = code(text(resolve(SRC, "design/logic/fields.js")));
    for (const m of fields.matchAll(/this\.notify\s*\(([^)]*)\)/g)) expect(m[1], `fields.js: a notice that could carry a label or a value: ${m[1]}`).not.toMatch(/\bff\.(label|value)\b|origLabel/);
  });

  it("every logic caller of a write action looks at readbackError: a write whose re-read failed is said to have happened, never 'Nothing was changed'", () => {
    // [how the logic names it, the action]
    const ACTIONS: Array<[string, string]> = [
      ["write.", "createEntry"], ["write.", "createEntries"], ["write.", "acceptPending"], ["write.", "discardPending"], ["write.", "sealNode"], ["write.", "restoreNode"], ["write.", "createNodeWithPolicy"],
      ["write.", "addFields"], ["write.", "updateField"], ["write.", "removeField"], ["write.", "reorderFields"], ["write.", "undoFieldChange"],
      ["", "lockNode"], ["", "unlockNode"], ["", "renameNode"],
      ["admin.", "createGrant"], ["admin.", "revokeGrant"], ["admin.", "runDoctor"],
    ];
    const calls = new Map<string, number>();
    for (const f of files((r) => r.startsWith("design/logic/"))) {
      const t = code(text(f));
      for (const [prefix, name] of ACTIONS) {
        for (const m of t.matchAll(new RegExp(String.raw`(?<![A-Za-z0-9_$.])${prefix.replace(".", String.raw`\.`)}${name}\s*\(`, "g"))) {
          calls.set(name, (calls.get(name) ?? 0) + 1);
          expect(t.slice(m.index, m.index + 1500), `${relative(SRC, f)}: ${prefix}${name}() never looks at readbackError`).toMatch(/readbackError/);
        }
      }
    }
    for (const [, name] of ACTIONS) expect(calls.get(name) ?? 0, `no logic caller of ${name}() was found: the check is not looking at anything`).toBeGreaterThan(0);
    // the check can fail
    const careless = "const r=await write.createEntry(this.model,nid,x); this.notify('success','Saved.');" + " ".repeat(1600) + "readbackError";
    expect(careless.slice(careless.indexOf("write.createEntry"), careless.indexOf("write.createEntry") + 1500)).not.toMatch(/readbackError/);
  });

  it("no logic file changes the broker's view in place: every change to what is on screen is a broker call and a re-read", () => {
    for (const f of files((r) => r.startsWith("design/logic/"))) {
      const t = code(text(f));
      expect(t, relative(SRC, f)).not.toMatch(VIEW_MUTATION);
    }
    // the check can fail: it sees the shapes the design's old local-only write paths used
    for (const bad of ["this.vault.pending.push(x)", "v.nodes.splice(i,1)", "this.vault.sealed[i].label = 'x'", "v.grants[0].reason += 'x'", "vault.entries[nid] = []", "this.vault.links.sort()", "n.counts.entries++"]) {
      expect(bad, bad).toMatch(VIEW_MUTATION);
    }
    // and does not trip over reads
    for (const fine of ["v.nodes.filter(n=>n.id)", "this.vault.entries[nid].map(e=>e.id)", "const list=v.entries[nid]||[]", "v.nodes.length>0", "if(v.pending.length===0)x()"]) {
      expect(fine, fine).not.toMatch(VIEW_MUTATION);
    }
  });
});

/** Source with its comments and the contents of its comment-looking text removed (good enough to grep code; not a parser). */
function code(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/[^\n]*/g, "$1");
}

/**
 * Every module of the page that may import from the Tauri JavaScript API, and exactly which modules it may import.
 *   - src/lib/bridge.ts is the typed client: the broker's commands (`core`) and the two shell facts that are not broker calls
 *     (`app` for the version, `path` for the home directory).
 *   - src/vault/shell-events.ts is the one place the page listens to the shell (`event`).
 * A new entry here is a new door from the webview to the shell: it needs a reason, and a review.
 */
const TAURI_IMPORTS: Record<string, string[]> = {
  "lib/bridge.ts": ["@tauri-apps/api/app", "@tauri-apps/api/core", "@tauri-apps/api/path"],
  "vault/shell-events.ts": ["@tauri-apps/api/event"],
};

/** The `@tauri-apps/...` module specifiers a source file names outside its comments, whatever the import syntax. */
function tauriModules(src: string): string[] {
  return [...new Set([...code(src).matchAll(/@tauri-apps\/[A-Za-z0-9_\-/]*[A-Za-z0-9_-]/g)].map((m) => m[0]))];
}
const CLIPBOARD_API = /\bnavigator\s*(?:\.|\[\s*["'`])\s*clipboard|execCommand\s*\(\s*["'`](?:copy|cut)|clipboardData\s*\.\s*setData|\bwriteText\s*\(/;
/** A mutation of something read off the view: `view.nodes.push(`, `v.nodes[i].label =`, `n.counts.entries++`. */
const VIEW_MUTATION = new RegExp(
  [
    String.raw`(?:this\.vault|\bvault|\bv)\s*\.\s*(?:nodes|entries|links|grants|orphans|sealed|pending)\b(?:\s*\[[^\]\n]*\]|\s*\.\s*[A-Za-z_$][\w$]*)*?\s*\.\s*(?:push|splice|unshift|pop|shift|sort|reverse|fill|copyWithin)\s*\(`,
    String.raw`(?:this\.vault|\bvault|\bv)\s*\.\s*(?:nodes|entries|links|grants|orphans|sealed|pending)\b(?:\s*\[[^\]\n]*\]|\s*\.\s*[A-Za-z_$][\w$]*)*\s*(?:=(?![=>])|\+=|-=|\+\+|--)`,
    String.raw`\b[a-z]\w*\.counts\.(?:entries|totp)\s*(?:=(?![=>])|\+\+|--|\+=|-=)`,
  ].join("|"),
);

describe("the frozen interface", () => {
  it("VaultModel has the members the packages call", () => {
    const m = createModel();
    for (const name of ["boot", "unlock", "gateVerify", "lock", "clear", "loadAll", "refresh", "mutate", "subscribe", "reveal", "plain", "hide", "wipeSecrets", "sweepSecrets", "node", "children", "entriesOf",
      // ADR-078: an entry's fields are read into the model (never into the view), and values are held per field
      "detail", "loadDetail", "dropDetail", "revealMany", "dropEntrySecrets"]) {
      expect(typeof (m as unknown as Record<string, unknown>)[name], name).toBe("function");
    }
    for (const field of ["view", "generation", "orphanNodeId", "status", "gateConfirmed", "wipeCount"]) expect(field in m, field).toBe(true);
    expect(m).toBeInstanceOf(VaultModel);
  });

  it("the logic class has the notice API and the error router", () => {
    const proto = (Component as unknown as { prototype: Record<string, unknown> }).prototype;
    for (const name of ["notify", "routeError", "routeHost", "lockVault", "showLock", "bootModel", "onModelChange", "toggleReveal", "copyField"]) {
      expect(typeof proto[name], name).toBe("function");
    }
  });

  it("the session actions are real (work package A): each exists, and the logic reaches them through the vault index", () => {
    for (const name of ["beginVault", "confirmVault", "beginGateEnrolment", "confirmGateEnrolment", "recoverGate", "confirmFirstRun", "describeEnrolment", "recoverAndUnlock", "createFirstProjects", "lockNoteFor", "onShellLocked", "onShellWindowInactive", "shellLockNote"]) {
      expect(typeof (session as unknown as Record<string, unknown>)[name], `session.${name}`).toBe("function");
    }
  });

  it("the write actions are real (work package C): each exists, and the logic reaches them through the vault index", () => {
    for (const name of ["createEntry", "createEntries", "listPending", "acceptPending", "discardPending", "createNode", "setNodePolicy", "createNodeWithPolicy", "sealNode", "restoreNode",
      "addFields", "updateField", "removeField", "reorderFields", "previewPaste", "previewRows", "previewFieldInputs"]) {
      expect(typeof (write as unknown as Record<string, unknown>)[name], name).toBe("function");
    }
    const m = createModel();
    for (const name of ["rememberSealed", "forgetSealed"]) expect(typeof (m as unknown as Record<string, unknown>)[name], name).toBe("function");
  });

  it("the read-path actions are wired (work package B): they exist, and the logic reaches them through the vault index", async () => {
    for (const name of ["searchEntries", "loadNotes", "lockNode", "unlockNode", "renameNode", "readTotp", "readTotpSeed", "copyEntry", "loadEntryDetail", "revealUnmasked"]) {
      expect(typeof (read as unknown as Record<string, unknown>)[name], `read.${name}`).toBe("function");
    }
    const index = await import("../../src/vault/index");
    for (const name of ["searchEntries", "loadNotes", "lockNode", "unlockNode", "renameNode", "readTotp", "readTotpSeed", "copyEntry", "loadEntryDetail", "revealUnmasked"]) {
      expect(typeof (index as unknown as Record<string, unknown>)[name], `index.${name}`).toBe("function");
    }
  });

  it("the administration actions are wired: package D exports every one of them, none is a stub", () => {
    for (const name of ["createGrant", "revokeGrant", "readAudit", "getAudit", "verifyVault", "runDoctor", "backupVault", "rotateRootKey", "copyPlainText", "setAppIcon", "setCaptureProtection", "appVersion"]) {
      expect(typeof (admin as unknown as Record<string, unknown>)[name], name).toBe("function");
    }
    expect(text(resolve(SRC, "vault/actions/admin.ts"))).not.toMatch(/NotWiredError/);
  });

  it("the index hands the logic every action module and the prefs (the logic may import only the index), unchanged", () => {
    expect(vaultIndex.write).toBe(write);
    expect(vaultIndex.read).toBe(read);
    expect(vaultIndex.admin).toBe(admin);
    expect(vaultIndex.session).toBe(session);
    expect(vaultIndex.loadPrefs).toBe(loadPrefs);
    expect(vaultIndex.savePrefs).toBe(savePrefs);
    expect(vaultIndex.defaultPrefs).toBe(defaultPrefs);
    expect(vaultIndex.PREFS_KEY).toBe("credmgr_prefs");
  });

  it("prefs: defaults are the design's, loading gives them, and saving is wired (tests/unit/wp-d.test.ts covers it)", () => {
    expect(defaultPrefs()).toMatchObject({ autoLockMins: 15, revealWindowSecs: 20, hue: 198, intensity: 32 });
    expect(loadPrefs(null)).toEqual(defaultPrefs()); // no storage at all: the defaults, no throw
    expect(savePrefs({ hue: 1 }, null)).toMatchObject({ hue: 1 }); // and a write that cannot be stored still answers
  });

  it("outside the Tauri shell the model is the demo source; inside it, the bridge source", () => {
    expect(createModel().kind).toBe("demo");
    (globalThis as unknown as { window?: object }).window = { __TAURI_INTERNALS__: {} };
    try {
      expect(createModel().kind).toBe("bridge");
    } finally {
      delete (globalThis as unknown as { window?: object }).window;
    }
  });
});
