// The fixture broker must not drift from the real wire.
//
// The Playwright specs run the real bridge client, model and screens against tests/fixtures/broker, a hand-written fake of the
// Tauri shell.  If the fake answers with a different shape from the one src/lib/bridge.ts declares (a key renamed, a field the
// real broker never sends), a spec stays green and the real app breaks.  So this test runs every example the fixture
// registers (`B.examples`, see tests/fixtures/broker/core.js) and checks the answer, key by key and type by type, against the
// TypeScript declaration of that command in bridge.ts, which src-tauri/tests/ts_client.rs in turn ties to the Rust side.
//
// It reads bridge.ts as TEXT (the declarations are flat object types), so it needs no compiler API and fails loudly if a
// declaration becomes something it cannot read.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";

import { brokerScript, FIXTURE_GATE_CODE, FIXTURE_PASSPHRASE } from "../fixtures/broker/index";

const ROOT = resolve(__dirname, "../..");
const BRIDGE = readFileSync(resolve(ROOT, "src/lib/bridge.ts"), "utf8");
const FIXTURE_DIR = resolve(ROOT, "tests/fixtures/broker");

// ───────────────────────── reading bridge.ts ─────────────────────────

function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/[^\n]*/g, "$1");
}

/** The text between the bracket at `open` and its partner (exclusive), counting all bracket kinds. */
function balanced(s: string, open: number): string {
  const pairs: Record<string, string> = { "{": "}", "[": "]", "(": ")", "<": ">" };
  const stack: string[] = [];
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (pairs[c]) stack.push(pairs[c]);
    else if ((c === "}" || c === "]" || c === ")" || c === ">") && !(c === ">" && s[i - 1] === "=")) {
      if (stack.pop() !== c) throw new Error(`unbalanced at ${i}`);
      if (stack.length === 0) return s.slice(open + 1, i);
    }
  }
  throw new Error("unterminated bracket");
}

/** Split `s` on `sep` characters that are not inside any bracket. */
function splitTop(s: string, seps: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  let inStr: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") inStr = c;
    else if ("{[(<".includes(c)) depth++;
    else if ("}])>".includes(c) && !(c === ">" && s[i - 1] === "=")) depth--;
    else if (depth === 0 && seps.includes(c)) {
      out.push(s.slice(start, i));
      start = i + 1;
    }
  }
  out.push(s.slice(start));
  return out.map((x) => x.trim()).filter((x) => x.length > 0);
}

interface Declarations {
  interfaces: Map<string, string>;
  aliases: Map<string, string>;
  commands: Map<string, string>;
}

function readDeclarations(source: string): Declarations {
  const src = stripComments(source);
  const interfaces = new Map<string, string>();
  const aliases = new Map<string, string>();
  const commands = new Map<string, string>();
  for (const m of src.matchAll(/export interface (\w+)\s*\{/g)) interfaces.set(m[1], balanced(src, m.index! + m[0].length - 1));
  for (const m of src.matchAll(/export type (\w+)\s*=\s*/g)) {
    const from = m.index! + m[0].length;
    let end = from;
    let depth = 0;
    for (; end < src.length; end++) {
      const c = src[end];
      if ("{[(<".includes(c)) depth++;
      else if ("}])>".includes(c) && !(c === ">" && src[end - 1] === "=")) depth--;
      else if (c === ";" && depth === 0) break;
    }
    aliases.set(m[1], src.slice(from, end).trim());
  }
  for (const m of src.matchAll(/\binvoke</g)) {
    const lt = m.index! + m[0].length - 1; // the "<"
    const generic = balanced(src, lt);
    const rest = src.slice(lt + generic.length + 2); // past the closing ">"
    const cmd = /^\s*\(\s*"([^"]+)"/.exec(rest);
    if (!cmd) throw new Error(`cannot read the command name after invoke<${generic.slice(0, 40)}…>`);
    commands.set(cmd[1], generic.trim());
  }
  return { interfaces, aliases, commands };
}

const D = readDeclarations(BRIDGE);

// ───────────────────────── checking a value against a declaration ─────────────────────────

const PRIMITIVES: Record<string, (v: unknown) => boolean> = {
  string: (v) => typeof v === "string",
  number: (v) => typeof v === "number" && Number.isFinite(v),
  boolean: (v) => typeof v === "boolean",
  true: (v) => v === true,
  false: (v) => v === false,
  null: (v) => v === null,
  unknown: () => true,
  undefined: (v) => v === undefined,
};

function members(body: string): Array<{ key: string; optional: boolean; type: string }> {
  return splitTop(body, ";,").map((m) => {
    const p = /^(?:readonly\s+)?(\w+)(\?)?\s*:\s*([\s\S]+)$/.exec(m);
    if (!p) throw new Error(`cannot read the member "${m.slice(0, 60)}"`);
    return { key: p[1], optional: p[2] === "?", type: p[3].trim() };
  });
}

/** Problems found in `value` against the type text `type`; empty means it fits. */
function check(value: unknown, type: string, path = "$"): string[] {
  const t = type.trim().replace(/^\|\s*/, "");
  const alts = splitTop(t, "|");
  if (alts.length > 1) {
    const results = alts.map((a) => check(value, a, path));
    return results.some((r) => r.length === 0) ? [] : results.sort((a, b) => a.length - b.length)[0];
  }
  if (t.startsWith("(") && t.endsWith(")")) return check(value, t.slice(1, -1), path);
  if (t.includes(" & ")) return []; // `(string & {})`: any string
  const arr = /^(?:Array<([\s\S]+)>|([\s\S]+)\[\])$/.exec(t);
  if (arr) {
    if (!Array.isArray(value)) return [`${path}: expected an array`];
    return value.flatMap((v, i) => check(v, arr[1] ?? arr[2], `${path}[${i}]`));
  }
  if (t.startsWith("{")) return checkObject(value, members(balanced(t, 0)), path);
  if (/^"[^"]*"$/.test(t)) return value === t.slice(1, -1) ? [] : [`${path}: expected ${t}`];
  if (t in PRIMITIVES) return PRIMITIVES[t](value) ? [] : [`${path}: expected ${t}`];
  if (/^Record<|^Required<|^Partial<|^Omit<|^Pick</.test(t)) return typeof value === "object" && value !== null ? [] : [`${path}: expected an object`];
  const iface = D.interfaces.get(t);
  if (iface !== undefined) return checkObject(value, members(iface), path);
  const alias = D.aliases.get(t);
  if (alias !== undefined) return check(value, alias, path);
  throw new Error(`the guard does not know the type "${t}" (at ${path}); teach it in tests/unit/fixture-shape.test.ts`);
}

function checkObject(value: unknown, declared: ReturnType<typeof members>, path: string): string[] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return [`${path}: expected an object`];
  const obj = value as Record<string, unknown>;
  const problems: string[] = [];
  const known = new Set(declared.map((m) => m.key));
  for (const k of Object.keys(obj)) if (!known.has(k)) problems.push(`${path}.${k}: not in the declaration`);
  for (const m of declared) {
    if (!(m.key in obj) || obj[m.key] === undefined) {
      if (!m.optional) problems.push(`${path}.${m.key}: missing`);
      continue;
    }
    problems.push(...check(obj[m.key], m.type, `${path}.${m.key}`));
  }
  return problems;
}

// ───────────────────────── running the fixture ─────────────────────────

interface Example {
  reset?: Record<string, unknown>;
  setup?: () => void;
  args: Record<string, unknown> | (() => Record<string, unknown>);
  error?: string;
}
interface Fixture {
  handlers: Record<string, unknown>;
  examples: Record<string, Example[]>;
  reset(options: Record<string, unknown>): void;
  invoke(cmd: string, args: Record<string, unknown>): Promise<unknown>;
}

function loadFixture(): Fixture {
  const win: Record<string, unknown> = {};
  runInNewContext(brokerScript({}), { window: win, setTimeout, JSON, Date, Math, Promise }, { timeout: 5_000 });
  return win.__brokerFixture as Fixture;
}

const BASE = { passphrase: FIXTURE_PASSPHRASE, gateCode: FIXTURE_GATE_CODE };
const shellCommand = (c: string) => c.startsWith("plugin:");

describe("the declarations are read correctly (so the guard cannot pass by reading nothing)", () => {
  it("finds the shapes the app depends on", () => {
    expect(splitTop(D.interfaces.get("AuthState")!, ";").length).toBe(4);
    expect(D.commands.get("vault_status")).toBe("AuthState");
    expect(D.commands.get("entry_list")).toBe("EntryList");
    expect(D.commands.get("vault_pending_list")).toMatch(/pending: PendingItem\[\]/);
    expect(D.commands.size).toBeGreaterThan(40);
  });

  it("can fail: a missing key, an extra key, a wrong type and a wrong literal are each found", () => {
    const ok = { locked: true, authenticated: false, initialized: true };
    expect(check(ok, "AuthState")).toEqual([]);
    expect(check({ locked: true, authenticated: false }, "AuthState")).toEqual(["$.initialized: missing"]);
    expect(check({ ...ok, extra: 1 }, "AuthState")).toEqual(["$.extra: not in the declaration"]);
    expect(check({ ...ok, locked: "yes" }, "AuthState")).toEqual(["$.locked: expected boolean"]);
    expect(check({ nodes: [{ id: "a", label: "a", kind: "planet", depth: 0, parentId: null, counts: { entries: 0, totp: 0 }, gate: { locked: false, twofa: "none" }, health: null }], links: [], meta: { generatedAt: 1, vaultLocked: false } }, "GraphSnapshot")).toEqual(['$.nodes[0].kind: expected "global"']);
    expect(check({ node: "n", entry: "e", pending: true }, "{ node: string; entry: string; pending: true } | { node: string; entry: string; pending: false; generation: number }")).toEqual([]);
    expect(check({ node: "n", entry: "e", pending: false }, "{ node: string; entry: string; pending: true } | { node: string; entry: string; pending: false; generation: number }")).not.toEqual([]);
  });
});

describe("the fixture broker answers exactly as src/lib/bridge.ts declares", () => {
  const fixture = loadFixture();
  const commands = Object.keys(fixture.handlers).filter((c) => !shellCommand(c));

  it("has handlers, and every one is a command the bridge really has", () => {
    expect(commands.length).toBeGreaterThanOrEqual(29);
    for (const c of commands) expect(D.commands.has(c), `${c} is not a command in src/lib/bridge.ts`).toBe(true);
  });

  it("every handler has at least one example (see tests/fixtures/broker/core.js)", () => {
    for (const c of commands) expect(fixture.examples[c]?.length ?? 0, `fixture handler "${c}" has no B.examples entry`).toBeGreaterThan(0);
    for (const c of Object.keys(fixture.examples)) expect(commands, `B.examples.${c} has no handler`).toContain(c);
  });

  for (const cmd of commands) {
    it(`${cmd}: every example answers in the declared shape`, async () => {
      const type = D.commands.get(cmd)!;
      for (const [i, ex] of (fixture.examples[cmd] ?? []).entries()) {
        const label = `${cmd} example ${i + 1}`;
        fixture.reset({ ...BASE, ...(ex.reset ?? {}) });
        ex.setup?.();
        const args = typeof ex.args === "function" ? ex.args() : ex.args;
        let answer: unknown;
        let refused: unknown;
        try {
          answer = await fixture.invoke(cmd, args);
        } catch (e) {
          refused = e;
        }
        if (ex.error) {
          expect(answer, `${label} should have been refused with ${ex.error}`).toBeUndefined();
          expect(check(refused, "BridgeError"), `${label}: the refusal is not a BridgeError`).toEqual([]);
          expect((refused as { code: string }).code, label).toBe(ex.error);
        } else {
          expect(refused, `${label} was refused: ${JSON.stringify(refused)}`).toBeUndefined();
          expect(check(answer, type), `${label} does not fit ${type.replace(/\s+/g, " ").slice(0, 100)}`).toEqual([]);
        }
      }
    });
  }

  it("every error code the fixture raises is one the broker or the bridge really has", () => {
    const codes = new Set<string>();
    for (const name of ["core.js", "seed.js", "fields.js", "session.js", "read.js", "write.js", "admin.js"]) {
      const src = readFileSync(resolve(FIXTURE_DIR, name), "utf8");
      for (const m of src.matchAll(/B\.error\(\s*"([a-z_]+)"/g)) codes.add(m[1]);
      for (const m of src.matchAll(/error:\s*"([a-z_]+)"/g)) codes.add(m[1]);
    }
    const known = new Set([...D.aliases.get("BrokerErrorCode")!.matchAll(/"([a-z_]+)"/g), ...D.aliases.get("BridgeLocalCode")!.matchAll(/"([a-z_]+)"/g)].map((m) => m[1]));
    expect(codes.size).toBeGreaterThan(5);
    for (const c of codes) expect(known.has(c), `the fixture raises "${c}", which bridge.ts does not declare`).toBe(true);
  });
});
