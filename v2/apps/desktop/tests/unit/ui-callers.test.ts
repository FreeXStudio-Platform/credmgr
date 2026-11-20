// rc.2 §1 item 10: every command the bridge exposes (an `invoke("<command>")` in src/lib/bridge.ts, which tests in src-tauri hold to
// commands.rs) has a caller in the app (src/design or src/vault), or says why it has none with the one marker bridge.ts documents at its
// top: `@no-ui-caller <reason>` in the JSDoc right above the export.  A new op bridged without a screen, or a screen dropped without its
// op, fails here and names the command.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = resolve(__dirname, "../..");
const BRIDGE = readFileSync(resolve(ROOT, "src/lib/bridge.ts"), "utf8");
const MARKER = "@no-ui-caller";

interface Bridged {
  /** The exported function's name. */
  name: string;
  /** The command it invokes. */
  command: string;
  /** The reason given with the marker, or null. */
  reason: string | null;
}

/** Every `export const <name> = (...) => invoke<...>("<command>"...)` with the JSDoc block right above it. */
export function bridged(src: string): Bridged[] {
  const out: Bridged[] = [];
  const re = /export const (\w+)\s*=\s*\([^)]*\)[^=]*=>\s*\n?\s*invoke\s*<[\s\S]*?>\s*\(\s*"(\w+)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    // the export's own statement must contain the invoke: stop at the first `;` after the `=`, or a second `export`
    const stmt = src.slice(m.index, re.lastIndex);
    if ((stmt.match(/export const /g) || []).length > 1) continue;
    const before = src.slice(0, m.index);
    const doc = /\/\*\*((?:(?!\*\/)[\s\S])*)\*\/\s*$/.exec(before);
    const marked = doc ? new RegExp(`${MARKER}\\s+([^\\n*]+)`).exec(doc[1]) : null;
    out.push({ name: m[1], command: m[2], reason: marked ? marked[1].trim() : null });
  }
  return out;
}

function files(dir: string, exts: string[]): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...files(p, exts));
    else if (exts.some((x) => p.endsWith(x))) out.push(p);
  }
  return out;
}

/** Everything the app's own code says, comments dropped (a name in a comment is not a caller). */
function appSource(): string {
  return [...files(resolve(ROOT, "src/design"), [".js", ".ts"]), ...files(resolve(ROOT, "src/vault"), [".ts", ".js"])]
    .map((p) => readFileSync(p, "utf8").replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'`\\])\/\/[^\n]*/g, "$1"))
    .join("\n");
}

describe("every bridged command has a caller in the app, or a stated reason it has none", () => {
  const list = bridged(BRIDGE);
  const app = appSource();
  const called = (name: string) => new RegExp(`\\b${name}\\b`).test(app);

  it("the parser reads the bridge (one row per invoked command, and none twice)", () => {
    const commands = list.map((b) => b.command);
    expect(new Set(commands).size).toBe(commands.length);
    expect(commands.length).toBeGreaterThan(100); // 97 broker commands + 18 shell commands, less the few built from others
    expect(commands).toContain("entry_rotate");
    expect(commands).toContain("backup_restore");
  });

  it("no command is both unused by the app and unmarked", () => {
    const orphans = list.filter((b) => !called(b.name) && !b.reason).map((b) => `${b.name} (${b.command})`);
    expect(orphans, `bridged with no caller in src/design or src/vault and no "${MARKER} <reason>" in its JSDoc:\n  ${orphans.join("\n  ")}`).toEqual([]);
  });

  it("a marker is not left on a command the app does call (the reason would be false)", () => {
    const stale = list.filter((b) => b.reason && called(b.name)).map((b) => `${b.name} (${b.command})`);
    expect(stale, `marked ${MARKER} but called by the app:\n  ${stale.join("\n  ")}`).toEqual([]);
  });

  it("every marker gives a reason", () => {
    const empty = list.filter((b) => b.reason !== null && b.reason.length < 12).map((b) => b.name);
    expect(empty).toEqual([]);
  });

  it("the check can fail: a made-up export with no caller and no marker is caught", () => {
    const fake = bridged(`/** something */\nexport const neverCalledAnywhere = (x: string) => invoke<void>("never_called_anywhere", { x });\n`);
    expect(fake).toEqual([{ name: "neverCalledAnywhere", command: "never_called_anywhere", reason: null }]);
    expect(called("neverCalledAnywhere")).toBe(false);
    const marked = bridged(`/** something\n * ${MARKER} only the CLI needs it */\nexport const y = () => invoke<void>("y_cmd");\n`);
    expect(marked[0].reason).toBe("only the CLI needs it");
  });
});
