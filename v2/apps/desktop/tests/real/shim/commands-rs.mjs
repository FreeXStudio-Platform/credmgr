/**
 * Reads the Tauri shell's command table straight out of the Rust source, so the drift guard compares the shim against what the
 * shell really exposes rather than against a second copy somebody keeps by hand.
 *
 * Three places in `src-tauri/src/commands.rs` define the surface:
 *
 *   1. the `#[tauri::command]` functions written by hand (`vault_status` ... `entry_reveal`, plus the two shell-only ones),
 *   2. the `bridge_ops! { ... }` block, one row per generated command:  `name / core => "op" { arg: Type => "wireKey" [optional], ... }`
 *   3. the `HAND_WRITTEN` and `SHELL_COMMANDS` metadata tables the Rust drift guards read.
 *
 * Everything is parsed from text (comments stripped first: the doc comments in that block contain quotes and braces).
 * `src-tauri/src/session.rs` and `error.rs` supply the constants the shim's session logic must agree with.
 *
 * No dependency: this runs under plain `node`, so the drift guard needs neither a browser nor a Rust build.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const SRC_TAURI = resolve(HERE, "../../../src-tauri");
export const COMMANDS_RS = join(SRC_TAURI, "src/commands.rs");
export const SESSION_RS = join(SRC_TAURI, "src/session.rs");
export const ERROR_RS = join(SRC_TAURI, "src/error.rs");
export const OPS_RS = resolve(HERE, "../../../../../crates/brokerd/src/ops.rs");
export const BRIDGE_TS = resolve(HERE, "../../../src/lib/bridge.ts");

/** Drop `//`, `///` and `//!` comments (whole-line and trailing). The sources parsed here keep no `//` inside a string literal. */
export function stripComments(text) {
  return text
    .split("\n")
    .map((line) => {
      const i = line.indexOf("//");
      return i < 0 ? line : line.slice(0, i);
    })
    .join("\n");
}

/** The text between the `open` bracket at `from` and its match, brackets nested. */
function balanced(text, from, open = "{", close = "}") {
  let depth = 0;
  for (let i = from; i < text.length; i++) {
    if (text[i] === open) depth++;
    else if (text[i] === close && --depth === 0) return text.slice(from + 1, i);
  }
  throw new Error(`unbalanced ${open}${close} from offset ${from}`);
}

/** Split on commas that are not inside <>, (), [] or {} . */
function splitTop(text) {
  const out = [];
  let depth = 0;
  let cur = "";
  let prev = "";
  for (const ch of text) {
    // `=>` and `->` are arrows, not a closing angle bracket.
    if ("<([{".includes(ch)) depth++;
    else if (">)]}".includes(ch) && !(ch === ">" && (prev === "=" || prev === "-"))) depth--;
    prev = ch;
    if (ch === "," && depth === 0) {
      out.push(cur);
      cur = "";
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out.map((s) => s.trim()).filter(Boolean);
}

/** Rust type -> the shim's argument kind, and whether the argument is optional. */
export function rustType(ty) {
  let t = ty.replace(/\s+/g, "");
  let optional = false;
  const m = /^Option<(.+)>$/.exec(t);
  if (m) {
    optional = true;
    t = m[1];
  }
  const kinds = { String: "string", bool: "bool", u64: "u64", Value: "json", "Vec<String>": "string[]" };
  if (!(t in kinds)) throw new Error(`commands-rs: no shim kind for Rust type ${ty}`);
  return { kind: kinds[t], optional };
}

/** `[ ["key", "kind", required], ... ]` for the generated rows. */
function parseBridgeOps(src) {
  const start = src.indexOf("bridge_ops! {");
  if (start < 0) throw new Error("commands.rs: no bridge_ops! block");
  const body = balanced(src, src.indexOf("{", start));
  const rows = [];
  // name / core => "op" { ...args... }
  const head = /(\w+)\s*\/\s*\w+\s*=>\s*"([a-z_.]+)"\s*\{/g;
  let m;
  while ((m = head.exec(body))) {
    const inner = balanced(body, m.index + m[0].length - 1);
    const params = splitTop(inner).map((a) => {
      const am = /^(\w+)\s*:\s*(.+?)\s*=>\s*"(\w+)"\s*(\[optional\])?$/s.exec(a);
      if (!am) throw new Error(`commands.rs: cannot read bridge_ops arg ${JSON.stringify(a)} in ${m[1]}`);
      const { kind, optional } = rustType(am[2]);
      // Optional-ness is stated twice in the source: `Option<T>` and `[optional]`. They must agree.
      if (optional !== Boolean(am[4])) throw new Error(`commands.rs: ${m[1]}.${am[1]} disagrees with itself about being optional`);
      return { key: am[3], rustArg: am[1], kind, required: !optional };
    });
    rows.push({ command: m[1], op: m[2], params });
    head.lastIndex = m.index + m[0].length + inner.length + 1;
  }
  return rows;
}

/** The `#[tauri::command]` functions written by hand: `{ name, args: [{name, kind}] }` (arguments the Tauri runtime injects - State<>, AppHandle<>, WebviewWindow<> - are dropped; a `<R: Runtime>` generic is allowed). */
function parseTauriFns(src) {
  const out = [];
  const re = /#\[tauri::command\]\s*pub\s+(?:async\s+)?fn\s+(\w+)\s*(?:<[^>(]*>)?\s*\(/g;
  let m;
  while ((m = re.exec(src))) {
    const inner = balanced(src, m.index + m[0].length - 1, "(", ")");
    const args = splitTop(inner)
      .filter((a) => !/:\s*(?:State|(?:tauri::)?AppHandle|(?:tauri::)?WebviewWindow|(?:tauri::)?Window)\s*</.test(a))
      .map((a) => {
        const am = /^(\w+)\s*:\s*(.+)$/s.exec(a);
        if (!am) throw new Error(`commands.rs: cannot read argument ${JSON.stringify(a)} of ${m[1]}`);
        const { kind, optional } = rustType(am[2]);
        return { name: am[1], kind, optional };
      });
    out.push({ name: m[1], args });
  }
  return out;
}

/** `HAND_WRITTEN: &[BridgedOp]` rows. */
function parseHandWritten(src) {
  const start = src.indexOf("pub const HAND_WRITTEN");
  const body = balanced(src, src.indexOf("[", src.indexOf("=", start)), "[", "]");
  const rows = [];
  const re = /BridgedOp\s*\{/g;
  let m;
  while ((m = re.exec(body))) {
    const inner = balanced(body, m.index + m[0].length - 1);
    const command = /command:\s*"(\w+)"/.exec(inner)[1];
    const op = /op:\s*"([a-z_.]+)"/.exec(inner)[1];
    const params = [...(/params:\s*&\[([\s\S]*?)\],\s*args/.exec(inner)?.[1] ?? "").matchAll(/\(\s*"(\w+)"\s*,\s*(true|false)\s*\)/g)].map((p) => ({ key: p[1], required: p[2] === "true" }));
    rows.push({ command, op, params });
  }
  return rows;
}

/** `SHELL_COMMANDS: &[ShellCommand]` rows. */
function parseShellCommands(src) {
  const start = src.indexOf("pub const SHELL_COMMANDS");
  const body = balanced(src, src.indexOf("[", src.indexOf("=", start)), "[", "]");
  const rows = [];
  const re = /ShellCommand\s*\{/g;
  let m;
  while ((m = re.exec(body))) {
    const inner = balanced(body, m.index + m[0].length - 1);
    const strs = (re2) => [...(re2.exec(inner)?.[1] ?? "").matchAll(/"(\w+)"/g)].map((s) => s[1]);
    rows.push({
      command: /command:\s*"(\w+)"/.exec(inner)[1],
      args: strs(/args:\s*&\[([^\]]*)\]/),
      wrapsOp: /wraps_op:\s*Some\("([a-z_.]+)"\)/.exec(inner)?.[1] ?? null,
      opParams: strs(/op_params:\s*&\[([^\]]*)\]/),
    });
  }
  return rows;
}

function stringList(src, constName) {
  const at = src.indexOf(`pub const ${constName}`);
  if (at < 0) throw new Error(`no pub const ${constName}`);
  const eq = src.indexOf("=", at);
  return [...balanced(src, src.indexOf("[", eq), "[", "]").matchAll(/"([^"]+)"/g)].map((s) => s[1]);
}

/**
 * Everything the drift guard needs from the Rust side. Each source defaults to the file on disk; a test passes its own text to
 * prove the guard notices a change (a canary), without touching the real files.
 * @param {{commandsText?: string, sessionText?: string, errorText?: string, clipboardText?: string}} [sources]
 */
export function readShellSurface(sources = {}) {
  const commandsRaw = sources.commandsText ?? readFileSync(COMMANDS_RS, "utf8");
  const commands = stripComments(commandsRaw);
  const session = stripComments(sources.sessionText ?? readFileSync(SESSION_RS, "utf8"));
  const error = stripComments(sources.errorText ?? readFileSync(ERROR_RS, "utf8"));
  const clipboard = stripComments(sources.clipboardText ?? readFileSync(join(SRC_TAURI, "src/clipboard.rs"), "utf8"));

  const fns = parseTauriFns(commands);
  const fnByName = Object.fromEntries(fns.map((f) => [f.name, f]));

  // Hand-written broker commands: wire keys/required from HAND_WRITTEN, kinds from the function signature.
  const hand = parseHandWritten(commands).map((row) => {
    const fn = fnByName[row.command];
    if (!fn) throw new Error(`commands.rs: HAND_WRITTEN names ${row.command} but no #[tauri::command] fn has that name`);
    if (fn.args.length !== row.params.length) throw new Error(`commands.rs: ${row.command}: HAND_WRITTEN lists ${row.params.length} params, the fn takes ${fn.args.length}`);
    return { command: row.command, op: row.op, params: row.params.map((p, i) => ({ key: p.key, kind: fn.args[i].kind, required: p.required })) };
  });
  const generated = parseBridgeOps(commands).map((r) => ({ command: r.command, op: r.op, params: r.params.map(({ key, kind, required }) => ({ key, kind, required })) }));

  const shell = parseShellCommands(commands).map((row) => {
    const fn = fnByName[row.command];
    if (!fn) throw new Error(`commands.rs: SHELL_COMMANDS names ${row.command} but no #[tauri::command] fn has that name`);
    return { ...row, kinds: fn.args.map((a) => a.kind) };
  });

  const copyTextMax = Number(/pub const COPY_TEXT_MAX_BYTES:\s*usize\s*=\s*(\d+)/.exec(commands)?.[1]);
  const clipboardTtl = Number(/pub const CLEAR_AFTER:\s*Duration\s*=\s*Duration::from_secs\((\d+)\)/.exec(clipboard)?.[1]);

  return {
    broker: [...hand, ...generated],
    shell,
    vaultStateOps: stringList(session, "VAULT_STATE_OPS"),
    sessionEndedCodes: stringList(error, "SESSION_ENDED_CODES"),
    brokerErrorCodes: stringList(error, "BROKER_ERROR_CODES"),
    bridgeLocalCodes: stringList(error, "BRIDGE_LOCAL_CODES"),
    copyTextMaxBytes: Number.isFinite(copyTextMax) ? copyTextMax : null,
    clipboardTtlSeconds: Number.isFinite(clipboardTtl) ? clipboardTtl : null,
  };
}

/** Every op the broker dispatches: the `"op.name" =>` match arms in ops.rs, dotted names plus the two bare ones. */
export function readBrokerOps(text = readFileSync(OPS_RS, "utf8")) {
  const names = new Set([...text.matchAll(/^\s*"([a-z_.]+)"\s*=>/gm)].map((m) => m[1]));
  return [...names].filter((n) => n.includes(".") || n === "search" || n === "whoami").sort();
}

/** Every `invoke<...>("name"` the typed client makes, in file order. */
export function readBridgeInvokes(text = readFileSync(BRIDGE_TS, "utf8")) {
  return [...text.matchAll(/invoke(?:<[\s\S]*?>)?\(\s*"([a-z_|:]+)"/g)].map((m) => m[1]);
}
