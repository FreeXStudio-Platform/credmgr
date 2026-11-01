#!/usr/bin/env node
/**
 * compile.mjs - the build-time template compiler.
 *
 * The KEEP design is authored as a ".dc.html" template: HTML plus `{{ path }}` holes, <sc-if value> and
 * <sc-for list as>.  The upstream runtime compiles that template in the browser (innerHTML + a DOM walk) and
 * evaluates the logic class with `new Function`, neither of which a strict Content-Security-Policy allows.
 * This module does the same job at BUILD time and emits a plain ES module of React.createElement calls, so
 * nothing is parsed or evaluated at runtime and the production CSP can stay `script-src 'self'` without
 * `'unsafe-eval'` or `'unsafe-inline'`.
 *
 * It is a clean-room implementation of the template semantics recorded in the architect's spec
 * (fe-spec.md section A1/A4), not a copy of the upstream runtime.
 *
 *   node scripts/dc/compile.mjs --check src/design/app.template.html      compile, report, exit 1 on error
 *   node scripts/dc/compile.mjs src/design/app.template.html --out x.js   write the generated module
 *   node scripts/dc/compile.mjs --flatten src/design/app.template.html    print the template with includes inlined
 *
 * Extensions over the upstream dialect (compile time only):
 *   <sc-include src="./screens/x.html"></sc-include>   replaced by the file's text, verbatim.  The tag must sit on a
 *   line of its own (indentation allowed); the included file's single trailing newline is dropped, so
 *   `--flatten` of a split template equals the unsplit template byte for byte.  Compile errors name the INCLUDED
 *   file and its own line number, not a position in the flattened text.
 *
 * Template expressions are NOT JavaScript.  Grammar (same as upstream): a dotted path `a.b.c`, `a[expr]`,
 * `true|false|null|undefined`, numbers, quoted strings, `!`, `===` `!==` `==` `!=`, and parentheses.  There are
 * no calls and no other operators; anything else is a compile error.  Nothing from a template is ever spliced
 * into the generated code unescaped (identifiers are validated, strings go through JSON.stringify).
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseFragment } from "parse5";

export class CompileError extends Error {
  constructor(message, file, line) {
    super(`${file || "<template>"}${line ? `:${line}` : ""}: ${message}`);
    this.name = "CompileError";
    this.file = file;
    this.line = line;
  }
}

// ───────────────────────────── includes ─────────────────────────────
const INCLUDE_LINE = /^[ \t]*<sc-include\s+src="([^"]+)"\s*>\s*<\/sc-include>[ \t]*$/;
const rel = (p) => relative(process.cwd(), p).split(sep).join("/");

/**
 * Expand every <sc-include> line.  Nested includes allowed, cycles are an error.
 * @returns {{ lines: string[], map: { file: string, line: number }[] }}  map[i] = where flattened line i came from
 */
export function expandIncludes(text, file, read = (p) => readFileSync(p, "utf8"), stack = []) {
  text = text.replace(/\r\n/g, "\n"); // a Windows checkout may hand us CRLF; the dialect is LF-only
  const abs = resolve(file);
  if (stack.includes(abs)) throw new CompileError(`include cycle: ${[...stack, abs].map(rel).join(" -> ")}`, rel(abs));
  const lines = [];
  const map = [];
  text.split("\n").forEach((line, i) => {
    const m = line.match(INCLUDE_LINE);
    if (!m) {
      if (line.includes("<sc-include")) throw new CompileError("an <sc-include> must be on a line of its own", rel(abs), i + 1);
      lines.push(line);
      map.push({ file: rel(abs), line: i + 1 });
      return;
    }
    const target = resolve(dirname(abs), m[1]);
    let body;
    try {
      body = read(target);
    } catch {
      throw new CompileError(`include not found: ${m[1]}`, rel(abs), i + 1);
    }
    const inner = expandIncludes(body.replace(/\n$/, ""), target, read, [...stack, abs]);
    lines.push(...inner.lines);
    map.push(...inner.map);
  });
  return { lines, map };
}

/** Same as expandIncludes, flattened to one string. */
export function inlineIncludes(text, file, read, stack) {
  return expandIncludes(text, file, read, stack).lines.join("\n");
}

export function flatten(file) {
  return inlineIncludes(readFileSync(file, "utf8"), file);
}

/** Read a root template with includes inlined; also report every file that contributed (for watch mode). */
export function readTemplate(file) {
  const files = new Set([resolve(file)]);
  const read = (p) => (files.add(resolve(p)), readFileSync(p, "utf8"));
  const { lines, map } = expandIncludes(read(file), file, read);
  return { text: lines.join("\n"), files: [...files], lineMap: map };
}

// ───────────────────────────── encoding ─────────────────────────────
// The HTML parser lowercases attribute names and hoists / drops some children of <select> and table elements.
// Both are undone by renaming BEFORE parsing, exactly like the upstream dialect does:
const CAMEL_PREFIX = "sc-camel-";
const CAMEL_ATTR_RE = /(\s)([a-z]+[A-Z][A-Za-z0-9]*)(\s*=)/g;
const RAW_WRAP = {
  select: "sc-raw-select",
  table: "sc-raw-table",
  tbody: "sc-raw-tbody",
  thead: "sc-raw-thead",
  tfoot: "sc-raw-tfoot",
  tr: "sc-raw-tr",
  td: "sc-raw-td",
  th: "sc-raw-th",
  caption: "sc-raw-caption",
};
const RAW_UNWRAP = Object.fromEntries(Object.entries(RAW_WRAP).map(([k, v]) => [v, k]));

export function encode(html) {
  html = html.replace(CAMEL_ATTR_RE, (_, sp, name, eq) => sp + CAMEL_PREFIX + name.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase()) + eq);
  for (const [real, alias] of Object.entries(RAW_WRAP)) {
    html = html.replace(new RegExp("(</?)" + real + "(?=[\\s>])", "gi"), "$1" + alias);
  }
  return html;
}

const kebabToCamel = (s) => s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());

/** `a:b;c-d:e` -> { a: "b", cD: "e" }.  Custom properties keep their name.  Same rules as the upstream dialect. */
export function cssToObj(text) {
  const o = {};
  for (const decl of text.split(";")) {
    const i = decl.indexOf(":");
    if (i < 0) continue;
    const prop = decl.slice(0, i).trim();
    o[prop.startsWith("--") ? prop : kebabToCamel(prop)] = decl.slice(i + 1).trim();
  }
  return o;
}

// ───────────────────────────── expressions ─────────────────────────────
const IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*/;
const NUMBER_RE = /^-?\d+(\.\d+)?$/;

function parensWrapWhole(expr) {
  let depth = 0;
  for (let i = 0; i < expr.length - 1; i++) {
    if (expr[i] === "(") depth++;
    else if (expr[i] === ")") {
      depth--;
      if (depth === 0) return false;
    }
  }
  return true;
}

function findTopLevelEquality(expr) {
  let depth = 0;
  for (let i = 0; i < expr.length; i++) {
    const c = expr[i];
    if (c === "[" || c === "(") depth++;
    else if (c === "]" || c === ")") depth--;
    else if (depth === 0 && (c === "=" || c === "!") && expr[i + 1] === "=") {
      if (i > 0 && (expr[i - 1] === "=" || expr[i - 1] === "!")) continue;
      if (!expr.slice(0, i).trim()) continue;
      const op = expr[i + 2] === "=" ? c + "==" : c + "=";
      return { index: i, op };
    }
  }
  return null;
}

/**
 * Translate one template expression into a JavaScript expression over the scope object `scope`.
 * `locals` are the names bound by enclosing <sc-for> (they are read from the scope object too, because the
 * loop scope is a copy of its parent plus the loop variables); everything else is recorded in `bindings`.
 */
function emitExpr(src, env, at) {
  const fail = (msg) => {
    throw new CompileError(`${msg} in {{ ${String(src).trim()} }}`, at.file, at.line);
  };
  const expr = String(src).trim();
  if (!expr) return fail("empty expression");
  if (expr[0] === "(" && expr[expr.length - 1] === ")" && parensWrapWhole(expr)) return emitExpr(expr.slice(1, -1), env, at);
  const eq = findTopLevelEquality(expr);
  if (eq) return `(${emitExpr(expr.slice(0, eq.index), env, at)} ${eq.op} ${emitExpr(expr.slice(eq.index + eq.op.length), env, at)})`;
  if (expr[0] === "!") return `(!${emitExpr(expr.slice(1), env, at)})`;
  if (expr === "true" || expr === "false" || expr === "null" || expr === "undefined") return expr;
  if (NUMBER_RE.test(expr)) return `(${Number(expr)})`;
  if (expr.length >= 2 && (expr[0] === '"' || expr[0] === "'") && expr[expr.length - 1] === expr[0]) return JSON.stringify(expr.slice(1, -1));

  const head = expr.match(IDENT_RE);
  if (!head) return fail("unsupported syntax (expected a path, a literal, ! or a comparison)");
  if (!env.locals.has(head[0])) env.bindings.add(head[0]);
  let out = `${env.scope}.${head[0]}`;
  let i = head[0].length;
  while (i < expr.length) {
    if (expr[i] === ".") {
      const rest = expr.slice(i + 1);
      const id = rest.match(IDENT_RE);
      const num = rest.match(/^\d+/);
      if (id) {
        out += `?.${id[0]}`;
        i += 1 + id[0].length;
      } else if (num) {
        out += `?.[${Number(num[0])}]`;
        i += 1 + num[0].length;
      } else return fail("unsupported syntax after '.'");
    } else if (expr[i] === "[") {
      let depth = 1;
      let j = i + 1;
      while (j < expr.length && depth > 0) {
        if (expr[j] === "[") depth++;
        else if (expr[j] === "]") {
          depth--;
          if (depth === 0) break;
        }
        j++;
      }
      if (depth !== 0) return fail("unbalanced '['");
      out += `?.[${emitExpr(expr.slice(i + 1, j), env, at)}]`;
      i = j + 1;
    } else return fail(`unsupported syntax at '${expr.slice(i, i + 8)}'`);
  }
  return out;
}

const WHOLE_RE = /^\s*\{\{([\s\S]+?)\}\}\s*$/;

// ───────────────────────────── events / pseudo classes ─────────────────────────────
const EVENT_MAP = Object.fromEntries(
  (
    "click Click,change Change,input Input,submit Submit,keydown KeyDown,keyup KeyUp,keypress KeyPress,mousedown MouseDown," +
    "mouseup MouseUp,mouseenter MouseEnter,mouseleave MouseLeave,focus Focus,blur Blur,doubleclick DoubleClick,dblclick DoubleClick," +
    "contextmenu ContextMenu,mousemove MouseMove,mouseover MouseOver,mouseout MouseOut,pointerdown PointerDown,pointerup PointerUp," +
    "pointermove PointerMove,pointerenter PointerEnter,pointerleave PointerLeave,pointercancel PointerCancel,pointerover PointerOver," +
    "pointerout PointerOut,touchstart TouchStart,touchend TouchEnd,touchmove TouchMove,touchcancel TouchCancel,dragstart DragStart," +
    "dragend DragEnd,dragenter DragEnter,dragleave DragLeave,dragover DragOver,wheel Wheel,scroll Scroll,animationend AnimationEnd," +
    "transitionend TransitionEnd"
  )
    .split(",")
    .map((p) => p.split(" "))
    .map(([dom, react]) => ["on" + dom, "on" + react]),
);

/** Add `!important` to every declaration (an inline style attribute would otherwise outrank the class rule). */
export function importantify(text) {
  text = text.replace(/\/\*[\s\S]*?\*\//g, " ");
  const decls = [];
  let start = 0;
  let depth = 0;
  let quote = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
    } else if (c === "'" || c === '"') quote = c;
    else if (c === "(") depth++;
    else if (c === ")") depth = Math.max(0, depth - 1);
    else if (c === ";" && depth === 0) {
      decls.push(text.slice(start, i));
      start = i + 1;
    }
  }
  decls.push(text.slice(start));
  return decls
    .map((d) => d.trim())
    .filter(Boolean)
    .map((d) => (/!\s*important$/i.test(d) ? d : d + " !important"))
    .join(";");
}

// Elements and attributes the production build refuses outright (CSP + no-network posture).
const FORBIDDEN_TAGS = new Set(["script", "style", "link", "meta", "base", "iframe", "frame", "object", "embed", "template", "x-import", "dc-import", "sc-helmet", "helmet"]);
// [template attribute (lower-case), React prop, generated value] added to every <input> and <textarea> that does not set it.
const TEXT_INPUT_DEFAULTS = [
  ["autocomplete", "autoComplete", '"off"'],
  ["autocorrect", "autoCorrect", '"off"'],
  ["autocapitalize", "autoCapitalize", '"off"'],
  ["spellcheck", "spellCheck", "false"],
];
const URL_ATTRS = new Set(["src", "srcset", "action", "formaction", "poster", "srcdoc", "data", "xlink:href"]);
const IS_IDENT = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const propKey = (k) => (IS_IDENT.test(k) ? k : JSON.stringify(k));

// ───────────────────────────── code generation ─────────────────────────────
/**
 * @param {string} source          the template, includes already inlined
 * @param {object} [opts]
 * @param {string} [opts.file]     name used in error messages
 * @param {string} [opts.runtimeImport]  module specifier of the runtime helpers
 * @returns {{ code: string, css: string, bindings: string[], stats: object }}
 */
export function compile(source, opts = {}) {
  const file = opts.file || "<template>";
  const runtimeImport = opts.runtimeImport || "../dc/runtime";
  const encoded = encode(source);
  const frag = parseFragment(encoded, { sourceCodeLocationInfo: true });

  const bindings = new Set();
  const styleConsts = new Map(); // css text -> const name
  const pseudoClasses = new Map(); // "pseudo|css" -> class
  const pseudoRules = [];
  const stats = { elements: 0, textNodes: 0, ifs: 0, fors: 0, expressions: 0 };

  const lineOf = (node) => node.sourceCodeLocation?.startLine;
  // Where a node came from: the included file and its own line when the template was split with <sc-include>.
  const origin = (node) => {
    const line = lineOf(node);
    const m = line && opts.lineMap ? opts.lineMap[line - 1] : null;
    return m ? { file: m.file, line: m.line } : { file, line };
  };
  const at = (node) => origin(node);

  function styleConst(text) {
    let name = styleConsts.get(text);
    if (!name) {
      name = `S${styleConsts.size}`;
      styleConsts.set(text, name);
    }
    return name;
  }

  function pseudoClass(pseudo, text) {
    const k = `${pseudo}|${text}`;
    let cls = pseudoClasses.get(k);
    if (!cls) {
      cls = `dch${pseudoClasses.size}`;
      pseudoClasses.set(k, cls);
      const isElement = pseudo === "before" || pseudo === "after";
      pseudoRules.push(`.${cls}${isElement ? "::" : ":"}${pseudo}{${isElement ? text : importantify(text)}}`);
    }
    return cls;
  }

  const ex = (src, env, node) => (stats.expressions++, emitExpr(src, env, at(node)));

  /** attribute value -> JS expression (a raw value for a whole `{{x}}`, a string otherwise) */
  function attrValue(raw, env, node) {
    const whole = raw.match(WHOLE_RE);
    if (whole) return ex(whole[1], env, node);
    if (raw.includes("{{")) {
      const parts = raw.split(/\{\{([\s\S]+?)\}\}/g);
      const items = parts.map((p, i) => (i & 1 ? `String(${ex(p, env, node)} ?? "")` : p === "" ? null : JSON.stringify(p))).filter((x) => x !== null);
      return items.length === 1 ? items[0] : items.join(" + ");
    }
    return JSON.stringify(raw);
  }

  function genChildren(parent, env, depth) {
    const out = [];
    for (const child of parent.childNodes || []) {
      const code = genNode(child, env, out.length, depth);
      if (code !== null) out.push(code);
    }
    return out;
  }

  const whereArgs = (node) => {
    const o = origin(node);
    return [o.file, o.line];
  };
  const pad = (n) => "  ".repeat(n);

  function genNode(node, env, idx, depth) {
    if (node.nodeName === "#text") {
      stats.textNodes++;
      const txt = node.value;
      if (!txt.includes("{{")) {
        if (!txt.trim() && !txt.includes(" ")) return null;
        return JSON.stringify(txt);
      }
      const parts = txt.split(/\{\{([\s\S]+?)\}\}/g);
      const items = parts.map((p, i) => (i & 1 ? `interp(${ex(p, env, node)}, ${i})` : p === "" ? null : JSON.stringify(p))).filter((x) => x !== null);
      return `F(${idx}, [${items.join(", ")}])`;
    }
    if (!node.tagName) return null; // comment
    const tag = node.tagName;

    if (tag === "sc-if") {
      stats.ifs++;
      const valueAttr = node.attrs.find((a) => a.name === "value");
      if (!valueAttr) throw new CompileError("<sc-if> needs a value attribute", ...whereArgs(node));
      const cond = attrValue(valueAttr.value, env, node);
      const kids = genChildren(node, env, depth + 1);
      return `(${cond}) ? F(${idx}, [${kids.length ? "\n" + kids.map((k) => pad(depth + 1) + k).join(",\n") + "\n" + pad(depth) : ""}]) : null`;
    }

    if (tag === "sc-for") {
      stats.fors++;
      const listAttr = node.attrs.find((a) => a.name === "list");
      const asName = node.attrs.find((a) => a.name === "as")?.value || "item";
      if (!listAttr || !WHOLE_RE.test(listAttr.value)) throw new CompileError("<sc-for> needs list=\"{{expr}}\"", ...whereArgs(node));
      if (!IS_IDENT.test(asName)) throw new CompileError(`<sc-for as="${asName}"> is not an identifier`, ...whereArgs(node));
      const list = attrValue(listAttr.value, env, node);
      const scope = `v${env.level + 1}`;
      const inner = { ...env, scope, level: env.level + 1, locals: new Set([...env.locals, asName, "$index"]) };
      const kids = genChildren(node, inner, depth + 2);
      return (
        `F(${idx}, L(${list}).map((item, i) => {\n` +
        `${pad(depth + 1)}const ${scope} = { ...${env.scope}, [${JSON.stringify(asName)}]: item, $index: i };\n` +
        `${pad(depth + 1)}return F(i, [${kids.length ? "\n" + kids.map((k) => pad(depth + 2) + k).join(",\n") + "\n" + pad(depth + 1) : ""}]);\n` +
        `${pad(depth)}}))`
      );
    }

    if (tag.startsWith("sc-") && !RAW_UNWRAP[tag]) {
      throw new CompileError(`unknown template element <${tag}>`, ...whereArgs(node));
    }

    // ── a real DOM element ──
    const real = RAW_UNWRAP[tag] || tag;
    if (FORBIDDEN_TAGS.has(real)) throw new CompileError(`<${real}> is not allowed in a template (production CSP, no runtime resources)`, ...whereArgs(node));
    stats.elements++;

    const props = [`key: ${idx}`];
    const pseudo = [];
    let classExpr = null;
    for (const a of node.attrs) {
      let key = a.name;
      if (key === "sc-name" || key === "data-dc-tpl" || key === "data-dc-atomics") {
        if (key === "data-dc-atomics") throw new CompileError("data-dc-atomics is not supported", ...whereArgs(node));
        continue;
      }
      if (key.startsWith(CAMEL_PREFIX)) key = kebabToCamel(key.slice(CAMEL_PREFIX.length));
      if (key.startsWith("hint-")) continue; // streaming placeholders, authoring-time only
      if (key.startsWith("style-")) {
        if (a.value.includes("{{")) {
          throw new CompileError(`${a.name}: pseudo-class styles must be static (a {{ }} here would need a runtime stylesheet)`, ...whereArgs(node));
        }
        pseudo.push(pseudoClass(key.slice(6), a.value));
        continue;
      }
      if (URL_ATTRS.has(key) && a.value.trim()) throw new CompileError(`${key}="${a.value}" would load a resource; the app is fully local`, ...whereArgs(node));
      if (key === "href" && a.value !== "#") throw new CompileError(`<a href="${a.value}"> is not allowed (only href="#")`, ...whereArgs(node));
      if (key === "class") key = "className";
      else if (key === "for") key = "htmlFor";
      else if (key.startsWith("on") && key.length > 2) {
        if (!WHOLE_RE.test(a.value)) throw new CompileError(`${a.name}: an event handler must be exactly one {{ path }}`, ...whereArgs(node));
        key = EVENT_MAP[key] || EVENT_MAP[key.toLowerCase()] || "on" + key[2].toUpperCase() + key.slice(3);
      }

      let value;
      if (key === "style") {
        if (a.value.includes("{{")) value = `css(${attrValue(a.value, env, node)})`;
        else value = styleConst(a.value);
      } else {
        value = attrValue(a.value, env, node);
        if ((key === "value" || key === "checked") && WHOLE_RE.test(a.value)) value = `${value} ?? ${key === "checked" ? "false" : '""'}`;
      }
      if (key === "className") {
        classExpr = value;
        continue;
      }
      props.push(`${propKey(key)}: ${value}`);
    }
    if (real === "input" || real === "textarea") {
      // Text typed into a field is never the system's to "correct": WebKit's autocorrect and autocapitalisation rewrote a typed
      // node name ("beta" -> "Beta", so the seal confirmation could not match), a search ("mfa" -> "Mea") and secret values, and
      // spellcheck hands the words to the OS.  A template that sets one of these itself keeps its own value.
      const named = new Set(node.attrs.map((a) => (a.name.startsWith(CAMEL_PREFIX) ? kebabToCamel(a.name.slice(CAMEL_PREFIX.length)) : a.name).toLowerCase()));
      for (const [attr, prop, value] of TEXT_INPUT_DEFAULTS) if (!named.has(attr)) props.push(`${prop}: ${value}`);
    }
    if (classExpr !== null || pseudo.length) {
      const extra = pseudo.map((c) => JSON.stringify(c));
      if (classExpr === null) props.push(`className: ${extra.join(" + ' ' + ")}`);
      else if (!pseudo.length) props.push(`className: ${classExpr}`);
      else props.push(`className: cx(${[classExpr, ...extra].join(", ")})`);
    }

    const kids = genChildren(node, env, depth + 1);
    const head = `h(${JSON.stringify(real)}, { ${props.join(", ")} }`;
    if (!kids.length) return `${head})`;
    return `${head},\n${kids.map((k) => pad(depth + 1) + k).join(",\n")}\n${pad(depth)})`;
  }

  const env = { scope: "v", level: 0, locals: new Set(), bindings };
  const top = genChildren(frag, env, 2);

  const consts = [...styleConsts].map(([text, name]) => `const ${name} = ${JSON.stringify(cssToObj(text))};`);
  const code =
    `// GENERATED by scripts/dc/compile.mjs from ${file} - do not edit.\n` +
    `import { h, F, L, interp, css, cx } from ${JSON.stringify(runtimeImport)};\n\n` +
    (consts.length ? consts.join("\n") + "\n\n" : "") +
    `export const bindings = ${JSON.stringify([...bindings].sort())};\n\n` +
    `export default function render(v) {\n  return [\n${top.map((k) => pad(2) + k).join(",\n")}\n  ];\n}\n`;
  return { code, css: pseudoRules.join("\n") + (pseudoRules.length ? "\n" : ""), bindings: [...bindings].sort(), stats };
}

export function compileFile(file, opts = {}) {
  const abs = resolve(file);
  const { text, files, lineMap } = readTemplate(abs);
  return { ...compile(text, { file: rel(abs), lineMap, ...opts }), files };
}

// ───────────────────────────── CLI ─────────────────────────────
function cli(argv) {
  const check = argv.includes("--check");
  const doFlatten = argv.includes("--flatten");
  const outIdx = argv.indexOf("--out");
  const out = outIdx >= 0 ? argv[outIdx + 1] : null;
  const file = argv.find((a, i) => !a.startsWith("--") && !(i > 0 && argv[i - 1] === "--out"));
  if (!file) {
    console.error("usage: node scripts/dc/compile.mjs [--check|--flatten] [--out file.js] <template.html>");
    return 2;
  }
  try {
    if (doFlatten) {
      process.stdout.write(flatten(file));
      return 0;
    }
    const r = compileFile(file);
    if (out) writeFileSync(out, r.code);
    if (check || out) {
      const s = r.stats;
      console.log(`compile ok: ${s.elements} elements, ${s.ifs} sc-if, ${s.fors} sc-for, ${s.expressions} expressions, ${r.bindings.length} bindings, ${r.css.split("\n").filter(Boolean).length} pseudo rules`);
    }
    return 0;
  } catch (e) {
    if (e instanceof CompileError) {
      console.error(`compile error: ${e.message}`);
      return 1;
    }
    throw e;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(cli(process.argv.slice(2)));
