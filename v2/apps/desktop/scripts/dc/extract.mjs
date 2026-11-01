#!/usr/bin/env node
/**
 * extract.mjs - split the (sanitized) upstream app file into its four parts.
 *
 *   node scripts/dc/extract.mjs [design-upstream/<date>]      (default: the newest dated snapshot)
 *
 * Writes <snapshot>/extracted/:
 *   app.template.html   the <x-dc> body without the <helmet> block, byte for byte
 *   app.logic.js        the `class Component extends DCLogic {...}` source, byte for byte, wrapped by two
 *                       fixed lines (the imports on top, `export default Component` below)
 *   app.helmet.css      the contents of the helmet's <style> elements (the <link> tags become imports in main.ts)
 *   app.props.json      the editor props metadata (theme, mode, ...), decoded
 *
 * These files are the three-way-merge BASE.  src/design/ starts as a copy and is hand-edited from there on
 * (it is a derived fork - ADR-075).  When a newer upstream drop arrives, run import.mjs + extract.mjs on it
 * and `git merge-file src/design/<f> <old extracted>/<f> <new extracted>/<f>` (see scripts/dc/sync.mjs).
 *
 * The extractor is string based on purpose: the compiler later re-parses the template with a spec-conformant
 * HTML parser, but extraction must not re-serialize anything, or the merge base would stop being the upstream.
 */
import { mkdirSync, readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");

export const LOGIC_HEAD = 'import React from "react";\nimport { DCLogic } from "../../dc/runtime";\n\n';
export const LOGIC_TAIL = "\n\nexport default Component;\n";

const ENTITIES = { "&quot;": '"', "&amp;": "&", "&lt;": "<", "&gt;": ">", "&#39;": "'", "&#x27;": "'", "&apos;": "'" };
const decodeEntities = (s) => s.replace(/&(?:quot|amp|lt|gt|#39|#x27|apos);/g, (m) => ENTITIES[m]);

export function extract(html) {
  const open = html.indexOf("<x-dc>");
  const close = html.indexOf("</x-dc>");
  if (open < 0 || close < open) throw new Error("no <x-dc>...</x-dc> block");
  let body = html.slice(open + "<x-dc>".length, close);
  if (body.startsWith("\n")) body = body.slice(1);

  // helmet: CSS out, <link> tags are accounted for (imports in main.ts), anything else is an error
  let css = "";
  const h0 = body.indexOf("<helmet>");
  const h1 = body.indexOf("</helmet>");
  if (h0 >= 0) {
    if (h1 < h0) throw new Error("unterminated <helmet>");
    const helmet = body.slice(h0 + "<helmet>".length, h1);
    const leftover = helmet
      .replace(/<link\s+rel="stylesheet"\s+href="\.\/assets\/(?:keep|keep-components)\.css">/g, "")
      .replace(/<style>([\s\S]*?)<\/style>/g, (_, c) => ((css += c.replace(/^\n/, "")), ""))
      .trim();
    if (leftover) throw new Error(`unexpected helmet content (only the two KEEP stylesheets and <style> are supported): ${leftover.slice(0, 120)}`);
    let end = h1 + "</helmet>".length;
    if (body[end] === "\n") end++;
    body = body.slice(0, h0) + body.slice(end);
  }

  // logic
  const sm = html.match(/<script\b[^>]*\bdata-dc-script\b([^>]*)>/);
  if (!sm) throw new Error("no <script data-dc-script>");
  const tagStart = html.indexOf(sm[0]);
  const logicStart = tagStart + sm[0].length;
  const logicEnd = html.indexOf("</script>", logicStart);
  if (logicEnd < 0) throw new Error("unterminated logic script");
  let logic = html.slice(logicStart, logicEnd);
  if (logic.startsWith("\n")) logic = logic.slice(1);
  if (!/^\s*class Component extends DCLogic\b/.test(logic)) throw new Error("logic must start with `class Component extends DCLogic`");

  const propsAttr = sm[0].match(/\bdata-props="([^"]*)"/);
  const props = propsAttr ? JSON.parse(decodeEntities(propsAttr[1])) : {};

  return { template: body, css, logic: LOGIC_HEAD + logic.replace(/\s+$/, "") + LOGIC_TAIL, props };
}

function main() {
  const base = join(ROOT, "design-upstream");
  const arg = process.argv[2];
  const snap = arg
    ? resolve(arg)
    : join(base, readdirSync(base).filter((d) => /^\d{4}-\d{2}-\d{2}$/.test(d)).sort().pop());
  const file = join(snap, "CredMgr App.dc.html");
  if (!existsSync(file)) {
    console.error("no snapshot at", snap);
    process.exit(2);
  }
  const { template, css, logic, props } = extract(readFileSync(file, "utf8"));
  const out = join(snap, "extracted");
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, "app.template.html"), template);
  writeFileSync(join(out, "app.helmet.css"), css);
  writeFileSync(join(out, "app.logic.js"), logic);
  writeFileSync(join(out, "app.props.json"), JSON.stringify(props, null, 2) + "\n");
  console.log(`extracted -> ${out}`);
  console.log(`  template ${template.split("\n").length} lines, logic ${logic.split("\n").length} lines, css ${css.split("\n").length} lines, props ${Object.keys(props).length}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
