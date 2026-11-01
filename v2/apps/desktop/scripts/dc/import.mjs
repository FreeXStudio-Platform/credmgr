#!/usr/bin/env node
/**
 * import.mjs - turn a Claude Design export directory into a committed, sanitized
 * snapshot under design-upstream/<date>/.
 *
 *   node scripts/dc/import.mjs <export-dir> [--date YYYY-MM-DD] [--exported-at ISO-8601]
 *
 * WHY THIS IS NOT A COPY.  The upstream export cannot be committed verbatim:
 *   1. the serving API injects <style|script data-omelette-injected> blocks into every .dc.html;
 *   2. the app file carries two private-key header strings (mock data) that the portfolio secret
 *      gate rejects, a contactable e-mail address on a real brand domain, and the operator's real
 *      project names as mock nodes - all forbidden in a tracked file (SESSION_PROTOCOL 6.5).
 * So the importer applies a fixed, re-runnable list of replacements and records the sha256 of
 * every file BEFORE (raw), after stripping, and after sanitizing in design-upstream/PROVENANCE.md.
 *
 * Only the files the build and its gates need are written (ALLOWLIST).  Everything else is recorded by sha256 only:
 * it is not needed, several carry forbidden data, and support.js / image-slot.js / doc-page.js carry
 * no redistribution grant.  The one development tool that IS committed is the design team's in-page audit probe
 * (audit-probe.js): `npm run test:design` runs it, and a gate whose input lives outside the repository skips on a fresh
 * clone, which is a gate nobody runs.  It goes through the same sanitizer as the app file (it is the design side's own
 * file; it carries no key, address or name today, and the sanitizer keeps it that way), and its sha256 before and after
 * is recorded in design-upstream/PROVENANCE.md, which scripts/verify-design-audit.mjs checks it against on every run.
 *
 * The project-name replacement pairs are NOT in this file, and the table is not kept in the repository tree at
 * all - writing it down would spell the names it exists to remove.  The pairs come from DC_SANITIZE_MAP (inline,
 * "from=to,from=to") or from the file named by DC_SANITIZE_MAP_FILE (one "from=to" per line, kept by the person
 * running the import outside the working tree).  With neither set the importer still replaces the generic items
 * (key headers, e-mail addresses) and says loudly that project names were NOT replaced.  PROVENANCE records only
 * how many tokens were replaced.
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../.."); // v2/apps/desktop

/** Files copied into the snapshot (relative to the export dir). */
const ALLOWLIST = [
  "CredMgr App.dc.html",
  "audit-probe.js",
  "assets/keep.css",
  "assets/keep-components.css",
  ...[
    "inter-latin-400",
    "inter-latin-500",
    "inter-latin-600",
    "inter-latin-700",
    "inter-tight-latin-600",
    "inter-tight-latin-700",
    "jetbrains-mono-latin-400",
    "jetbrains-mono-latin-500",
    "jetbrains-mono-latin-600",
    "jetbrains-mono-latin-700",
  ].map((n) => `assets/fonts/${n}.woff2`),
];

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

function walk(dir, base = dir) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p, base));
    else out.push(relative(base, p).split("\\").join("/"));
  }
  return out;
}

/** Remove <style|script data-omelette-injected> blocks, keeping their newlines so line numbers survive. */
export function stripInjected(text) {
  let n = 0;
  const keepNewlines = (block) => "\n".repeat((block.match(/\n/g) || []).length);
  let out = text.replace(
    /<style\b[^>]*\bdata-omelette-injected\b[^>]*>[\s\S]*?<\/style>/g,
    (m) => (n++, keepNewlines(m)),
  );
  out = out.replace(
    /<script\b[^>]*\bdata-omelette-injected\b[^>]*>[\s\S]*?<\/script>/g,
    (m) => (n++, keepNewlines(m)),
  );
  return { text: out, blocks: n };
}

const PUBLIC_CONTACT = "Admin@freexstudio.com";
const RESERVED_EMAIL_DOMAINS = new Set(["example.com", "example.net", "example.org"]);
const RESERVED_EMAIL_TLDS = [".example", ".test", ".invalid", ".localhost"];
const reservedDomain = (d) =>
  RESERVED_EMAIL_DOMAINS.has(d.toLowerCase()) || RESERVED_EMAIL_TLDS.some((t) => d.toLowerCase().endsWith(t));

function loadNameMap() {
  const pairs = [];
  const add = (spec) => {
    const i = spec.indexOf("=");
    if (i > 0) pairs.push([spec.slice(0, i).trim(), spec.slice(i + 1).trim()]);
  };
  if (process.env.DC_SANITIZE_MAP) process.env.DC_SANITIZE_MAP.split(",").forEach(add);
  const file = process.env.DC_SANITIZE_MAP_FILE;
  if (file) {
    if (!existsSync(file)) throw new Error(`DC_SANITIZE_MAP_FILE points at a file that does not exist: ${file}`);
    readFileSync(file, "utf8").split("\n").forEach((l) => l.trim() && !l.startsWith("#") && add(l));
  }
  return pairs.filter(([a, b]) => a && b);
}

const matchCase = (found, repl) =>
  found === found.toUpperCase() ? repl.toUpperCase() : found[0] === found[0].toUpperCase() ? repl[0].toUpperCase() + repl.slice(1) : repl;

/**
 * Apply the fixed replacements.  Returns the text plus a per-rule count (for PROVENANCE).
 * @param {string} text
 * @param {[string, string][]} [pairs] the project-name pairs (default: from the environment, see loadNameMap)
 */
export function sanitize(text, pairs = loadNameMap()) {
  const counts = { keyHeaders: 0, emails: 0, licence: 0, unlockCode: 0, names: 0, ipv4: 0 };
  // 1. private-key armour lines (mock data) -> a string no secret scanner reads as a key
  text = text.replace(/-----(BEGIN|END) (?:[A-Z]+ )*PRIVATE KEY-----/g, (_, w) => (counts.keyHeaders++, `-----${w} EXAMPLE KEY-----`));
  // 2. contactable e-mail on a real domain -> same local part on example.com
  //    The one public contact address (the donation-proof mailbox) is kept; the design's own placeholder for it,
  //    billing@example.com, is replaced by it (issue #34).
  text = text.replace(/\bbilling@example\.com\b/g, () => (counts.emails++, PUBLIC_CONTACT));
  text = text.replace(/\b([A-Za-z0-9._%+-]+)@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b/g, (m, user, dom) =>
    reservedDomain(dom) || m.toLowerCase() === PUBLIC_CONTACT.toLowerCase() ? m : (counts.emails++, `${user.toLowerCase()}@example.com`),
  );
  // 2b. an IPv4 address that is not a documentation, loopback, unspecified, broadcast or link-local constant (a mock server's host, e.g. a
  //     private-range one) -> the documentation range 203.0.113.0/24 with the same last octet.  The public-export leak gate refuses such an
  //     address in any tracked file, and a design's mock data has no business naming a real network.
  text = text.replace(/(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])/g, (m, a, b, c, d) => {
    const o = [a, b, c, d].map(Number);
    if (o.some((n) => n > 255)) return m;
    const [p, q, r] = o;
    const doc = (p === 192 && q === 0 && r === 2) || (p === 198 && q === 51 && r === 100) || (p === 203 && q === 0 && r === 113);
    const constant = p === 127 || (p === 0 && q === 0 && r === 0) || (p === 255 && q === 255 && r === 255) || (p === 169 && q === 254);
    return doc || constant ? m : (counts.ipv4++, `203.0.113.${o[3]}`);
  });
  // 3. the design's own licence sentence: it says organisational or commercial use needs a paid licence, which
  //    contradicts the LICENSE this repository ships (free today, future versions possibly paid, none stated as required now).  The sentence (and the "free for personal use" one before it)
  //    is replaced so the committed snapshot never states terms this project does not have.
  text = text.replace(/(?:Free for personal and individual use\.\s*)?[^.<>]*\brequires a paid licen[cs]e\b[^.<>]*\./g, () => (counts.licence++, "Source-available; see LICENSE for the terms."));
  // 4. a shared supporter unlock code must never be in the app file (ADR-082: the extras ship sealed, the code is not in the
  //    source).  Nothing is rewritten here: any hit is COUNTED and refusal() fails the import.  A hit is the old
  //    donateUnlockCodeVal function, or an all-caps run of 12+ letters assigned to a code-like constant.
  counts.unlockCode =
    (text.match(/\bdonateUnlockCodeVal\b/g) || []).length +
    (text.match(/(?:[Cc]ode|[Uu]nlock|[Ss]upporter)\w*\s*[:=]\s*(["'])[A-Z]{12,}\1/g) || []).length;
  // 5. the operator's real project names (table is untracked, see header)
  for (const [from, to] of pairs) {
    const re = new RegExp(`(?<![A-Za-z0-9])${from.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![A-Za-z0-9])`, "gi");
    text = text.replace(re, (found) => (counts.names++, matchCase(found, to)));
  }
  return { text, counts };
}

/** The exit code and message for a refusal, or null when the import may proceed. */
export function refusal({ pairs, noNameMap, nameTokens, missing, unlockCodes = 0 }) {
  if (unlockCodes > 0) {
    return `REFUSED: the export contains ${unlockCodes} shared unlock-code value(s) (donateUnlockCodeVal or an all-caps code constant). The supporter pack ships sealed and the code is not in the source (ADR-082); nothing was written.`;
  }
  if (missing.length) return `export is missing allowlisted files: ${missing.join(", ")}`;
  if (!pairs.length && !noNameMap) {
    return "REFUSED: no project-name map (DC_SANITIZE_MAP / DC_SANITIZE_MAP_FILE). The export carries real project names and no later gate can see them, so nothing was written. Supply the map, or pass --no-name-map only if you have checked by hand that the export holds no names.";
  }
  if (pairs.length && nameTokens === 0) {
    return "REFUSED: the project-name map replaced nothing in the app file. A stale or mistyped map is as dangerous as no map, so nothing was written. Check the map against the export.";
  }
  return null;
}

function main() {
  const argv = process.argv.slice(2);
  const flag = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
  const exportDir = argv.find((a, i) => !a.startsWith("--") && !(i > 0 && argv[i - 1].startsWith("--")));
  if (!exportDir || !existsSync(exportDir)) {
    console.error("usage: node scripts/dc/import.mjs <export-dir> [--date YYYY-MM-DD] [--exported-at ISO] [--no-name-map] [--root <dir>]");
    process.exit(2);
  }
  const date = flag("--date", new Date().toISOString().slice(0, 10));
  const exportedAt = flag("--exported-at", `${date}T00:00Z`);
  const outRoot = resolve(flag("--root", ROOT));
  const noNameMap = argv.includes("--no-name-map");
  const src = resolve(exportDir);
  const dest = join(outRoot, "design-upstream", date);

  const pairs = loadNameMap();
  if (!pairs.length && noNameMap) {
    console.error("import: WARNING - --no-name-map given: real project names in the export are NOT replaced. The result is recorded as such in PROVENANCE.md.");
  }

  // Phase 1: compute everything in memory.  Nothing touches the disk until every check has passed.
  const rows = [];
  const outputs = [];
  let nameTokens = 0;
  let unlockCodes = 0;
  for (const rel of walk(src)) {
    const raw = readFileSync(join(src, rel));
    const row = { rel, size: raw.length, raw: sha256(raw), imported: ALLOWLIST.includes(rel) };
    if (row.imported) {
      let buf = raw;
      if (rel.endsWith(".dc.html")) {
        const stripped = stripInjected(raw.toString("utf8"));
        row.stripped = sha256(Buffer.from(stripped.text));
        row.blocks = stripped.blocks;
        const clean = sanitize(stripped.text, pairs);
        row.counts = clean.counts;
        nameTokens += clean.counts.names;
        unlockCodes += clean.counts.unlockCode;
        buf = Buffer.from(clean.text);
      } else if (rel.endsWith(".js")) {
        // the audit probe: same sanitizer, counted apart (the name-map check below is about the APP file, where the names are)
        const clean = sanitize(raw.toString("utf8"), pairs);
        row.jsCounts = clean.counts;
        unlockCodes += clean.counts.unlockCode;
        buf = Buffer.from(clean.text);
      }
      row.committed = sha256(buf);
      row.committedSize = buf.length;
      outputs.push([join(dest, rel), buf]);
    }
    rows.push(row);
  }
  const missing = ALLOWLIST.filter((a) => !rows.some((r) => r.rel === a));
  const why = refusal({ pairs, noNameMap, nameTokens, missing, unlockCodes });
  if (why) {
    console.error(`import: ${why}`);
    process.exit(1);
  }

  // Phase 2: write.
  for (const [out, buf] of outputs) {
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, buf);
  }

  const table = [
    `| # | file (relative to the export) | bytes | sha256 of the raw download | disposition |`,
    `|---|---|---:|---|---|`,
    ...rows.map((r, i) => {
      let d = r.imported ? "**committed**" : "checksum only";
      if (r.imported && r.stripped) {
        d += `; stripped ${r.blocks} injected block${r.blocks === 1 ? "" : "s"} -> \`${r.stripped}\`; sanitized -> \`${r.committed}\` (${r.committedSize} B)`;
      } else if (r.imported && r.committed !== r.raw) {
        d += `; sanitized -> \`${r.committed}\` (${r.committedSize} B)`;
      } else if (r.imported) d += " (byte-identical to the raw download)";
      return `| ${i + 1} | \`${r.rel}\` | ${r.size} | \`${r.raw}\` | ${d} |`;
    }),
  ].join("\n");

  const sanitized = rows.find((r) => r.counts);
  const summary = [
    `Imported ${rows.filter((r) => r.imported).length} of ${rows.length} files; export time ${exportedAt}.`,
    sanitized
      ? `Sanitized: ${sanitized.counts.keyHeaders} private-key armour string(s), ${sanitized.counts.emails} contactable e-mail address(es), ${sanitized.counts.licence} licence sentence(s), ${sanitized.counts.ipv4} non-documentation IPv4 address(es), ${sanitized.counts.unlockCode} unlock-code value(s), ${nameTokens} project-name token(s)${pairs.length ? "" : " (NO name map was used: --no-name-map)"}.`
      : "",
  ].join(" ");

  console.log(summary);
  const marker = (k) => [`<!-- BEGIN generated:${k} -->`, `<!-- END generated:${k} -->`];
  const prov = join(outRoot, "design-upstream", "PROVENANCE.md");
  const block = `${marker("files")[0]}\n${summary}\n\n${table}\n${marker("files")[1]}`;
  if (existsSync(prov) && readFileSync(prov, "utf8").includes(marker("files")[0])) {
    const text = readFileSync(prov, "utf8");
    const a = text.indexOf(marker("files")[0]);
    const b = text.indexOf(marker("files")[1]) + marker("files")[1].length;
    writeFileSync(prov, text.slice(0, a) + block + text.slice(b));
    console.log("updated the generated block in", relative(outRoot, prov));
  } else {
    console.log("\nPROVENANCE.md has no generated block yet; paste this where the file table belongs:\n");
    console.log(block);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
