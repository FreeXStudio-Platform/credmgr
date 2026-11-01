#!/usr/bin/env node
/**
 * visual-engine CLI — the human/agent entry point for the direct adapter.
 *
 *   node adapters/echarts/cli.mjs render <job.json> [-o outdir] [--formats svg,png,html] [--evidence]
 *   node adapters/echarts/cli.mjs validate <job.json>
 *   node adapters/echarts/cli.mjs explain <job.json>
 *   node adapters/echarts/cli.mjs list-presets
 *   node adapters/echarts/cli.mjs list-capabilities
 *
 * Outputs land in --outdir (default renders/current/). Exit code 0 = all
 * gates passed; 1 = validation/render failure (fail-closed, T-R9).
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  renderSVG, renderPNG, renderInteractiveHTML, listPresets, listCapabilities,
  explainSelection, writeEvidence, ENGINE_ROOT,
} from "./render.mjs";

const args = process.argv.slice(2);
const cmd = args[0];

function flag(name, dflt) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
}

function loadJob(path) {
  if (!path) { console.error("usage: cli.mjs <cmd> <job.json>"); process.exit(1); }
  return JSON.parse(readFileSync(resolve(path), "utf8"));
}

try {
  if (cmd === "list-presets") {
    console.log(JSON.stringify(Object.values(listPresets()).map(({ id, visual, family, summary }) => ({ id, visual, family, summary })), null, 2));
  } else if (cmd === "list-capabilities") {
    console.log(JSON.stringify(listCapabilities(), null, 2));
  } else if (cmd === "validate") {
    const { validateVisualJob } = await import("./validate.mjs");
    const res = validateVisualJob(loadJob(args[1]));
    console.log(JSON.stringify({ ok: res.ok, no_chart: res.no_chart ?? false, warnings: res.warnings }, null, 2));
  } else if (cmd === "explain") {
    console.log(JSON.stringify(explainSelection(loadJob(args[1])), null, 2));
  } else if (cmd === "render") {
    const job = loadJob(args[1]);
    const outdir = resolve(flag("-o", join(ENGINE_ROOT, "renders", "current")));
    const formats = (flag("--formats", "svg")).split(",");
    mkdirSync(outdir, { recursive: true });
    const id = String(job.visual_id ?? "visual").replace(/[^A-Za-z0-9._-]/g, "_");
    let meta;
    if (formats.includes("png")) {
      const r = await renderPNG(job);
      if (r.no_chart) { console.log(JSON.stringify(r, null, 2)); process.exit(0); }
      writeFileSync(join(outdir, `${id}.png`), r.png);
      if (formats.includes("svg")) writeFileSync(join(outdir, `${id}.svg`), r.svg);
      meta = r.meta;
    } else {
      const r = renderSVG(job);
      if (r.no_chart) { console.log(JSON.stringify(r, null, 2)); process.exit(0); }
      if (formats.includes("svg")) writeFileSync(join(outdir, `${id}.svg`), r.svg);
      meta = r.meta;
    }
    if (formats.includes("html")) {
      const r = renderInteractiveHTML(job);
      writeFileSync(join(outdir, `${id}.html`), r.html);
      meta = { ...meta, html_sha256: r.meta.html_sha256 };
    }
    if (args.includes("--evidence")) meta.evidence_path = writeEvidence(meta);
    console.log(JSON.stringify(meta, null, 2));
  } else {
    console.error("unknown command. Commands: render | validate | explain | list-presets | list-capabilities");
    process.exit(1);
  }
} catch (e) {
  console.error(JSON.stringify({ error: e.message, gate: e.gate ?? null }));
  process.exit(1);
}
