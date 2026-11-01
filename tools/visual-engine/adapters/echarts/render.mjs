/**
 * Direct ECharts renderer — the non-MCP path (spec §9). CI, batch, offline,
 * fallback, and tests all run through here; the MCP facade is a thin wrapper
 * over these same functions, so the project never depends on an MCP process.
 *
 * Guarantees:
 *  - deterministic SVG (animation off, ids normalized, TZ forced to UTC so
 *    time-axis layout never depends on the host machine's timezone, floats
 *    as emitted by ECharts SSR which is stable for a pinned version) →
 *    build-twice byte-identical AND cross-machine byte-identical, same
 *    discipline as tools/docgen
 *  - every render stamped `generated-by credmgr-visual-engine` with a
 *    content sha256, matching the docgen provenance convention
 *  - evidence JSON per render (Gate G9)
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, basename } from "node:path";
import * as echarts from "echarts";
import { validateVisualJob, VisualJobError, SUPPORTED_VISUALS, THEMES } from "./validate.mjs";
import { buildOption } from "./option-builder.mjs";

// Force UTC for every render, everywhere this module runs. ECharts' time axis
// computes "nice" tick boundaries and formats labels using the PROCESS'S LOCAL
// system timezone (Intl/Date) — a render on a +03:30 laptop and the identical
// render in UTC CI produced genuinely different tick positions and SVG bytes
// for a time-axis job (found 2026-08-10: PR #111's own first CI run, on a
// timeline preset — TZ=UTC locally reproduced CI's exact output byte-for-byte,
// confirming the cause). Determinism must not depend on WHERE the process
// happens to run; this line makes that true by construction rather than by
// coincidence of the machine's configured timezone. Set at module load, well
// before any renderSVG() call performs the actual date/axis computation.
process.env.TZ = "UTC";
import { buildAllThemes } from "./theme-adapter.mjs";
import { interactiveHTML } from "./html-template.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
export const ENGINE_ROOT = join(HERE, "..", "..");
const PRESETS_DIR = join(ENGINE_ROOT, "presets");
const EVIDENCE_DIR = join(ENGINE_ROOT, "evidence", "validation");

export const ENGINE_VERSION = JSON.parse(readFileSync(join(ENGINE_ROOT, "package.json"), "utf8")).version;
export const ECHARTS_VERSION = JSON.parse(
  readFileSync(join(ENGINE_ROOT, "node_modules", "echarts", "package.json"), "utf8"),
).version;

let _themes;
export function themes() {
  if (!_themes) {
    _themes = buildAllThemes();
    for (const [name, t] of Object.entries(_themes)) echarts.registerTheme(name, t);
  }
  return _themes;
}

let _presets;
export function listPresets() {
  if (!_presets) {
    _presets = {};
    if (existsSync(PRESETS_DIR)) {
      for (const f of readdirSync(PRESETS_DIR).filter((f) => f.endsWith(".json")).sort()) {
        const p = JSON.parse(readFileSync(join(PRESETS_DIR, f), "utf8"));
        _presets[p.id] = p;
      }
    }
  }
  return _presets;
}

export function listCapabilities() {
  return {
    engine: "echarts",
    engine_version: ECHARTS_VERSION,
    adapter_version: ENGINE_VERSION,
    visuals: SUPPORTED_VISUALS.filter((v) => v !== "none"),
    themes: THEMES,
    presets: Object.keys(listPresets()),
    formats: ["svg", "png", "html"],
    no_chart_supported: true,
    routing_policy: "ENGINE_ROUTING_POLICY.json — documents/diagrams stay on tools/docgen; app UI stays on Recharts",
  };
}

export { validateVisualJob, VisualJobError };

function sha256(s) { return createHash("sha256").update(s).digest("hex"); }

/**
 * Normalize zrender instance/global counters so repeat renders are
 * byte-identical (build-twice determinism, docgen discipline). Two sources of
 * drift: the per-instance prefix `zr<N>-`, and global counters like
 * `cls-<N>` / `gradient-<N>` / `clip-<N>` that keep incrementing across
 * echarts.init() calls in one process. Both are renumbered by first
 * appearance, keeping intra-document references (class ↔ style, url(#id))
 * consistent.
 */
function normalizeSVG(svg) {
  let out = svg.replace(/zr\d+-/g, "zr-");
  for (const kind of ["cls", "gradient", "clip", "shadow", "pattern"]) {
    const seen = new Map();
    out = out.replace(new RegExp(`zr-${kind}-(\\d+)`, "g"), (_, n) => {
      if (!seen.has(n)) seen.set(n, seen.size);
      return `zr-${kind}-${seen.get(n)}`;
    });
  }
  return out;
}

function resolvePreset(job) {
  if (!job.preset) return undefined;
  const preset = listPresets()[job.preset];
  if (!preset) throw new VisualJobError("G-STRUCT", `unknown preset "${job.preset}" — see presets/`);
  if (preset.visual && preset.visual !== job.selected_visual) {
    throw new VisualJobError("G-STRUCT",
      `preset "${job.preset}" is for visual "${preset.visual}", job selected "${job.selected_visual}"`);
  }
  return preset;
}

/** Core: job → { svg, option, meta } (throws on any gate failure). */
export function renderSVG(rawJob, opts = {}) {
  const { job, warnings, no_chart } = validateVisualJob(rawJob, opts);
  if (no_chart) {
    return { no_chart: true, reason: job.no_chart_reason, warnings, meta: { visual_id: job.visual_id } };
  }
  const theme = themes()[job.theme];
  const preset = resolvePreset(job);
  const option = buildOption(job, theme, preset);

  const started = performance.now();
  const chart = echarts.init(null, job.theme, { renderer: "svg", ssr: true, width: job.width, height: job.height });
  let svg;
  try {
    chart.setOption(option);
    svg = chart.renderToSVGString();
  } finally {
    chart.dispose();
  }
  svg = normalizeSVG(svg);

  // Accessibility + provenance on the final artifact.
  const label = (job.accessibility?.aria_label ?? job.title ?? job.reader_question).replace(/"/g, "&quot;");
  svg = svg.replace("<svg ", `<svg role="img" aria-label="${label}" `);
  const hash = sha256(svg);
  svg += `\n<!-- generated-by credmgr-visual-engine v${ENGINE_VERSION} · echarts@${ECHARTS_VERSION} · theme:${job.theme} · content-sha256:${hash} -->\n`;

  const meta = {
    visual_id: job.visual_id,
    selected_visual: job.selected_visual,
    preset: job.preset ?? null,
    theme: job.theme,
    classification: job.classification,
    engine: `echarts@${ECHARTS_VERSION}`,
    adapter: `credmgr-visual-engine@${ENGINE_VERSION}`,
    width: job.width,
    height: job.height,
    svg_sha256: hash,
    option_sha256: sha256(JSON.stringify(option)),
    job_sha256: sha256(JSON.stringify(rawJob)),
    render_ms: Math.round(performance.now() - started),
    warnings,
  };
  return { svg, option, meta, warnings };
}

export async function renderPNG(rawJob, opts = {}) {
  const result = renderSVG(rawJob, opts);
  if (result.no_chart) return result;
  const { Resvg } = await import("@resvg/resvg-js");
  // System-font rasterization: PNG is a convenience export; SVG is canonical
  // (EXPORT_POLICY.md). Determinism of PNG is per-host, not cross-host.
  const png = new Resvg(result.svg, {
    fitTo: { mode: "width", value: (rawJob.width ?? 800) * (opts.scale ?? 2) },
    background: opts.background ?? "#060608",
  }).render().asPng();
  return { ...result, png, meta: { ...result.meta, png_sha256: sha256(png), png_bytes: png.length } };
}

export function renderInteractiveHTML(rawJob, opts = {}) {
  const result = renderSVG(rawJob, opts); // validation + option build (+ static meta)
  if (result.no_chart) return result;
  const theme = themes()[result.meta.theme];
  const html = interactiveHTML({
    job: { title: rawJob.title, reader_question: rawJob.reader_question, text_summary: rawJob.text_summary ?? rawJob.accessibility?.text_summary },
    option: result.option,
    theme,
    themeName: result.meta.theme,
    width: rawJob.width ?? 800,
    height: rawJob.height ?? 480,
    staticSVG: result.svg,
    versions: { echarts: ECHARTS_VERSION, adapter: ENGINE_VERSION },
  });
  return { ...result, html, meta: { ...result.meta, html_sha256: sha256(html) } };
}

export async function renderBatch(jobs, opts = {}) {
  const out = [];
  for (const job of jobs) {
    try {
      out.push(await renderPNG(job, opts));
    } catch (e) {
      out.push({ error: e.message, gate: e.gate ?? null, visual_id: job?.visual_id ?? null });
    }
  }
  return out;
}

/** Persist render evidence (Gate G9). Never writes outside evidence/.
 *
 * `render_ms` is stripped before writing: it is wall-clock timing, so persisting it into a
 * git-tracked artifact made every `npm test` leave the working tree dirty with a meaningless
 * one-line diff. The caller still receives it in the returned metadata — it is useful live,
 * just not as committed evidence. Hashes are the evidence; duration is telemetry.
 */
export function writeEvidence(meta) {
  mkdirSync(EVIDENCE_DIR, { recursive: true });
  const safe = basename(String(meta.visual_id)).replace(/[^A-Za-z0-9._-]/g, "_");
  const path = join(EVIDENCE_DIR, `${safe}.json`);
  const { render_ms, ...durable } = meta;
  writeFileSync(path, JSON.stringify(durable, null, 2) + "\n");
  return path;
}

/** Routing explanation for agents (visual.explain_selection). */
export function explainSelection(job) {
  const v = job?.selected_visual;
  const docgenFamilies = ["flowchart", "state_diagram", "system_map", "dependency_graph", "sequence", "isometric3d", "geo_map", "layered_workflow", "sankey_document"];
  if (docgenFamilies.includes(v)) {
    return { engine: "docgen", reason: `"${v}" is a document/diagram family — authoritative renderer is tools/docgen (deterministic SVG, KEEP tokens, collision validation). See ENGINE_ROUTING_POLICY.json.` };
  }
  if (SUPPORTED_VISUALS.includes(v)) {
    return { engine: "echarts", reason: `"${v}" is a data-chart family owned by the visual-engine ECharts adapter.`, preset_hint: Object.values(listPresets()).find((p) => p.visual === v)?.id ?? null };
  }
  return { engine: null, reason: `Unknown family "${v}". Consult knowledge/CHART_SELECTION_DECISION_TREE.json, or return NO_CHART.` };
}
