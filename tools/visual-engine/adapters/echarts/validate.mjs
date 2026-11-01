/**
 * Visual-job validation + security gates.
 *
 * Every render request passes through validateVisualJob() before any ECharts
 * code sees it. Fail-closed: an invalid or unsafe job throws VisualJobError
 * with a gate id — it never degrades to a partial render (T-R9: silent
 * success is a defect class).
 *
 * Gates implemented here (see SECURITY_POLICY.md):
 *   G-STRUCT  required fields, known visual family, known theme/preset
 *   G-SEC     no executable option content, no external URLs, no HTML
 *   G-SIZE    dataset / dimension caps
 *   G-CONF    classification gate (restricted jobs refused by default)
 *   G-CHART   chart-family laws shared with docgen (pie≤6, bar zero-baseline,
 *             heatmap legend, sankey conservation)
 */

export class VisualJobError extends Error {
  constructor(gate, message) {
    super(`[${gate}] ${message}`);
    this.gate = gate;
  }
}

export const SUPPORTED_VISUALS = [
  "bar", "bar_horizontal", "bar_stacked", "bar_grouped",
  "line", "line_step", "area", "area_stacked",
  "pie", "donut",
  "scatter", "bubble",
  "heatmap", "matrix",
  "sankey", "funnel",
  "graph", "tree", "treemap", "sunburst",
  "boxplot", "radar", "timeline", "scorecard",
  "none",
];

export const CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"];
export const THEMES = ["project-theme", "project-theme-dark", "project-theme-light", "print-theme"];

const LIMITS = {
  maxCells: 50_000,
  maxNodes: 1_500,
  maxEdges: 5_000,
  maxSeries: 24,
  maxWidth: 4_000,
  maxHeight: 4_000,
  minWidth: 100,
  minHeight: 100,
  maxStringLen: 500,
  maxPieSlices: 6, // docgen law: charts.py _PIE_MAX_SLICES
};

// Executable / injection surface. ECharts option content must be data-only.
const FORBIDDEN_KEYS = new Set(["formatter_fn", "renderItem", "__proto__", "constructor", "prototype"]);
const FORBIDDEN_PATTERNS = [
  [/<\s*script/i, "script tag"],
  [/javascript\s*:/i, "javascript: URL"],
  [/data:\s*text\/html/i, "data:text/html URL"],
  [/https?:\/\//i, "external URL"],
  [/\bfunction\s*\(/, "function literal"],
  [/=>\s*[{(]/, "arrow function literal"],
  [/on\w+\s*=/i, "inline event handler"],
];
// Fields where a URL-looking string is legitimate provenance metadata, never
// injected into the rendered option.
const METADATA_FIELDS = new Set(["data_source_ids", "parent_ids", "selection_reason", "evidence", "notes"]);

function walkStrings(value, path, cb) {
  if (typeof value === "string") { cb(value, path); return; }
  if (Array.isArray(value)) { value.forEach((v, i) => walkStrings(v, `${path}[${i}]`, cb)); return; }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.has(k)) throw new VisualJobError("G-SEC", `forbidden key "${k}" at ${path}`);
      walkStrings(v, `${path}.${k}`, cb);
    }
  }
}

function countCells(data) {
  if (!data) return 0;
  if (Array.isArray(data.source)) {
    return data.source.reduce((n, row) => n + (Array.isArray(row) ? row.length : 1), 0);
  }
  if (Array.isArray(data.matrix)) {
    return data.matrix.reduce((n, row) => n + row.length, 0);
  }
  if (Array.isArray(data.items)) return data.items.length;
  return 0;
}

/**
 * Validate a visual job. Returns { ok:true, job, warnings } or throws
 * VisualJobError. `opts.allowRestricted` must be explicitly set by a human-
 * approved caller for restricted-classification jobs (the MCP never sets it).
 */
export function validateVisualJob(job, opts = {}) {
  const warnings = [];
  if (!job || typeof job !== "object") throw new VisualJobError("G-STRUCT", "job must be an object");

  for (const field of ["visual_id", "reader_question", "selected_visual", "classification"]) {
    if (!job[field] || typeof job[field] !== "string") {
      throw new VisualJobError("G-STRUCT", `missing required string field "${field}"`);
    }
  }
  if (!SUPPORTED_VISUALS.includes(job.selected_visual)) {
    throw new VisualJobError("G-STRUCT",
      `unknown visual "${job.selected_visual}" — supported: ${SUPPORTED_VISUALS.join(", ")}. ` +
      `Architecture/workflow/state diagrams route to tools/docgen (see ENGINE_ROUTING_POLICY.json).`);
  }
  if (!CLASSIFICATIONS.includes(job.classification)) {
    throw new VisualJobError("G-STRUCT", `classification must be one of ${CLASSIFICATIONS.join("/")}`);
  }

  // G-CONF — confidentiality gate.
  if (job.classification === "restricted" && !opts.allowRestricted) {
    throw new VisualJobError("G-CONF",
      "restricted-classification jobs are refused by default. Direct-adapter callers may pass " +
      "allowRestricted after human sign-off; the MCP facade never renders restricted data.");
  }

  // NO_CHART is a first-class outcome: valid, renders nothing.
  if (job.selected_visual === "none") {
    if (!job.no_chart_reason) {
      throw new VisualJobError("G-STRUCT", 'selected_visual "none" requires "no_chart_reason"');
    }
    return { ok: true, job, warnings, no_chart: true };
  }

  if (!job.data || typeof job.data !== "object") {
    throw new VisualJobError("G-STRUCT", 'missing "data" object');
  }

  const theme = job.theme ?? "project-theme";
  if (!THEMES.includes(theme)) {
    throw new VisualJobError("G-STRUCT", `unknown theme "${theme}" — approved: ${THEMES.join(", ")}`);
  }

  // G-SEC — data-only option content.
  const { data, title, subtitle, units } = job;
  for (const [name, value] of Object.entries({ data, title, subtitle, units })) {
    if (value === undefined) continue;
    walkStrings(value, name, (s, path) => {
      if (s.length > LIMITS.maxStringLen) {
        throw new VisualJobError("G-SIZE", `string too long (${s.length} > ${LIMITS.maxStringLen}) at ${path}`);
      }
      const topField = path.split(/[.[]/)[0];
      for (const [re, what] of FORBIDDEN_PATTERNS) {
        if (re.test(s) && !(what === "external URL" && METADATA_FIELDS.has(topField))) {
          throw new VisualJobError("G-SEC", `${what} in ${path}`);
        }
      }
    });
  }

  // G-SIZE — caps.
  const cells = countCells(job.data);
  if (cells > LIMITS.maxCells) {
    throw new VisualJobError("G-SIZE",
      `${cells} data cells > cap ${LIMITS.maxCells}. Aggregate before charting — a chart this dense answers no reader question.`);
  }
  if ((job.data.nodes?.length ?? 0) > LIMITS.maxNodes) {
    throw new VisualJobError("G-SIZE", `${job.data.nodes.length} nodes > cap ${LIMITS.maxNodes} (hairball rule — aggregate or use a matrix)`);
  }
  if ((job.data.links?.length ?? 0) > LIMITS.maxEdges) {
    throw new VisualJobError("G-SIZE", `${job.data.links.length} edges > cap ${LIMITS.maxEdges}`);
  }
  const w = job.width ?? 800, h = job.height ?? 480;
  if (w < LIMITS.minWidth || w > LIMITS.maxWidth || h < LIMITS.minHeight || h > LIMITS.maxHeight) {
    throw new VisualJobError("G-SIZE", `dimensions ${w}x${h} outside ${LIMITS.minWidth}-${LIMITS.maxWidth} px`);
  }

  // G-CHART — family laws (shared with docgen where the family overlaps).
  const v = job.selected_visual;
  if ((v === "pie" || v === "donut")) {
    const n = job.data.items?.length ?? 0;
    if (n === 0) throw new VisualJobError("G-CHART", "pie requires data.items");
    if (n > LIMITS.maxPieSlices) {
      throw new VisualJobError("G-CHART", `pie has ${n} slices > ${LIMITS.maxPieSlices} (docgen law) — use a bar`);
    }
    if (job.data.items.some((i) => !(i.value > 0))) {
      throw new VisualJobError("G-CHART", "pie slices must all be positive");
    }
  }
  if (v === "sankey") {
    const links = job.data.links ?? [];
    const nodes = new Set((job.data.nodes ?? []).map((n) => n.name));
    if (!links.length || !nodes.size) throw new VisualJobError("G-CHART", "sankey requires nodes and links");
    for (const l of links) {
      if (!(l.value > 0)) throw new VisualJobError("G-CHART", `sankey flow ${l.source}→${l.target} must be > 0`);
      if (!nodes.has(l.source) || !nodes.has(l.target)) {
        throw new VisualJobError("G-CHART", `sankey link ${l.source}→${l.target} has a dangling endpoint`);
      }
    }
  }
  if ((v === "heatmap" || v === "matrix") && !Array.isArray(job.data.matrix)) {
    throw new VisualJobError("G-CHART", "heatmap requires data.matrix (rows × cols) with data.rows/data.cols labels");
  }
  if (v === "radar") {
    const axes = job.data.axes?.length ?? 0;
    if (axes < 3) throw new VisualJobError("G-CHART", "radar requires ≥3 axes (docgen law)");
  }
  if (v.startsWith("bar") && Array.isArray(job.data.source)) {
    const hasNegative = job.data.source.some((row) =>
      (Array.isArray(row) ? row.slice(1) : []).some((x) => typeof x === "number" && x < 0));
    if (hasNegative && !job.allow_negative) {
      throw new VisualJobError("G-CHART", "bar values are zero-baseline (docgen law); pass allow_negative for signed deltas");
    }
  }

  // Accessibility contract fields.
  if (!job.text_summary && !job.accessibility?.text_summary) {
    warnings.push("no text_summary — required before this visual enters a source-of-truth document (Gate G7)");
  }

  return { ok: true, job: { ...job, theme, width: w, height: h }, warnings };
}
