/**
 * Normalized visual job → ECharts option.
 *
 * The AI agent supplies a compact job packet (schemas/visual-job.schema.json);
 * this module owns ALL renderer syntax. Agents never hand-write ECharts
 * options for routine work (token-efficiency rule §32).
 *
 * Determinism: no Date.now, no Math.random, no force layouts. Graph presets
 * use circular/preset layouts so output is byte-stable for the regression
 * suite.
 */
import { VisualJobError } from "./validate.mjs";

const GRID = { left: 56, right: 24, top: 48, bottom: 40, containLabel: true };

function titleBlock(job) {
  const t = { left: 8, top: 6 };
  if (job.title) t.text = job.title;
  if (job.subtitle) t.subtext = job.subtitle;
  return job.title || job.subtitle ? { title: t } : {};
}

function datasetOf(job) {
  const { dimensions, source } = job.data;
  if (!Array.isArray(dimensions) || !Array.isArray(source)) {
    throw new VisualJobError("G-STRUCT", `visual "${job.selected_visual}" needs data.dimensions + data.source (table shape)`);
  }
  return { dataset: { dimensions, source } };
}

/**
 * Build one series per measure column, each with an EXPLICIT encode.
 *
 * Never rely on ECharts' implicit dataset dimension-to-axis inference — with
 * multiple series sharing one dataset it is order/name-sensitive, silently
 * mis-binds category/time axes (a `time` axis with no encode was seen
 * defaulting to nonsense tick values instead of the actual date column), and
 * its fallback resolution path is a measurable source of cross-platform
 * floating-point drift (macOS arm64 vs Linux x64 CI produced different bytes
 * for the identical job — caught by the golden-regression gate, 2026-08-10).
 * `orientation: "horizontal"` swaps the encode for bar_horizontal's category
 * y-axis; each series gets its OWN x per its OWN measure, never one shared
 * encode across every series (the bar_horizontal bug this replaces).
 */
function seriesForTable(job, type, { orientation = "vertical", ...extra } = {}) {
  const dims = job.data.dimensions;
  const measures = dims.slice(1);
  return measures.map((name) => ({
    type,
    name,
    encode: orientation === "horizontal" ? { y: dims[0], x: name } : { x: dims[0], y: name },
    ...extra,
  }));
}

const BUILDERS = {
  bar(job) {
    return { ...datasetOf(job), ...titleBlock(job), grid: GRID, legend: legend(job),
      xAxis: { type: "category" }, yAxis: valueAxis(job),
      series: seriesForTable(job, "bar", job.stack ? { stack: "total" } : {}) };
  },
  bar_grouped(job) { return BUILDERS.bar(job); },
  bar_stacked(job) { return BUILDERS.bar({ ...job, stack: true }); },
  bar_horizontal(job) {
    return { ...datasetOf(job), ...titleBlock(job), grid: GRID, legend: legend(job),
      yAxis: { type: "category", inverse: true }, xAxis: valueAxis(job),
      series: seriesForTable(job, "bar", { orientation: "horizontal", ...(job.stack ? { stack: "total" } : {}) }) };
  },
  line(job) {
    return { ...datasetOf(job), ...titleBlock(job), grid: GRID, legend: legend(job),
      xAxis: { type: job.time_axis ? "time" : "category", boundaryGap: false }, yAxis: valueAxis(job),
      series: seriesForTable(job, "line") };
  },
  line_step(job) {
    const o = BUILDERS.line(job); o.series.forEach((s) => (s.step = "end")); return o;
  },
  area(job) {
    const o = BUILDERS.line(job); o.series.forEach((s) => (s.areaStyle = { opacity: 0.25 })); return o;
  },
  area_stacked(job) {
    const o = BUILDERS.area(job); o.series.forEach((s) => (s.stack = "total")); return o;
  },
  scatter(job) {
    return { ...datasetOf(job), ...titleBlock(job), grid: GRID, legend: legend(job),
      xAxis: { type: "value", name: job.data.dimensions[0], nameLocation: "middle", nameGap: 28 },
      yAxis: { type: "value", name: job.data.dimensions[1] },
      series: [{ type: "scatter", symbolSize: 9, encode: { x: 0, y: 1, tooltip: [0, 1] } }] };
  },
  bubble(job) {
    const o = BUILDERS.scatter(job);
    const sizes = job.data.source.map((r) => Number(r[2]) || 0);
    const max = Math.max(1, ...sizes);
    o.series[0].symbolSize = (val) => 6 + 30 * Math.sqrt((Number(val[2]) || 0) / max);
    return o;
  },
  pie(job, { donut = false } = {}) {
    return { ...titleBlock(job), legend: legend(job),
      series: [{ type: "pie", radius: donut ? ["45%", "72%"] : "72%", center: ["50%", "56%"],
        data: job.data.items, label: { show: true, formatter: "{b}: {c}" },
        emphasis: { scale: false } }] };
  },
  donut(job) { return BUILDERS.pie(job, { donut: true }); },
  heatmap(job, theme) {
    const { rows, cols, matrix } = job.data;
    const points = [];
    matrix.forEach((row, r) => row.forEach((v, c) => points.push([c, r, v ?? "-"])));
    const flat = matrix.flat().filter((v) => typeof v === "number");
    return { ...titleBlock(job),
      grid: { ...GRID, right: 96 },
      xAxis: { type: "category", data: cols, splitArea: { show: true } },
      yAxis: { type: "category", data: rows, inverse: true, splitArea: { show: true } },
      // docgen law: a heatmap never ships without its scale legend.
      visualMap: { min: job.scale_min ?? Math.min(0, ...flat), max: job.scale_max ?? Math.max(1, ...flat),
        calculable: false, orient: "vertical", right: 8, top: "center",
        // Fallback mirrors heatRamp(KEEP) exactly (steel-2 -> sig-dim -> sig-hi) so a
        // themeless render still looks like this product, not like the engine's origin.
        inRange: { color: theme?.semantic?.heatRamp ?? ["#131318", "#173B33", "#5FBFA8"] } },
      series: [{ type: "heatmap", data: points, label: { show: job.show_values ?? true, fontSize: 10 } }] };
  },
  matrix(job, theme) { return BUILDERS.heatmap(job, theme); },
  sankey(job) {
    return { ...titleBlock(job),
      series: [{ type: "sankey", data: job.data.nodes, links: job.data.links,
        emphasis: { focus: "adjacency" }, nodeAlign: "left",
        lineStyle: { color: "gradient", curveness: 0.5 }, label: { fontSize: 11 } }] };
  },
  funnel(job) {
    return { ...titleBlock(job), legend: legend(job),
      series: [{ type: "funnel", data: job.data.items, sort: "descending", gap: 2,
        label: { show: true, formatter: "{b}: {c}" } }] };
  },
  graph(job) {
    return { ...titleBlock(job),
      series: [{ type: "graph", layout: job.layout ?? "circular", // deterministic; never "force"
        data: job.data.nodes.map((n) => ({ ...n, symbolSize: n.symbolSize ?? 24 })),
        links: job.data.links, roam: false, label: { show: true, position: "right", fontSize: 11 },
        edgeSymbol: ["none", "arrow"], edgeSymbolSize: 7,
        lineStyle: { curveness: job.layout === "none" ? 0 : 0.18 } }] };
  },
  tree(job) {
    return { ...titleBlock(job),
      series: [{ type: "tree", data: [job.data.root], orient: "LR", symbolSize: 8,
        label: { position: "left", fontSize: 11 }, leaves: { label: { position: "right" } },
        expandAndCollapse: false, initialTreeDepth: -1 }] };
  },
  treemap(job) {
    return { ...titleBlock(job),
      series: [{ type: "treemap", data: job.data.root.children ?? job.data.items,
        roam: false, nodeClick: false, breadcrumb: { show: false },
        label: { show: true, fontSize: 11 } }] };
  },
  sunburst(job) {
    return { ...titleBlock(job),
      series: [{ type: "sunburst", data: job.data.root.children ?? job.data.items,
        radius: ["12%", "82%"], label: { fontSize: 10 } }] };
  },
  boxplot(job) {
    return { ...titleBlock(job), grid: GRID,
      xAxis: { type: "category", data: job.data.categories },
      yAxis: valueAxis(job),
      series: [{ type: "boxplot", data: job.data.values }] }; // pre-computed [min,q1,med,q3,max]
  },
  radar(job) {
    return { ...titleBlock(job), legend: legend(job),
      radar: { indicator: job.data.axes, radius: "62%" },
      series: [{ type: "radar", data: job.data.series.map((s) => ({ name: s.name, value: s.values })) }] };
  },
  timeline(job) {
    const events = job.data.events;
    return { ...titleBlock(job), grid: { ...GRID, top: 64, bottom: 56 },
      xAxis: { type: "time" },
      yAxis: { type: "value", show: false, min: -1, max: 1 },
      series: [{ type: "scatter", symbolSize: 12,
        data: events.map((e, i) => ({ name: e.name, value: [e.date, i % 2 === 0 ? 0.35 : -0.35] })),
        label: { show: true, formatter: (p) => p.name, position: "top", fontSize: 10, rotate: 0 },
        markLine: { silent: true, symbol: "none", label: { show: false },
          data: events.map((e) => ({ xAxis: e.date })), lineStyle: { type: "dashed", opacity: 0.3 } } }] };
  },
  scorecard(job) {
    // Status scorecard = horizontal bar with semantic status colors, value labels.
    return BUILDERS.bar_horizontal(job);
  },
};

function legend(job) {
  const show = job.legend ?? (job.data?.dimensions?.length > 2 || job.data?.items?.length > 1);
  return { show: Boolean(show), top: job.title ? 28 : 8, right: 8 };
}

function valueAxis(job) {
  const axis = { type: job.log_scale ? "log" : "value" };
  if (job.units?.[0]) axis.name = job.units[0];
  if (job.scale_min !== undefined) axis.min = job.scale_min;
  if (job.scale_max !== undefined) axis.max = job.scale_max;
  return axis;
}

/**
 * Apply semantic severity/status colors when the preset declares them.
 *
 * KEEP's own state_semantics table (v2/design/tokens/keep.tokens.json) is
 * the mapping, verbatim: "sensitivity=critical" is the only sensitivity
 * level that carries the danger colour; "sensitivity low/medium/high" are
 * explicitly listed under `none` — achromatic, not merely undefined. This
 * function does not invent a broader mapping (e.g. "high" -> warn) — that
 * would be a decorative use of colour the token source itself forbids.
 */
function applySemantics(option, job, preset, theme) {
  const sem = preset?.semantics;
  if (!sem || !theme) return option;
  if (sem.severity_items && Array.isArray(option.series)) {
    for (const s of option.series) {
      if (Array.isArray(s.data)) {
        s.data = s.data.map((d) => {
          const key = (d.severity ?? d.name ?? "").toString().toLowerCase();
          const color = key === "critical" ? theme.severity?.danger : undefined;
          return color ? { ...d, itemStyle: { ...(d.itemStyle ?? {}), color } } : d;
        });
      }
    }
  }
  return option;
}

export function buildOption(job, theme, preset) {
  const builder = BUILDERS[job.selected_visual];
  if (!builder) {
    throw new VisualJobError("G-ROUTE",
      `no ECharts builder for "${job.selected_visual}" — check ENGINE_ROUTING_POLICY.json for the owning engine`);
  }
  let option = builder(job, theme);
  // Preset defaults merge under the job (job-derived structure wins).
  if (preset?.defaults) option = deepMerge(structuredClone(preset.defaults), option);
  option = applySemantics(option, job, preset, theme);
  option.animation = false; // SSR determinism; interactive HTML re-enables
  option.aria = { enabled: true, decal: { show: Boolean(job.accessibility?.decal) } };
  if (job.tooltip !== false) option.tooltip = option.tooltip ?? { trigger: "item" };
  return option;
}

function deepMerge(base, over) {
  if (Array.isArray(base) || Array.isArray(over) || typeof base !== "object" || typeof over !== "object" || !base || !over) {
    return over ?? base;
  }
  const out = { ...base };
  for (const [k, v] of Object.entries(over)) out[k] = k in base ? deepMerge(base[k], v) : v;
  return out;
}
