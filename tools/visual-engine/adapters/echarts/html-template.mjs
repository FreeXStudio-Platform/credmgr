/**
 * Self-contained interactive HTML export.
 *
 * Docgen law carried over: zero external references — ECharts is inlined from
 * the pinned node_modules copy, the theme is inlined, no CDN, no @import.
 * Reduced-motion users and print get the static SVG fallback via
 * `prefers-reduced-motion` / `print` media queries (same pattern as docgen's
 * layered_workflow dual-variant SVG).
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));

let _echartsDist;
function echartsDist() {
  if (!_echartsDist) {
    _echartsDist = readFileSync(join(HERE, "..", "..", "node_modules", "echarts", "dist", "echarts.min.js"), "utf8");
  }
  return _echartsDist;
}

const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

export function interactiveHTML({ job, option, theme, themeName, width, height, staticSVG, versions }) {
  const interactiveOption = { ...option, animation: true, animationDuration: 400 };
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(job.title ?? "CredMgr visual")}</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; background: #060608; color: #EAEEF5;
         font-family: "Inter", system-ui, -apple-system, sans-serif; }
  main { max-width: ${width + 48}px; margin: 24px auto; padding: 0 16px; }
  h1 { font-family: "Inter", system-ui, sans-serif; font-size: 18px; font-weight: 600; margin: 0 0 4px; }
  p.q { color: #8A96AE; font-size: 13px; margin: 0 0 16px; }
  #chart { width: ${width}px; height: ${height}px; max-width: 100%; }
  .static-fallback { display: none; }
  figcaption { color: #8A96AE; font-size: 12px; margin-top: 12px; }
  @media (prefers-reduced-motion: reduce), print {
    #chart { display: none; }
    .static-fallback { display: block; }
  }
</style>
</head>
<body>
<main>
  <h1>${esc(job.title ?? "")}</h1>
  <p class="q">${esc(job.reader_question ?? "")}</p>
  <figure>
    <div id="chart" role="img" aria-label="${esc(job.title ?? job.reader_question ?? "chart")}"></div>
    <div class="static-fallback">${staticSVG}</div>
    <figcaption>${esc(job.text_summary ?? "")}</figcaption>
  </figure>
</main>
<script>${echartsDist()}</script>
<script>
  (function () {
    var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduced) return; // static fallback is already visible via CSS
    echarts.registerTheme(${JSON.stringify(themeName)}, ${JSON.stringify(theme)});
    var chart = echarts.init(document.getElementById("chart"), ${JSON.stringify(themeName)}, { renderer: "canvas" });
    chart.setOption(${JSON.stringify(interactiveOption)});
    window.addEventListener("resize", function () { chart.resize(); });
  })();
</script>
<!-- generated-by credmgr-visual-engine · echarts@${versions.echarts} inlined (self-contained, no CDN) -->
</body>
</html>
`;
}
