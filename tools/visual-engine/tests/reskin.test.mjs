import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { renderSVG } from "../adapters/echarts/render.mjs";
import { buildAllThemes, categoricalPalette, loadTokens } from "../adapters/echarts/theme-adapter.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(readFileSync(join(HERE, "..", "fixtures", "normal", "crate-test-coverage-heatmap.json"), "utf8"));
const THEMES = ["project-theme", "project-theme-dark", "project-theme-light", "print-theme"];

/** Extract the semantic payload of an option — everything the reskin law locks. */
function semanticChecksum(option) {
  return JSON.stringify({
    series: (option.series ?? []).map((s) => ({ type: s.type, data: s.data, stack: s.stack ?? null })),
    dataset: option.dataset ?? null,
    xAxis: option.xAxis ? { type: option.xAxis.type, data: option.xAxis.data ?? null } : null,
    yAxis: option.yAxis ? { type: option.yAxis.type, data: option.yAxis.data ?? null } : null,
    visualMap: option.visualMap ? { min: option.visualMap.min, max: option.visualMap.max } : null,
  });
}

test("reskin law: all four themes produce identical semantics, different appearance", () => {
  const results = THEMES.map((theme) => renderSVG({ ...fixture, theme }));
  const checksums = results.map((r) => semanticChecksum(r.option));
  for (const c of checksums) assert.equal(c, checksums[0], "semantic drift between themes");
  const svgs = new Set(results.map((r) => r.meta.svg_sha256));
  assert.ok(svgs.size >= 2, "themes render identically — reskin layer is dead");
});

test("themes derive from KEEP tokens — no invented colors", () => {
  const tokens = loadTokens();
  const themes = buildAllThemes();
  const palette = categoricalPalette(tokens, "dark");
  assert.deepEqual(themes["project-theme"].color, palette);
  assert.equal(themes["project-theme"].severity.danger, tokens.signal.danger);
  assert.equal(themes["project-theme-light"].textStyle.color, tokens.inks_light.bone);
  assert.equal(themes["print-theme"].backgroundColor, "#FFFFFF");
});

test("severity lattice reserved for severity semantics", () => {
  const themes = buildAllThemes();
  const sev = themes["project-theme"].severity;
  // KEEP has exactly three signal states — deliberately not a wider severity lattice.
  assert.equal(sev.danger, "#B3373A");
  assert.equal(sev.warn, "#B0812E");
  assert.equal(sev.sig, "#3E9C86");
  // decorative palette must not silently include unexpected values
  assert.equal(themes["project-theme"].color.length, 6);
});
