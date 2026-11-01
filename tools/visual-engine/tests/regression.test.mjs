import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { renderSVG } from "../adapters/echarts/render.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const GOLDEN = join(ROOT, "renders", "golden");

/**
 * Visual regression (spec §28): every committed golden render must be exactly
 * reproducible from its committed job. A diff after an engine/theme change is
 * classified in renders/diffs/ before goldens are re-baselined — never
 * silently accepted.
 */
test("golden renders reproduce byte-identically from their jobs", () => {
  assert.ok(existsSync(GOLDEN), "renders/golden missing — run `npm run simulate` once and commit");
  const jobs = readdirSync(GOLDEN).filter((f) => f.endsWith(".job.json"));
  assert.ok(jobs.length >= 10, `expected ≥10 golden jobs, found ${jobs.length}`);
  for (const jf of jobs) {
    const job = JSON.parse(readFileSync(join(GOLDEN, jf), "utf8"));
    const expected = readFileSync(join(GOLDEN, jf.replace(".job.json", ".svg")), "utf8");
    const actual = renderSVG(job, { allowRestricted: false }).svg;
    assert.equal(actual, expected, `golden drift: ${jf} — classify in renders/diffs/ (EXPECTED_ENGINE_UPGRADE / THEME_DRIFT / LAYOUT_REGRESSION / …) before re-baselining`);
  }
});
