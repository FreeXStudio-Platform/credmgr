#!/usr/bin/env node
/**
 * make-marks.mjs - rasterise the six app-icon choices (X9, command `app_icon_set`) to 1024 px PNGs.
 *
 *   node scripts/icons/make-marks.mjs        writes src-tauri/icons/marks/<id>.png
 *
 * The marks are the KEEP Identity marks M1..M4 (design-upstream/PROVENANCE.md, ADR-082 / SUPPORTER_EXTRAS_PLAN X9), drawn
 * on the same 24-unit grid and stroke weight as the design.  Six choices: keep on void (the default, same art as the
 * bundle's own icon), keep on bone (inverted), cells, node, seal, keep on signal.  The PNGs are committed: a build never
 * needs this script, and the shell embeds them (`include_bytes!`).  Rendering uses Chromium from the Playwright the e2e
 * suite already pins, so no new dependency is added.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(HERE, "../../src-tauri/icons/marks");

const VOID = "#050506";
const BONE = "#E9ECF1";
const SIG = "#3E9C86";

const KEEP = '<rect x="3.5" y="3.5" width="17" height="17"/><rect x="8" y="8" width="8" height="8"/><rect x="11" y="11" width="2" height="2" fill="currentColor" stroke="none"/>';
const CELLS = '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/><circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none"/>';
const NODE = '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="3" fill="currentColor" stroke="none"/>';
const SEAL = '<path d="M12 3 L19.8 7.5 V16.5 L12 21 L4.2 16.5 V7.5 Z"/><path d="M12 8 L15.5 10 V14 L12 16 L8.5 14 V10 Z"/>';

/** id (the `app_icon_set` argument) -> ground, ink, art. */
export const MARKS = {
  keep: { ground: VOID, ink: BONE, art: KEEP },
  keepbone: { ground: BONE, ink: VOID, art: KEEP },
  cells: { ground: VOID, ink: BONE, art: CELLS },
  node: { ground: VOID, ink: BONE, art: NODE },
  seal: { ground: VOID, ink: BONE, art: SEAL },
  keepsig: { ground: SIG, ink: VOID, art: KEEP },
};

function html({ ground, ink, art }) {
  // A 1024 canvas, a squircle-ish rounded ground (22.5% radius, the macOS proportion), the mark at 62% of the canvas.
  return `<!doctype html><meta charset="utf-8"><style>html,body{margin:0;background:transparent}
  .g{width:1024px;height:1024px;border-radius:230px;background:${ground};display:grid;place-items:center}
  svg{width:640px;height:640px;color:${ink}}</style>
  <div class="g"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="square">${art}</svg></div>`;
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1024, height: 1024 }, deviceScaleFactor: 1 });
  for (const [id, spec] of Object.entries(MARKS)) {
    await page.setContent(html(spec));
    const png = await page.screenshot({ omitBackground: true, clip: { x: 0, y: 0, width: 1024, height: 1024 } });
    writeFileSync(join(OUT, `${id}.png`), png);
    console.log(`wrote ${id}.png (${png.length} bytes)`);
  }
  await browser.close();
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
