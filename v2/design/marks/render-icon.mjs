// Rasterises keep.svg to a 1024 x 1024 PNG with a transparent margin, for
// `npx tauri icon`. Playwright is the app's own dev dependency, so this script
// borrows its module resolution rather than adding a second toolchain.
//
//   cd v2/apps/desktop
//   node ../../design/marks/render-icon.mjs ../../design/marks/icon.png
//   npx tauri icon ../../design/marks/icon.png   # regenerates src-tauri/icons/*
//
// Usage: node render-icon.mjs <out.png>
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const desktop = resolve(here, "../../apps/desktop");
const require = createRequire(join(desktop, "package.json"));
const { chromium } = require("playwright");

const out = process.argv[2];
if (!out) {
  console.error("usage: node render-icon.mjs <out.png>");
  process.exit(2);
}

const svg = readFileSync(join(here, "keep.svg"), "utf8");
const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 1024, height: 1024 }, deviceScaleFactor: 1 });
  await page.setContent(
    `<!doctype html><meta charset="utf-8"><style>html,body{margin:0;background:transparent}svg{display:block}</style>${svg}`,
  );
  const png = await page.screenshot({ omitBackground: true, clip: { x: 0, y: 0, width: 1024, height: 1024 } });
  writeFileSync(resolve(out), png);
  console.log(`wrote ${resolve(out)} (${png.length} bytes)`);
} finally {
  await browser.close();
}
