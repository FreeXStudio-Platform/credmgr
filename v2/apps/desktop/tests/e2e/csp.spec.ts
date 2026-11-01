/**
 * The e2e harness's own CSP check must be able to fail.  (verify-csp.mjs has the same canaries for the plain gate.)
 * A gate that has never failed proves nothing: every other spec in this directory ends by asserting "zero policy violations".
 */
import { expect, test } from "./harness";

/** The browser also logs each refusal to the console; a canary provokes exactly that. */
const REFUSAL = /Refused to|violates the following Content Security Policy|Failed to load resource/;

test("canary: an injected inline <style> is a recorded violation", async ({ app }) => {
  app.expectConsoleError(REFUSAL);
  await app.open({ broker: false, htmlTransform: (h) => h.replace("</head>", "<style>body{margin:0}</style></head>") });
  await expect(app.screen("S1 Main")).toBeVisible();
  const seen = app.takeViolations();
  expect(seen.some((v) => /^style-src/.test(v))).toBe(true);
});

test("canary: an injected inline <script> is a recorded violation", async ({ app }) => {
  app.expectConsoleError(REFUSAL);
  await app.open({ broker: false, htmlTransform: (h) => h.replace("</head>", "<script>window.__x=1</script></head>") });
  await expect(app.screen("S1 Main")).toBeVisible();
  const seen = app.takeViolations();
  expect(seen.some((v) => /^script-src/.test(v))).toBe(true);
});

test("canary: a request that leaves the app origin is recorded (and aborted)", async ({ app }) => {
  app.expectConsoleError(REFUSAL);
  await app.open({ broker: false, htmlTransform: (h) => h.replace("</head>", '<link rel="stylesheet" href="https://example.invalid/x.css"></head>') });
  await expect(app.screen("S1 Main")).toBeVisible();
  expect(app.external.length > 0 || app.violations.length > 0).toBe(true);
  app.external.length = 0;
  app.takeViolations();
});

test("the real page, with the fixture broker installed, has none of them", async ({ app }) => {
  await app.open({ broker: { locked: false } });
  await expect(app.screen("S1 Main")).toBeVisible();
  expect(app.violations).toEqual([]);
  expect(app.external).toEqual([]);
});
