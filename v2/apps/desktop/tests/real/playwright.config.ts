import { defineConfig } from "@playwright/test";

/**
 * The real-broker end-to-end suite: the BUILT app (build/, production CSP, served from disk by page.route) with the Tauri shell
 * replaced by the Node shim, in front of a REAL `credmgrd` on a throwaway vault. Run it with `npm run test:real` (which builds
 * credmgrd and the front end first, then runs the drift guard, then this).
 *
 * Each test starts its own daemon, its own temp root and its own browser context, so tests share nothing and can run in parallel
 * (the daemon's key derivation is memory-hard, so the default is two workers; CREDMGR_REAL_WORKERS overrides).
 *
 * WebKit is the gate (same engine family as the WKWebView Tauri uses on macOS); Chromium is the second opinion.
 * No TCP port is opened by anything here: the bundle is answered from disk by page.route, the daemon listens on a Unix socket.
 */
export default defineConfig({
  testDir: ".",
  testMatch: "**/*.spec.ts",
  timeout: 120_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  workers: Number(process.env.CREDMGR_REAL_WORKERS ?? 2),
  retries: 0,
  reporter: [["list"]],
  outputDir: ".results",
  use: {
    // A click that cannot find its target fails in 30 s with the locator, instead of hanging until the test timeout.
    actionTimeout: 30_000,
    viewport: { width: 1440, height: 900 },
    // Playwright's screenshot and trace helpers inject a <style> element, which the policy under test would (correctly) refuse.
    screenshot: "off",
    trace: "off",
    video: "off",
  },
  projects: [
    { name: "webkit", use: { browserName: "webkit" } },
    { name: "chromium", use: { browserName: "chromium" } },
  ],
});
