import { defineConfig } from "@playwright/test";

/**
 * End-to-end specs: the BUILT app (build-test/, which `npm run test:e2e` builds first) served the way Tauri serves it, under
 * the production Content-Security-Policy, with the Tauri shell's `invoke` replaced by the fixture broker (tests/fixtures/broker).
 * No server process: tests/e2e/harness.ts answers every request from the build directory and aborts anything else.
 *
 * WebKit is the gate (same engine family as the WKWebView Tauri uses on macOS); Chromium is the second opinion.
 */
export default defineConfig({
  testDir: "tests/e2e",
  testMatch: "**/*.spec.ts",
  timeout: 45_000,
  expect: { timeout: 8_000 },
  fullyParallel: true,
  workers: 3,
  retries: 0,
  reporter: [["list"]],
  outputDir: "test-results",
  use: {
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
