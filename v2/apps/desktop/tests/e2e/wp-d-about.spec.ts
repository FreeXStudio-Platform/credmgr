/**
 * About, Help, Donate, the presence notice, and the Security section's claims: every sentence on these screens has to be
 * true of the product as built.
 *
 * The version comes from the shell (a scripted answer proves it is read, not typed in); the licence is the source-available FreexStudio licence; the privacy
 * text lists exactly the storage keys the app writes; the donation addresses are the ones in DONATE.md; Help describes the
 * graph glyphs the way the rail draws them; no section carries a "mock" badge or a claim nothing backs.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { FIXTURE_GATE_CODE, FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import { TEST_CODE } from "../fixtures/extras/seal-test-pack.mjs";
import { expect, test, type App } from "./harness";
import { openFromMenu, openSettings } from "./wp-d-helpers";

const HERE = dirname(fileURLToPath(import.meta.url));
const DONATE_MD = readFileSync(resolve(HERE, "../../../../DONATE.md"), "utf8");

async function open(app: App, script?: Record<string, Array<{ result: unknown }>>) {
  const broker = (await app.open({ broker: { locked: false }, script }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  return broker;
}

test("About shows the version the shell reports, not a number typed into the screen", async ({ app }) => {
  const { page } = app;
  const broker = await open(app, { "plugin:app|version": [{ result: "9.9.9-test" }] });
  await openFromMenu(app, "About CredMgr");
  await expect(app.screen("S18 About")).toBeVisible();
  await expect(page.locator('[data-about-version="true"]')).toHaveText("9.9.9-test");
  expect(await broker.calls("plugin:app|version")).toHaveLength(1);
});

test("About shows the real configured version when nothing is scripted", async ({ app }) => {
  const { page } = app;
  await open(app);
  await openFromMenu(app, "About CredMgr");
  await expect(page.locator('[data-about-version="true"]')).toHaveText("2.0.0-beta.1");
});

test("a shell that cannot report its version is shown as unknown, not as a guess", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await broker.script("plugin:app|version", { error: { code: "internal", source: "bridge" } });
  await openFromMenu(app, "About CredMgr");
  await expect(page.locator('[data-about-version="true"]')).toHaveText("unknown");
});

test("in a browser with no shell, About says it is a preview instead of inventing a version", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: false });
  await expect(app.screen("S1 Main")).toBeVisible();
  await openFromMenu(app, "About CredMgr");
  await expect(page.locator('[data-about-version="true"]')).toHaveText("browser preview");
});

test("Licences describes the source-available licence, and nothing about a paid licence", async ({ app }) => {
  const { page } = app;
  await open(app);
  await openFromMenu(app, "About CredMgr");
  await page.getByRole("link", { name: "Licences" }).click();
  const about = app.screen("S18 About");
  await expect(about).toContainText("source-available");
  await expect(about).toContainText("LICENSE");
  await expect(about).toContainText("TRADEMARKS.md");
  await expect(about).toContainText("SIL Open Font Licence");
  const text = (await about.innerText()).toLowerCase();
  for (const bad of ["paid licence", "commercial use requires", "organisational", "subscription", "enterprise"]) expect(text, bad).not.toContain(bad);
});

test("Privacy lists every storage key the app writes, and promises nothing the build does not do", async ({ app }) => {
  const { page } = app;
  await open(app);
  // make the app write every kind of key it can
  await openSettings(app, "Security");
  await page.getByLabel("auto-lock after").selectOption("60");
  await page.evaluate((c) => (window as any).__cm.extrasUnlock(c), TEST_CODE); // a supporter code: the extras key and flag
  await openSettings(app, "Appearance");
  await page.getByRole("button", { name: "node + ring" }).click(); // cosmetics
  await page.getByRole("button", { name: "Single-key shortcuts" }).click(); // credmgr_keys
  await page.keyboard.press("Escape");
  await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
  await page.waitForTimeout(150);
  const written = await page.evaluate(() => Object.keys(localStorage));
  expect(written).toContain("credmgr_prefs");
  expect(written).toContain("credmgr_cosmetics");
  for (const key of ["credmgr_donate_unlocked", "credmgr_extras_key", "credmgr_usage", "credmgr_keys"]) expect(written, key).toContain(key);

  await openFromMenu(app, "About CredMgr");
  await page.getByRole("link", { name: "Privacy" }).click();
  const list = (await page.locator('[data-storage-keys="true"]').innerText()).split(/[\s,]+/);
  for (const key of written) expect(list, `Privacy does not list the key ${key}`).toContain(key);
  for (const key of ["credmgr_prefs", "credmgr_cosmetics", "credmgr_donate_unlocked", "credmgr_extras_key", "credmgr_usage", "credmgr_keys", "credmgr_gposV", "credmgr_gpos", "credmgr_gposEntry", "credpong_best", "credpong_level"]) expect(list, key).toContain(key);

  const about = app.screen("S18 About");
  await expect(about).toContainText("no telemetry");
  await expect(about).toContainText("makes no network requests");
  await expect(about).toContainText("never written to storage or to a log");
});

test("Donate in About is one static entry: five chains, the addresses in DONATE.md, the checks before sending, and no code box of its own (the reminder is covered by extras.spec.ts)", async ({ app }) => {
  const { page } = app;
  await page.clock.install();
  await open(app);
  await page.clock.fastForward(30_000); // longer than the six seconds the reminder waits: a young vault is never asked
  await expect(page.locator('[role="dialog"]')).toHaveCount(0);
  await expect(page.locator("[data-donate-toast]")).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText("THANKS" + "CREDMGR"); // the retired public code, built from pieces so it is not spelled in the repo

  await openFromMenu(app, "About CredMgr");
  await page.getByRole("link", { name: "Donate" }).click();
  const about = app.screen("S18 About");
  await expect(about).toContainText("buy no features");
  await expect(about).toContainText("verify the first and last six characters");
  await expect(about).toContainText("send a small test amount first");
  const tabs = about.getByRole("button").filter({ hasText: /^(EVM|BTC|SOL|TRX|TON)$/ });
  await expect(tabs).toHaveCount(5);
  for (const short of ["EVM", "BTC", "SOL", "TRX", "TON"]) {
    await about.getByRole("button", { name: short, exact: true }).click();
    const shown = (await about.locator("div[style*='user-select']").first().innerText()).trim();
    expect(shown.length).toBeGreaterThan(20);
    expect(DONATE_MD, `${short}: the address on screen is not in DONATE.md`).toContain(shown);
  }
  await expect(about).not.toContainText("@"); // no email address
  await expect(about.getByRole("textbox")).toHaveCount(0); // no code to enter
});

/** A page clipboard that records what it is given: inside the shell, nothing may reach it. */
async function recordPageClipboard(app: App) {
  await app.page.addInitScript(() => {
    (window as any).__written = [];
    Object.defineProperty(navigator, "clipboard", { value: { writeText: (t: string) => ((window as any).__written.push(t), Promise.resolve()), readText: () => Promise.resolve("") }, configurable: true });
  });
}

test("copying a donation address sends copy_text with the address shown, and says copied only after the shell did it", async ({ app }) => {
  const { page } = app;
  await recordPageClipboard(app);
  const broker = await open(app);
  await openFromMenu(app, "About CredMgr");
  await page.getByRole("link", { name: "Donate" }).click();
  const shown = (await app.screen("S18 About").locator("div[style*='user-select']").first().innerText()).trim();
  expect(DONATE_MD).toContain(shown); // the text that goes to the shell is a published address, not something else on the page
  await page.getByRole("button", { name: "copy address" }).click();
  await expect(page.getByRole("button", { name: /copied/ })).toBeVisible();
  expect(await broker.calls("copy_text")).toEqual([{ cmd: "copy_text", args: { text: shown } }]); // exactly the command, and exactly the address
  expect(await broker.calls("entry_copy")).toEqual([]); // an address is not a secret: the concealed copy is for entries
  expect(await page.evaluate(() => (window as any).__written)).toEqual([]); // inside the shell the page's own clipboard is not used
});

test("a copy the shell refuses is reported as a failure, and the page's own clipboard is not used instead", async ({ app }) => {
  const { page } = app;
  await recordPageClipboard(app);
  const broker = await open(app);
  await broker.script("copy_text", { error: { code: "clipboard_failed", message: "the pasteboard refused", source: "bridge" } });
  await openFromMenu(app, "About CredMgr");
  await page.getByRole("link", { name: "Donate" }).click();
  await page.getByRole("button", { name: "copy address" }).click();
  await expect(page.getByRole("button", { name: "copy failed" })).toBeVisible();
  await expect(page.getByRole("button", { name: /copied/ })).toHaveCount(0);
  await expect(page.getByRole("alert")).toContainText("Could not copy the address");
  expect(await broker.calls("copy_text")).toHaveLength(1);
  expect(await page.evaluate(() => (window as any).__written)).toEqual([]); // no silent second attempt through the page
});

test("Help describes the graph glyphs the way the rail draws them, and mentions nothing that is not built", async ({ app }) => {
  const { page } = app;
  await open(app);
  // the locked node (cobalt) is drawn with the glyph Help calls "locked"
  await expect(page.locator(".cm-rail .k-tree-row", { hasText: "cobalt" }).first()).toContainText("⌐");
  await page.getByRole("button", { name: "help", exact: true }).click();
  const help = app.screen("S21 Help");
  await expect(help).toBeVisible();
  await expect(help).toContainText("⌐ means the node itself is locked");
  await expect(help).toContainText("‖ means the node asks every caller but you for a second factor on reveal (requireTwoFactor, enforced by the broker once a second factor is set up)");
  const text = (await help.innerText()).toLowerCase();
  // "agents" is no longer a banned word: the searchable topic list below the short sections (help-data.js) is about AI agents by design.
  // What stays banned is each claim of something that is not built ("settings → agents" is the screen that does not exist).
  for (const bad of ["security level", "settings → agents", "touch id and a fresh 2fa", "deliberate friction", "expiry", "settings → nodes lists everything"]) expect(text, bad).not.toContain(bad);
  await expect(help).toContainText("needs presence (Touch ID), which this beta cannot attest yet");
});

test("the presence notice dialog explains the refusal and offers nothing to press but Close", async ({ app }) => {
  const { page } = app;
  await open(app);
  await page.evaluate(() => (window as any).__cm.setState({ dialog: "touch", touch: { title: "open a sealed item", body: "Sealed values cannot be opened from this app." } }));
  const dialog = app.screen("Presence notice");
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("open a sealed item");
  await expect(dialog).toContainText("Sealed values cannot be opened from this app.");
  await expect(dialog).toContainText("This needs presence (Touch ID), which this beta cannot attest yet. Nothing was changed.");
  await expect(dialog.getByRole("button")).toHaveCount(1);
  await expect(dialog.getByRole("textbox")).toHaveCount(0); // no 2FA code field
  await dialog.getByRole("button", { name: "Close" }).click();
  await expect(dialog).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__cm.state.dialog)).toBeNull();
});

test("no settings section carries a mock badge or a claim nothing backs", async ({ app }) => {
  const { page } = app;
  await open(app);
  const BANNED = [/^mock\b/im, /not built yet/i, /last backup: 2h ago/i, /checked 04:00/i, /machine lock/i, /export with --age/i, /search inside saved values/i, /security level/i, /thankscredmgr/i, /on app switch/i];
  await page.getByRole("button", { name: "settings", exact: true }).click();
  const nav = page.locator(".cm-settings > div:first-child > button");
  const names = (await nav.allTextContents()).map((t) => t.trim());
  expect(names.length).toBeGreaterThanOrEqual(10);
  for (const name of names) {
    if (name.startsWith("Operations")) continue; // a different overlay, covered below
    await page.locator(".cm-settings > div:first-child > button", { hasText: name }).first().click();
    const text = await page.locator(".cm-settings").innerText();
    for (const re of BANNED) expect(text, `${name}: ${re}`).not.toMatch(re);
    await expect(page.locator(".cm-settings .k-type", { hasText: /^mock/i })).toHaveCount(0);
  }
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "vault menu" }).click();
  await page.locator(".cm-vaultmenu button", { hasText: "Operations" }).first().click();
  const ops = await app.screen("S14 Operations").innerText();
  for (const re of BANNED) expect(ops, `operations: ${re}`).not.toMatch(re);
  for (const gone of ["Merge entries", "Re-key", "Export node", "Import .env", "Purge access log"]) expect(ops, gone).not.toContain(gone);
  for (const here of ["Verify integrity", "Doctor", "Back up vault", "Rotate root key", "Audit report"]) expect(ops, here).toContain(here);
});

test("Security says what is known about the second factor: enrolled after a login that asked for it, not confirmed after one that did not", async ({ app }) => {
  const { page } = app;
  const unlock = async () => {
    await page.locator('input[type="password"]').fill(FIXTURE_PASSPHRASE);
    await page.getByRole("button", { name: "Unlock", exact: true }).click();
  };
  await app.open({ broker: { locked: true, gate: true } });
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await unlock();
  await page.getByPlaceholder("______").fill(FIXTURE_GATE_CODE);
  await expect(app.screen("S1 Main")).toBeVisible();
  await openSettings(app, "Security");
  await expect(page.locator(".cm-settings .k-chip", { hasText: "enrolled" })).toBeVisible();
  await expect(page.locator(".cm-settings")).toContainText("credmgr gate enroll");

  // a login that never asked for a code cannot say whether a gate exists, and does not claim one
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "vault menu" }).click();
  await page.locator(".cm-vaultmenu button", { hasText: "Lock vault" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  const broker = app.broker!;
  await broker.set({ gateEnrolled: false });
  await unlock();
  await expect(app.screen("S1 Main")).toBeVisible();
  await openSettings(app, "Security");
  await expect(page.locator(".cm-settings .k-chip", { hasText: "not confirmed" })).toBeVisible();
  await expect(page.locator(".cm-settings .k-chip", { hasText: "enrolled" })).toHaveCount(0);
});
