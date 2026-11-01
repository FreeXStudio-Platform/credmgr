/**
 * Preferences: the settings a user picks are remembered across a restart, under the ONE documented storage key, and
 * nothing else about the vault goes with them.
 *
 * The browsers here start in the light colour scheme with no contrast or motion preference, so a "dark" or "high contrast"
 * that is still there after a reload can only have come from the stored preference.
 */
import { expect, test, type App } from "./harness";
import { openSettings } from "./wp-d-helpers";

const DOCUMENTED = ["credmgr_gposV", "credmgr_gpos", "credmgr_gposEntry", "credmgr_cosmetics", "credmgr_prefs", "credpong_best", "credpong_level"];

async function open(app: App) {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  return broker;
}

const stored = (app: App) => app.page.evaluate(() => localStorage.getItem("credmgr_prefs"));
const storedJson = async (app: App) => JSON.parse((await stored(app)) ?? "null");
const theme = (app: App) => app.page.evaluate(() => document.documentElement.dataset.theme);

async function reload(app: App) {
  await app.page.reload({ waitUntil: "load" });
  await expect(app.screen("S1 Main")).toBeVisible();
}

test("nothing is written just by starting: with no choice made there is no preferences key", async ({ app }) => {
  await open(app);
  await app.page.waitForTimeout(300);
  expect(await stored(app)).toBeNull();
});

test("settings survive a reload through credmgr_prefs, and only the changed ones are stored", async ({ app }) => {
  const { page } = app;
  await open(app);
  expect(await theme(app)).toBe("light"); // the operating system's scheme, until one is chosen

  await openSettings(app, "Appearance");
  await page.getByRole("button", { name: "dark", exact: true }).click();
  await page.getByRole("button", { name: "on", exact: true }).first().click(); // colour: on
  await page.getByLabel("contrast").selectOption("high");
  await page.getByLabel("motion").selectOption("reduced");
  await page.getByRole("button", { name: "greyscale off" }).click();
  await openSettings(app, "Security");
  await page.getByLabel("auto-lock after").selectOption("5");
  await page.getByLabel("reveal window").selectOption("10");
  await openSettings(app, "Backup");
  await page.getByLabel("backup retention").selectOption("30");

  expect(await storedJson(app)).toEqual({ theme: "dark", colour: "on", contrastMode: "high", motion: "reduced", greyscale: true, autoLockMins: 5, revealWindowSecs: 10, backupRetain: 30 });
  expect(await theme(app)).toBe("dark");

  await reload(app);
  expect(await theme(app)).toBe("dark"); // the operating system says light; the stored choice wins
  await expect(page.locator('[data-contrast="high"]')).toHaveCount(1);
  await expect(page.locator('[data-reduced-motion="true"]')).toHaveCount(1);
  expect(await page.evaluate(() => (window as any).__cm.state.greyscale)).toBe(true);
  await openSettings(app, "Security");
  await expect(page.getByLabel("auto-lock after")).toHaveValue("5");
  await expect(page.getByLabel("reveal window")).toHaveValue("10");
  await openSettings(app, "Backup");
  await expect(page.getByLabel("backup retention")).toHaveValue("30");
  await openSettings(app, "Appearance");
  await expect(page.getByLabel("contrast")).toHaveValue("high");
  await expect(page.getByLabel("motion")).toHaveValue("reduced");
  expect(await storedJson(app)).toEqual({ theme: "dark", colour: "on", contrastMode: "high", motion: "reduced", greyscale: true, autoLockMins: 5, revealWindowSecs: 10, backupRetain: 30 }); // loading wrote nothing new
});

test("the storage holds only documented keys and no node or entry name, hashed or not", async ({ app }) => {
  const { page } = app;
  await open(app);
  // touch every writer: settings, cosmetics, the graph layout (select a node so positions persist)
  await openSettings(app, "Security");
  await page.getByLabel("auto-lock after").selectOption("60");
  await page.keyboard.press("Escape");
  await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
  await page.waitForTimeout(150);
  const dump = await app.storageDump();
  const keys = await page.evaluate(() => Object.keys(localStorage));
  expect(keys).toContain("credmgr_prefs");
  for (const k of keys) expect(DOCUMENTED, `undocumented key ${k}`).toContain(k);
  for (const word of ["atlas", "beacon", "cobalt", "staging", "global", "stripe-live", "pg-main", "registry-token", "e-a1"]) expect(dump, `storage mentions ${word}`).not.toContain(word);
  // and the prefs hold nothing but settings
  for (const v of Object.values(await storedJson(app))) expect(["string", "number", "boolean"]).toContain(typeof v);
});

test("Lite mode is remembered, and keeps revoking a grant reachable", async ({ app }) => {
  const { page } = app;
  await open(app);
  await openSettings(app, "Mode");
  await page.getByRole("button", { name: "Lite", exact: true }).click();
  expect((await storedJson(app)).mode).toBe("lite");
  await reload(app);
  await page.getByRole("button", { name: "settings", exact: true }).click();
  const nav = page.locator(".cm-settings > div:first-child > button");
  const names = (await nav.allTextContents()).map((t) => t.trim());
  expect(names).toContain("Grants");
  expect(names).not.toContain("Nodes");
  expect(names).not.toContain("Audit");
  expect(names).not.toContain("Advanced");
});

test("a damaged or hostile stored value cannot break the app or smuggle anything in", async ({ app }) => {
  const { page } = app;
  await page.addInitScript(() => {
    localStorage.setItem("credmgr_prefs", '{"theme":"neon","colour":"on","hue":9999,"autoLockMins":7,"revealWindowSecs":10,"evil":"<img src=x onerror=alert(1)>","__proto__":{"polluted":true}}');
  });
  await open(app);
  expect(await page.evaluate(() => (({}) as any).polluted)).toBeUndefined();
  expect(await theme(app)).toBe("light"); // "neon" is not a theme: ignored
  expect(await page.evaluate(() => (window as any).__cm.state.colour)).toBe("on"); // the valid fields still apply
  expect(await page.evaluate(() => (window as any).__cm.state.hue)).toBe(198); // out of range: the default
  expect(await page.evaluate(() => (window as any).__cm.state.autoLockMins)).toBe(15); // not one of the offered choices: the default
  expect(await page.evaluate(() => (window as any).__cm.state.revealWindowSecs)).toBe(10);
  await expect(page.locator("img[src='x']")).toHaveCount(0);
  // saving writes back only what is valid
  await openSettings(app, "Security");
  await page.getByLabel("auto-lock after").selectOption("5");
  expect(await storedJson(app)).toEqual({ colour: "on", revealWindowSecs: 10, autoLockMins: 5 });
  // and a value that is not JSON at all is just "nothing stored"
  await page.evaluate(() => localStorage.setItem("credmgr_prefs", "{not json"));
  await page.getByLabel("auto-lock after").selectOption("60");
  expect(await storedJson(app)).toEqual({ autoLockMins: 60 });
});

test("a webview that refuses storage still runs, and the settings apply for the session", async ({ app }) => {
  const { page } = app;
  await page.addInitScript(() => {
    Object.defineProperty(window, "localStorage", { get() { throw new DOMException("denied", "SecurityError"); }, configurable: true });
  });
  await open(app);
  await openSettings(app, "Appearance");
  await page.getByRole("button", { name: "dark", exact: true }).click();
  expect(await theme(app)).toBe("dark");
});

test("the operating system's colour scheme is followed until a theme is chosen", async ({ app }) => {
  const { page } = app;
  await page.emulateMedia({ colorScheme: "dark" });
  await open(app);
  expect(await theme(app)).toBe("dark");
  expect(await stored(app)).toBeNull(); // following the system is not a choice
  await openSettings(app, "Appearance");
  await page.getByRole("button", { name: "light", exact: true }).click();
  expect(await theme(app)).toBe("light");
  await reload(app);
  expect(await theme(app)).toBe("light"); // the chosen theme beats the system's
});

test("high contrast follows the operating system until one is picked; a pick wins afterwards", async ({ app }) => {
  const { page } = app;
  await page.emulateMedia({ contrast: "more" });
  await open(app);
  await expect(page.locator('[data-contrast="high"]')).toHaveCount(1);
  expect(await stored(app)).toBeNull();
  await openSettings(app, "Appearance");
  await page.getByLabel("contrast").selectOption("standard");
  await expect(page.locator('[data-contrast="standard"]')).toHaveCount(1);
  await reload(app);
  await expect(page.locator('[data-contrast="standard"]')).toHaveCount(1); // the operating system still says more; the pick stands
  expect((await storedJson(app)).contrastMode).toBe("standard");
});
