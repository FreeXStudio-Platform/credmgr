/**
 * Settings → Security → "Hide the window from screen capture and screen sharing" (threat T10).
 *
 * The window is created protected, so the page calls the shell (`capture_protection_set`) only when the user turns it OFF, and again
 * on a start where the stored choice is OFF.  Turning it OFF goes through the app's own confirmation (a WKWebView has no confirm()),
 * turning it ON does not.  The choice lives in the ONE documented preferences key, and locking the vault does not change it.
 */
import { FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import { expect, test, type App } from "./harness";
import { openSettings } from "./wp-d-helpers";

const ROW = "Hide the window from screen capture and screen sharing";

async function open(app: App) {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  return broker;
}

const toggle = (app: App) => app.page.getByRole("button", { name: ROW });
const chip = (app: App) => app.page.locator("[data-capture-chip]");
const dialog = (app: App) => app.page.getByRole("dialog", { name: /show this window to screen capture/i });
const stored = (app: App) => app.page.evaluate(() => JSON.parse(localStorage.getItem("credmgr_prefs") ?? "null"));
const calls = async (app: App) => (await app.broker!.calls("capture_protection_set")).map((c) => c.args);

async function reload(app: App) {
  await app.page.reload({ waitUntil: "load" });
  await expect(app.screen("S1 Main")).toBeVisible();
}

test("a new install is protected: nothing is stored, the shell is never called, and the row says on", async ({ app }) => {
  await open(app);
  await app.page.waitForTimeout(300);
  expect(await calls(app)).toEqual([]);
  expect(await stored(app)).toBeNull();
  await openSettings(app, "Security");
  await expect(toggle(app)).toHaveText("on");
  await expect(toggle(app)).toHaveAttribute("aria-pressed", "true");
  await expect(chip(app)).toHaveCount(0);
});

test("turning it OFF asks first, in the app's own dialog; cancelling or Escape changes nothing", async ({ app }) => {
  const { page } = app;
  await open(app);
  await openSettings(app, "Security");

  await toggle(app).click();
  await expect(dialog(app)).toBeVisible();
  await expect(dialog(app)).toContainText("appear in screenshots, recordings and screen shares");
  expect(await calls(app)).toEqual([]); // asking is not doing
  expect(await stored(app)).toBeNull();

  await page.getByRole("button", { name: "Keep it hidden" }).click();
  await expect(dialog(app)).toHaveCount(0);
  await expect(toggle(app)).toHaveText("on");
  expect(await calls(app)).toEqual([]);
  expect(await stored(app)).toBeNull();

  await toggle(app).click();
  await expect(dialog(app)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog(app)).toHaveCount(0);
  await openSettings(app, "Security");
  await expect(toggle(app)).toHaveText("on");
  expect(await calls(app)).toEqual([]);
  expect(await stored(app)).toBeNull();
  app.assertClean();
});

test("confirming turns it off: one shell call, the choice stored under credmgr_prefs, a 'capture allowed' chip; turning it back on needs no question", async ({ app }) => {
  const { page } = app;
  await open(app);
  await openSettings(app, "Security");

  await toggle(app).click();
  await page.getByRole("button", { name: "Allow capture" }).click();
  await expect(dialog(app)).toHaveCount(0);
  await expect(toggle(app)).toHaveText("off");
  await expect(toggle(app)).toHaveAttribute("aria-pressed", "false");
  await expect(chip(app)).toHaveText("capture allowed");
  expect(await calls(app)).toEqual([{ enabled: false }]);
  expect(await stored(app)).toEqual({ captureProtection: false });

  await toggle(app).click(); // ON again: no dialog
  await expect(dialog(app)).toHaveCount(0);
  await expect(toggle(app)).toHaveText("on");
  await expect(chip(app)).toHaveCount(0);
  expect(await calls(app)).toEqual([{ enabled: false }, { enabled: true }]);
  expect(await stored(app)).toEqual({ captureProtection: true });
  app.assertClean();
});

test("the OFF choice survives a restart: the page tells the shell once, after it boots, and the row still says off", async ({ app }) => {
  const { page } = app;
  await open(app);
  await openSettings(app, "Security");
  await toggle(app).click();
  await page.getByRole("button", { name: "Allow capture" }).click();
  expect(await stored(app)).toEqual({ captureProtection: false });

  await reload(app);
  await expect.poll(() => calls(app)).toEqual([{ enabled: false }]);
  await openSettings(app, "Security");
  await expect(toggle(app)).toHaveText("off");
  await expect(chip(app)).toHaveText("capture allowed");
  expect(await stored(app)).toEqual({ captureProtection: false }); // loading wrote nothing new
  app.assertClean();
});

test("locking the vault does not change the choice, and calls the shell about nothing", async ({ app }) => {
  const { page } = app;
  await open(app);
  await openSettings(app, "Security");
  await toggle(app).click();
  await page.getByRole("button", { name: "Allow capture" }).click();
  await page.keyboard.press("Escape");

  await page.getByRole("button", { name: "lock the vault" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await page.locator('input[type="password"]').fill(FIXTURE_PASSPHRASE);
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible();

  expect(await calls(app)).toEqual([{ enabled: false }]); // the one call from the confirmation, none from the lock or the unlock
  expect(await stored(app)).toEqual({ captureProtection: false });
  await openSettings(app, "Security");
  await expect(toggle(app)).toHaveText("off");
  app.assertClean();
});

test("an unreadable or hostile stored value is not 'off': the window stays protected and the shell is not called", async ({ app }) => {
  await app.page.addInitScript(() => localStorage.setItem("credmgr_prefs", '{"captureProtection":"off","theme":"dark"}'));
  await open(app);
  await app.page.waitForTimeout(300);
  expect(await calls(app)).toEqual([]);
  await openSettings(app, "Security");
  await expect(toggle(app)).toHaveText("on");
  await expect(chip(app)).toHaveCount(0);
  app.assertClean();
});
