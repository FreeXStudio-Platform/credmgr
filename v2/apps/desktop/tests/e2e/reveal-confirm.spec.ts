/**
 * ADR-150, "Confirm before showing secrets", against the fixture broker (tests/fixtures/broker/confirm.js): the broker refuses a reveal
 * with confirmation_required, the bridge asks the confirm dialog, the person confirms with the passphrase or Touch ID, and the SAME
 * reveal is sent again once.  The trust window, every-time, only-high-and-critical, a cancel, loosening the setting, the Settings rows
 * (Lite and Pro), a lock, and About's build line.
 */
import { FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import type { BrokerOptions } from "../fixtures/broker/index";
import { expect, test, type App } from "./harness";
import { MASK, notice, openNodeEntry, valueOf } from "./wp-b-helpers";

const STRIPE = valueOf("stripe-live");
const ON = { mode: "window" as const, windowSeconds: 300, scope: "all" as const };
const dialog = (app: App) => app.screen("Confirm it is you");

async function openOn(app: App, revealConfirm: BrokerOptions["revealConfirm"], extra: BrokerOptions = {}) {
  const broker = (await app.open({ broker: { locked: false, ...(revealConfirm ? { revealConfirm } : {}), ...extra } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  return broker;
}
async function revealStripe(app: App) {
  await openNodeEntry(app, "atlas", "stripe-live");
  await app.page.getByRole("button", { name: "reveal", exact: true }).click();
}
async function confirmWithPassphrase(app: App, pass = FIXTURE_PASSPHRASE) {
  await expect(dialog(app)).toBeVisible();
  await dialog(app).locator("input[data-confirm-pass]").fill(pass);
  await dialog(app).locator("[data-confirm-submit]").click();
}
const field = (app: App) => app.page.locator(".k-field-value").first();

test.describe("confirm before showing secrets", () => {
  test("off (the default): a reveal shows at once and nothing asks", async ({ app }) => {
    const broker = await openOn(app, undefined);
    await revealStripe(app);
    await expect(field(app)).toHaveText(STRIPE);
    await expect(dialog(app)).toHaveCount(0);
    expect(await broker.calls("session_confirm")).toEqual([]);
  });

  test("on: the reveal asks, the passphrase confirms, the same reveal is sent again and the value shows", async ({ app }) => {
    const broker = await openOn(app, ON);
    await revealStripe(app);
    await expect(dialog(app)).toBeVisible();
    await expect(field(app)).toHaveText(MASK);
    await confirmWithPassphrase(app);
    await expect(dialog(app)).toHaveCount(0);
    await expect(field(app)).toHaveText(STRIPE);
    const reveals = await broker.calls("entry_reveal");
    expect(reveals.length).toBe(2);
    expect(reveals[1].args).toEqual(reveals[0].args);
    expect(await broker.calls("session_confirm")).toEqual([{ cmd: "session_confirm", args: { passphrase: FIXTURE_PASSPHRASE } }]);
    // the passphrase was wiped from the input and never reached the page's state or storage
    expect(await app.viewJson()).not.toContain(FIXTURE_PASSPHRASE);
    expect(await app.storageDump()).not.toContain(FIXTURE_PASSPHRASE);
  });

  test("within the trust window a second reveal does not ask; after it, it asks again", async ({ app }) => {
    const { page } = app;
    const broker = await openOn(app, ON);
    await revealStripe(app);
    await confirmWithPassphrase(app);
    await expect(field(app)).toHaveText(STRIPE);
    await page.getByRole("button", { name: /^hide(, re-masks in \d+ seconds)?$/ }).click();
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(field(app)).toHaveText(STRIPE);
    await expect(dialog(app)).toHaveCount(0);
    expect((await broker.calls("session_confirm")).length).toBe(1);
    // the window ends (the fixture's clock moved past it)
    await broker.set({ confirmedAt: Math.floor(Date.now() / 1000) - 400 });
    await page.getByRole("button", { name: /^hide(, re-masks in \d+ seconds)?$/ }).click();
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(dialog(app)).toBeVisible();
  });

  test("a wrong passphrase is said in the dialog, nothing is shown, and the right one then works", async ({ app }) => {
    const broker = await openOn(app, ON);
    await revealStripe(app);
    await confirmWithPassphrase(app, "not-the-passphrase");
    await expect(dialog(app).getByRole("alert")).toHaveText("Wrong passphrase.");
    await expect(field(app)).toHaveText(MASK);
    await confirmWithPassphrase(app);
    await expect(field(app)).toHaveText(STRIPE);
    expect((await broker.calls("entry_reveal")).length).toBe(2);
  });

  test("cancel: nothing is shown, a quiet notice says so, and nothing is sent again", async ({ app }) => {
    const broker = await openOn(app, ON);
    await revealStripe(app);
    await expect(dialog(app)).toBeVisible();
    await dialog(app).locator("[data-confirm-cancel]").click();
    await expect(dialog(app)).toHaveCount(0);
    await expect(notice(app, "Not confirmed. Nothing was shown.")).toBeVisible();
    await expect(field(app)).toHaveText(MASK);
    expect((await broker.calls("entry_reveal")).length).toBe(1);
  });

  test("Escape cancels too", async ({ app }) => {
    const broker = await openOn(app, ON);
    await revealStripe(app);
    await expect(dialog(app)).toBeVisible();
    await app.page.keyboard.press("Escape");
    await expect(dialog(app)).toHaveCount(0);
    await expect(field(app)).toHaveText(MASK);
    expect((await broker.calls("entry_reveal")).length).toBe(1);
  });

  test("every time: each reveal asks again", async ({ app }) => {
    const { page } = app;
    const broker = await openOn(app, { mode: "everyTime", windowSeconds: 300, scope: "all" });
    await revealStripe(app);
    await expect(dialog(app)).toContainText("You will be asked again for the next secret.");
    await confirmWithPassphrase(app);
    await expect(field(app)).toHaveText(STRIPE);
    await page.getByRole("button", { name: /^hide(, re-masks in \d+ seconds)?$/ }).click();
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(dialog(app)).toBeVisible();
    await confirmWithPassphrase(app);
    await expect(field(app)).toHaveText(STRIPE);
    expect((await broker.calls("session_confirm")).length).toBe(2);
  });

  test("only high and critical: a low entry shows without asking, a high one asks", async ({ app }) => {
    const broker = await openOn(app, { mode: "window", windowSeconds: 300, scope: "high" });
    await openNodeEntry(app, "global", "licence-server");
    await app.page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(field(app)).toHaveText(valueOf("licence-server"));
    await expect(dialog(app)).toHaveCount(0);
    await revealStripe(app);
    await expect(dialog(app)).toBeVisible();
    expect(await broker.calls("session_confirm")).toEqual([]);
  });

  test("Touch ID: offered first when this Mac has a presence key, and confirms with no passphrase sent", async ({ app }) => {
    const broker = await openOn(app, ON, { touchId: true });
    await broker.script("presence_probe", { result: { secureEnclave: true, biometry: "touchid", passcode: true, keyOnThisMac: true } });
    await broker.script("presence_status", { result: { helper: true, secureEnclave: true, biometry: "touchid", passcode: true, enrolled: [{ id: "pk1", label: "This Mac", createdAt: 1 }], touchIdUnlock: false } });
    await revealStripe(app);
    const touch = dialog(app).locator("[data-confirm-touch]");
    await expect(touch).toHaveText("Use Touch ID");
    await touch.click();
    await expect(field(app)).toHaveText(STRIPE);
    expect(await broker.calls("session_confirm")).toEqual([{ cmd: "session_confirm", args: {} }]);
  });

  test("a copy asks too, and is sent again after the confirmation", async ({ app }) => {
    const broker = await openOn(app, ON);
    await openNodeEntry(app, "atlas", "stripe-live");
    await app.page.getByRole("button", { name: "copy", exact: true }).click();
    await confirmWithPassphrase(app);
    await expect(dialog(app)).toHaveCount(0);
    await expect(app.page.getByRole("button", { name: "copied" })).toBeVisible();
    expect((await broker.calls("entry_copy")).length).toBe(2);
  });

  test("a lock while the dialog is open closes it and confirms nothing", async ({ app }) => {
    const broker = await openOn(app, ON);
    await revealStripe(app);
    await expect(dialog(app)).toBeVisible();
    await app.page.keyboard.press("Meta+l");
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    await expect(dialog(app)).toHaveCount(0);
    expect(await broker.calls("session_confirm")).toEqual([]);
  });
});

test.describe("the setting", () => {
  async function security(app: App) {
    await app.page.evaluate(() => (window as any).__cm.setState({ overlay: "settings", setSection: "security" }));
    const row = app.screen("S12e Confirm before showing secrets");
    await expect(row).toBeVisible();
    return row;
  }

  test("off by default; turning it on needs no confirmation and the trust window defaults to 5 min", async ({ app }) => {
    const broker = await openOn(app, undefined);
    const row = await security(app);
    const toggle = row.locator("[data-rc-toggle]");
    await expect(toggle).toHaveText("off");
    await toggle.click();
    await expect(toggle).toHaveText("on");
    await expect(row.getByLabel("trust window")).toHaveValue("300");
    const policy = await broker.calls("node_policy");
    expect(policy.length).toBe(1);
    expect(policy[0].args).toMatchObject({ node: "global", policy: { revealConfirm: { mode: "window", windowSeconds: 300, scope: "all" } } });
    expect(await broker.calls("session_confirm")).toEqual([]);
    // a shorter window is stricter: no confirmation either
    await row.getByLabel("trust window").selectOption("60");
    await expect(row.getByLabel("trust window")).toHaveValue("60");
    expect(await broker.calls("session_confirm")).toEqual([]);
  });

  test("turning it off asks for a confirmation first; cancelled, the setting stays on", async ({ app }) => {
    const broker = await openOn(app, ON);
    const row = await security(app);
    const toggle = row.locator("[data-rc-toggle]");
    await expect(toggle).toHaveText("on");
    await toggle.click();
    await expect(dialog(app)).toBeVisible();
    await expect(dialog(app)).toContainText("Loosening this setting needs a quick check first.");
    await dialog(app).locator("[data-confirm-cancel]").click();
    await expect(notice(app, "Not confirmed. The setting was not changed.")).toBeVisible();
    await expect(toggle).toHaveText("on");
    expect((await broker.state() as any).revealConfirm.mode).toBe("window");
    // and confirmed, it turns off
    await toggle.click();
    await confirmWithPassphrase(app);
    await expect(toggle).toHaveText("off");
    expect((await broker.state() as any).revealConfirm.mode).toBe("off");
  });

  test("Pro: when to ask and which secrets; Lite hides those two", async ({ app }) => {
    const broker = await openOn(app, ON);
    await app.page.evaluate(() => (window as any).__cm.setState({ mode: "pro" }));
    const row = await security(app);
    const pro = app.screen("S12f Confirm options (Pro)");
    await expect(pro).toBeVisible();
    await pro.getByLabel("when to ask").selectOption("everyTime");
    await expect(pro.getByLabel("when to ask")).toHaveValue("everyTime");
    await expect(row.getByLabel("trust window")).toHaveCount(0);
    expect((await broker.state() as any).revealConfirm).toMatchObject({ mode: "everyTime" });
    // only high and critical is a loosening: it asks
    await pro.getByLabel("which secrets").selectOption("high");
    await confirmWithPassphrase(app);
    await expect(pro.getByLabel("which secrets")).toHaveValue("high");
    expect((await broker.state() as any).revealConfirm).toMatchObject({ mode: "everyTime", scope: "high" });
    await app.page.evaluate(() => (window as any).__cm.setState({ mode: "lite" }));
    await expect(app.screen("S12f Confirm options (Pro)")).toHaveCount(0);
    await expect(row).toContainText("set to ask every time");
  });
});

test("About shows the commit the build was made from", async ({ app }) => {
  await openOn(app, undefined);
  await app.page.evaluate(() => (window as any).__cm.setState({ dialog: "about", aboutTab: "main" }));
  await expect(app.page.locator("[data-about-build]")).toHaveText(/^build ([0-9a-f]{7,12}|unknown)$/);
});
