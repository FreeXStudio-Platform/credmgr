/**
 * The milestone ask and the sealed supporter extras (ADR-082), end to end: a real page, the production policy, the fixture broker.
 *
 * Time is injected, never slept: Playwright's clock stands in for the calendar day and for the six seconds the ask waits after an unlock
 * (`runFor`).  The count of entries and unlock days is set through the test-only handle `__cm.usageSet`, which a release build does not have.
 * The extras pack in a TEST build is the same data sealed under a code that exists only for tests (tests/fixtures/extras/seal-test-pack.mjs).
 *
 * The rules under test, from the plan: asks at 50 entries / 14 days, 150 / 45, 300 / 90, at most three, the highest only on a jump; never
 * locked, over a dialog, in a game, after a code, after "don't remind me", or twice in a day.
 */
import { FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import { TEST_CODE } from "../fixtures/extras/seal-test-pack.mjs";
import { expect, ORIGIN, test, type App } from "./harness";
import { openFromMenu, openSettings } from "./wp-d-helpers";

const DAY = "2026-03-10";
const NEXT_DAY = "2026-03-11";

const toast = (app: App) => app.page.locator("[data-donate-toast]");
const usage = (app: App) => app.page.evaluate(() => (window as any).__cm.usageGet());
const stored = (app: App, key: string) => app.page.evaluate((k) => localStorage.getItem(k), key);

async function lockScreen(app: App) {
  await expect(app.screen("S16 Lock screen")).toBeVisible();
}
async function unlock(app: App) {
  await app.page.locator('input[type="password"]').fill(FIXTURE_PASSPHRASE);
  await app.page.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible();
}
/** Lock the vault the way Cmd-L does and wait for the Lock screen. */
async function lock(app: App) {
  await app.page.evaluate(() => (window as any).__cm.lockVault());
  await lockScreen(app);
}
/** The six seconds the ask waits after an unlock, without waiting. */
const sixSeconds = (app: App) => app.page.clock.runFor(6100);

/** Start at the Lock screen on a fixed day with `entries` live entries and `days` unlock days behind (the last one today, so unlocking does not add a day). */
async function start(app: App, { entries, days, broker = { locked: true } }: { entries: number; days: number; broker?: Record<string, unknown> }) {
  await app.page.clock.install({ time: new Date(`${DAY}T10:00:00`) });
  const b = (await app.open({ broker }))!;
  await lockScreen(app);
  await app.page.evaluate((o) => (window as any).__cm.usageSet(o), { entries, days, last: DAY });
  return b;
}

test.describe("when the ask appears", () => {
  test("not at 49 entries / 30 days, not at 60 entries / 13 days", async ({ app }) => {
    await start(app, { entries: 49, days: 30 });
    await unlock(app);
    await sixSeconds(app);
    await expect(toast(app)).toHaveCount(0);
    expect((await usage(app)).asked).toEqual([]);
    await lock(app);
    await app.page.evaluate(() => (window as any).__cm.usageSet({ entries: 60, days: 13, last: "2026-03-10" }));
    await unlock(app);
    await sixSeconds(app);
    await expect(toast(app)).toHaveCount(0);
    expect((await usage(app)).asked).toEqual([]);
  });

  test("once at 50 entries / 14 days, labelled with the milestone; not again the same day, nor the next day", async ({ app }) => {
    await start(app, { entries: 50, days: 14 });
    await unlock(app);
    await expect(toast(app)).toHaveCount(0); // not before the six seconds
    await sixSeconds(app);
    await expect(toast(app)).toBeVisible();
    await expect(toast(app)).toContainText("50 entries");
    await expect(toast(app)).toContainText("enjoying credmgr?");
    await expect(toast(app).getByRole("button", { name: "don't remind me" })).toBeVisible();
    expect(await usage(app)).toMatchObject({ asked: ["m1"], lastAsk: DAY, optout: false, days: 14 });

    await toast(app).getByRole("button", { name: "dismiss" }).click(); // the cross dismisses this milestone only
    await expect(toast(app)).toHaveCount(0);
    expect((await usage(app)).optout).toBe(false);

    await lock(app);
    await unlock(app); // the same day
    await sixSeconds(app);
    await expect(toast(app)).toHaveCount(0);

    await lock(app);
    await app.page.clock.setSystemTime(new Date(`${NEXT_DAY}T10:00:00`)); // the next day: a new day is counted, m1 is spent, m2 needs 150
    await unlock(app);
    await sixSeconds(app);
    await expect(toast(app)).toHaveCount(0);
    expect(await usage(app)).toMatchObject({ days: 15, last: NEXT_DAY, asked: ["m1"] });
  });

  test("a jump from below 50 to 300 asks once, for the highest, and marks the lower ones passed", async ({ app }) => {
    await start(app, { entries: 300, days: 90 });
    await unlock(app);
    await sixSeconds(app);
    await expect(toast(app)).toBeVisible();
    await expect(toast(app)).toContainText("300 entries");
    expect((await usage(app)).asked).toEqual(["m1", "m2", "m3"]);
    await toast(app).getByRole("button", { name: "dismiss" }).click();
    await lock(app);
    await app.page.clock.setSystemTime(new Date(`${NEXT_DAY}T10:00:00`));
    await unlock(app);
    await sixSeconds(app);
    await expect(toast(app)).toHaveCount(0); // three is the most there ever are
  });

  test("not on the Lock screen: locking inside the six seconds cancels the ask, and nothing is marked", async ({ app }) => {
    await start(app, { entries: 300, days: 90 });
    await unlock(app);
    await lock(app);
    await sixSeconds(app);
    await expect(toast(app)).toHaveCount(0);
    await lockScreen(app);
    expect(await usage(app)).toMatchObject({ asked: [], lastAsk: "" });
  });

  test("not over a dialog", async ({ app }) => {
    await start(app, { entries: 300, days: 90 });
    await unlock(app);
    await openFromMenu(app, "Help");
    await expect(app.screen("S21 Help")).toBeVisible();
    await sixSeconds(app);
    await expect(toast(app)).toHaveCount(0);
    expect((await usage(app)).asked).toEqual([]);
  });

  test("not in a game", async ({ app }) => {
    await start(app, { entries: 300, days: 90 });
    await unlock(app);
    await openFromMenu(app, "Games");
    await expect(app.screen("S19 CredGames")).toBeVisible();
    await sixSeconds(app);
    await expect(toast(app)).toHaveCount(0);
    expect((await usage(app)).asked).toEqual([]);
  });

  test("not after 'don't remind me': the toast says where Donate is, closes, and the choice survives the next milestone", async ({ app }) => {
    await start(app, { entries: 50, days: 14 });
    await unlock(app);
    await sixSeconds(app);
    await toast(app).getByRole("button", { name: "don't remind me" }).click();
    await expect(toast(app)).toContainText("Okay — About → Donate is always there.");
    expect((await usage(app)).optout).toBe(true);
    await app.page.clock.runFor(2700);
    await expect(toast(app)).toHaveCount(0);
    await lock(app);
    await app.page.clock.setSystemTime(new Date(`${NEXT_DAY}T10:00:00`));
    await app.page.evaluate(() => (window as any).__cm.usageSet({ entries: 300, days: 90, last: "2026-03-11" }));
    await unlock(app);
    await sixSeconds(app);
    await expect(toast(app)).toHaveCount(0);
  });

  test("not after a supporter code", async ({ app }) => {
    await start(app, { entries: 300, days: 90 });
    await unlock(app);
    await app.page.evaluate((c) => (window as any).__cm.extrasUnlock(c), TEST_CODE);
    await lock(app);
    await unlock(app);
    await sixSeconds(app);
    await expect(toast(app)).toHaveCount(0);
    expect((await usage(app)).asked).toEqual([]);
  });
});

test.describe("the supporter code", () => {
  const settingsExtras = (app: App) => app.screen("S12a Supporter extras");

  /** Open Settings -> Appearance, press "Enter code" (it raises the reminder's code view), type `typed`, press Submit. */
  async function enterCode(app: App, typed: string) {
    await openSettings(app, "Appearance");
    await settingsExtras(app).getByRole("button", { name: "Enter code" }).click();
    await expect(toast(app)).toBeVisible();
    await toast(app).getByLabel("supporter code").fill(typed);
    await toast(app).getByRole("button", { name: "Submit" }).click();
  }

  test("typed in lower case with spaces it opens the extras; the key and flag are stored; nothing is requested; the shape works; it survives a relaunch", async ({ app }) => {
    const { page } = app;
    const requests: string[] = [];
    await start(app, { entries: 0, days: 0 });
    page.on("request", (r) => requests.push(`${r.resourceType()} ${r.url()}`));
    await unlock(app);

    // sealed: the pickers are visible but off, and nothing is stored
    await openSettings(app, "Appearance");
    await expect(settingsExtras(app).getByRole("button", { name: "hexagon" })).toBeDisabled();
    expect(await stored(app, "credmgr_extras_key")).toBeNull();
    expect(await stored(app, "credmgr_donate_unlocked")).toBeNull();

    await enterCode(app, `  ${TEST_CODE.toLowerCase().replace("-", " - ")}  `);
    await expect(toast(app)).toContainText("Thanks — you won't see this again.");
    expect(await stored(app, "credmgr_donate_unlocked")).toBe("1");
    expect(await stored(app, "credmgr_extras_key")).toMatch(/^[A-Za-z0-9+/]{43}=$/);

    // the extras are open: the hexagon option works, is remembered, and draws a hexagon (a point inside the circle but outside the hexagon is not in the path)
    await openSettings(app, "Appearance");
    await expect(settingsExtras(app).getByText("unlocked", { exact: true })).toBeVisible();
    const hexagon = settingsExtras(app).getByRole("button", { name: "hexagon" });
    await expect(hexagon).toBeEnabled();
    await hexagon.click();
    await expect(hexagon).toHaveAttribute("aria-pressed", "true");
    expect(JSON.parse((await stored(app, "credmgr_cosmetics"))!)).toMatchObject({ shape: "hexagon" });
    const geometry = await page.evaluate(() => {
      const cm = (window as any).__cm, ctx = document.createElement("canvas").getContext("2d")!;
      cm.shapePath(ctx, 50, 50, 20, cm.cosmEff().shape);
      return { shape: cm.cosmEff().shape, insideCircleOutsideHexagon: ctx.isPointInPath(50 + 19, 50), nearVertex: ctx.isPointInPath(50, 50 - 19) };
    });
    expect(geometry).toEqual({ shape: "hexagon", insideCircleOutsideHexagon: false, nearVertex: true });

    // relaunch: the stored key opens the pack without the code
    await page.reload();
    await lockScreen(app);
    await unlock(app);
    await expect.poll(() => page.evaluate(() => !!(window as any).__cm.state.pack)).toBe(true);
    await expect.poll(() => page.evaluate(() => (window as any).__cm.cosmEff().shape)).toBe("hexagon");
    await openSettings(app, "Appearance");
    await expect(settingsExtras(app).getByText("unlocked", { exact: true })).toBeVisible();
    expect(await stored(app, "credmgr_donate_unlocked")).toBe("1");

    // the code never leaves the page: no fetch, XHR, socket or beacon at all, and nothing outside the app
    expect(requests.filter((r) => /^(fetch|xhr|websocket|eventsource|ping) /.test(r))).toEqual([]);
    expect(requests.filter((r) => !r.includes(ORIGIN))).toEqual([]);
  });

  test("a wrong code stores nothing, says so, and leaves the extras sealed", async ({ app }) => {
    await start(app, { entries: 0, days: 0 });
    await unlock(app);
    await enterCode(app, "not-the-code");
    await expect(toast(app)).toContainText("That code doesn't look right.");
    expect(await stored(app, "credmgr_extras_key")).toBeNull();
    expect(await stored(app, "credmgr_donate_unlocked")).toBeNull();
    expect(await app.page.evaluate(() => (window as any).__cm.state.pack)).toBeNull();
    await toast(app).getByLabel("supporter code").fill("");
    await toast(app).getByRole("button", { name: "Submit" }).click();
    await expect(toast(app)).toContainText("That code doesn't look right."); // an empty code is wrong, not an error
  });

  test("a window without Web Crypto says so instead of calling the code wrong", async ({ app }) => {
    await start(app, { entries: 0, days: 0 });
    await unlock(app);
    await app.page.evaluate(() => Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true }));
    await enterCode(app, TEST_CODE);
    await expect(toast(app)).toContainText("This window can't open the extras: it has no secure context.");
    expect(await stored(app, "credmgr_extras_key")).toBeNull();
  });
});

test.describe("the unlock flourish", () => {
  const flourish = (app: App) => app.screen("X11 Unlock flourish");

  test("plays on a successful unlock only: not when the app opens onto a login that exists, not when a window comes back into view", async ({ app }) => {
    const { page } = app;
    await page.clock.install({ time: new Date(`${DAY}T10:00:00`) });
    await app.open({ broker: { locked: false } }); // the broker already has a login: the app opens straight onto it
    await expect(app.screen("S1 Main")).toBeVisible();
    await page.evaluate(async (c) => { const cm = (window as any).__cm; await cm.extrasUnlock(c); cm.setCosm({ flourish: "on" }); }, TEST_CODE);
    await expect(flourish(app)).toHaveCount(0);

    // a relaunch onto the same live login: the extras and the choice are back, and no flourish
    await page.reload();
    await expect(app.screen("S1 Main")).toBeVisible();
    await expect.poll(() => page.evaluate(() => (window as any).__cm.cosmEff().flourish)).toBe("on");
    await page.clock.runFor(1500);
    await expect(flourish(app)).toHaveCount(0);

    // a window coming back into view is not an unlock
    await page.evaluate(() => { document.dispatchEvent(new Event("visibilitychange")); });
    await page.clock.runFor(100);
    await expect(flourish(app)).toHaveCount(0);

    // a real unlock plays it, over the app, without blocking it, and it goes by itself
    await lock(app);
    await unlock(app);
    await expect(flourish(app)).toHaveCount(1);
    await expect(flourish(app)).toHaveCSS("pointer-events", "none");
    await expect(flourish(app)).toHaveAttribute("aria-hidden", "true");
    await page.clock.runFor(1300);
    await expect(flourish(app)).toHaveCount(0);

    // reduced motion: off, whatever was chosen
    await page.evaluate(() => (window as any).__cm.setState({ motion: "reduced" }));
    await lock(app);
    await unlock(app);
    await expect(flourish(app)).toHaveCount(0);
  });
});
