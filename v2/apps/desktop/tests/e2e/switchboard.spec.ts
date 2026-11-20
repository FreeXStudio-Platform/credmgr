/**
 * ADR-155, the switchboard, against the fixture broker (tests/fixtures/broker/switchboard.js): the app's preferences are the broker's
 * `app.*` settings, the same registry an agent changes through MCP.
 *   - after an unlock the broker's values are shown, even when this Mac's cache says otherwise (the broker wins), and the cache follows;
 *   - a change in Settings is sent to the broker as `settings_set` with `app.<key>`;
 *   - an agent's waiting request is listed in Settings › Agents; Approve asks "Confirm it is you" and sends `settings_request_decide`
 *     with approve true (the change then shows at once), Deny sends approve false and changes nothing.
 */
import { FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import type { BrokerOptions } from "../fixtures/broker/index";
import { expect, test, type App } from "./harness";
import { notice, unlockUi } from "./wp-b-helpers";
import { openSettings } from "./wp-d-helpers";

const REQUEST = { id: "app.autoLockMins", from: 15, to: 60, reason: "the agent wants longer sessions", cwd: "/work/fixture-project" };
const requests = (app: App) => app.screen("S21b Requests from agents");
const confirmDialog = (app: App) => app.screen("Confirm it is you");
const storedPrefs = (app: App) => app.page.evaluate(() => JSON.parse(localStorage.getItem("credmgr_prefs") ?? "null"));

async function openUnlocked(app: App, broker: BrokerOptions = {}) {
  const b = (await app.open({ broker: { locked: false, ...broker } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  return b;
}

test("after an unlock the broker's values are shown even when this Mac's cache differs, and the cache follows", async ({ app }) => {
  const { page } = app;
  // This Mac remembers 5 minutes and light; the vault's registry says 60 minutes and dark.
  await page.addInitScript(() => {
    if (!sessionStorage.getItem("seeded")) {
      localStorage.setItem("credmgr_prefs", JSON.stringify({ autoLockMins: 5, theme: "light" }));
      sessionStorage.setItem("seeded", "1");
    }
  });
  const broker = (await app.open({ broker: { locked: true, settings: { "app.autoLockMins": 60, "app.theme": "dark" } } }))!;
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe("light"); // before the unlock, the cache
  await unlockUi(app);
  await expect(app.screen("S1 Main")).toBeVisible();

  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.theme)).toBe("dark");
  await openSettings(app, "Security");
  await expect(page.getByLabel("auto-lock after")).toHaveValue("60");
  await expect.poll(() => storedPrefs(app)).toEqual({ autoLockMins: 60, theme: "dark" });
  expect(await broker.calls("settings_list")).toHaveLength(1);
  // the broker's values were shown, not sent back to it
  await page.waitForTimeout(700);
  expect(await broker.calls("settings_set")).toEqual([]);
});

test("a choice this Mac made before the vault kept app settings is sent up, not thrown away", async ({ app }) => {
  const { page } = app;
  await page.addInitScript(() => {
    if (!sessionStorage.getItem("seeded")) {
      localStorage.setItem("credmgr_prefs", JSON.stringify({ autoLockMins: 5 }));
      sessionStorage.setItem("seeded", "1");
    }
  });
  const broker = await openUnlocked(app);
  await expect.poll(async () => (await broker.calls("settings_set")).map((c) => c.args)).toEqual([
    { id: "app.autoLockMins", value: 5, reason: "kept from this Mac: chosen before the vault kept app settings" },
  ]);
  expect(((await broker.state()) as any).settings).toEqual({ "app.autoLockMins": 5 });
  await openSettings(app, "Security");
  await expect(page.getByLabel("auto-lock after")).toHaveValue("5");
});

test("changing auto-lock in Settings sends settings_set with app.autoLockMins", async ({ app }) => {
  const { page } = app;
  const broker = await openUnlocked(app);
  await openSettings(app, "Security");
  await page.getByLabel("auto-lock after").selectOption("5");
  await expect.poll(async () => (await broker.calls("settings_set")).map((c) => c.args)).toEqual([
    { id: "app.autoLockMins", value: 5, reason: "changed in the app" },
  ]);
  expect(((await broker.state()) as any).settings).toEqual({ "app.autoLockMins": 5 });
  expect(await storedPrefs(app)).toEqual({ autoLockMins: 5 });
});

test("a refused settings_set is a notice, and the change still applies on this Mac", async ({ app }) => {
  const { page } = app;
  const broker = await openUnlocked(app);
  await broker.script("settings_set", { error: { code: "internal" } });
  await openSettings(app, "Security");
  await page.getByLabel("auto-lock after").selectOption("60");
  await expect(notice(app, "the vault did not record the auto-lock setting")).toBeVisible();
  await expect(page.getByLabel("auto-lock after")).toHaveValue("60");
  expect(await storedPrefs(app)).toEqual({ autoLockMins: 60 });
});

test("an agent's waiting request is announced, listed in Settings › Agents, and Approve asks for a confirmation then sends approve true", async ({ app }) => {
  const { page } = app;
  const broker = await openUnlocked(app, { settingRequests: [REQUEST] });
  await expect(notice(app, "An agent asks to change app.autoLockMins from 15 to 60")).toBeVisible();

  await openSettings(app, "Agents");
  const list = requests(app);
  await expect(list).toBeVisible();
  await expect(list).toContainText("Requests from agents");
  const row = list.locator('[data-setting-request="srq-1"]');
  await expect(row).toContainText("app.autoLockMins");
  await expect(row).toContainText("from 15 to 60");
  await expect(row).toContainText("the agent wants longer sessions");
  await expect(row).toContainText("/work/fixture-project");
  await expect(row).toContainText(/\d+ s left/);

  await row.getByRole("button", { name: "approve the request to change app.autoLockMins" }).click();
  await expect(confirmDialog(app)).toBeVisible();
  await expect(confirmDialog(app)).toContainText("Loosening this setting needs a quick check first.");
  await confirmDialog(app).locator("input[data-confirm-pass]").fill(FIXTURE_PASSPHRASE);
  await confirmDialog(app).locator("[data-confirm-submit]").click();

  await expect(notice(app, "Approved. The setting is changed.")).toBeVisible();
  const decided = (await broker.calls("settings_request_decide")).map((c) => c.args);
  expect(decided).toEqual([{ request: "srq-1", approve: true }, { request: "srq-1", approve: true }]); // refused for a confirmation, then sent again once
  expect(await broker.calls("session_confirm")).toEqual([{ cmd: "session_confirm", args: { passphrase: FIXTURE_PASSPHRASE } }]);
  await expect(list).toHaveCount(0);
  // the approved change shows at once: settings were read again
  await openSettings(app, "Security");
  await expect(page.getByLabel("auto-lock after")).toHaveValue("60");
  expect(await storedPrefs(app)).toEqual({ autoLockMins: 60 });
});

test("a cancelled confirmation approves nothing", async ({ app }) => {
  const broker = await openUnlocked(app, { settingRequests: [REQUEST] });
  await openSettings(app, "Agents");
  await requests(app).getByRole("button", { name: "approve the request to change app.autoLockMins" }).click();
  await expect(confirmDialog(app)).toBeVisible();
  await confirmDialog(app).locator("[data-confirm-cancel]").click();
  await expect(notice(app, "Not confirmed. The setting was not changed.")).toBeVisible();
  await expect(requests(app).locator('[data-setting-request="srq-1"]')).toBeVisible();
  expect(((await broker.state()) as any).settings).toEqual({});
});

test("Deny sends approve false, asks for nothing and changes nothing", async ({ app }) => {
  const { page } = app;
  const broker = await openUnlocked(app, { settingRequests: [REQUEST] });
  await openSettings(app, "Agents");
  await requests(app).getByRole("button", { name: "deny the request to change app.autoLockMins" }).click();
  await expect(notice(app, "Denied. Nothing was changed.")).toBeVisible();
  expect((await broker.calls("settings_request_decide")).map((c) => c.args)).toEqual([{ request: "srq-1", approve: false }]);
  expect(await broker.calls("session_confirm")).toEqual([]);
  await expect(confirmDialog(app)).toHaveCount(0);
  await expect(requests(app)).toHaveCount(0);
  expect(((await broker.state()) as any).settings).toEqual({});
  await openSettings(app, "Security");
  await expect(page.getByLabel("auto-lock after")).toHaveValue("15");
});

test("with no requests the list is not shown", async ({ app }) => {
  await openUnlocked(app);
  await openSettings(app, "Agents");
  await expect(app.screen("S21 Agents")).toBeVisible();
  await expect(requests(app)).toHaveCount(0);
});

// Visual check of 2026-11-09 (RELEASE_VERIFICATION §16a): a long reason was cut at 300 characters, and the notice
// announcing requests covered the list (and its Deny button) in a narrow window.
test("a long reason is shown whole and a long folder wraps inside the row", async ({ app }) => {
  const reason = ("The user asked me to stop being prompted so often during the migration; an hour is fine for today. ").repeat(4).trim();
  const cwd = "/srv/work/clients/acme-holdings/projects/an-unusually-long-project-folder-name/services/payments-gateway/infrastructure/terraform";
  await openUnlocked(app, { settingRequests: [{ ...REQUEST, reason, cwd }] });
  await openSettings(app, "Agents");
  const row = requests(app).locator('[data-setting-request="srq-1"]');
  await expect(row).toContainText(reason.slice(-60));
  await expect(row).not.toContainText("…");
  // Nothing spills out of the row: every line fits its width.
  const overflow = await row.evaluate((el) => [...el.querySelectorAll("div,span")].some((d) => (d as HTMLElement).scrollWidth > (d as HTMLElement).clientWidth + 1));
  expect(overflow).toBe(false);
});

test("in a narrow window the requests notice never covers the list: opening Agents clears it, and none is raised there", async ({ app }) => {
  const { page } = app;
  await page.setViewportSize({ width: 640, height: 480 });
  const broker = await openUnlocked(app, { settingRequests: [REQUEST] });
  await expect(notice(app, "An agent asks to change app.autoLockMins from 15 to 60")).toBeVisible();
  await openSettings(app, "Agents");
  await expect(requests(app)).toBeVisible();
  await expect(page.locator("text=Approve or deny it in Settings, under Agents.")).toHaveCount(0);
  // A new request that arrives while the list is open is listed, not announced over it.
  const now = Math.floor(Date.now() / 1000);
  const first = ((await broker.state()) as any).settingRequests[0];
  await broker.set({ settingRequests: [first, { request: "srq-2", id: "app.revealWindowSecs", node: null, from: 20, to: 60, reason: "a second ask", cwd: "/work/fixture-project", requestedAt: now, expiresAt: now + 600, decided: null, changeId: null }] });
  await page.evaluate(() => (window as any).__cm.pollSettingRequests());
  await expect(requests(app).locator('[data-setting-request="srq-2"]')).toBeVisible();
  await expect(page.locator("text=Approve or deny it in Settings, under Agents.")).toHaveCount(0);
  const deny = requests(app).locator('[data-setting-request="srq-2"]').getByRole("button", { name: /^deny/ });
  await deny.scrollIntoViewIfNeeded();
  await expect(deny).toBeInViewport();
});
