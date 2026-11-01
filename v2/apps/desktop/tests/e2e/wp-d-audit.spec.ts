/**
 * Settings -> Audit: the audit trail as the broker serves it.
 *
 * Asserts audit.tail's exact arguments, the rows rendered (newest first, node and entry ids shown as their names, the
 * redacted agent shape without its missing fields), that a session token never reaches the page whatever the record holds,
 * that opening a record is audit.get and its presence_required is shown honestly, and the failure paths.
 */
import { expect, test, type App } from "./harness";
import { everything, notice, openSettings } from "./wp-d-helpers";

const BEARER_A = "cmt_0123456789abcdef0123456789abcdef";
const BEARER_B = "cmt_deadbeefcafebabe00112233445566ff";
const ROW = '[data-audit-row="true"]';

async function open(app: App) {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const now = Math.floor(Date.now() / 1000);
  // oldest first: the broker answers newest first
  await broker.set({
    audit: [
      { id: "a_4", timestamp: now - 240, actor: "Agent", action: "audit.tail" }, // the redacted agent shape: four fields only
      { id: "a_3", timestamp: now - 180, actor: `HumanUi:${BEARER_A}`, action: "vault.unlock", node: null, entry: null, decision: "allow", detail: `bearer ${BEARER_B} was used`, generation: null },
      { id: "a_2", timestamp: now - 120, actor: "Agent", action: "entry.reveal", node: "beacon", entry: "e-b1", decision: "deny", detail: "capability_not_held", generation: null },
      { id: "a_1", timestamp: now - 60, actor: "HumanUi:s_0123456789abcdef", action: "entry.reveal", node: "atlas", entry: "e-a1", decision: "allow", detail: null, generation: null },
    ],
  });
  return broker;
}

test("Audit lists the trail newest first: names for ids, the origin of the actor, and no field the broker did not send", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Audit");

  const rows = page.locator(ROW);
  await expect(rows).toHaveCount(4);
  expect(await broker.calls("audit_tail")).toEqual([{ cmd: "audit_tail", args: { limit: 50 } }]);
  await expect(page.getByText("4 records, newest first")).toBeVisible();

  // newest first, with the node's label and the entry's name instead of their ids
  await expect(rows.nth(0)).toContainText("entry.reveal");
  await expect(rows.nth(0)).toContainText("atlas · stripe-live");
  await expect(rows.nth(0)).toContainText("app");
  await expect(rows.nth(1)).toContainText("beacon · registry-token");
  await expect(rows.nth(1)).toContainText("agent");
  await expect(rows.nth(2)).toContainText("vault.unlock");
  await expect(rows.nth(3)).toContainText("audit.tail");
  await expect(rows.nth(3)).toContainText("—"); // the agent shape carries no node: nothing is invented
  // the time column is a local MM-DD HH:MM:SS
  await expect(rows.nth(0).locator("span").first()).toHaveText(/^\d\d-\d\d \d\d:\d\d:\d\d$/);
});

test("a session token in a record never reaches the page, the storage or the state", async ({ app }) => {
  const { page } = app;
  await open(app);
  await openSettings(app, "Audit");
  await expect(page.locator(ROW)).toHaveCount(4);
  const all = await everything(app);
  expect(all).not.toContain(BEARER_A);
  expect(all).not.toContain(BEARER_B);
  expect(all).not.toMatch(/cmt_[0-9a-f]{8}/i);
  // the actor of that record is still shown, with the token replaced
  await expect(page.locator(`${ROW} span[title*="[redacted-token]"]`)).toHaveCount(1);
});

test("opening a record is audit.get, and its presence_required is shown honestly", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Audit");
  await page.locator(ROW).first().click();
  await expect(page.getByRole("alert").filter({ hasText: "Needs presence (Touch ID)" })).toContainText("(audit.get)");
  expect(await broker.calls("audit_get")).toEqual([{ cmd: "audit_get", args: { id: "a_1" } }]);
});

test("Refresh reads the trail again and shows what is new", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Audit");
  await expect(page.locator(ROW)).toHaveCount(4);
  await broker.set({ audit: [{ id: "a_9", timestamp: Math.floor(Date.now() / 1000), actor: "HumanUi:s_aaaaaaaaaaaaaaaa", action: "grant.revoke", node: null, entry: null, decision: "allow", detail: null, generation: null }] });
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.locator(ROW)).toHaveCount(1);
  await expect(page.locator(ROW).first()).toContainText("grant.revoke");
  expect(await broker.calls("audit_tail")).toHaveLength(2);
});

test("a trail the broker refuses to serve is said so, with its rule, and no stale rows are kept", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Audit");
  await expect(page.locator(ROW)).toHaveCount(4);
  await broker.script("audit_tail", { error: { code: "capability_not_held", detail: { rule: "list is not held" } } });
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Not permitted (list is not held)." })).toBeVisible();
  await expect(page.getByText("the audit trail could not be read")).toBeVisible();
  // the rows of the last good read are NOT left on screen under "could not be read": they would pass for the trail
  await expect(page.locator(ROW)).toHaveCount(0);
  expect(await page.locator(ROW).count()).toBe(0);
  // and the next successful Refresh brings the trail back
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.locator(ROW)).toHaveCount(4);
  await expect(page.getByText("4 records, newest first")).toBeVisible();
});

test("an empty trail is an empty state, not an error", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await broker.set({ audit: [] });
  await openSettings(app, "Audit");
  await expect(page.getByText("The audit trail is empty.")).toBeVisible();
  await expect(notice(app)).toHaveCount(0);
});

test("in a browser with no broker the Audit section says it needs the app", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: false });
  await expect(app.screen("S1 Main")).toBeVisible();
  await openSettings(app, "Audit");
  await expect(page.getByText("the audit trail needs the CredMgr app")).toBeVisible();
});
