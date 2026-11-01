/**
 * The edges of a session: what a lock does to things still in flight, and what it says when the broker could not confirm it.
 *
 *  - A value the broker is still answering for when the user locks, hides the field or moves to another node must never land
 *    in memory or on the page: the screen it was for is gone.
 *  - A lock the broker could not confirm still ends on the Lock screen with nothing left behind, and says so.  "This window
 *    is locked" and "the broker locked the vault" are different claims, and only the first is certain.
 */
import { expect, test, type App } from "./harness";
import { entryOpened } from "./wp-b-helpers";

const VALUE = "fixture-value-stripe-live";

async function openFirstEntry(app: App, node: string) {
  await app.page.locator(".cm-rail .k-tree-row", { hasText: node }).first().click();
  await app.page.locator("aside.cm-insp button.k-entry").first().click();
  await entryOpened(app);
}

async function lockFromMenu(app: App) {
  await app.page.getByRole("button", { name: "vault menu" }).click();
  await app.page.locator(".cm-vaultmenu button", { hasText: "Lock vault" }).click();
}

test("a reveal still in flight when the user locks never lands: not in the model, not on the page", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await openFirstEntry(app, "atlas");

  await broker.script("entry_reveal", { delayMs: 500 }); // the broker is slow to answer; the real handler then answers
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect.poll(async () => (await broker.calls("entry_reveal")).length).toBe(1);

  await lockFromMenu(app);
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await page.waitForTimeout(900); // well after the answer has arrived
  expect(await app.secretCount()).toBe(0);
  expect(await page.content()).not.toContain(VALUE);
  expect(await app.storageDump()).not.toContain(VALUE);
  expect(await broker.calls("vault_lock")).toEqual([{ cmd: "vault_lock", args: {} }]);
  // the menu's lock locked the BROKER and emptied the MODEL: no names, no notes, no grants are left behind the Lock screen
  expect((await broker.state()).locked).toBe(true);
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  expect(JSON.parse(await app.viewJson()).entries).toEqual({});
});

test("a reveal still in flight when the user moves to another node is dropped on arrival", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await openFirstEntry(app, "atlas");

  await broker.script("entry_reveal", { delayMs: 500 });
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect.poll(async () => (await broker.calls("entry_reveal")).length).toBe(1);

  await page.locator(".cm-rail .k-tree-row", { hasText: "beacon" }).first().click(); // a revealed value does not follow the user
  await page.waitForTimeout(900);
  expect(await app.secretCount()).toBe(0);
  expect(await page.content()).not.toContain(VALUE);
  await expect(app.screen("S1 Main")).toBeVisible(); // still logged in: only the value was dropped
});

test("a reveal the model dropped (the user left the node and came back) is not shown as revealed when the same entry is open again", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await openFirstEntry(app, "atlas");

  await broker.script("entry_reveal", { delayMs: 800 });
  await page.getByRole("button", { name: "reveal", exact: true }).click({ noWaitAfter: true });
  await expect.poll(async () => (await broker.calls("entry_reveal")).length).toBe(1);
  // leave the node (the model cancels the request) and come back to the very same entry before the broker has answered
  await page.locator(".cm-rail .k-tree-row", { hasText: "beacon" }).first().click();
  await openFirstEntry(app, "atlas");
  await page.waitForTimeout(1300); // the answer to the cancelled request has arrived by now
  expect(await app.secretCount()).toBe(0); // the model dropped it
  // and the screen agrees with the model: still masked, offering "reveal", no countdown claiming otherwise
  await expect(page.locator(".k-field-value")).toHaveText("••••••••••••");
  await expect(page.getByRole("button", { name: "reveal", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "hide", exact: true })).toHaveCount(0);
  expect(await page.content()).not.toContain(VALUE);
});

test("a reveal that finishes while the user is still looking is held, and is gone the moment they lock", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await openFirstEntry(app, "atlas");
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(page.locator(".k-field-value")).toHaveText(VALUE);
  expect(await app.secretCount()).toBe(1);
  await lockFromMenu(app);
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await app.secretCount()).toBe(0);
  expect(await page.content()).not.toContain(VALUE);
  expect((await broker.calls("entry_reveal")).length).toBe(1);
});

test("a lock the broker cannot confirm still ends on the Lock screen, empty, and says the vault may be open", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await openFirstEntry(app, "atlas");
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(page.locator(".k-field-value")).toHaveText(VALUE);

  await broker.script("vault_lock", { error: { code: "broker_unreachable", source: "transport", message: "credmgrd is not running" } });
  await lockFromMenu(app);

  await expect(app.screen("S16 Lock screen")).toBeVisible();
  const notice = page.locator("[data-notice]");
  await expect(notice).toContainText("This window is locked, but the broker could not be reached");
  await expect(notice).toContainText("may stay open");
  expect(await broker.calls("vault_lock")).toEqual([{ cmd: "vault_lock", args: {} }]); // asked once
  // nothing the session held is left, whatever the broker said
  expect(await app.secretCount()).toBe(0);
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  expect(await page.content()).not.toContain(VALUE);
  expect(await page.content()).not.toContain("stripe-live");
});

test("a lock the broker refuses names the code and nothing else", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await broker.script("vault_lock", { error: { code: "internal", message: "stack trace with /private/path and a name" } });
  await lockFromMenu(app);
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  const notice = page.locator("[data-notice]");
  await expect(notice).toContainText("did not confirm that the vault locked (internal)");
  await expect(notice).not.toContainText("stack trace");
  await expect(notice).not.toContainText("/private/path");
});

test("a lock the broker confirms raises no warning", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: { locked: false } });
  await expect(app.screen("S1 Main")).toBeVisible();
  await lockFromMenu(app);
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await page.waitForTimeout(300); // the warning, if there were one, is raised a tick after the screen changes
  await expect(page.locator("[data-notice]")).toHaveCount(0);
});

/** What a Lock screen must not be sitting on top of. */
async function expectNothingOfTheLastSession(app: App) {
  const { page } = app;
  expect(await app.secretCount()).toBe(0);
  expect(await page.evaluate(() => (window as any).__cm.model.plain("atlas", "e-a1", 0))).toBeUndefined(); // a later login cannot copy the old value
  const view = JSON.parse(await app.viewJson());
  expect(view.nodes).toEqual([]);
  expect(view.entries).toEqual({});
  expect(view.grants).toEqual([]);
  expect(await page.content()).not.toContain(VALUE);
  expect(await page.content()).not.toContain("stripe-live"); // names go too
  expect(await app.storageDump()).not.toContain(VALUE);
}

test("a Lock screen reached through the broker-down screen's Retry holds nothing of the previous session", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await openFirstEntry(app, "atlas");
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(page.locator(".k-field-value")).toHaveText(VALUE);

  // the broker goes away and the next question finds out; then it comes back restarted, with the vault locked
  await broker.set({ unreachable: true });
  await page.evaluate(() => (window as any).__cm.checkLiveness());
  await expect(app.screen("S16 Broker unreachable")).toBeVisible();
  await broker.set({ unreachable: false, locked: true, authenticated: false });
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expectNothingOfTheLastSession(app);
});

test("the model itself forgets on that Retry: a broker-down screen that was shown without the model being told changes nothing", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await openFirstEntry(app, "atlas");
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(page.locator(".k-field-value")).toHaveText(VALUE);
  expect(await app.secretCount()).toBe(1);

  // put the broker-down screen over the app WITHOUT clearing the model (any screen change that forgot to), then Retry onto a locked vault
  await page.evaluate(() => (window as any).__cm.setState({ screen: "brokerdown" }));
  await expect(app.screen("S16 Broker unreachable")).toBeVisible();
  expect(await page.evaluate(() => (window as any).__cm.model.status)).toBe("unlocked");
  expect(await app.secretCount()).toBe(1); // still held: nothing has cleared it yet
  await broker.set({ locked: true, authenticated: false });
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expectNothingOfTheLastSession(app);
});
