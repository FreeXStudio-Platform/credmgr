/**
 * rc.2 §1: the app controls for operations the broker already had and the app did not show.
 *
 *   item 1  Rotate…, Remove… and Undo-remove on an entry (entry_rotate, entry_remove, entry_restore)
 *   item 2  Restore from a backup (backup_restore, the shell's own command; ADR-166)
 *
 * Every test asserts the EXACT bridge command and arguments the app sends and what it renders from the answer.  A typed value is in
 * the DOM of the open dialog only: never in the view, the logic's state after the dialog closes, storage, or a notice.
 */
import { expect, test } from "./harness";
import { openApp, openEntryOf, PG } from "./field-ui-helpers";
import { notice, stateJson } from "./wp-c-util";
import { openSettings } from "./wp-d-helpers";

const NEW_VALUE = "fixture-value-rotated-e2e-41b7";

test.describe("item 1: rotate, remove, undo-remove", () => {
  test("Rotate sends one entry_rotate for the chosen field, offers Undo, and the value is nowhere afterwards", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    const gen = (await broker.state()).generation.atlas || 1; // the fixture starts every node at generation 1
    await app.page.locator(".cm-rotate-btn").click();
    const dlg = app.screen("S5g Rotate");
    await expect(dlg).toBeVisible();
    await expect(dlg.getByLabel("field to rotate")).toHaveValue(PG.password);
    await expect(dlg.getByRole("button", { name: "Rotate", exact: true })).toBeDisabled();
    await dlg.getByLabel("new value").fill(NEW_VALUE);
    await dlg.getByRole("button", { name: "Rotate", exact: true }).click();
    await expect(notice(app)).toContainText("“pg-main” rotated. The previous value is kept as history; Undo puts it back.");
    await expect(dlg).toBeHidden();
    expect(await broker.calls("entry_rotate")).toEqual([
      { cmd: "entry_rotate", args: { node: "atlas", entry: PG.entry, value: NEW_VALUE, generation: gen, field: PG.password } },
    ]);
    await expect(app.page.locator(".cm-undo-btn")).toContainText("Undo rotate");
    expect(await app.viewJson()).not.toContain(NEW_VALUE);
    expect(await stateJson(app)).not.toContain(NEW_VALUE);
    expect(await app.storageDump()).not.toContain(NEW_VALUE);
    expect(await app.page.content()).not.toContain(NEW_VALUE);
  });

  test("Remove asks first, then removes; the list's Undo brings it back with entry_restore", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "stripe-live");
    const gen = (await broker.state()).generation.atlas || 1; // the fixture starts every node at generation 1
    await app.page.locator(".cm-remove-btn").click();
    const dlg = app.screen("S5h Remove entry");
    await expect(dlg).toBeVisible();
    await expect(dlg).toContainText("kept, sealed, for 7 days; Undo brings it back until then");
    expect(await broker.calls("entry_remove")).toEqual([]);
    await dlg.getByRole("button", { name: "Remove entry" }).click();
    await expect(notice(app)).toContainText("“stripe-live” removed.");
    expect(await broker.calls("entry_remove")).toEqual([{ cmd: "entry_remove", args: { node: "atlas", entry: "e-a1", generation: gen } }]);
    await expect(app.page.locator("aside.cm-insp button.k-entry", { hasText: "stripe-live" })).toHaveCount(0);
    const bar = app.page.locator('[data-removed-bar="true"]');
    await expect(bar).toContainText("“stripe-live” was removed. It is kept for 7 days.");
    await bar.getByRole("button", { name: "Undo" }).click();
    await expect(notice(app)).toContainText("“stripe-live” is back.");
    expect(await broker.calls("entry_restore")).toEqual([{ cmd: "entry_restore", args: { node: "atlas", entry: "e-a1", generation: gen + 1 } }]);
    await expect(app.screen("S5 Entry detail")).toBeVisible();
    await expect(bar).toHaveCount(0);
  });
});

const TEST_BACKUP_PASS = "fixture-backup-passphrase";

test.describe("item 2: restore from a backup", () => {
  test("Settings › Backup › Restore… is refused while this window's broker runs, says what to do, and keeps no passphrase", async ({ app }) => {
    const broker = await openApp(app);
    await openSettings(app, "Backup");
    await app.page.locator(".cm-settings .cm-restore-btn").click();
    const dlg = app.screen("S12b Restore");
    await expect(dlg).toBeVisible();
    await expect(dlg.locator('[data-restore-live="true"]')).toContainText("connected to a running broker");
    await dlg.getByLabel("backup archive file").fill("/fixture/backups/a.enc");
    await dlg.getByLabel("backup passphrase").fill(TEST_BACKUP_PASS);
    await dlg.getByRole("button", { name: "Restore", exact: true }).click();
    await expect(dlg.getByRole("alert")).toContainText("never runs beside it. Quit CredMgr");
    expect(await broker.calls("backup_restore")).toEqual([{ cmd: "backup_restore", args: { archive: "/fixture/backups/a.enc", passphrase: TEST_BACKUP_PASS } }]);
    await dlg.getByRole("button", { name: "Cancel" }).click();
    await expect(dlg).toBeHidden();
    expect(await stateJson(app)).not.toContain(TEST_BACKUP_PASS);
    expect(await app.storageDump()).not.toContain(TEST_BACKUP_PASS);
  });

  test("on the broker-unreachable screen the restore goes through and says what was written", async ({ app }) => {
    const broker = (await app.open({ broker: { unreachable: true } }))!;
    await expect(app.screen("S16 Broker unreachable")).toBeVisible();
    await app.page.getByRole("button", { name: "Restore from a backup…" }).click();
    const dlg = app.screen("S12b Restore");
    await expect(dlg).toBeVisible();
    await expect(dlg.locator('[data-restore-live="true"]')).toHaveCount(0);
    await dlg.getByLabel("backup archive file").fill("/fixture/backups/a.enc");
    await dlg.getByLabel("folder to restore into").fill("/fixture/new");
    await dlg.getByLabel("backup passphrase").fill(TEST_BACKUP_PASS);
    await dlg.getByRole("button", { name: "Restore", exact: true }).click();
    await expect(dlg.locator('[data-restore-done="true"]')).toContainText("12 files restored into /fixture/new.");
    expect(await broker.calls("backup_restore")).toEqual([
      { cmd: "backup_restore", args: { archive: "/fixture/backups/a.enc", passphrase: TEST_BACKUP_PASS, target: "/fixture/new" } },
    ]);
    expect(await stateJson(app)).not.toContain(TEST_BACKUP_PASS);
    await dlg.getByRole("button", { name: "Close" }).click();
    await expect(app.screen("S16 Broker unreachable")).toBeVisible();
  });
});

test.describe("item 3: find by reference, node search, the audit report", () => {
  test("typing #2 in the search box looks the reference up and opens that entry", async ({ app }) => {
    const broker = await openApp(app);
    const box = app.page.getByLabel("search entries");
    await box.fill("#2");
    const row = app.page.getByRole("button", { name: /stripe-live/ }).first();
    await expect(row).toContainText("#2 · atlas");
    expect(await broker.calls("entry_get_by_ref")).toEqual([{ cmd: "entry_get_by_ref", args: { reference: 2 } }]);
    await row.click();
    await expect(app.screen("S5 Entry detail")).toContainText("stripe-live");
  });

  test("the rail's filter narrows the nodes with no broker call, and Find in this node asks entry.search", async ({ app }) => {
    const broker = await openApp(app);
    const before = (await broker.calls()).length;
    await app.page.getByLabel("filter nodes by name").fill("stag");
    const rows = app.page.locator(".cm-rail .k-tree-row");
    await expect(rows).toHaveCount(2); // the project it belongs to, and the matching sub-node
    await expect(rows.nth(1)).toContainText("staging");
    expect((await broker.calls()).length).toBe(before);
    await app.page.getByLabel("clear the node filter").click();
    await rows.filter({ hasText: "atlas" }).first().click();
    await app.page.getByLabel("find in this node").fill("deploy");
    const hit = app.page.locator('[data-nodefind-results="true"] button', { hasText: "deploy-otp" });
    await expect(hit).toBeVisible();
    expect(await broker.calls("entry_search")).toEqual([{ cmd: "entry_search", args: { node: "atlas", term: "deploy" } }]);
    await hit.click();
    await expect(app.screen("S5 Entry detail")).toContainText("deploy-otp");
  });

  test("Settings › Audit report sends the range and the node, and lists actions, sessions and refusals", async ({ app }) => {
    const broker = await openApp(app);
    await app.page.evaluate(() => {
      const S = (window as any).__brokerFixture.S;
      S.audit.push({ id: "aud-r1", timestamp: Math.floor(Date.now() / 1000) - 60, actor: "ses_fixture_agent", action: "entry.reveal", node: "atlas", entry: "e-a1", decision: "deny" });
    });
    await openSettings(app, "Audit report");
    const screen = app.screen("S13b Audit report");
    await expect(screen).toBeVisible();
    await screen.getByLabel("report range").selectOption("7");
    await screen.getByLabel("report node").selectOption("atlas");
    await screen.getByRole("button", { name: "Make report" }).click();
    const report = screen.locator('[data-audit-report="true"]');
    await expect(report).toContainText("atlas only");
    await expect(report).toContainText("ses_fixture_agent");
    await expect(report).toContainText("node_access_denied");
    const [call] = await broker.calls("audit_report");
    expect(call.args.node).toBe("atlas");
    expect((call.args.to as number) - (call.args.from as number)).toBe(7 * 86400 + 1);
  });
});
