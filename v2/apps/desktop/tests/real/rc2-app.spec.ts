/**
 * rc.2 §1 against the real vault: the controls the app gained for operations the broker already had.
 *
 *   item 1  Rotate…, Remove… and Undo-remove on an entry: checked at the vault by the oracle (an independent login), never only on screen.
 *   item 2  Restore from a backup (ADR-166): the real `credmgr restore --json` refuses while the real broker answers on the vault's socket,
 *           and writes nothing.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";

import { expect, fixtureSecret, test, type RealApp } from "./harness";
import { addEntry, createVaultViaWizard, KDF, MASKED_LABEL, notice, openEntry, openSettings, railRow } from "./helpers";

async function vaultWith(app: RealApp, project: string): Promise<void> {
  await app.open();
  await createVaultViaWizard(app);
  await app.page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await app.page.getByLabel("project name 1").fill(project);
  await app.page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
  await expect(railRow(app, project)).toBeVisible();
}

test("rotate keeps the old value for Undo, remove takes the entry out of the vault, and Undo in the list brings it back", async ({ app }) => {
  const { page } = app;
  const first = fixtureSecret("first-value");
  const second = fixtureSecret("rotated-value");
  await vaultWith(app, "Atlas");
  await addEntry(app, "Atlas", { name: "stripe-live", label: MASKED_LABEL, value: first });
  await openEntry(app, "stripe-live");

  // Rotate: one entry.rotate with the field id and the new value; the vault now holds the new value
  await page.locator(".cm-rotate-btn").click();
  const rot = app.screen("S5g Rotate");
  await rot.getByLabel("new value").fill(second);
  await rot.getByRole("button", { name: "Rotate", exact: true }).click();
  await expect(notice(app, "rotated. The previous value is kept as history")).toBeVisible();
  const [frame] = app.frames("entry.rotate");
  expect(frame.params).toMatchObject({ node: "atlas", value: second });
  expect(typeof frame.params.field).toBe("string");
  await app.oracle.login();
  expect((await app.oracle.entries("atlas"))["stripe-live"]).toBe(second);

  // Undo puts the old value back (entry.undo with the rotation's own audit id)
  await page.locator(".cm-undo-btn").click();
  await expect.poll(() => app.frames("entry.undo").length).toBe(1);
  await expect(page.getByText("(undone rotate)")).toBeVisible(); // said once the entry was read again, at the node's new generation
  await expect.poll(async () => (await app.oracle.entries("atlas"))["stripe-live"]).toBe(first);

  // Remove: asked first, then the entry is out of the vault
  await page.locator(".cm-remove-btn").click();
  await app.screen("S5h Remove entry").getByRole("button", { name: "Remove entry" }).click();
  await expect(notice(app, "“stripe-live” removed.")).toBeVisible(KDF); // the broker re-derives the root key to archive it: memory-hard
  expect(app.frames("entry.remove")).toHaveLength(1);
  expect(Object.keys(await app.oracle.entries("atlas"))).not.toContain("stripe-live");

  // Undo in the list: entry.restore by node and entry id; the entry and its value are back
  await page.locator('[data-removed-bar="true"]').getByRole("button", { name: "Undo" }).click();
  await expect(notice(app, "“stripe-live” is back.")).toBeVisible(KDF); // and again to open the archive
  expect(app.frames("entry.restore")).toHaveLength(1);
  expect((await app.oracle.entries("atlas"))["stripe-live"]).toBe(first);
  const dump = await app.pageDump();
  expect(dump).not.toContain(second);
});

test("a restore from the app is refused by the real credmgr while the real broker runs, and nothing is written", async ({ app }) => {
  const { page } = app;
  const backupPhrase = fixtureSecret("backup-phrase");
  await vaultWith(app, "Atlas");
  await openSettings(app, "Backup");
  await page.getByRole("button", { name: "Back up now" }).click();
  const prompt = app.screen("Passphrase prompt");
  await prompt.getByLabel("backup passphrase", { exact: true }).fill(backupPhrase);
  await prompt.getByLabel("repeat the passphrase").fill(backupPhrase);
  await prompt.getByRole("button", { name: "Back up", exact: true }).click();
  await expect(prompt).toHaveCount(0, KDF);
  const archive = (await app.answerOf("maintenance_backup")).result.path as string;
  expect(existsSync(archive)).toBe(true);

  const target = join(app.daemon.root, "restored");
  await page.locator(".cm-settings .cm-restore-btn").click();
  const dlg = app.screen("S12b Restore");
  await dlg.getByLabel("backup archive file").fill(archive);
  await dlg.getByLabel("folder to restore into").fill(target);
  await dlg.getByLabel("backup passphrase").fill(backupPhrase);
  await dlg.getByRole("button", { name: "Restore", exact: true }).click();
  await expect(dlg.getByRole("alert")).toContainText("never runs beside it", KDF);
  expect(existsSync(target)).toBe(false);
  await dlg.getByRole("button", { name: "Cancel" }).click(); // closing the dialog drops the typed passphrase
  await expect(dlg).toHaveCount(0);
  expect(await app.pageDump()).not.toContain(backupPhrase);
});

test("find by reference, Find in this node and the audit report answer from the real broker, and never carry a value", async ({ app }) => {
  const { page } = app;
  const value = fixtureSecret("found-value");
  await vaultWith(app, "Atlas");
  await addEntry(app, "Atlas", { name: "stripe-live", label: MASKED_LABEL, value });
  await app.oracle.login();
  const meta = await app.oracle.entryMeta("atlas", "stripe-live");
  expect(typeof meta.ref).toBe("number");

  // the reference, typed into the search box, opens the entry it names
  await page.getByLabel("search entries").fill(`#${meta.ref}`);
  const row = page.getByRole("button", { name: /stripe-live/ }).first();
  await expect(row).toContainText(`#${meta.ref} · Atlas`);
  expect(app.frames("entry.get_by_ref").map((f) => f.params)).toEqual([{ reference: meta.ref }]);
  await row.click();
  await expect(app.screen("S5 Entry detail")).toContainText("stripe-live");
  await page.getByRole("button", { name: "← Atlas" }).click();

  // Find in this node: entry.search on the selected node
  await page.getByLabel("find in this node").fill("stripe");
  await expect(page.locator('[data-nodefind-results="true"] button', { hasText: "stripe-live" })).toBeVisible();
  expect(app.frames("entry.search").map((f) => f.params)).toEqual([{ node: "atlas", term: "stripe" }]);

  // the audit report of the last 24 hours: the real broker's counts
  await openSettings(app, "Audit report");
  const screen = app.screen("S13b Audit report");
  await screen.getByLabel("report range").selectOption("1");
  await screen.getByRole("button", { name: "Make report" }).click();
  const report = screen.locator('[data-audit-report="true"]');
  await expect(report).toContainText("entry.create");
  // The chain line is there. (Whether it verified depends on the moment: the broker verifies the month's tip while the app's own calls
  // may still be appending records, and a tip one record behind reads as unverified. That is the broker's, recorded in the rc.2 report.)
  await expect(report).toContainText("hash chain");
  expect(app.frames("audit.report")).toHaveLength(1);
  const dump = await app.pageDump();
  expect(dump).not.toContain(value);
});
