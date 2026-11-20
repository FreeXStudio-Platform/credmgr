/**
 * ADR-111 (issue #40) over the real broker: a field that could be a 2FA seed but is typed as text is named in the window, and one click
 * types it `totp-seed`.  Both halves are checked at the vault by the independent oracle client, not only on screen: the broker's own
 * heuristic decides what is flagged (the page has none), and the typed field is a seed in the vault afterwards.
 */
import { expect, test, type RealApp } from "./harness";
import { addEntry, createVaultViaWizard, KDF, notice, openEntry, railRow, selectNode } from "./helpers";

/** The well-known RFC example secret, lower-cased: a plain run the app's own inference does not call a seed, which the broker's hint does. */
const LOWER = "jbswy3dpehpk3pxp";

async function vaultWith(app: RealApp, project: string): Promise<void> {
  await app.open();
  await createVaultViaWizard(app);
  await app.page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await app.page.getByLabel("project name 1").fill(project);
  await app.page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
  await expect(railRow(app, project)).toBeVisible();
}

test("a saved field that could be a 2FA seed is named, one click types it totp-seed, and the vault agrees", async ({ app }) => {
  test.setTimeout(180_000);
  const { page } = app;
  await vaultWith(app, "Atlas");
  await addEntry(app, "Atlas", { name: "exchange", label: "backup", value: LOWER }, "Saved 1 entry to");

  // the broker said so in its answer to the create, and the window says it without naming the field
  await expect(notice(app, "could be a 2FA seed")).toBeVisible();
  await expect(notice(app)).not.toContainText("backup");

  // the entry is open with the warning on the field it names, from entry.get's `possibleSeed`
  await expect(app.screen("S5 Entry detail")).toBeVisible();
  const hint = page.locator('[data-seed-hint="true"]');
  await expect(hint).toHaveCount(1);
  await expect(hint).toContainText("“backup” could be a 2FA seed");
  await app.oracle.login();
  const before = (await app.oracle.entryMeta("atlas", "exchange")).fields;
  expect(before).toHaveLength(1);
  expect(before[0]).toMatchObject({ label: "backup", type: "text", possibleSeed: true });

  await hint.getByRole("button", { name: "This is a 2FA seed" }).click();
  await expect(notice(app, "Typed as a 2FA seed in “exchange”.")).toBeVisible();
  const update = app.frames("field.update").at(-1)!;
  expect(update.params).toMatchObject({ node: "atlas", field: before[0].id, patch: { type: "totp-seed" } });
  expect(Object.keys(update.params.patch)).toEqual(["type"]);

  // the vault holds a seed now, the hint is gone, and the window never shows it
  const after = (await app.oracle.entryMeta("atlas", "exchange")).fields;
  expect(after[0]).toMatchObject({ label: "backup", type: "totp-seed", typeOverridden: true, masked: true });
  expect(after[0].possibleSeed).toBeUndefined();
  await expect(hint).toHaveCount(0);
  await expect(page.locator('[data-field-type="true"]')).toHaveText("totp-seed");
  expect(await app.pageDump(), "the seed is nowhere on the page").not.toContain(LOWER);

  // reopening the entry from the list asks the broker again and finds nothing to say
  await selectNode(app, "Atlas");
  await openEntry(app, "exchange");
  await expect(page.locator('[data-seed-hint="true"]')).toHaveCount(0);
});
