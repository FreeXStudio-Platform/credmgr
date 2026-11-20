/**
 * ADR-111 (issue #40) in the window: a field that could be a 2FA seed but is not typed as one is NAMED to its owner, with one click that
 * types it `totp-seed` through the ordinary `field_update` path.
 *
 * What is asserted: where the hint comes from (`entry_get`'s `possibleSeed` on the field row, and `possibleSeedFields` in a write's answer),
 * what the screen says (the field's own label in the entry view; never in a notice), the exact command the click sends (`type` only), what
 * the screen shows after (no hint, type `totp-seed`, the seed is never shown), and that a field its owner already typed is never flagged.
 */
import { expect, test } from "./harness";
import { fieldRow, multi, openEntryOf, openWithExtra } from "./field-ui-helpers";
import { addRow, fillRow, notice, openAddEntry } from "./wp-c-util";

/** The shapes the issue names: a plain lower-case run, and a padded one. Neither is a seed to the app's own inference. */
const LOWER = "jbswy3dpehpk3pxp";
const PADDED = "JBSWY3DPEHPK3PXP====";

const SEEDY = multi("e-s1", "bank", [
  { id: "f_00d10001", label: "username", value: "fixture-value-bank-user" },
  { id: "f_00d10002", label: "backup", value: LOWER },
  { id: "f_00d10003", label: "recovery", value: PADDED },
  { id: "f_00d10004", label: "typed", value: "kfzxw5dpehpk3pxq", typePin: "text" }, // the owner answered: it is text, on purpose
]);

const hint = (app: Parameters<typeof fieldRow>[0], id: string) => fieldRow(app, id).locator('[data-seed-hint="true"]');

test("the entry view names each field the broker flagged, and only those", async ({ app }) => {
  const broker = await openWithExtra(app, "atlas", [SEEDY]);
  await openEntryOf(app, "atlas", "bank");

  // the flag is the broker's, read from entry_get; the page keeps no heuristic of its own
  expect((await broker.calls("entry_get"))[0].args).toEqual({ node: "atlas", entry: "e-s1" });
  await expect(app.page.locator('[data-seed-hint="true"]')).toHaveCount(2);
  await expect(hint(app, "f_00d10002")).toContainText("“backup” could be a 2FA seed");
  await expect(hint(app, "f_00d10003")).toContainText("“recovery” could be a 2FA seed");
  await expect(hint(app, "f_00d10001")).toHaveCount(0);
  await expect(hint(app, "f_00d10004")).toHaveCount(0); // typed by its owner (to text): answered
  await expect(hint(app, "f_00d10002").getByRole("button", { name: "This is a 2FA seed" })).toBeVisible();
});

test("one click types the field as a 2FA seed with exactly one field_update, then the hint is gone and the seed is never shown", async ({ app }) => {
  const { page } = app;
  const broker = await openWithExtra(app, "atlas", [SEEDY]);
  await openEntryOf(app, "atlas", "bank");

  await hint(app, "f_00d10002").getByRole("button", { name: "This is a 2FA seed" }).click();
  await expect(notice(app)).toContainText("Typed as a 2FA seed in “bank”.");
  await expect(notice(app)).not.toContainText("backup"); // a notice never names a label

  // the exact command: the one key, through the ordinary field-update path
  const calls = await broker.calls("field_update");
  expect(calls).toHaveLength(1);
  expect(calls[0].args).toMatchObject({ node: "atlas", entry: "e-s1", field: "f_00d10002", patch: { type: "totp-seed" } });
  expect(Object.keys((calls[0].args as { patch: object }).patch)).toEqual(["type"]);

  // re-read: that field is a seed now (shows a code, never the seed), the other flagged one still asks
  await expect(fieldRow(app, "f_00d10002").locator('[data-field-type="true"]')).toHaveText("totp-seed");
  await expect(hint(app, "f_00d10002")).toHaveCount(0);
  await expect(hint(app, "f_00d10003")).toBeVisible();
  await expect(fieldRow(app, "f_00d10002").getByRole("button", { name: "show seed" })).toBeVisible();
  expect(await page.content()).not.toContain(LOWER);
  expect(await app.viewJson()).not.toContain(LOWER);

  // the change is undoable like any field change
  await expect(page.getByRole("button", { name: /^Undo/ })).toBeVisible();
});

test("a refused change says so and leaves the hint where it was", async ({ app }) => {
  const broker = await openWithExtra(app, "atlas", [SEEDY]);
  await openEntryOf(app, "atlas", "bank");
  await broker.script("field_update", { error: { code: "conflict" } });
  await hint(app, "f_00d10003").getByRole("button", { name: "This is a 2FA seed" }).click();
  await expect(notice(app)).toBeVisible();
  await expect(fieldRow(app, "f_00d10003").locator('[data-field-type="true"]')).not.toHaveText("totp-seed");
});

test("Add entry: a saved entry whose field could be a seed opens with the warning, and the notice says so without naming the field", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");
  await dlg.getByLabel("entry name").fill("exchange");
  await fillRow(dlg, 1, { label: "login", value: "someone@example.test" });
  await addRow(dlg);
  await fillRow(dlg, 2, { label: "backup", value: LOWER });
  await dlg.getByRole("button", { name: "Save", exact: true }).click();

  // the broker's answer carried the hint
  expect(await broker.calls("entry_create")).toHaveLength(1);
  await expect(notice(app)).toContainText("A field in it could be a 2FA seed: it is open so you can mark it.");
  await expect(notice(app)).not.toContainText("backup");

  // the new entry is open, with the warning on the field it names
  await expect(app.screen("S5 Entry detail")).toContainText("exchange");
  await expect(page.locator('[data-seed-hint="true"]')).toHaveCount(1);
  await expect(page.locator('[data-seed-hint="true"]')).toContainText("“backup” could be a 2FA seed");

  // and the click does the work
  await page.locator('[data-seed-hint="true"]').getByRole("button", { name: "This is a 2FA seed" }).click();
  await expect(page.locator('[data-seed-hint="true"]')).toHaveCount(0);
  expect(await broker.calls("field_update")).toHaveLength(1);
});

test("Add entry: an ordinary entry says nothing about seeds and stays on the list", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");
  await dlg.getByLabel("entry name").fill("plain");
  await fillRow(dlg, 1, { label: "host", value: "plain.example.test" });
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(notice(app)).toContainText("Saved 1 entry to atlas.");
  await expect(notice(app)).not.toContainText("seed");
  await expect(page.locator('[data-seed-hint="true"]')).toHaveCount(0);
  expect(await broker.calls("field_update")).toEqual([]);
});
