/**
 * ADR-169: Tidy up › Apply all moves (vault_doctor_apply).
 *
 * The confirm lists every move before anything is sent; Apply sends exactly the report's move proposals (entry, from, to, the generation the
 * scan read) in one bridge call; Cancel sends nothing; afterwards the scan runs again and the entry is in its new project.  No value is shown.
 */
import { expect, test } from "./harness";
import { openWithExtra } from "./field-ui-helpers";
import { notice } from "./wp-c-util";
import { openSettings } from "./wp-d-helpers";

const HOOK = { id: "e-g2", name: "atlas-hook", type: "api", sensitivity: "low", value: "fixture-value-atlas-hook-e2e", modified: 1760000000, rotatedAt: null, expiresAt: null };

test("Apply all moves lists each move, sends nothing until Apply, then sends the plan the scan showed", async ({ app }) => {
  const broker = await openWithExtra(app, "global", [HOOK]);
  await openSettings(app, "Maintenance");
  await app.page.getByRole("button", { name: "Tidy up…" }).click();
  const tidy = app.screen("S22 Tidy up");
  await expect(tidy).toBeVisible();
  await expect(tidy.locator('[data-tidy-summary="true"]')).toBeVisible();

  const scans = await broker.calls("vault_doctor_scan");
  expect(scans.length).toBe(1);
  const applyAll = tidy.locator('[data-tidy-apply-all="1"]');
  await expect(applyAll).toBeVisible();
  const label = (await applyAll.textContent()) || "";
  const n = Number((label.match(/\((\d+)\)/) || [])[1]);
  expect(n).toBeGreaterThan(0);

  // Cancel sends nothing.
  await applyAll.click();
  const confirm = tidy.locator('[data-tidy-apply-confirm="1"]');
  await expect(confirm).toBeVisible();
  await expect(confirm.locator('[data-tidy-apply-row="1"]')).toHaveCount(n);
  await expect(confirm).toContainText("atlas-hook: global → atlas");
  await confirm.locator('[data-tidy-apply-cancel="1"]').click();
  await expect(confirm).toHaveCount(0);
  expect(await broker.calls("vault_doctor_apply")).toEqual([]);

  // Apply sends the whole list once, exactly as the scan carried it.
  const genGlobal = (await broker.state()).generation.global || 1;
  await applyAll.click();
  await expect(confirm).toBeVisible();
  await confirm.locator('[data-tidy-apply-go="1"]').click();
  await expect(notice(app)).toContainText(`Moved ${n === 1 ? "1 entry" : `${n} entries`} as planned.`);
  const sent = await broker.calls("vault_doctor_apply");
  expect(sent).toHaveLength(1);
  const moves = (sent[0].args as { moves: { node: string; entry: string; to: string; generation: number }[] }).moves;
  expect(moves).toHaveLength(n);
  expect(moves).toContainEqual({ node: "global", entry: "e-g2", to: "atlas", generation: genGlobal });
  const after = await broker.state();
  expect(after.entries.atlas.map((e: { id: string }) => e.id)).toContain("e-g2");
  expect(after.entries.global.map((e: { id: string }) => e.id)).not.toContain("e-g2");
  // The scan ran again and the confirm is gone; no value reached the page.
  await expect.poll(async () => (await broker.calls("vault_doctor_scan")).length).toBe(2);
  await expect(confirm).toHaveCount(0);
  expect(await app.page.content()).not.toContain(HOOK.value);
});
