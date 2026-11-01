/**
 * Helpers shared by the work-package-C specs (writes): what a user does to reach the dialogs, and what they see afterwards.
 * Everything is found by role, label or visible text, so a restyle of the screens does not break the specs.
 */
import { FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import { expect, type App, type Locator } from "./harness";

/** The global notice (`this.notify`). */
export const notice = (app: App): Locator => app.page.locator("[data-notice]");

/** Select a node in the rail. */
export async function selectNode(app: App, label: string): Promise<void> {
  await app.page.locator(".cm-rail .k-tree-row", { hasText: label }).first().click();
}

/** Select `node`, press "+ New entry" (or "+ New note") in the inspector, and wait for the dialog. */
export async function openAddEntry(app: App, node: string, note = false): Promise<Locator> {
  await selectNode(app, node);
  await app.page.getByRole("button", { name: note ? "+ New note" : "+ New entry" }).first().click();
  const dlg = app.screen("S6 Add entry");
  await expect(dlg).toBeVisible();
  await dialogFocusSettled(dlg.getByLabel("entry location (node)"));
  return dlg;
}

/**
 * The design moves focus to a dialog's FIRST control 30 ms after it opens (core.js focusModalFirst; for S6 that is the "where"
 * select).  A person cannot type inside that window, but Playwright's `fill` can: it focuses the field, focus then moves, and the
 * text goes nowhere (measured: no `input` event at all, in about one run in twenty under load).  Wait for the move to have
 * happened before touching the form; the app is unchanged, since a person never meets the race.
 */
export async function dialogFocusSettled(firstControl: Locator): Promise<void> {
  await expect(firstControl).toBeFocused();
}

/** Fill the single-entry form. */
export async function fillSingle(dlg: Locator, f: { name: string; value: string; label?: string }): Promise<void> {
  await dlg.getByLabel("entry name").fill(f.name);
  if (f.label !== undefined) await dlg.getByLabel("label (optional)").fill(f.label);
  await dlg.getByLabel("value", { exact: true }).fill(f.value);
}

/** Press "+ Add field" in the single-entry form: another label + value row (rows are numbered from 1). */
export async function addRow(dlg: Locator): Promise<void> {
  await dlg.getByRole("button", { name: "+ Add field" }).click();
}

/** Fill row `n` (from 1) of the single-entry form.  Row 1 keeps the names the form always had; later rows say which field they are. */
export async function fillRow(dlg: Locator, n: number, f: { label: string; value: string }): Promise<void> {
  await dlg.getByLabel(n === 1 ? "label (optional)" : `label of field ${n}`, { exact: true }).fill(f.label);
  await dlg.getByLabel(n === 1 ? "value" : `value of field ${n}`, { exact: true }).fill(f.value);
}

/** The preview's rows (one per field) of the open add-entry dialog. */
export const previewRows = (dlg: Locator): Locator => dlg.locator('[data-preview-row="true"]');

/** Switch the open add-entry dialog to Bulk and type a paste. */
export async function fillBulk(dlg: Locator, text: string): Promise<void> {
  await dlg.getByRole("radio", { name: "Bulk" }).check();
  await dlg.getByLabel("bulk paste").fill(text);
}

/** Open Settings and its Nodes section (pro mode: the app's default). */
export async function openSettingsNodes(app: App): Promise<Locator> {
  await app.page.getByRole("button", { name: "settings", exact: true }).click();
  const settings = app.screen("S12 Settings");
  await expect(settings).toBeVisible();
  await settings.getByRole("button", { name: "Nodes", exact: true }).click();
  return settings;
}

/** Open the new-project dialog from Settings, which is where a node is added in normal use. */
export async function openAddNode(app: App): Promise<Locator> {
  const settings = await openSettingsNodes(app);
  await settings.getByRole("button", { name: "+ New project" }).click();
  const dlg = app.screen("S8 Add node");
  await expect(dlg).toBeVisible(); // opened over Settings: something was already open, so the design schedules no focus move
  return dlg;
}

/** Lock from the vault menu, then unlock again with the passphrase (no second factor in these fixtures). */
export async function lockAndUnlock(app: App): Promise<void> {
  const { page } = app;
  await page.getByRole("button", { name: "vault menu" }).click();
  await page.locator(".cm-vaultmenu button", { hasText: "Lock vault" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await page.locator('input[type="password"]').fill(FIXTURE_PASSPHRASE);
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible();
}

/** What the logic holds in its state, as text (to prove a typed value is gone from it). */
export function stateJson(app: App): Promise<string> {
  return app.page.evaluate(() => JSON.stringify((window as any).__cm.state));
}

/** An entry the fixture broker can be given behind the UI's back (a write by another process). */
export function foreignEntry(id: string, name: string) {
  return { id, name, type: "other", sensitivity: "low", value: "fixture-value-" + name, modified: 1760000000, rotatedAt: null, expiresAt: null };
}
