/**
 * What a person does in the app, as functions, found by role, label or visible text (so a restyle does not break the journeys).
 * These drive the REAL UI; none of them reaches into the page's state or the shim.
 */
import { expect, type Locator, type RealApp } from "./harness";

export const MASK = "••••••••••••";

/**
 * Anything that makes the broker derive a key (create a vault, unlock, back up, rotate) is memory-hard by design: about a second
 * on a quiet machine, several when other builds are running. Waits for those get a generous ceiling; everything else keeps the
 * suite's normal 10 s, so a hang in the UI itself is still caught quickly.
 */
export const KDF = { timeout: 60_000 };

export const passInput = (app: RealApp): Locator => app.page.locator('input[type="password"]');
export const unlockButton = (app: RealApp): Locator => app.page.getByRole("button", { name: "Unlock", exact: true });
export const notice = (app: RealApp, text?: string | RegExp): Locator => (text === undefined ? app.page.locator("[data-notice]") : app.page.locator("[data-notice]").filter({ hasText: text }));
export const railRow = (app: RealApp, label: string | RegExp): Locator => app.page.locator(".cm-rail .k-tree-row", { hasText: label }).first();
export const inspector = (app: RealApp): Locator => app.page.locator("aside.cm-insp");

const next = (app: RealApp, name: string): Locator => app.page.getByRole("button", { name, exact: true });

/** Lock-screen unlock with the test vault's passphrase. */
export async function unlockUi(app: RealApp, passphrase = app.passphrase): Promise<void> {
  await passInput(app).fill(passphrase);
  await unlockButton(app).click();
}

/** Unlock and wait for the main screen (no second factor). */
export async function unlockToMain(app: RealApp, passphrase = app.passphrase): Promise<void> {
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await unlockUi(app, passphrase);
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
}

/** Lock from the header chip. */
export async function lockUi(app: RealApp): Promise<void> {
  await app.page.getByRole("button", { name: "lock the vault" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
}

/**
 * The first-run wizard, steps 1-2: choose a passphrase, retype the recovery code the BROKER made. Leaves the wizard on step 3 with
 * the vault created and open. Returns the root recovery code (read from the page, as a person would copy it).
 */
export async function createVaultViaWizard(app: RealApp): Promise<string> {
  const { page } = app;
  await expect(app.screen("S17 First run")).toBeVisible();
  await page.getByPlaceholder("passphrase", { exact: true }).fill(app.passphrase);
  await page.getByPlaceholder("repeat it").fill(app.passphrase);
  await next(app, "Continue").click();
  await expect(page.getByText("first run · step 2 of 4")).toBeVisible(KDF);
  const code = (await page.locator("[data-recovery-code]").innerText()).trim();
  expect(code, "the broker's recovery code is shown").toMatch(/^[0-9A-F]{4}(-[0-9A-F]{4}){15}$/);
  await page.getByPlaceholder("retype the recovery code").fill(code);
  await page.getByLabel("I have written the recovery code down").check();
  await next(app, "Create vault").click();
  await expect(page.getByText("first run · step 3 of 4")).toBeVisible(KDF);
  return code;
}

/** Wizard steps 3 and 4 skipped: no second factor, no first project. Ends on the main screen. */
export async function finishWizardBare(app: RealApp): Promise<void> {
  await next(app, "Enrol later").click();
  await expect(app.page.getByText("first run · step 4 of 4")).toBeVisible();
  await next(app, "Open the vault").click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
}

export async function selectNode(app: RealApp, label: string | RegExp): Promise<void> {
  await railRow(app, label).click();
}

/**
 * The design moves focus to a dialog's first control 30 ms after it opens; a person cannot type inside that window but
 * Playwright can. Wait for the move before touching the form (the app is unchanged: nobody meets the race).
 */
export async function dialogFocusSettled(first: Locator): Promise<void> {
  await expect(first).toBeFocused();
}

/** Select `node`, press "+ New entry" (or "+ New note"), wait for the dialog. */
export async function openAddEntry(app: RealApp, node: string | RegExp, note = false): Promise<Locator> {
  await selectNode(app, node);
  await app.page.getByRole("button", { name: note ? "+ New note" : "+ New entry" }).first().click();
  const dlg = app.screen("S6 Add entry");
  await expect(dlg).toBeVisible();
  await dialogFocusSettled(dlg.getByLabel("entry location (node)"));
  return dlg;
}

export async function fillSingle(dlg: Locator, f: { name: string; value: string; label?: string }): Promise<void> {
  await dlg.getByLabel("entry name").fill(f.name);
  if (f.label !== undefined) await dlg.getByLabel("label (optional)").fill(f.label);
  await dlg.getByLabel("value", { exact: true }).fill(f.value);
}

/**
 * Bulk mode with `text` pasted. ADR-078: by default the whole paste is ONE entry (named in the "entry name" box) holding every
 * field, in order; `split` ticks "split each /// segment into its own entry", which makes one entry per `///` block, each named
 * from its first label.
 */
export async function fillBulk(dlg: Locator, text: string, options: { split?: boolean } = {}): Promise<void> {
  await dlg.getByRole("radio", { name: "Bulk" }).check();
  await dlg.getByLabel("bulk paste").fill(text);
  if (options.split) await dlg.getByLabel("split each /// segment into its own entry").check();
}

/** Add one entry through the single-entry form; resolves when the broker has taken it. */
export async function addEntry(app: RealApp, node: string | RegExp, f: { name: string; value: string; label?: string }, savedText = "Saved 1 entry to"): Promise<void> {
  const dlg = await openAddEntry(app, node);
  await fillSingle(dlg, f);
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(notice(app, savedText)).toBeVisible();
  await expect(dlg).toBeHidden();
}

/** Open an entry of the selected node's inspector by its name. */
export async function openEntry(app: RealApp, name: string): Promise<void> {
  await inspector(app).locator("button.k-entry", { hasText: name }).first().click();
  await expect(app.screen("S5 Entry detail")).toBeVisible();
}

/**
 * A field label that makes the inference give a MASKED type (a password). ADR-078: an open entry shows every field that is not
 * masked at once, with no button, so a journey about the reveal control must put its value in a masked field. A value typed with no
 * label is plain text, which is not masked.
 */
export const MASKED_LABEL = "password";

/**
 * Press reveal on the open entry's first (masked) field and return what the page shows. A field that is not masked has no reveal
 * button, so this waits for one and fails if the entry never offers it: use {@link MASKED_LABEL} when the entry is made.
 */
export async function revealOpenEntry(app: RealApp): Promise<string> {
  await app.page.getByRole("button", { name: "reveal", exact: true }).click();
  const field = app.page.locator(".k-field-value").first();
  await expect(field).toHaveAttribute("data-masked", "false");
  return (await field.innerText()).trim();
}

/** Right-click a rail row and return the context menu. */
export async function ctxMenu(app: RealApp, label: string | RegExp): Promise<Locator> {
  await railRow(app, label).click({ button: "right" });
  const menu = app.page.locator(".cm-ctxmenu");
  await expect(menu).toBeVisible();
  return menu;
}

/** Open Settings and one of its sections (by the label on its nav button). */
export async function openSettings(app: RealApp, section?: string): Promise<Locator> {
  if ((await app.page.locator(".cm-settings").count()) === 0) {
    await app.page.getByRole("button", { name: "settings", exact: true }).click();
    await expect(app.screen("S12 Settings")).toBeVisible();
  }
  if (section) await app.page.locator(".cm-settings > div:first-child > button", { hasText: section }).first().click();
  return app.screen("S12 Settings");
}

/** Close Settings. */
export async function closeSettings(app: RealApp): Promise<void> {
  await app.screen("S12 Settings").getByRole("button", { name: "Close", exact: true }).click();
  await expect(app.screen("S12 Settings")).toBeHidden();
}
