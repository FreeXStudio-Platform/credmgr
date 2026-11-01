/**
 * Shared by the field-UI specs (field-ui-*.spec.ts).  Not a spec itself.
 *
 * The default fixture vault holds one multi-field entry (atlas / pg-main, e-a2: host, port, username, password, note) and two entries written
 * before the field model (e-a1, e-a3: one field each, id f_00000000, no label).  `openWithExtra` adds more BEFORE the app unlocks, so the app
 * reads them the way it reads everything: from the broker.
 */
import type { Broker } from "../fixtures/broker/index";
import { expect, type App, type Locator } from "./harness";
import { entryOpened, unlockUi } from "./wp-b-helpers";

/** The ids the default vault's pg-main fields have (tests/fixtures/broker/seed.js). */
export const PG = {
  entry: "e-a2",
  host: "f_00a20001",
  port: "f_00a20002",
  user: "f_00a20003",
  password: "f_00a20004",
  note: "f_00a20005",
} as const;

/** The plaintext the fixture holds for pg-main's fields (distinctive, so a spec can search the page, the storage and the logs for them). */
export const PG_VALUE = {
  host: "fixture-value-pg-main.example.test",
  port: "5432",
  user: "fixture-value-pg-main-user",
  password: "fixture-value-pg-main-password",
  note: "fixture-value-pg-main-note",
} as const;

/** Every plaintext of pg-main, for "it is nowhere" assertions. */
export const PG_SECRETS = [PG_VALUE.host, PG_VALUE.user, PG_VALUE.password, PG_VALUE.note] as const;

export async function openApp(app: App): Promise<Broker> {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  return broker;
}

/** Open the app on a locked fixture vault, add `extra` entries to `node`, unlock through the real lock screen, and wait for the main screen. */
export async function openWithExtra(app: App, node: string, extra: object[]): Promise<Broker> {
  const broker = (await app.open({ broker: { locked: true } }))!;
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await app.page.evaluate(([n, list]) => {
    const S = (window as any).__brokerFixture.S;
    S.entries[n] = [...(S.entries[n] || []), ...list];
  }, [node, extra] as const);
  await unlockUi(app);
  await expect(app.screen("S1 Main")).toBeVisible();
  return broker;
}

/** Select a node in the rail and open one of its entries from the inspector's list. */
export async function openEntryOf(app: App, node: string, entry: string): Promise<void> {
  await app.page.locator(".cm-rail .k-tree-row", { hasText: node }).first().click();
  await app.page.locator("aside.cm-insp button.k-entry", { hasText: entry }).first().click();
  await entryOpened(app);
}

/** A field's row in the open entry, by the id the broker minted. */
export const fieldRow = (app: App, id: string): Locator => app.page.locator(`.k-field[data-field-id="${id}"]`);

/** All the field rows of the open entry. */
export const fieldRows = (app: App): Locator => app.page.locator('[data-fields="true"] .k-field');

/** A field's value cell. */
export const valueOf = (app: App, id: string): Locator => fieldRow(app, id).locator(".k-field-value");

/** Open a field's ⋮ menu and return the menu. */
export async function openMenu(app: App, id: string): Promise<Locator> {
  await fieldRow(app, id).getByRole("button", { name: "field menu" }).click();
  const menu = app.page.locator(".cm-fieldmenu");
  await expect(menu).toBeVisible();
  return menu;
}

/** The field dialog (add, edit, remove). */
export const fieldDialog = (app: App): Locator => app.screen("S5a Field");

/**
 * The field dialog, open AND settled.  The design moves focus to a dialog's first control 30 ms after it opens (core.js focusModalFirst), and
 * Playwright's `fill` can land in that window, where the text goes nowhere (see wp-c-util.ts dialogFocusSettled).  A person never meets the
 * race; a spec waits for the move to have happened before it types.
 */
export async function dialogReady(app: App): Promise<Locator> {
  const dlg = fieldDialog(app);
  await expect(dlg).toBeVisible();
  await expect(dlg.locator("input, textarea, select, button").first()).toBeFocused();
  return dlg;
}

/** An entry with several fields as the fixture vault stores it (see tests/fixtures/broker/fields.js). */
export const multi = (id: string, name: string, fields: Array<{ id: string; label: string; value: string; typePin?: string; maskedPin?: boolean }>, type = "login", sensitivity = "high") => ({
  id, name, type, sensitivity, value: fields[0].value, fields, modified: 1760000000, rotatedAt: null, expiresAt: null,
});
