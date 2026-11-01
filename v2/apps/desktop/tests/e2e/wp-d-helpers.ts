/**
 * Shared steps for the settings-and-administration specs (work package D).  Not a spec itself (Playwright only runs *.spec.ts).
 */
import { expect, type App } from "./harness";

export const SETTINGS_NAV = ".cm-settings > div:first-child > button";

/** Open the settings overlay and go to one of its sections (by the label on its nav button). */
export async function openSettings(app: App, section: string) {
  if ((await app.page.locator(".cm-settings").count()) === 0) {
    await app.page.getByRole("button", { name: "settings", exact: true }).click();
    await expect(app.screen("S12 Settings")).toBeVisible();
  }
  await app.page.locator(SETTINGS_NAV, { hasText: section }).first().click();
}

/** Open the Operations overlay from the vault menu. */
export async function openOps(app: App) {
  await app.page.getByRole("button", { name: "vault menu" }).click();
  await app.page.locator(".cm-vaultmenu button", { hasText: "Operations" }).first().click();
  await expect(app.screen("S14 Operations")).toBeVisible();
}

/** Open an item of the vault menu. */
export async function openFromMenu(app: App, item: string) {
  await app.page.getByRole("button", { name: "vault menu" }).click();
  await app.page.locator(".cm-vaultmenu button", { hasText: item }).first().click();
}

/** The notice the app raises for an error or a refusal (role alert) or for a plain message (role status). */
export function notice(app: App) {
  return app.page.locator("[data-notice]");
}

/** Everything the page shows and keeps, as one string: the DOM, local and session storage, and the logic's state. */
export async function everything(app: App): Promise<string> {
  const html = await app.page.content();
  const storage = await app.storageDump();
  const state = await app.page.evaluate(() => JSON.stringify((window as any).__cm.state));
  return [html, storage, state].join("\n");
}
