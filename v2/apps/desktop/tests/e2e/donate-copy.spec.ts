/**
 * About -> Donate -> "copy address" must report what really happened.
 *
 * The first version called navigator.clipboard.writeText inside a try/catch that never saw the promise rejection, so the
 * button said "copied" even when the write was refused.  That is the one flow where it matters: the page itself warns that
 * clipboard hijackers target donation addresses.  Now the page does not write to the clipboard at all: the address goes to the
 * shell (`copy_text`), and "copied" is said only after the shell has answered.  (wp-d-about.spec.ts covers the shell's own
 * answers, a refusal included.)
 */
import { expect, test, type App } from "./harness";

async function openDonate(app: App) {
  await app.page.getByRole("button", { name: "vault menu" }).click();
  await app.page.locator(".cm-vaultmenu button", { hasText: "About CredMgr" }).click();
  await app.page.getByRole("link", { name: "Donate" }).click();
  await expect(app.page.getByRole("button", { name: /copy address|copied|copy failed/ })).toBeVisible();
}

/** A page clipboard that records what it is given: the page must never use it. */
async function recordPageClipboard(app: App) {
  await app.page.addInitScript(() => {
    (window as any).__written = [];
    Object.defineProperty(navigator, "clipboard", { value: { writeText: (t: string) => ((window as any).__written.push(t), Promise.resolve()), readText: () => Promise.resolve("") }, configurable: true });
  });
}

test("with no shell there is nothing to copy with: the button says 'copy failed', and the page's own clipboard is never written", async ({ app }) => {
  const { page } = app;
  await recordPageClipboard(app);
  await app.open({ broker: false });
  await expect(app.screen("S1 Main")).toBeVisible();
  await openDonate(app);
  await page.getByRole("button", { name: "copy address" }).click();
  await expect(page.getByRole("button", { name: "copy failed" })).toBeVisible();
  await expect(page.getByRole("button", { name: /copied/ })).toHaveCount(0);
  await expect(page.getByRole("alert")).toContainText("Could not copy the address");
  expect(await page.evaluate(() => (window as any).__written)).toEqual([]);
});

test("'copied' appears only after the shell has answered, never while the copy is still pending", async ({ app }) => {
  const { page } = app;
  await recordPageClipboard(app);
  const broker = (await app.open({ broker: { locked: false }, script: { copy_text: [{ delayMs: 900 }] } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await openDonate(app);
  await page.getByRole("button", { name: "copy address" }).click({ noWaitAfter: true });
  await expect.poll(async () => (await broker.calls("copy_text")).length).toBe(1);
  await expect(page.getByRole("button", { name: /copied/ })).toHaveCount(0); // asked, not answered: nothing is claimed
  await expect(page.getByRole("button", { name: /copied/ })).toBeVisible(); // answered
  expect(await page.evaluate(() => (window as any).__written)).toEqual([]);
});
