/**
 * ADR-150, "Confirm before showing secrets", against the real daemon: turned on in Settings (a real `node.policy` on the global node,
 * checked by the oracle), the next reveal is refused with `confirmation_required`, the dialog takes the passphrase (a real
 * `session.confirm`), the same reveal is sent again and shows what the vault holds; inside the trust window nothing asks again; turning
 * it off asks for a confirmation first; a lock ends the confirmation.
 */
import { expect, fixtureSecret, test, type RealApp } from "./harness";
import { addEntry, createVaultViaWizard, KDF, lockUi, MASKED_LABEL, openEntry, openSettings, selectNode, unlockToMain } from "./helpers";

const dialog = (app: RealApp) => app.screen("Confirm it is you");
const field = (app: RealApp) => app.page.locator(".k-field-value").first();

async function vaultWithEntry(app: RealApp, value: string): Promise<void> {
  await app.open();
  await createVaultViaWizard(app);
  await app.page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await app.page.getByLabel("project name 1").fill("Atlas");
  await app.page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
  await addEntry(app, "Atlas", { name: "stripe-live", value, label: MASKED_LABEL });
}

async function confirmWithPassphrase(app: RealApp, pass: string): Promise<void> {
  await expect(dialog(app)).toBeVisible();
  await dialog(app).locator("input[data-confirm-pass]").fill(pass);
  await dialog(app).locator("[data-confirm-submit]").click();
}

test("turned on: a reveal asks, the passphrase confirms, the same reveal shows the vault's value; the window holds; off asks first; a lock ends it", async ({ app }) => {
  const { page } = app;
  const value = fixtureSecret("stripe-value");
  await vaultWithEntry(app, value);

  await test.step("turn it on in Settings › Security: a real node.policy on global, no confirmation needed", async () => {
    const settings = await openSettings(app, "Security");
    const row = settings.locator('[data-screen-label="S12e Confirm before showing secrets"]');
    await expect(row.locator("[data-rc-toggle]")).toHaveText("off");
    await row.locator("[data-rc-toggle]").click();
    await expect(row.locator("[data-rc-toggle]")).toHaveText("on");
    expect(app.frames("node.policy").map((f) => f.params.policy)).toEqual([{ revealConfirm: { mode: "window", windowSeconds: 300, scope: "all" } }]);
    expect(app.frames("session.confirm")).toEqual([]);
    await settings.getByRole("button", { name: "Close", exact: true }).click();
  });

  await test.step("the reveal is refused by the broker, the dialog takes the passphrase, and the same reveal is sent again", async () => {
    await selectNode(app, "Atlas");
    // the inspector's own note read on selecting the node is refused too (ADR-156 §5), but it is nobody's click: no dialog opens for it
    await expect.poll(() => (app.shim.answers as any[]).filter((a) => a.cmd === "notes_read").at(-1)?.error?.code).toBe("confirmation_required");
    await expect(dialog(app)).toHaveCount(0);
    await openEntry(app, "stripe-live");
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(dialog(app)).toBeVisible();
    expect((await app.answerOf("entry_reveal")).error.code).toBe("confirmation_required");
    await confirmWithPassphrase(app, "not-the-passphrase");
    await expect(dialog(app).getByRole("alert")).toHaveText("Wrong passphrase.");
    await confirmWithPassphrase(app, app.passphrase);
    await expect(dialog(app)).toHaveCount(0);
    await expect(field(app)).toHaveText(value);
    const reveals = app.frames("entry.reveal");
    expect(reveals.length).toBe(2);
    expect(reveals[1].params).toEqual(reveals[0].params);
    expect(await app.pageDump()).not.toContain(app.passphrase);
  });

  await test.step("inside the trust window a second reveal does not ask", async () => {
    await page.getByRole("button", { name: /^hide(, re-masks in \d+ seconds)?$/ }).click();
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(field(app)).toHaveText(value);
    await expect(dialog(app)).toHaveCount(0);
    expect(app.frames("session.confirm").length).toBe(2); // the wrong one and the right one
  });

  await test.step("a lock ends the confirmation: after unlocking, the reveal asks again", async () => {
    await lockUi(app);
    await unlockToMain(app);
    await selectNode(app, "Atlas");
    await openEntry(app, "stripe-live");
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(dialog(app)).toBeVisible();
    await dialog(app).locator("[data-confirm-cancel]").click();
    await expect(field(app)).not.toHaveText(value);
  });

  await test.step("turning it off asks for a confirmation first, then the broker holds off", async () => {
    const settings = await openSettings(app, "Security");
    const row = settings.locator('[data-screen-label="S12e Confirm before showing secrets"]');
    await row.locator("[data-rc-toggle]").click();
    await confirmWithPassphrase(app, app.passphrase);
    await expect(row.locator("[data-rc-toggle]")).toHaveText("off");
    await app.oracle.login();
    const snap = (await app.oracle.call("graph.snapshot", {})) as { revealConfirm?: { mode: string } };
    expect(snap.revealConfirm?.mode ?? "off").toBe("off");
  });
});
