/**
 * The Lock screen against the broker's real refusals: a wrong passphrase, and the broker's own backoff (five failures, then a
 * wait the broker names). The screen must show the broker's words, keep the passphrase nowhere, and keep Unlock off for as long as
 * the broker said - and the correct passphrase must NOT get in during the wait (the broker refuses it too).
 */
import { expect, test } from "./harness";
import { createVaultViaWizard, finishWizardBare, KDF, lockUi, passInput, unlockButton, unlockToMain, unlockUi } from "./helpers";

test("a wrong passphrase is refused by the broker and forgotten; five of them start the broker's backoff, which the screen obeys until it is over", async ({ app }) => {
  const { page } = app;
  await page.clock.install();
  await app.open();
  await createVaultViaWizard(app);
  await finishWizardBare(app);
  await lockUi(app);
  const answered = () => app.shim.answers.filter((a: any) => a.cmd === "vault_unlock").length;
  const start = answered(); // the wizard's own login is already among them

  // refusal 1: said next to the field, once, and the field is emptied (the secret is not left in it or in the page)
  await unlockUi(app, "not the passphrase 1");
  await expect(page.getByRole("alert")).toHaveText("Wrong passphrase.", KDF);
  await expect(passInput(app)).toHaveValue("");
  expect((await app.answerOf("vault_unlock")).error).toMatchObject({ source: "broker", code: "wrong_passphrase" });
  expect(await app.pageDump()).not.toContain("not the passphrase 1");
  expect(app.shim.session.isAuthenticated()).toBe(false);

  // failures 2-5: the broker counts consecutive failures per user
  for (let i = 2; i <= 5; i++) {
    await unlockUi(app, `not the passphrase ${i}`);
    await expect.poll(answered, KDF).toBe(start + i);
  }
  const unlocksBeforeBackoff = app.frames("vault.unlock").length;

  // the sixth attempt meets the backoff: the broker names the wait, the screen shows it and turns Unlock off
  await unlockUi(app, app.passphrase); // even the CORRECT passphrase is refused during the wait
  await expect(page.getByRole("alert")).toHaveText(/^Too many attempts\. Try again in (2[0-9]|30) s\.$/, KDF);
  const refusal = (await app.answerOf("vault_unlock")).error;
  expect(refusal).toMatchObject({ source: "broker", code: "rate_limited" });
  expect(refusal.detail.retryAfterSeconds).toBeGreaterThanOrEqual(25);
  expect(refusal.detail.retryAfterSeconds).toBeLessThanOrEqual(30);
  await passInput(app).fill(app.passphrase);
  await expect(unlockButton(app)).toBeDisabled();
  expect(app.shim.session.isAuthenticated(), "the correct passphrase did not get in during the wait").toBe(false);
  expect(app.frames("vault.unlock")).toHaveLength(unlocksBeforeBackoff + 1); // the disabled button sent nothing more

  // the broker's backoff is in its memory; a restart clears it (an operator action), and the screen's own wait runs out with the clock
  await app.restartDaemon();
  await page.clock.fastForward("00:31");
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(unlockButton(app)).toBeEnabled();
  await unlockButton(app).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
  expect(app.shim.session.isAuthenticated()).toBe(true);
  expect(await app.pageDump()).not.toContain(app.passphrase);
  void unlockToMain;
});
