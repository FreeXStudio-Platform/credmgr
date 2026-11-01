/**
 * The second factor against the real broker: enrol in the first-run wizard with a code from a real authenticator (RFC 6238, computed
 * here from the secret the wizard displays), then every way a login is completed or refused afterwards.
 *
 * A real gate has properties no fake has: a code is accepted once and then refused (the replay ledger), a recovery code burns, the
 * gate survives a daemon restart, a wrong pair at "lost your authenticator?" never says which factor was wrong, and the passphrase
 * alone no longer opens the vault. Each is asserted here against the broker's own answers.
 */
import { expect, test } from "./harness";
import { createVaultViaWizard, KDF, lockUi, passInput, unlockButton, unlockToMain, unlockUi } from "./helpers";
import { Authenticator } from "./totp.mjs";

test("enrol in the wizard, then: the passphrase alone is not enough, a code completes the login, the gate survives a restart, a recovery code works once, and a lost authenticator is reset with the root recovery code", async ({ app }) => {
  const { page } = app;
  const codeField = page.getByPlaceholder("______");
  const verify = page.getByRole("button", { name: "Verify" });
  await app.open();
  const rootRecovery = await createVaultViaWizard(app);

  let auth!: Authenticator;
  let gateCodes: string[] = [];

  await test.step("step 3: the broker's secret is drawn as a QR and shown as text; a wrong code does not enrol, a right one does", async () => {
    await expect(page.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
    const shown = (await page.locator("[data-totp-secret]").innerText()).trim();
    const begin = app.shim.answers.find((a: any) => a.cmd === "vault_gate_enroll_begin");
    expect(begin.result.otpauthUri, "the wizard displays the secret the broker made").toContain(`secret=${shown.replace(/\s+/g, "")}`);
    auth = new Authenticator(shown);

    const confirm = page.getByPlaceholder("confirm one code");
    await confirm.fill(auth.wrong());
    await expect(page.getByRole("alert")).toHaveText("That code was not accepted.");
    expect(app.frames("vault.gate_enroll_confirm")).toHaveLength(1);

    await confirm.fill(await auth.next());
    await expect(page.locator("[data-gate-codes] div")).toHaveCount(10);
    gateCodes = (await page.locator("[data-gate-codes] div").allTextContents()).map((t) => t.trim());
    expect(new Set(gateCodes).size, "ten distinct recovery codes").toBe(10);
    // acknowledging the codes is optional
    await expect(page.getByRole("button", { name: "Continue", exact: true })).toBeEnabled();
    await page.getByLabel("I have saved these recovery codes").check();
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    // they leave the page with the step
    await expect(page.getByText("first run · step 4 of 4")).toBeVisible();
    const dump = await app.pageDump();
    for (const c of gateCodes) expect(dump, "a gate recovery code is still on the page").not.toContain(c);
    expect(dump).not.toContain(shown.replace(/\s+/g, ""));
    await page.getByRole("button", { name: "Open the vault", exact: true }).click();
    await expect(app.screen("S1 Main")).toBeVisible(KDF);
  });

  await test.step("lock, then unlock with the passphrase: the broker asks for the second factor and no login exists yet", async () => {
    await lockUi(app);
    await unlockUi(app);
    await expect(codeField).toBeVisible(KDF);
    expect(app.shim.session.isAuthenticated(), "the passphrase alone must not log in").toBe(false);
    expect(app.calls("vault_unlock").at(-1)!.args).toEqual({ passphrase: app.passphrase });
    expect((app.shim.answers.filter((a: any) => a.cmd === "vault_unlock").at(-1) as any).error.code).toBe("two_factor_required");
    await expect(app.screen("S1 Main")).toHaveCount(0);
    // the passphrase has been taken out of the field and the page
    expect(await app.pageDump()).not.toContain(app.passphrase);
  });

  await test.step("a wrong code is refused by the broker; the next, real code logs in", async () => {
    await codeField.fill(auth.wrong());
    await expect(page.getByRole("alert")).toHaveText("That code was not accepted.");
    expect(app.shim.session.isAuthenticated()).toBe(false);
    await codeField.fill(await auth.next());
    await expect(app.screen("S1 Main")).toBeVisible(KDF);
    expect(app.shim.session.isAuthenticated()).toBe(true);
    expect(app.frames("vault.gate_verify")).toHaveLength(2);
  });

  await test.step("the gate survives a daemon restart: the passphrase still is not enough", async () => {
    await lockUi(app);
    await app.restartDaemon();
    await unlockUi(app);
    await expect(codeField).toBeVisible(KDF);
    expect(app.shim.session.isAuthenticated()).toBe(false);
  });

  await test.step("a gate recovery code completes the login once and is then burned", async () => {
    await codeField.fill(gateCodes[0]);
    await verify.click();
    await expect(app.screen("S1 Main")).toBeVisible(KDF);

    await lockUi(app);
    await unlockUi(app);
    await expect(codeField).toBeVisible(KDF);
    await codeField.fill(gateCodes[0]);
    await verify.click();
    await expect(page.getByRole("alert")).toHaveText("That code was not accepted.");
    expect(app.shim.session.isAuthenticated()).toBe(false);
    // "back" starts over from the passphrase, and a different recovery code still works
    await page.getByRole("button", { name: "back" }).click();
    await expect(page.getByPlaceholder("enter passphrase")).toBeVisible();
    await unlockUi(app);
    await codeField.fill(gateCodes[1]);
    await verify.click();
    await expect(app.screen("S1 Main")).toBeVisible(KDF);
  });

  await test.step("lost your authenticator: a wrong pair is refused without saying which factor, the root recovery code resets the gate", async () => {
    await lockUi(app);
    await unlockUi(app);
    await expect(codeField).toBeVisible(KDF);
    await page.getByRole("button", { name: "lost your authenticator?" }).click();
    const pass = page.getByPlaceholder("passphrase");
    const code = page.getByPlaceholder("root recovery code");
    const submit = page.getByRole("button", { name: "Reset and unlock" });
    await expect(submit).toBeDisabled();

    await pass.fill(app.passphrase);
    await code.fill("0000-0000-0000-0000");
    await submit.click();
    await expect(page.getByRole("alert")).toHaveText("The passphrase or the recovery code is wrong.", KDF);
    await expect(pass).toHaveValue("");
    await expect(code).toHaveValue("");
    expect(app.shim.session.isAuthenticated()).toBe(false);

    await pass.fill(app.passphrase);
    await code.fill(rootRecovery);
    await code.press("Enter");
    await expect(app.screen("S1 Main")).toBeVisible(KDF);
    expect(app.frames("vault.gate_recover").map((f) => f.params.recoveryCode)).toEqual(["0000-0000-0000-0000", rootRecovery]);
    // the reset does not log in by itself: the passphrase unlock after it does
    expect(app.commands().filter((c) => c === "vault_gate_recover" || c === "vault_unlock").slice(-3)).toEqual(["vault_gate_recover", "vault_gate_recover", "vault_unlock"]);
    const dump = await app.pageDump();
    expect(dump).not.toContain(rootRecovery);
    expect(dump).not.toContain(app.passphrase);
  });

  await test.step("after the reset the passphrase alone opens the vault again, and the old authenticator's codes are no longer asked for", async () => {
    await lockUi(app);
    await unlockToMain(app);
    expect(app.shim.answers.filter((a: any) => a.cmd === "vault_unlock").at(-1)).toHaveProperty("result");
    await expect(passInput(app)).toHaveCount(0);
    await expect(unlockButton(app)).toHaveCount(0);
  });
});
