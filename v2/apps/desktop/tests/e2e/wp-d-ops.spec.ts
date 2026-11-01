/**
 * Operations and the maintenance settings: verify, doctor, backup, rotate root key.
 *
 * Asserts the exact bridge commands and arguments, the results rendered from the broker's answers, the refusals (a
 * capability the session lacks, a request that needs presence), and the two things that must never happen:
 *   - a passphrase sitting anywhere (the page, local storage, the logic's state) after it was handed to the broker;
 *   - the model being read after a root-key rotation, which would send the user to the lock screen before they saw the code.
 */
import { FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import { expect, test, type App } from "./harness";
import { everything, notice, openOps, openSettings } from "./wp-d-helpers";

const BACKUP_PHRASE = "backup-pass-tango-7731";
const NEW_CODE = "ROT8-TEST-CODE-0001";

async function open(app: App) {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  return broker;
}

const result = (app: App) => app.page.locator('[data-ops-result="true"]');

test("Verify integrity sends maintenance.verify and renders the broker's answer, including a problem", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openOps(app);

  await page.getByRole("button", { name: "Verify integrity" }).click();
  await expect(result(app)).toContainText("Verify integrity");
  await expect(result(app)).toContainText("ok · 6 nodes checked");
  expect(await broker.calls("maintenance_verify")).toEqual([{ cmd: "maintenance_verify", args: {} }]);

  await broker.script("maintenance_verify", {
    result: { ok: false, nodesChecked: 3, errors: [{ node: "atlas", detail: "manifest checksum does not match" }], warnings: [{ node: null, detail: "3 old archives could be removed" }] },
  });
  await page.getByRole("button", { name: "Verify integrity" }).click();
  await expect(result(app)).toContainText("1 problem in 3 nodes checked");
  await expect(result(app)).toContainText("atlas: manifest checksum does not match");
  await expect(result(app)).toContainText("warning · vault: 3 old archives could be removed");
});

test("Verify, in Settings -> Backup, shows the same answer as a chip", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Backup");
  await expect(page.locator(".k-chip", { hasText: "not checked yet" })).toBeVisible(); // nothing is claimed before it is run
  await page.getByRole("button", { name: "Verify now" }).click();
  await expect(page.locator(".k-chip", { hasText: "ok · 6 nodes checked" })).toBeVisible();
  expect(await broker.calls("maintenance_verify")).toHaveLength(1);
});

test("a verify the broker refuses is shown and leaves the chip as it was", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Backup");
  await broker.script("maintenance_verify", { error: { code: "capability_not_held", detail: { rule: "list is not held" } } });
  await page.getByRole("button", { name: "Verify now" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Not permitted (list is not held)." })).toBeVisible();
  await expect(page.locator(".k-chip", { hasText: "not checked yet" })).toBeVisible();
});

test("Doctor: a dry run first, the fixes listed, and Apply sends apply:true and reads the graph again", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openOps(app);
  await broker.script("maintenance_doctor", { result: { applied: false, fixCount: 1, fixes: [{ node: "atlas", type: "cross-binding-resync", generation: 4 }], unfixable: [] } });

  await page.getByRole("button", { name: "Doctor", exact: true }).click();
  expect(await broker.calls("maintenance_doctor")).toEqual([{ cmd: "maintenance_doctor", args: { apply: false } }]); // the dry run: a plain run never asks for the purge
  await expect(result(app)).toContainText("Doctor · checked");
  await expect(result(app)).toContainText("1 fix would be applied");
  await expect(result(app)).toContainText("atlas · cross-binding-resync");
  expect((await broker.calls("graph_snapshot")).length).toBe(1); // a dry run changes nothing, so nothing is reloaded

  await broker.script("maintenance_doctor", { result: { applied: true, fixCount: 1, fixes: [{ node: "atlas", type: "cross-binding-resync", generation: 4 }], unfixable: [] } });
  await result(app).getByRole("button", { name: "Apply 1 fix" }).click();
  await expect(result(app)).toContainText("Doctor · applied");
  await expect(result(app)).toContainText("1 fix applied");
  expect((await broker.calls("maintenance_doctor")).map((c) => c.args)).toEqual([{ apply: false }, { apply: true }]);
  expect((await broker.calls("graph_snapshot")).length).toBe(2); // an applied fix can change what the graph shows
});

test("Doctor with nothing to fix says so, and offers nothing to apply", async ({ app }) => {
  const { page } = app;
  await open(app);
  await openOps(app);
  await page.getByRole("button", { name: "Doctor", exact: true }).click();
  await expect(result(app)).toContainText("nothing needs fixing");
  await expect(result(app).getByRole("button")).toHaveCount(0);
});

test("Doctor: a problem it cannot fix offers a registry rebuild, which asks for the backup passphrase and meets presence_required", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openOps(app);
  await broker.script("maintenance_doctor", { result: { applied: false, fixCount: 0, fixes: [], unfixable: [{ node: null, detail: "the registry file cannot be read" }] } });
  await page.getByRole("button", { name: "Doctor", exact: true }).click();
  await expect(result(app)).toContainText("cannot fix · vault: the registry file cannot be read");
  await result(app).getByRole("button", { name: "Rebuild registry…" }).click();

  const prompt = app.screen("Passphrase prompt");
  await expect(prompt).toBeVisible();
  await expect(prompt).toContainText("Rebuilds the registry from the most recent backup");
  await prompt.getByLabel("passphrase of the latest backup").fill(BACKUP_PHRASE);
  await prompt.getByRole("button", { name: "Rebuild" }).click();

  await expect(page.getByRole("alert").filter({ hasText: "Needs presence (Touch ID)" })).toContainText("(maintenance.doctor)");
  expect((await broker.calls("maintenance_doctor")).pop()).toEqual({ cmd: "maintenance_doctor", args: { apply: true, rebuildRegistry: true, passphrase: BACKUP_PHRASE } });
  await expect(prompt).toHaveCount(0); // refused for lack of presence: nothing to retry here
  expect(await everything(app)).not.toContain(BACKUP_PHRASE);
});

test("Back up: the passphrase is asked twice, sent once with the retention, and the archive's path is shown; the passphrase is kept nowhere", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Backup");
  await page.getByRole("button", { name: "Back up now" }).click();

  const prompt = app.screen("Passphrase prompt");
  await expect(prompt).toBeVisible();
  await expect(prompt).toContainText("cannot be opened without it");
  const [first, second] = [prompt.getByLabel("backup passphrase", { exact: true }), prompt.getByLabel("repeat the passphrase")];
  await expect(first).toBeFocused(); // the keyboard goes into the dialog that opened over Settings

  await prompt.getByRole("button", { name: "Back up", exact: true }).click();
  await expect(prompt.getByRole("alert")).toHaveText("Enter the passphrase.");
  await first.fill(BACKUP_PHRASE);
  await second.fill("something else");
  await prompt.getByRole("button", { name: "Back up", exact: true }).click();
  await expect(prompt.getByRole("alert")).toHaveText("The two passphrases are different.");
  expect(await broker.calls("maintenance_backup")).toEqual([]); // a typo never reaches the broker

  await second.fill(BACKUP_PHRASE);
  await prompt.getByRole("button", { name: "Back up", exact: true }).click();
  await expect(prompt).toHaveCount(0);
  expect(await broker.calls("maintenance_backup")).toEqual([{ cmd: "maintenance_backup", args: { passphrase: BACKUP_PHRASE, retain: 14 } }]);
  await expect(page.getByText(/last backup this session: backups\/credmgr-backup-\d+\.enc · 0 older archives removed/)).toBeVisible();
  await expect(notice(app)).toContainText("Backup written.");
  expect(await everything(app)).not.toContain(BACKUP_PHRASE); // not in the DOM, local storage or the logic's state
});

test("the retention setting is what a backup sends", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Backup");
  await page.getByLabel("backup retention").selectOption("30");
  await page.getByRole("button", { name: "Back up now" }).click();
  const prompt = app.screen("Passphrase prompt");
  await prompt.getByLabel("backup passphrase", { exact: true }).fill(BACKUP_PHRASE);
  await prompt.getByLabel("repeat the passphrase").fill(BACKUP_PHRASE);
  await prompt.getByLabel("repeat the passphrase").press("Enter"); // Enter submits
  await expect(prompt).toHaveCount(0);
  expect(await broker.calls("maintenance_backup")).toEqual([{ cmd: "maintenance_backup", args: { passphrase: BACKUP_PHRASE, retain: 30 } }]);
});

test("a backup the broker refuses is shown inside the prompt, which stays open with its inputs emptied", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openOps(app);
  await broker.script("maintenance_backup", { error: { code: "capability_not_held", detail: { rule: "admin is required" } } });
  await page.getByRole("button", { name: "Back up vault" }).click();
  const prompt = app.screen("Passphrase prompt");
  await prompt.getByLabel("backup passphrase", { exact: true }).fill(BACKUP_PHRASE);
  await prompt.getByLabel("repeat the passphrase").fill(BACKUP_PHRASE);
  await prompt.getByRole("button", { name: "Back up", exact: true }).click();

  await expect(prompt.getByRole("alert")).toHaveText("Not permitted (admin is required).");
  await expect(prompt).toBeVisible();
  await expect(prompt.getByLabel("backup passphrase", { exact: true })).toHaveValue(""); // the secret is not left in the field
  await expect(prompt.getByLabel("repeat the passphrase")).toHaveValue("");
  expect(await everything(app)).not.toContain(BACKUP_PHRASE);
  // trying again with nothing typed does not resend the old passphrase
  await prompt.getByRole("button", { name: "Back up", exact: true }).click();
  await expect(prompt.getByRole("alert")).toHaveText("Enter the passphrase.");
  expect(await broker.calls("maintenance_backup")).toHaveLength(1);
});

test("Escape closes the prompt and takes the typed passphrase with it", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Backup");
  await page.getByRole("button", { name: "Back up now" }).click();
  const prompt = app.screen("Passphrase prompt");
  await prompt.getByLabel("backup passphrase", { exact: true }).fill(BACKUP_PHRASE);
  await page.keyboard.press("Escape"); // the app's own handler closes every dialog and overlay
  await expect(prompt).toHaveCount(0);
  await expect.poll(async () => page.evaluate(() => JSON.stringify([(window as any).__cm._adminPass, (window as any).__cm._adminRepeat, (window as any).__cm.state.admin?.prompt ?? null]))).toBe('["","",null]');
  expect(await everything(app)).not.toContain(BACKUP_PHRASE);
  expect(await broker.calls("maintenance_backup")).toEqual([]);
});

test("Rotate root key: the vault passphrase is asked, sent, and the broker's presence_required is shown; no code appears", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Advanced");
  await page.getByRole("button", { name: "Rotate…" }).click();
  const prompt = app.screen("Passphrase prompt");
  await expect(prompt).toContainText("needs presence (Touch ID)");
  await expect(prompt.getByLabel("repeat the passphrase")).toHaveCount(0); // only a new passphrase is typed twice
  await prompt.getByLabel("vault passphrase").fill(FIXTURE_PASSPHRASE);
  await prompt.getByRole("button", { name: "Rotate", exact: true }).click();

  await expect(page.getByRole("alert").filter({ hasText: "Needs presence (Touch ID)" })).toContainText("(maintenance.rotate_root)");
  expect(await broker.calls("maintenance_rotate_root")).toEqual([{ cmd: "maintenance_rotate_root", args: { passphrase: FIXTURE_PASSPHRASE } }]);
  await expect(prompt).toHaveCount(0);
  await expect(app.screen("New recovery code")).toHaveCount(0);
  expect(await everything(app)).not.toContain(FIXTURE_PASSPHRASE);
});

test("Rotate root key, when the broker does it: the new recovery code is shown once, must be acknowledged, and then it is gone; the model is not read in between", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Advanced");
  await broker.script("maintenance_rotate_root", {
    result: { rotated: true, recoveryCode: NEW_CODE, nodesRewrapped: 5, vaultGeneration: 9, filesReplaced: 12, artifactsResigned: 3, completionPending: false, notResigned: [] },
  });
  const before = (await broker.commands()).length;
  await page.getByRole("button", { name: "Rotate…" }).click();
  const prompt = app.screen("Passphrase prompt");
  await prompt.getByLabel("vault passphrase").fill(FIXTURE_PASSPHRASE);
  await prompt.getByRole("button", { name: "Rotate", exact: true }).click();

  const dialog = app.screen("New recovery code");
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('[data-recovery-code="true"]')).toHaveText(NEW_CODE);
  await expect(dialog).toContainText("Your previous recovery code no longer works");
  // the call, and nothing read after it: a rotation that is still finishing locks the vault, and a read would hide the code behind the lock screen
  expect((await broker.commands()).slice(before)).toEqual(["maintenance_rotate_root"]);
  await expect(dialog.getByRole("button", { name: "Done" })).toBeDisabled(); // not until it is written down
  await dialog.getByLabel("I have written it down").check();
  await dialog.getByRole("button", { name: "Done" }).click();

  await expect(dialog).toHaveCount(0);
  expect(await everything(app)).not.toContain(NEW_CODE); // gone from the page, storage and state
  expect(await everything(app)).not.toContain(FIXTURE_PASSPHRASE);
});

test("the recovery code survives a stray Escape until it is acknowledged, and does not outlive its dialog after that or when the vault locks", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  const rotate = async () => {
    await broker.script("maintenance_rotate_root", {
      result: { rotated: true, recoveryCode: NEW_CODE, nodesRewrapped: 5, vaultGeneration: 9, filesReplaced: 12, artifactsResigned: 3, completionPending: false, notResigned: [] },
    });
    await openSettings(app, "Advanced");
    await page.getByRole("button", { name: "Rotate…" }).click();
    const prompt = app.screen("Passphrase prompt");
    await prompt.getByLabel("vault passphrase").fill(FIXTURE_PASSPHRASE);
    await prompt.getByRole("button", { name: "Rotate", exact: true }).click();
    await expect(app.screen("New recovery code")).toBeVisible();
  };

  await rotate();
  const dialog = app.screen("New recovery code");
  // The previous code is already dead and this one is shown once: the app's own Escape handler (it closes every dialog and
  // overlay) must not be able to throw the only copy away.
  await page.keyboard.press("Escape");
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('[data-recovery-code="true"]')).toHaveText(NEW_CODE);
  await expect(dialog.getByRole("button", { name: "Done" })).toBeDisabled();
  // Once it is written down, Escape closes it like any dialog, and the code goes with it.
  await dialog.getByLabel("I have written it down").check();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect.poll(async () => page.evaluate(() => (window as any).__cm.state.admin?.recovery ?? null)).toBeNull();
  expect(await page.evaluate(() => (window as any).__cm.state.dialog ?? null)).toBeNull();
  expect(await everything(app)).not.toContain(NEW_CODE);

  // A lock is the other way out: the code is dropped, the lock screen is shown, and no dialog is left set behind it.
  await rotate();
  await page.evaluate(() => (window as any).__cm.lockVault()); // what the idle timer and Cmd+L do
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await everything(app)).not.toContain(NEW_CODE);
  expect(await page.evaluate(() => (window as any).__cm.state.admin ?? null)).toBeNull();
  expect(await page.evaluate(() => (window as any).__cm.state.dialog ?? null)).toBeNull();
});

test("Rotate root key whose last step is still pending: the code is shown with the explanation, even though the vault locked itself", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Advanced");
  await broker.script("maintenance_rotate_root", {
    result: { rotated: true, recoveryCode: NEW_CODE, nodesRewrapped: 5, vaultGeneration: 9, filesReplaced: 11, artifactsResigned: 3, completionPending: true, notResigned: [] },
  });
  await page.getByRole("button", { name: "Rotate…" }).click();
  const prompt = app.screen("Passphrase prompt");
  await prompt.getByLabel("vault passphrase").fill(FIXTURE_PASSPHRASE);
  await prompt.getByRole("button", { name: "Rotate", exact: true }).click();
  const dialog = app.screen("New recovery code");
  await expect(dialog).toContainText("already the live one");
  await expect(dialog.locator('[data-recovery-code="true"]')).toHaveText(NEW_CODE);
});

test("a wrong vault passphrase for a rotation is shown in the prompt, which stays open", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Advanced");
  await broker.script("maintenance_rotate_root", { error: { code: "wrong_passphrase" } });
  await page.getByRole("button", { name: "Rotate…" }).click();
  const prompt = app.screen("Passphrase prompt");
  await prompt.getByLabel("vault passphrase").fill("not-the-passphrase");
  await prompt.getByRole("button", { name: "Rotate", exact: true }).click();
  await expect(prompt.getByRole("alert")).toHaveText("Wrong passphrase.");
  await expect(prompt).toBeVisible();
});

test("losing the login during an operation goes to the lock screen and drops what the screens held", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openOps(app);
  await page.getByRole("button", { name: "Verify integrity" }).click();
  await expect(result(app)).toBeVisible();
  await broker.script("maintenance_verify", { error: { code: "vault_locked" } });
  await page.getByRole("button", { name: "Verify integrity" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await page.evaluate(() => (window as any).__cm.state.admin ?? null)).toBeNull(); // the results are gone with the session
});

test("audit report in Operations: denied requests and grant changes of the last 30 days, nothing else", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  const now = Math.floor(Date.now() / 1000);
  const rec = (id: string, ago: number, action: string, decision: string, node: string | null) => ({ id, timestamp: now - ago, actor: "HumanUi:s_0011223344556677", action, node, entry: null, decision, detail: null, generation: null });
  await broker.set({
    audit: [
      rec("a_old", 40 * 86400, "entry.reveal", "deny", "atlas"), // too old
      rec("a_plain", 600, "entry.reveal", "allow", "atlas"), // allowed and not a grant
      rec("a_deny", 500, "entry.reveal", "deny", "beacon"),
      rec("a_grant", 400, "grant.revoke", "allow", null),
    ],
  });
  await openOps(app);
  await page.getByRole("button", { name: "Audit report" }).click();
  expect(await broker.calls("audit_tail")).toEqual([{ cmd: "audit_tail", args: { limit: 500 } }]);
  await expect(result(app)).toContainText("Audit report · last 30 days");
  await expect(result(app)).toContainText("2 denied or grant records in the 4 records read");
  await expect(result(app)).toContainText("entry.reveal · deny · beacon · app");
  await expect(result(app)).toContainText("grant.revoke · allow · vault · app");
  await expect(result(app)).not.toContainText("atlas");
});

test("in a browser with no broker, Operations says so instead of pretending", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: false });
  await expect(app.screen("S1 Main")).toBeVisible();
  await openOps(app);
  await page.getByRole("button", { name: "Verify integrity" }).click();
  await expect(notice(app)).toContainText("This browser preview has no broker.");
  await page.getByRole("button", { name: "Back up vault" }).click();
  await expect(app.screen("Passphrase prompt")).toHaveCount(0);
  await expect(notice(app)).toContainText("This browser preview has no broker.");
});
