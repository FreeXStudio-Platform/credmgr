/**
 * Every way a login ends, against a real broker: the app must find out, wipe what it held, say why, and let the person in again.
 *
 *   1. the login is revoked from outside (the CLI's `lock`, an idle lock)        -> the next call is refused -> Lock screen, "session ended"
 *   2. the daemon crashes and comes back (a new process knows no logins)         -> the next call is refused -> Lock screen; the data survived
 *   3. the daemon goes away while the app is open                                 -> the 30 s check -> "broker unreachable" -> Retry after it returns
 *   4. the app's own idle auto-lock                                               -> the app locks the REAL broker and says why
 *   5. the shell locks the vault (sleep, screen lock)                             -> the page forgets and says why
 *   6. the daemon is not running when the app starts                              -> "broker unreachable" with Retry, and no passphrase asked for
 *
 * "Revoked" is verified at the broker, not on screen: a dead token is refused as session_expired (ADR-068).
 */
import { expect, fixtureSecret, test, type RealApp } from "./harness";
import { addEntry, createVaultViaWizard, inspector, KDF, lockUi, MASKED_LABEL, openEntry, passInput, railRow, revealOpenEntry, selectNode, unlockToMain } from "./helpers";

const lockNote = (app: RealApp) => app.page.locator("[data-lock-note]");

/** A vault with one project and one ordinary entry (its value in a MASKED field, so the open entry offers a reveal), the app unlocked on its main screen. */
async function vaultWithEntry(app: RealApp, value: string): Promise<void> {
  await app.open();
  await createVaultViaWizard(app);
  await app.page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await app.page.getByLabel("project name 1").fill("Atlas");
  await app.page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
  await addEntry(app, "Atlas", { name: "stripe-live", label: MASKED_LABEL, value });
}

test("1. a login revoked from outside is found at the next call: the Lock screen says the session ended, and nothing of the vault stays on the page", async ({ app }) => {
  const { page } = app;
  const value = fixtureSecret("stripe-value");
  await vaultWithEntry(app, value);
  await openEntry(app, "stripe-live");
  expect(await revealOpenEntry(app)).toBe(value);

  // another process locks the vault (this is what `credmgr lock` and the broker's idle lock do): every token dies at once
  await app.oracle.login();
  await app.oracle.lockVault();
  await expect(app.screen("S5 Entry detail")).toBeVisible(); // the app has not been told: there is no push channel
  await expect(page.locator(".k-field-value").first()).toHaveText(value); // and still shows what it fetched while the login was good

  await page.getByRole("button", { name: "hide", exact: true }).click(); // local: no call
  await page.getByRole("button", { name: "reveal", exact: true }).click(); // a call: the broker answers it with a refusal
  await expect(app.screen("S16 Lock screen")).toBeVisible(KDF);
  await expect(lockNote(app)).toHaveText("Your session ended. Unlock to continue.");
  const refusals = app.shim.answers.filter((a: any) => a.cmd === "entry_reveal" && a.error?.code === "session_expired");
  expect(refusals, "the broker refused the second reveal with session_expired").toHaveLength(1);
  expect(app.shim.session.isAuthenticated(), "the shim dropped the dead login").toBe(false);
  expect(app.frames("vault.lock"), "nothing to lock: the login was already gone").toEqual([]);
  const dump = await app.pageDump();
  for (const gone of ["Atlas", "stripe-live", value]) expect(dump, `${gone} is still on the Lock screen`).not.toContain(gone);

  // the vault opens again from scratch, and the value is still where it was
  await unlockToMain(app);
  await selectNode(app, "Atlas");
  await openEntry(app, "stripe-live");
  expect(await revealOpenEntry(app)).toBe(value);
});

test("2. a daemon that crashes and returns knows no logins: the next call ends the session, and what was written is still there", async ({ app }) => {
  const { page } = app;
  const value = fixtureSecret("stripe-value");
  await vaultWithEntry(app, value);
  const pid = app.daemon.pid;

  await app.restartDaemon({ crash: true }); // SIGKILL, no clean shutdown
  expect(app.daemon.pid).not.toBe(pid);
  await expect(app.screen("S1 Main")).toBeVisible(); // not told yet
  await selectNode(app, "Global"); // a call: the new process has never seen this token
  await expect(app.screen("S16 Lock screen")).toBeVisible(KDF);
  await expect(lockNote(app)).toHaveText(/^(Your session ended\. Unlock to continue\.|The vault was locked\.)$/);
  expect(app.shim.session.isAuthenticated()).toBe(false);
  const refusal = app.shim.answers.filter((a: any) => a.error).at(-1) as any;
  expect(["session_expired", "vault_locked"], `the refusal was ${refusal.error.code}`).toContain(refusal.error.code);
  expect(await app.pageDump()).not.toContain(value);

  await unlockToMain(app);
  await selectNode(app, "Atlas");
  await openEntry(app, "stripe-live");
  expect(await revealOpenEntry(app), "the value written before the crash survived it").toBe(value);
  await app.oracle.login();
  expect((await app.oracle.call("maintenance.verify")).ok, "the vault verifies clean after a crash").toBe(true);
  void page;
});

test("3. the daemon goes away while the app is open: the 30 s check shows the broker-unreachable screen, Retry waits for it, and a returned broker leads to the Lock screen", async ({ app }) => {
  const { page } = app;
  const value = fixtureSecret("stripe-value");
  await page.clock.install();
  await vaultWithEntry(app, value);
  // COMPLETED questions, not started ones: a stop that lands between "asked" and "answered" is a different test
  const statusCalls = () => app.shim.timings.filter((t: any) => t.cmd === "vault_status").length;
  const before = statusCalls();

  // all well: the check asks the real broker, finds the vault open, and changes nothing
  await page.clock.fastForward("00:31");
  await expect.poll(statusCalls).toBe(before + 1);
  await expect(app.screen("S1 Main")).toBeVisible();

  await app.daemon.stop();
  await page.clock.fastForward("00:31");
  await expect(app.screen("S16 Broker unreachable")).toBeVisible();
  const dump = await app.pageDump();
  for (const gone of ["Atlas", "stripe-live", value]) expect(dump, `${gone} is still on the broker-unreachable screen`).not.toContain(gone);
  expect((app.shim.answers.filter((a: any) => a.cmd === "vault_status").at(-1) as any).error).toMatchObject({ source: "transport", code: "broker_unreachable" });
  expect(app.shim.session.isAuthenticated(), "a transport failure says nothing about the token, so the shim keeps it").toBe(true);

  // Retry while it is still gone: the same screen
  await page.getByRole("button", { name: "Retry" }).click();
  await expect.poll(statusCalls).toBe(before + 3);
  await expect(app.screen("S16 Broker unreachable")).toBeVisible();

  // it returns (a new process: locked, no logins): Retry leads to the Lock screen, not to the old session
  await app.restartDaemon();
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await unlockToMain(app);
  await selectNode(app, "Atlas");
  await openEntry(app, "stripe-live");
  expect(await revealOpenEntry(app)).toBe(value);
});

test("4. the app's own idle auto-lock locks the real broker, and says why", async ({ app }) => {
  const { page } = app;
  await page.clock.install();
  await vaultWithEntry(app, fixtureSecret("stripe-value"));
  await app.oracle.login();

  await page.clock.fastForward("14:00");
  await expect(app.screen("S1 Main")).toBeVisible(); // 14 minutes in: still open
  expect(app.frames("vault.lock")).toEqual([]);
  await page.clock.fastForward("02:00");
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(lockNote(app)).toHaveText("Locked after 15 minutes without activity.");
  expect(app.frames("vault.lock")).toHaveLength(1);
  // at the broker: it is locked, and the oracle's login died with it
  await expect(app.oracle.call("entry.list", { node: "atlas" })).rejects.toMatchObject({ source: "broker", code: "session_expired" });
  expect(await app.pageDump()).not.toContain("stripe-live");
  void inspector;
});

test("5. the shell locks the vault (sleep): the page forgets and says why, without locking a second time", async ({ app }) => {
  const { page } = app;
  const value = fixtureSecret("stripe-value");
  await vaultWithEntry(app, value);
  await openEntry(app, "stripe-live");
  expect(await revealOpenEntry(app)).toBe(value);
  expect(await page.evaluate(() => (window as any).__REAL__.listening())).toEqual(expect.arrayContaining(["credmgr://locked", "credmgr://window-inactive"]));

  // what the real shell does on sleep: lock the broker itself (clearing the clipboard and its own login), then tell the page
  await app.shim.invoke("vault_lock");
  const delivered = await page.evaluate(() => (window as any).__REAL__.emit("credmgr://locked", "sleep"));
  expect(delivered).toBeGreaterThan(0);
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(lockNote(app)).toHaveText("Locked because this Mac went to sleep.");
  expect(app.frames("vault.lock"), "the app did not lock again: the shell already had").toHaveLength(1);
  const dump = await app.pageDump();
  for (const gone of ["stripe-live", "Atlas", value]) expect(dump, `${gone} is still on the Lock screen`).not.toContain(gone);
  await unlockToMain(app);
});

test("6. the daemon is not running when the app starts: broker-unreachable with Retry, no passphrase is asked for, and once it runs the app goes on to first run", async ({ app }) => {
  const { page } = app;
  await app.daemon.stop();
  await app.open();
  await expect(app.screen("S16 Broker unreachable")).toBeVisible();
  await expect(page.getByText("credmgr cannot reach its broker")).toBeVisible();
  expect(app.commands()).toEqual(["vault_status"]); // the one question, and nothing after it
  await expect(passInput(app)).toHaveCount(0);
  expect((app.shim.answers[0] as any).error).toMatchObject({ source: "transport", code: "broker_unreachable" });

  await app.restartDaemon(); // starts it again on the same (still empty) vault directory
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(app.screen("S17 First run")).toBeVisible(); // a broker that is up, with no vault yet
  void lockUi;
  void railRow;
});
