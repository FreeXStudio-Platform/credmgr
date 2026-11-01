/**
 * Work package A, the Lock screen and every road to it: unlock (with the broker's backoff), the second factor (a code and a recovery
 * code), "lost your authenticator?", and the ways a login ends (the user, Cmd/Ctrl-L, idle, a hidden window, the 30 s check,
 * the shell's lock event, a rejected call, a broker that went away).
 *
 * Each control is checked for the exact bridge command and arguments it sends and for what it renders from the answer, with at
 * least one refusal.  Every spec also ends by asserting 0 CSP violations / console errors / external requests (harness.ts).
 */
import { FIXTURE_GATE_CODE, FIXTURE_PASSPHRASE, FIXTURE_ROOT_RECOVERY_CODE } from "../fixtures/broker/index";
import { expect, test, type App } from "./harness";

const GATE_RECOVERY_CODE = "FIXT-GATE-RC01-0000-0000-0000-0000-0000-0000";

const stateJson = (app: App): Promise<string> => app.page.evaluate(() => JSON.stringify((window as any).__cm.state));
const passInput = (app: App) => app.page.locator('input[type="password"]');
const unlockButton = (app: App) => app.page.getByRole("button", { name: "Unlock", exact: true });

async function unlock(app: App, passphrase = FIXTURE_PASSPHRASE) {
  await passInput(app).fill(passphrase);
  await unlockButton(app).click();
}

test("a wrong passphrase, then the broker's backoff: the message says how long, Unlock stays off until then, and the right passphrase opens the vault", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true } }))!;
  await expect(app.screen("S16 Lock screen")).toBeVisible();

  // refusal 1: wrong passphrase.  Shown next to the field, once, and the field is emptied (the secret is not left in it or in state)
  await unlock(app, "wrong-passphrase-one");
  await expect(page.getByRole("alert")).toHaveText("Wrong passphrase.");
  await expect(passInput(app)).toHaveValue("");

  // refusal 2: the broker's backoff.  The wait is in the message, and the button stays off for exactly that long
  await broker.script("vault_unlock", { error: { code: "rate_limited", detail: { retryAfterSeconds: 2 } } });
  await passInput(app).fill("wrong-passphrase-two");
  await unlockButton(app).click();
  await expect(page.getByRole("alert")).toHaveText("Too many attempts. Try again in 2 s.");
  await passInput(app).fill(FIXTURE_PASSPHRASE);
  await expect(unlockButton(app)).toBeDisabled();
  await expect(page.getByRole("alert")).toHaveCount(0, { timeout: 6000 }); // the wait is over: the message goes
  await expect(unlockButton(app)).toBeEnabled();

  await unlockButton(app).click();
  await expect(app.screen("S1 Main")).toBeVisible();
  const unlocks = await broker.calls("vault_unlock");
  expect(unlocks.map((c) => c.args)).toEqual([{ passphrase: "wrong-passphrase-one" }, { passphrase: "wrong-passphrase-two" }, { passphrase: FIXTURE_PASSPHRASE }]);

  // no passphrase is kept anywhere the page can be asked
  const dump = (await stateJson(app)) + (await app.storageDump()) + (await page.content());
  for (const secret of ["wrong-passphrase-one", "wrong-passphrase-two", FIXTURE_PASSPHRASE]) expect(dump).not.toContain(secret);
});

test("Enter in the passphrase field unlocks; the button shows it is working and cannot be pressed twice", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true } }))!;
  await broker.script("vault_unlock", { delayMs: 600 }); // the real unlock is a memory-hard KDF: it takes a moment
  await passInput(app).fill(FIXTURE_PASSPHRASE);
  await passInput(app).press("Enter");
  await expect(page.getByRole("button", { name: "Unlocking…" })).toBeDisabled();
  await expect(app.screen("S1 Main")).toBeVisible();
  expect((await broker.calls("vault_unlock")).length).toBe(1);
});

test("the second-factor step takes a code from the authenticator and a recovery code, and does not send a half-typed code", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true, gate: true } }))!;
  await broker.set({ gateRecoveryCodes: [GATE_RECOVERY_CODE] });
  await unlock(app);
  const code = page.getByPlaceholder("______");
  await expect(code).toBeVisible();

  // six digits typed, then more: the six are NOT sent on their own (the 250 ms auto-send only fires if the entry is still exactly them)
  await code.pressSequentially("424242");
  await code.pressSequentially("77");
  await page.waitForTimeout(500);
  expect(await broker.calls("vault_gate_verify")).toEqual([]);
  await code.fill("");
  await expect(page.getByRole("button", { name: "Verify" })).toBeDisabled();

  // a recovery code is longer than six characters: it waits for Verify, and is sent as typed
  await code.fill(GATE_RECOVERY_CODE);
  await expect(page.getByRole("button", { name: "Verify" })).toBeEnabled();
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(app.screen("S1 Main")).toBeVisible();
  expect(await broker.calls("vault_gate_verify")).toEqual([{ cmd: "vault_gate_verify", args: { code: GATE_RECOVERY_CODE } }]);

  // it burned: the same code is refused the next time round
  await page.getByRole("button", { name: "lock the vault" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await unlock(app);
  await code.fill(GATE_RECOVERY_CODE);
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("alert")).toHaveText("That code was not accepted.");
  // and "back" starts over from the passphrase
  await page.getByRole("button", { name: "back" }).click();
  await expect(page.getByPlaceholder("enter passphrase")).toBeVisible();
  await unlock(app);
  await code.fill(FIXTURE_GATE_CODE);
  await expect(app.screen("S1 Main")).toBeVisible();
});

test("lost your authenticator: a wrong pair is refused without saying which factor, the right pair resets the gate and logs in", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true, gate: true } }))!;
  await unlock(app);
  await expect(page.getByPlaceholder("______")).toBeVisible();
  await page.getByRole("button", { name: "lost your authenticator?" }).click();
  const recoverPass = page.getByPlaceholder("passphrase");
  const recoverCode = page.getByPlaceholder("root recovery code");
  const submit = page.getByRole("button", { name: "Reset and unlock" });
  await expect(submit).toBeDisabled();

  // refusal: the right passphrase with a wrong code (and vice versa) gives the same answer, in the same words
  await recoverPass.fill(FIXTURE_PASSPHRASE);
  await recoverCode.fill("not-the-recovery-code");
  await submit.click();
  await expect(page.getByRole("alert")).toHaveText("The passphrase or the recovery code is wrong.");
  await expect(recoverPass).toHaveValue("");
  await expect(recoverCode).toHaveValue("");
  expect((await broker.state()).gateEnrolled).toBe(true); // nothing was reset

  await recoverPass.fill(FIXTURE_PASSPHRASE);
  await recoverCode.fill(FIXTURE_ROOT_RECOVERY_CODE);
  await recoverCode.press("Enter");
  await expect(app.screen("S1 Main")).toBeVisible();
  const cmds = await broker.commands();
  expect((await broker.calls("vault_gate_recover")).map((c) => c.args)).toEqual([
    { passphrase: FIXTURE_PASSPHRASE, recoveryCode: "not-the-recovery-code" },
    { passphrase: FIXTURE_PASSPHRASE, recoveryCode: FIXTURE_ROOT_RECOVERY_CODE },
  ]);
  // the reset does not log in; the passphrase unlock after it does, and it needs no second factor any more
  const order = cmds.filter((c) => c === "vault_gate_recover" || c === "vault_unlock");
  expect(order).toEqual(["vault_unlock", "vault_gate_recover", "vault_gate_recover", "vault_unlock"]); // the wrong pair, then the right one, then the login
  expect((await broker.state()).gateEnrolled).toBe(false);
  await expect(page.getByRole("status").filter({ hasText: "Second factor reset" })).toBeVisible();
  const dump = (await stateJson(app)) + (await app.storageDump());
  expect(dump).not.toContain(FIXTURE_ROOT_RECOVERY_CODE);
});

test("a reset whose login then fails is still a reset: the user goes on to the passphrase step", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true, gate: true } }))!;
  await unlock(app);
  await page.getByRole("button", { name: "lost your authenticator?" }).click();
  await broker.script("vault_unlock", { error: { code: "rate_limited", detail: { retryAfterSeconds: 300 } } });
  await page.getByPlaceholder("passphrase").fill(FIXTURE_PASSPHRASE);
  await page.getByPlaceholder("root recovery code").fill(FIXTURE_ROOT_RECOVERY_CODE);
  await page.getByRole("button", { name: "Reset and unlock" }).click();
  await expect(page.getByPlaceholder("enter passphrase")).toBeVisible();
  await expect(page.locator("[data-lock-note]")).toHaveText("Second factor reset. Unlock with your passphrase.");
  await expect(page.getByRole("alert")).toHaveText("Too many attempts. Try again in 5 min.");
  expect((await broker.state()).gateEnrolled).toBe(false);
});

test("Lock: the chip and the vault menu tell the broker, once, and leave nothing of the session behind", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await expect(page.locator("header").getByText("credmgr", { exact: true })).toBeVisible(); // a static label: there is no vault name to show

  // the menu no longer has the two demo items
  await page.getByRole("button", { name: "vault menu" }).click();
  const items = await page.locator(".cm-vaultmenu button").allTextContents();
  expect(items.join("|")).toContain("Lock vault");
  expect(items.join("|")).not.toMatch(/Lock screen|Replay first run/);
  await page.keyboard.press("Escape");

  await page.getByRole("button", { name: "lock the vault" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await broker.calls("vault_lock")).toEqual([{ cmd: "vault_lock", args: {} }]);
  await expect(page.locator("[data-lock-note]")).toHaveCount(0); // the user asked: no reason is given
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  expect(await page.content()).not.toContain("atlas");
});

test("Cmd/Ctrl-L locks from anywhere, including with a dialog open and something half-typed in it, and the half-typed text goes with it", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await page.evaluate(() => (window as any).__cm.setState({ dialog: "addEntry", selected: "atlas", addNode: "atlas", addName: "half-typed-name", singleFields: [{ label: "token", value: "half-typed-secret-value" }], bulkText: "bulk-typed-secret" }));
  await expect(page.getByPlaceholder("vps-root")).toBeVisible();
  await page.getByPlaceholder("vps-root").focus(); // typing in a field: a bare shortcut would be ignored, this one is not

  await page.keyboard.press("Control+l");
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect((await broker.calls("vault_lock")).length).toBe(1);
  const dump = (await stateJson(app)) + (await page.content());
  for (const gone of ["half-typed-secret-value", "half-typed-name", "bulk-typed-secret", "atlas"]) expect(dump, gone).not.toContain(gone);

  // on the Lock screen the shortcut is inert (nothing to lock)
  await page.keyboard.press("Control+l");
  expect((await broker.calls("vault_lock")).length).toBe(1);

  // the Mac's own key, Cmd-L, does the same
  await passInput(app).fill(FIXTURE_PASSPHRASE);
  await unlockButton(app).click();
  await expect(app.screen("S1 Main")).toBeVisible();
  await page.keyboard.press("Meta+l");
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect((await broker.calls("vault_lock")).length).toBe(2);
});

test("a fresh second factor wanted for a reveal mid-session opens the second-factor dialog (no notice, no new login), and nothing is sent until a code is typed", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false, gate: true } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
  await page.locator("aside.cm-insp button.k-entry").first().click();
  await broker.script("entry_reveal", { error: { code: "two_factor_required", detail: { challenge: "totp", scope: "global" } } });
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(app.screen("S5c Second factor")).toBeVisible();
  await expect(page.locator("[data-notice]")).toHaveCount(0); // the dialog is the explanation
  await expect(app.screen("S1 Main")).toBeVisible(); // still logged in
  expect(await broker.calls("vault_gate_verify")).toEqual([]); // no code was sent: the user has not typed one
  expect(await app.secretCount()).toBe(0);
});

test("an idle vault locks itself after the auto-lock time and says why", async ({ app }) => {
  const { page } = app;
  await page.clock.install();
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await page.evaluate(() => {
    (window as any).__cm.setState({ autoLockMins: 2 });
    (window as any).__cm.armAutoLock();
  });
  await page.clock.fastForward("01:00");
  await expect(app.screen("S1 Main")).toBeVisible(); // a minute in: still open
  await page.clock.fastForward("01:30");
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(page.locator("[data-lock-note]")).toHaveText("Locked after 2 minutes without activity.");
  expect((await broker.calls("vault_lock")).length).toBe(1);
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
});

test("a hidden window wipes revealed values and locks; coming back asks the broker, it does not guess", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
  await page.locator("aside.cm-insp button.k-entry").first().click();
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(page.locator(".k-field-value")).toHaveText("fixture-value-stripe-live");
  expect(await app.secretCount()).toBe(1);

  await page.evaluate(() => {
    Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await app.secretCount()).toBe(0);
  await expect(page.locator("[data-lock-note]")).toHaveText("Locked because the window was hidden.");
  expect((await broker.calls("vault_lock")).length).toBe(1);
  expect(await page.content()).not.toContain("fixture-value-stripe-live");
});

test("session_expired mid-use goes to the Lock screen with the reason, drops the model and every name, and unlocking again works", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
  await page.locator("aside.cm-insp button.k-entry").first().click();
  await broker.script("entry_reveal", { error: { code: "session_expired" } });
  await page.getByRole("button", { name: "reveal", exact: true }).click();

  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(page.locator("[data-lock-note]")).toHaveText("Your session ended. Unlock to continue.");
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  expect(await app.secretCount()).toBe(0);
  expect(await broker.calls("vault_lock")).toEqual([]); // nothing to lock: the login was already gone
  const dump = (await stateJson(app)) + (await page.content());
  for (const gone of ["atlas", "stripe-live", "e-a1"]) expect(dump, gone).not.toContain(gone);

  // the note goes with the next attempt, and the vault opens again from scratch
  await broker.set({ locked: true, authenticated: false });
  await unlock(app);
  await expect(app.screen("S1 Main")).toBeVisible();
  await expect(page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first()).toBeVisible();
});

test("the 30 s check: a vault locked behind the app's back (idle lock, the CLI) is found, and a broker that went away is shown as that", async ({ app }) => {
  const { page } = app;
  await page.clock.install();
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const statusCalls = async () => (await broker.calls("vault_status")).length;
  expect(await statusCalls()).toBe(1); // boot

  // all well: the check asks, finds the vault open, and changes nothing
  await page.clock.fastForward("00:31");
  await expect.poll(statusCalls).toBe(2);
  await expect(app.screen("S1 Main")).toBeVisible();

  // locked elsewhere
  await broker.set({ locked: true, authenticated: false });
  await page.clock.fastForward("00:31");
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(page.locator("[data-lock-note]")).toHaveText("The vault was locked.");
  expect(await statusCalls()).toBe(3);
  expect((await broker.calls("vault_lock")).length).toBe(0);
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);

  // the 30 s liveness check is for an open vault only. The Lock screen's own five-second look at the count of waiting agent requests (ADR-090) is
  // a `vault.status` too (a fast-forward fires an interval once), and it is the only thing the Lock screen asks: no graph, no list, no lock call.
  const otherCalls = async () => (await broker.calls()).filter((c) => c.cmd !== "vault_status").length;
  const others = await otherCalls();
  await page.clock.fastForward("01:05");
  expect(await statusCalls()).toBeLessThanOrEqual(4);
  expect(await otherCalls()).toBe(others);

  // a broker that went away while the app was open
  await broker.set({ locked: false, authenticated: true });
  await unlock(app);
  await expect(app.screen("S1 Main")).toBeVisible();
  await broker.set({ unreachable: true });
  await page.clock.fastForward("00:31");
  await expect(app.screen("S16 Broker unreachable")).toBeVisible();
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  expect(await page.content()).not.toContain("atlas");
  // Retry while it is still gone: the same screen
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(app.screen("S16 Broker unreachable")).toBeVisible();
  // it comes back (restarted, so locked): Retry leads to the Lock screen, not to the old session
  await broker.set({ unreachable: false, locked: true, authenticated: false });
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
});

test("the shell locks the vault (sleep, screen lock): the page forgets and says why, without locking again", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  expect(await broker.listening()).toEqual(["credmgr://locked", "credmgr://window-inactive"]);

  // reveal something first: it must not survive
  await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
  await page.locator("aside.cm-insp button.k-entry").first().click();
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(page.locator(".k-field-value")).toHaveText("fixture-value-stripe-live");

  expect(await broker.emit("credmgr://locked", "sleep")).toBe(1);
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(page.locator("[data-lock-note]")).toHaveText("Locked because this Mac went to sleep.");
  expect(await app.secretCount()).toBe(0);
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  expect(await broker.calls("vault_lock")).toEqual([]); // the shell already did it and dropped the login
  expect(await page.content()).not.toContain("fixture-value-stripe-live");

  // an event with a reason this build has never heard of still locks, with a generic reason; an event on the Lock screen changes nothing
  await broker.set({ locked: false, authenticated: true });
  await unlock(app);
  await expect(app.screen("S1 Main")).toBeVisible();
  await broker.emit("credmgr://locked", "something-new");
  await expect(page.locator("[data-lock-note]")).toHaveText("The vault was locked by the system.");
  await broker.emit("credmgr://locked", "screen_locked");
  await expect(page.locator("[data-lock-note]")).toHaveText("The vault was locked by the system."); // already locked: the second event is ignored
});

test("a failed subscription to the shell's events is said, not swallowed, and the app still works", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: { locked: false }, script: { "plugin:event|listen": [{ error: { code: "internal", message: "event plugin refused", source: "bridge" } }] } });
  await expect(app.screen("S1 Main")).toBeVisible();
  await expect(page.getByRole("status").or(page.getByRole("alert")).filter({ hasText: "Could not subscribe to system lock events" })).toBeVisible();
});

test("a broker that answers the first question with something unusable is a screen with Retry, not a blank 'starting' for ever", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true }, script: { vault_status: [{ error: { code: "internal", message: "boom" } }] } }))!;
  await expect(app.screen("S0 Start failed")).toBeVisible();
  await expect(page.getByRole("alert").filter({ hasText: "Unexpected error (internal). Nothing was changed." })).toBeVisible();
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await broker.commands()).toEqual(["vault_status", "vault_status"]);
});

test("the Lock screen puts the caret back in its field after a refusal, and the graph canvas exists after unlock (it is created when the app first mounts)", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: { locked: true } });
  await expect(page.locator("canvas")).toHaveCount(0); // nothing of the app yet
  await unlock(app, "wrong");
  await expect(page.getByRole("alert")).toHaveText("Wrong passphrase.");
  await expect(passInput(app)).toBeFocused();
  await unlock(app);
  await expect(app.screen("S1 Main")).toBeVisible();
  await expect(page.locator("canvas")).toHaveCount(1);
  // lock and unlock again: the same canvas is put back, not a second one
  await page.getByRole("button", { name: "lock the vault" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await unlock(app);
  await expect(app.screen("S1 Main")).toBeVisible();
  await expect(page.locator("canvas")).toHaveCount(1);
});

test("a broker that is not running at start is a screen with Retry: no session is shown, Retry asks again, and a broker that came back leads to the Lock screen", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { unreachable: true } }))!;
  await expect(app.screen("S16 Broker unreachable")).toBeVisible();
  await expect(page.getByText("credmgr cannot reach its broker")).toBeVisible();
  expect(await broker.commands()).toEqual(["vault_status"]); // the one question, and nothing after it
  await expect(page.locator('input[type="password"]')).toHaveCount(0); // no passphrase is asked for until there is a broker to give it to

  // Retry while it is still gone: the same screen, exactly one more question
  await page.getByRole("button", { name: "Retry" }).click();
  await expect.poll(async () => (await broker.commands()).length).toBe(2);
  await expect(app.screen("S16 Broker unreachable")).toBeVisible();
  expect(await broker.commands()).toEqual(["vault_status", "vault_status"]);

  // it comes back: Retry leads to the Lock screen, with no reason given (nothing ended), and the vault then opens
  await broker.set({ unreachable: false });
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(page.locator("[data-lock-note]")).toHaveCount(0);
  await unlock(app);
  await expect(app.screen("S1 Main")).toBeVisible();
  expect((await broker.calls("vault_unlock")).map((c) => c.args)).toEqual([{ passphrase: FIXTURE_PASSPHRASE }]);
});

test("the broker going away between the Lock screen and the unlock is the broker-down screen, and the typed passphrase is not kept", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true } }))!;
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await broker.set({ unreachable: true });
  await unlock(app, "typed-while-broker-gone");
  await expect(app.screen("S16 Broker unreachable")).toBeVisible();
  expect((await broker.calls("vault_unlock")).map((c) => c.args)).toEqual([{ passphrase: "typed-while-broker-gone" }]);
  const dump = (await stateJson(app)) + (await app.storageDump()) + (await page.content());
  expect(dump).not.toContain("typed-while-broker-gone");

  await broker.set({ unreachable: false });
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await unlock(app);
  await expect(app.screen("S1 Main")).toBeVisible();
});

test("a vault another process unlocked is still locked for this window: the Lock screen, and no vault data is read", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false }, script: { vault_status: [{ result: { locked: false, authenticated: false, initialized: true } }] } }))!;
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(app.page.locator("[data-lock-note]")).toHaveCount(0);
  expect(await broker.commands()).toEqual(["vault_status"]); // no graph, no entry list: this window holds no login
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
});

test("Lock vault in the vault menu locks like the chip: the broker is told once, and nothing of the session stays", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
  await page.getByRole("button", { name: "vault menu" }).click();
  await page.locator(".cm-vaultmenu button", { hasText: "Lock vault" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await broker.calls("vault_lock")).toEqual([{ cmd: "vault_lock", args: {} }]);
  await expect(page.locator("[data-lock-note]")).toHaveCount(0); // the user asked: no reason is given
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  expect(await page.content()).not.toContain("atlas");
  expect((await broker.state()).locked).toBe(true);
});

test("the shell says the window is no longer in front: revealed values are wiped, the vault stays open, nothing is sent to the broker", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
  await page.locator("aside.cm-insp button.k-entry").first().click();
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(page.locator(".k-field-value")).toHaveText("fixture-value-stripe-live");
  expect(await app.secretCount()).toBe(1);
  const before = (await broker.commands()).length;

  // every reason the shell has: the page treats them alike (a minimised window, a hidden app, focus moving to another app)
  expect(await broker.emit("credmgr://window-inactive", "blurred")).toBe(1);
  await expect(page.locator(".k-field-value")).not.toHaveText("fixture-value-stripe-live");
  expect(await app.secretCount()).toBe(0);
  expect(await page.content()).not.toContain("fixture-value-stripe-live");
  await expect(app.screen("S1 Main")).toBeVisible(); // not locked
  expect((await broker.commands()).length).toBe(before); // and nothing was asked of the broker
  expect(await broker.calls("vault_lock")).toEqual([]);

  // the same for the other two reasons, and for one this build has never heard of
  for (const reason of ["minimized", "hidden", "something-new"]) {
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(page.locator(".k-field-value")).toHaveText("fixture-value-stripe-live");
    await broker.emit("credmgr://window-inactive", reason);
    await expect(page.locator(".k-field-value")).not.toHaveText("fixture-value-stripe-live");
    expect(await app.secretCount()).toBe(0);
  }
  await expect(app.screen("S1 Main")).toBeVisible();
});

test("a failed subscription to the shell's focus events is said, and the lock event still works", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false }, script: { "plugin:event|listen": [{ delayMs: 0 }, { error: { code: "internal", message: "event plugin refused", source: "bridge" } }] } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await expect(page.getByRole("status").or(page.getByRole("alert")).filter({ hasText: "Could not subscribe to window focus events" })).toBeVisible();
  expect(await broker.listening()).toEqual(["credmgr://locked"]);
  await broker.emit("credmgr://locked", "sleep");
  await expect(app.screen("S16 Lock screen")).toBeVisible();
});

test("Lock does not wait for a slow broker: the Lock screen is there at once and empty, Unlock waits for the broker's answer, then works", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
  await broker.script("vault_lock", { delayMs: 1500 }); // a broker that takes its time (the shell gives up after 30 s)
  await page.getByRole("button", { name: "lock the vault" }).click();

  // well before the broker answers: the Lock screen, with nothing of the vault behind it
  await expect(app.screen("S16 Lock screen")).toBeVisible({ timeout: 700 });
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  expect(await page.content()).not.toContain("atlas");
  expect((await broker.calls("vault_lock")).length).toBe(1);
  expect((await broker.state()).locked).toBe(false); // the broker has not been told yet

  // a login that overlapped the lock call could be dropped by it: Unlock stays off until the broker has answered
  await passInput(app).fill(FIXTURE_PASSPHRASE);
  await expect(page.getByRole("button", { name: "Locking…" })).toBeDisabled();
  await expect(unlockButton(app)).toBeEnabled({ timeout: 4000 });
  expect((await broker.state()).locked).toBe(true);
  expect(await broker.calls("vault_unlock")).toEqual([]); // nothing was sent while it waited
  await unlockButton(app).click();
  await expect(app.screen("S1 Main")).toBeVisible();
  expect((await broker.commands()).filter((c) => c === "vault_lock" || c === "vault_unlock")).toEqual(["vault_lock", "vault_unlock"]);
});
