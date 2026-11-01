/**
 * Work package A, first run: a machine with no vault is routed to the wizard, which creates one, opens it, offers the second factor
 * (QR drawn in the page, no remote service) and the first projects, and ends in the app.  The wizard holds secrets (the passphrase,
 * the recovery code, the authenticator's secret, the gate's recovery codes): each must leave the page when its step does.
 */
import { FIXTURE_ENROL_CODE, FIXTURE_INIT_RECOVERY_CODE } from "../fixtures/broker/index";
import { expect, test, type App } from "./harness";

const PASSPHRASE = "first-run-passphrase-9";
const SECRET_TEXT = "JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP"; // the fixture's authenticator secret, grouped in fours

const stateJson = (app: App): Promise<string> => app.page.evaluate(() => JSON.stringify((window as any).__cm.state));
const next = (app: App, name: string) => app.page.getByRole("button", { name, exact: true });

/** Steps 1 and 2: choose a passphrase, retype the recovery code; leaves the wizard on step 3 with the vault open. */
async function createVault(app: App) {
  const { page } = app;
  await page.getByPlaceholder("passphrase", { exact: true }).fill(PASSPHRASE);
  await page.getByPlaceholder("repeat it").fill(PASSPHRASE);
  await next(app, "Continue").click();
  await expect(page.locator("[data-recovery-code]")).toHaveText(FIXTURE_INIT_RECOVERY_CODE);
  await page.getByPlaceholder("retype the recovery code").fill(FIXTURE_INIT_RECOVERY_CODE);
  await page.getByLabel("I have written the recovery code down").check();
  await next(app, "Create vault").click();
}

test("a first run end to end: passphrase, recovery code, second factor with a local QR, first project, then the app", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { initialized: false } }))!;
  await expect(app.screen("S17 First run")).toBeVisible();
  expect(await broker.commands()).toEqual(["vault_status"]);
  await expect(page.getByText("first run · step 1 of 4")).toBeVisible();

  // step 1: too short, then a mismatch, then good.  Nothing is sent until it is good.
  const pass = page.getByPlaceholder("passphrase", { exact: true });
  const again = page.getByPlaceholder("repeat it");
  await pass.fill("abc"); // three characters: under the four-character floor
  await again.fill("abc");
  await expect(next(app, "Continue")).toBeDisabled();
  await expect(page.getByText("at least 4 characters · 8 or more is recommended")).toBeVisible();
  await pass.fill(PASSPHRASE);
  await again.fill(PASSPHRASE + "x");
  await expect(page.getByText("Passphrases don't match")).toBeVisible();
  await expect(next(app, "Continue")).toBeDisabled();
  await again.fill(PASSPHRASE);
  expect(await broker.calls("vault_init_begin")).toEqual([]);
  await next(app, "Continue").click();

  // step 2: the recovery code, once.  The passphrase is no longer in a field or in state; the code is shown, not yet kept.
  await expect(page.getByText("first run · step 2 of 4")).toBeVisible();
  expect(await broker.calls("vault_init_begin")).toEqual([{ cmd: "vault_init_begin", args: { passphrase: PASSPHRASE } }]);
  await expect(page.locator("[data-recovery-code]")).toHaveText(FIXTURE_INIT_RECOVERY_CODE);
  expect(await stateJson(app)).not.toContain(PASSPHRASE);
  await expect(next(app, "Create vault")).toBeEnabled(); // retyping and ticking the box are optional

  // refusal: a wrong retype writes nothing and says so next to the field
  await page.getByPlaceholder("retype the recovery code").fill("WRONG-RETYPE");
  await page.getByLabel("I have written the recovery code down").check();
  await next(app, "Create vault").click();
  await expect(page.getByRole("alert")).toHaveText("The recovery code does not match.");
  expect((await broker.state()).initialized).toBe(false);
  await expect(page.getByText("first run · step 2 of 4")).toBeVisible();

  // the right retype creates the vault and logs in (a created vault starts locked), then the app loads it
  await page.getByPlaceholder("retype the recovery code").fill(FIXTURE_INIT_RECOVERY_CODE);
  await next(app, "Create vault").click();
  await expect(page.getByText("first run · step 3 of 4")).toBeVisible();
  const session = (await broker.commands()).filter((c) => c.startsWith("vault_"));
  expect(session.slice(0, 5)).toEqual(["vault_status", "vault_init_begin", "vault_init_confirm", "vault_init_confirm", "vault_unlock"]);
  expect(await broker.commands()).toContain("graph_snapshot"); // the new vault is read once it is open
  expect(await broker.calls("vault_init_confirm")).toEqual([
    { cmd: "vault_init_confirm", args: { recoveryCode: "WRONG-RETYPE" } },
    { cmd: "vault_init_confirm", args: { recoveryCode: FIXTURE_INIT_RECOVERY_CODE } },
  ]);
  expect(await broker.calls("vault_unlock")).toEqual([{ cmd: "vault_unlock", args: { passphrase: PASSPHRASE } }]);
  expect((await broker.state()).initialized).toBe(true);
  // the passphrase and the recovery code have left the page
  expect(await page.evaluate(() => (window as any).__cm._frPass)).toBe("");
  let dump = (await stateJson(app)) + (await app.storageDump());
  expect(dump).not.toContain(PASSPHRASE);
  expect(dump).not.toContain(FIXTURE_INIT_RECOVERY_CODE);

  // step 3: the enrolment starts by itself; its QR is a path drawn in the page, with the secret as text for typing by hand
  await expect(page.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
  expect(await broker.calls("vault_gate_enroll_begin")).toEqual([{ cmd: "vault_gate_enroll_begin", args: {} }]);
  const d = await page.locator('svg[aria-label="QR code for your authenticator app"] path').getAttribute("d");
  expect(d && d.length).toBeGreaterThan(500);
  expect(d).toMatch(/^M\d+,\d+h\d+v1h-\d+z/);
  await expect(page.locator("[data-totp-secret]")).toHaveText(SECRET_TEXT);
  await expect(next(app, "Confirm code")).toBeDisabled();

  // refusal: a wrong code does not enrol
  const code = page.getByPlaceholder("confirm one code");
  await code.fill("000000");
  await expect(page.getByRole("alert")).toHaveText("That code was not accepted.");
  expect((await broker.state()).gateEnrolled).toBe(false);

  await code.fill(FIXTURE_ENROL_CODE);
  await expect(page.locator("[data-gate-codes] div")).toHaveCount(10);
  expect((await broker.calls("vault_gate_enroll_confirm")).map((c) => c.args)).toEqual([{ code: "000000" }, { code: FIXTURE_ENROL_CODE }]);
  expect((await broker.state()).gateEnrolled).toBe(true);
  await expect(next(app, "Continue")).toBeEnabled(); // acknowledging the codes is optional
  const shownCodes = await page.locator("[data-gate-codes] div").allTextContents();
  await page.getByLabel("I have saved these recovery codes").check();
  await next(app, "Continue").click();

  // step 4: the first project.  node.create under global, with a slug for an id.
  await expect(page.getByText("first run · step 4 of 4")).toBeVisible();
  dump = (await stateJson(app)) + (await app.storageDump()) + (await page.content());
  for (const c of shownCodes) expect(dump, "a gate recovery code is still on the page").not.toContain(c);
  await page.getByLabel("project name 1").fill("Shop Front");
  await next(app, "Open the vault").click();
  await expect(app.screen("S1 Main")).toBeVisible();
  expect(await broker.calls("node_create")).toEqual([{ cmd: "node_create", args: { id: "shop-front", label: "Shop Front", parentId: "global" } }]);
  await expect(page.locator(".cm-rail .k-tree-row", { hasText: "Shop Front" }).first()).toBeVisible();
  expect(JSON.parse(await app.viewJson()).nodes.map((n: { id: string }) => n.id)).toEqual(["global", "shop-front"]);
});

test("the second factor and the first projects can both be skipped; nothing is enrolled or created", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { initialized: false } }))!;
  await createVault(app);
  await expect(page.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
  await next(app, "Enrol later").click();
  await expect(page.getByText("first run · step 4 of 4")).toBeVisible();
  await next(app, "Open the vault").click();
  await expect(app.screen("S1 Main")).toBeVisible();
  expect(await broker.calls("vault_gate_enroll_confirm")).toEqual([]);
  expect(await broker.calls("node_create")).toEqual([]);
  expect((await broker.state()).gateEnrolled).toBe(false);
  const dump = (await stateJson(app)) + (await page.content());
  expect(dump).not.toContain("JBSW");
});

test("first-run refusals are shown on the step that caused them", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { initialized: false }, script: { vault_init_begin: [{ error: { code: "vault_inside_git_working_tree" } }] } }))!;

  // the vault folder is inside a git working tree: stays on step 1, says so, and the next try goes through
  await page.getByPlaceholder("passphrase", { exact: true }).fill(PASSPHRASE);
  await page.getByPlaceholder("repeat it").fill(PASSPHRASE);
  await next(app, "Continue").click();
  await expect(page.getByRole("alert")).toHaveText("The vault folder is inside a git working tree. Choose another location.");
  await expect(page.getByText("first run · step 1 of 4")).toBeVisible();
  await next(app, "Continue").click();
  await expect(page.getByText("first run · step 2 of 4")).toBeVisible();

  // Back returns to step 1 and forgets the code
  await next(app, "Back").click();
  await expect(page.getByText("first run · step 1 of 4")).toBeVisible();
  expect(await stateJson(app)).not.toContain(FIXTURE_INIT_RECOVERY_CODE);
  expect(await broker.calls("vault_init_begin")).toHaveLength(2);

  // the broker has forgotten the pending creation (it expires): the wizard goes back to step 1 instead of retrying a dead code
  await page.getByPlaceholder("passphrase", { exact: true }).fill(PASSPHRASE);
  await page.getByPlaceholder("repeat it").fill(PASSPHRASE);
  await next(app, "Continue").click();
  await broker.script("vault_init_confirm", { error: { code: "vault_init_not_pending" } });
  await page.getByPlaceholder("retype the recovery code").fill(FIXTURE_INIT_RECOVERY_CODE);
  await page.getByLabel("I have written the recovery code down").check();
  await next(app, "Create vault").click();
  await expect(page.getByRole("alert")).toHaveText("No vault creation is in progress. Start again.");
  await expect(page.getByText("first run · step 1 of 4")).toBeVisible();
});

test("a vault that appeared while the wizard was open (another process created it) sends the user to the Lock screen", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: { initialized: false }, script: { vault_init_begin: [{ error: { code: "vault_already_initialized" } }] } });
  await page.getByPlaceholder("passphrase", { exact: true }).fill(PASSPHRASE);
  await page.getByPlaceholder("repeat it").fill(PASSPHRASE);
  await next(app, "Continue").click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(page.getByRole("status").filter({ hasText: "A vault already exists. Unlock it instead." })).toBeVisible();
  expect(await stateJson(app)).not.toContain(PASSPHRASE);
});

test("a project that fails to create stays on the step with the error; the ones that were made are not made twice on the retry", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { initialized: false } }))!;
  await createVault(app);
  await next(app, "Enrol later").click();
  await page.getByLabel("project name 1").fill("First One");
  await page.getByLabel("project name 2").fill("Second One");
  await broker.script("node_create", { delayMs: 0 }, { error: { code: "node_access_denied", detail: { rule: "needs admin" } } });
  await next(app, "Open the vault").click();
  await expect(page.getByRole("alert")).toHaveText("Not permitted (needs admin).");
  await expect(page.getByText("first run · step 4 of 4")).toBeVisible();
  await expect(page.getByLabel("project name 1")).toHaveValue(""); // made: not offered again
  await expect(page.getByLabel("project name 2")).toHaveValue("Second One");
  expect((await broker.state()).nodes.map((n) => n.id)).toContain("first-one");

  await next(app, "Open the vault").click();
  await expect(app.screen("S1 Main")).toBeVisible();
  expect((await broker.calls("node_create")).map((c) => c.args.id)).toEqual(["first-one", "second-one", "second-one"]);
});

test("a login lost during the wizard (the second factor step) goes to the Lock screen, and nothing the wizard held is left", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { initialized: false } }))!;
  await createVault(app);
  await expect(page.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
  await broker.script("vault_gate_enroll_confirm", { error: { code: "session_expired" } });
  await page.getByPlaceholder("confirm one code").fill(FIXTURE_ENROL_CODE);
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(page.locator("[data-lock-note]")).toHaveText("Your session ended. Unlock to continue.");
  const dump = (await stateJson(app)) + (await page.content());
  expect(dump).not.toContain("JBSW");
  expect(dump).not.toContain(PASSPHRASE);
});

test("a vault that was created but could not be opened afterwards goes to the Lock screen, saying so, with the broker's wait", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { initialized: false } }))!;
  await broker.script("vault_unlock", { error: { code: "rate_limited", detail: { retryAfterSeconds: 2 } } });
  await createVault(app);

  // the vault exists (init_confirm went through once), so this is not "creating it failed": it is a Lock screen with a reason
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(page.locator("[data-lock-note]")).toHaveText("The vault was created. Unlock it with your passphrase.");
  await expect(page.getByRole("alert")).toHaveText("Too many attempts. Try again in 2 s.");
  expect((await broker.state()).initialized).toBe(true);
  expect(await broker.calls("vault_init_confirm")).toEqual([{ cmd: "vault_init_confirm", args: { recoveryCode: FIXTURE_INIT_RECOVERY_CODE } }]);
  const dump = (await stateJson(app)) + (await app.storageDump()) + (await page.content());
  expect(dump).not.toContain(PASSPHRASE);
  expect(dump).not.toContain(FIXTURE_INIT_RECOVERY_CODE);

  // after the wait the passphrase chosen in the wizard opens the new vault
  await expect(page.getByRole("alert")).toHaveCount(0, { timeout: 6000 });
  await page.locator('input[type="password"]').fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible();
  expect((await broker.calls("vault_unlock")).map((c) => c.args)).toEqual([{ passphrase: PASSPHRASE }, { passphrase: PASSPHRASE }]);
});

test("a four-character passphrase is accepted with a recommendation, and the recovery code can be skipped: the shown code is what is confirmed", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { initialized: false } }))!;
  const pass = page.getByPlaceholder("passphrase", { exact: true });
  const again = page.getByPlaceholder("repeat it");
  await pass.fill("abcd");
  await again.fill("abcd");
  await expect(page.getByText("Short passphrases are easier to guess. 8 or more is recommended")).toBeVisible();
  await expect(next(app, "Continue")).toBeEnabled(); // a recommendation, never a requirement
  await pass.fill("abcdefgh");
  await again.fill("abcdefgh");
  await expect(page.getByText("Short passphrases are easier to guess")).toHaveCount(0);
  await pass.fill("abcd");
  await again.fill("abcd");
  await next(app, "Continue").click();

  await expect(page.locator("[data-recovery-code]")).toHaveText(FIXTURE_INIT_RECOVERY_CODE);
  await next(app, "Skip for now").click(); // nothing retyped, nothing ticked
  await expect(page.getByText("first run · step 3 of 4")).toBeVisible();
  expect((await broker.calls("vault_init_confirm")).map((c) => c.args)).toContainEqual({ recoveryCode: FIXTURE_INIT_RECOVERY_CODE });
  expect((await broker.state()).initialized).toBe(true);
  expect(await stateJson(app)).not.toContain(FIXTURE_INIT_RECOVERY_CODE); // a skip leaves nothing of the code in the page either
  expect(await stateJson(app)).not.toContain("abcd");

  // the recovery codes of an enrolled second factor can be skipped too
  await page.getByPlaceholder("confirm one code").fill(FIXTURE_ENROL_CODE);
  await expect(page.locator("[data-gate-codes] div")).toHaveCount(10);
  await next(app, "Skip for now").click(); // box unticked
  await expect(page.getByText("first run · step 4 of 4")).toBeVisible();
});
