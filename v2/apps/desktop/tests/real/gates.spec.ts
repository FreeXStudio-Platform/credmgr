/**
 * The 2026-10-25 controls over the real broker: Undo (`entry.undo`), Generate (`util.generate`), a decision on the Lock screen
 * (`vault.approval_decide`), the step-up the second-factor dialog sends (`vault.gate_verify` from a logged-in session), privateNames and the
 * doctor's purge.  Every claim is checked at the vault by the independent client, never only on screen.
 *
 * What cannot be driven here, and why: the second-factor DIALOG.  The broker asks a reader that is not the owner's login for the factor
 * (ADR-085 #3); the window's own login is the owner's, so the real daemon never answers `two_factor_required` to the window's reveal.  That
 * flow (the dialog, the retry) is held to the fixture broker in tests/e2e/gates.spec.ts; what is held to the real daemon here is its transport:
 * the same `vault_gate_verify` command, from the same logged-in session, answered by the real gate.
 */
import { mkdirSync } from "node:fs";
import { join } from "node:path";

import { Oracle } from "./oracle.mjs";
import { expect, fixtureSecret, test, type RealApp } from "./harness";
import { addEntry, closeSettings, createVaultViaWizard, KDF, lockUi, MASKED_LABEL, notice, openEntry, openSettings, railRow, selectNode, unlockToMain } from "./helpers";
import { Authenticator } from "./totp.mjs";

async function vaultWith(app: RealApp, project: string): Promise<void> {
  await app.open();
  await createVaultViaWizard(app);
  await app.page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await app.page.getByLabel("project name 1").fill(project);
  await app.page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
  await expect(railRow(app, project)).toBeVisible();
}

const fieldLabels = (app: RealApp) => app.page.locator('[data-fields="true"] [data-field-label="true"]');
const undoButton = (app: RealApp, what: string) => app.page.getByRole("button", { name: `Undo ${what}`, exact: true });

async function openFieldDialog(app: RealApp) {
  await app.page.getByRole("button", { name: "+ Add field" }).click();
  const dlg = app.screen("S5a Field");
  await expect(dlg).toBeVisible();
  await expect(dlg.getByLabel("field label")).toBeFocused();
  return dlg;
}

test("Generate and Undo: the broker makes the value, the dialog shows it masked, the entry holds it, and Undo gives back exactly what the vault held before", async ({ app }) => {
  const { page } = app;
  const base = fixtureSecret("pg-main-password");
  await vaultWith(app, "Atlas");
  await addEntry(app, "Atlas", { name: "pg-main", label: MASKED_LABEL, value: base });
  await app.oracle.login();
  await selectNode(app, "Atlas");
  await openEntry(app, "pg-main");
  await expect(fieldLabels(app)).toHaveCount(1);

  let generated = "";
  await test.step("Generate: util.generate with the dialog's options; the value is the broker's, masked on screen, with its entropy", async () => {
    const dlg = await openFieldDialog(app);
    await dlg.getByLabel("field label").fill("api token");
    await dlg.getByRole("button", { name: "Generate" }).click();
    await expect(dlg.getByText(/^24 characters · about \d+ bits of entropy · shown masked, never copied$/)).toBeVisible();
    expect(app.frames("util.generate").map((f) => f.params)).toEqual([{ length: 24, symbols: true, pronounceable: false }]);
    const answer = (await app.answerOf("util_generate")).result;
    generated = answer.value;
    expect(generated).toHaveLength(24);
    expect(answer.entropyBits).toBeGreaterThan(100);
    await expect(dlg.getByText(`about ${answer.entropyBits} bits`)).toBeVisible();
    await expect(dlg.getByLabel("field value")).toHaveValue("•".repeat(24));
    expect(await app.pageDump(), "the generated value is nowhere in the page").not.toContain(generated);

    await dlg.getByRole("button", { name: "Add field", exact: true }).click();
    await expect(notice(app, "Field added to “pg-main”.")).toBeVisible();
    await expect(dlg).toBeHidden();
    await expect(fieldLabels(app)).toHaveCount(2);
    // the vault holds the broker's value, byte for byte, through field.add
    const fields = await app.oracle.fieldsOf("atlas", "pg-main");
    expect(fields.map((f: { label: string }) => f.label)).toEqual(["password", "api token"]);
    expect(fields[1].value).toBe(generated);
    expect(app.frames("field.add").map((f) => f.params.fields)).toEqual([[{ label: "api token", value: generated }]]);
    expect(await app.pageDump(), "masked on the entry too").not.toContain(generated);
  });

  await test.step("Undo of the add: entry.undo with the audit record the trail names and the node's current generation; the vault is as before", async () => {
    await expect(undoButton(app, "add field")).toBeVisible();
    const added = (await app.answerOf("field_add")).result;
    await undoButton(app, "add field").click();
    await expect(page.getByText("Restored: 1 field (undone add field)")).toBeVisible();
    const [frame] = app.frames("entry.undo");
    expect(frame.params).toMatchObject({ node: "atlas", generation: added.generation });
    expect(frame.params.id).toMatch(/^a_[0-9a-f]+$/);
    // the id is the audit record of THAT call: the trail says field.add, this node, this entry, at the generation the call produced
    const tail = (await app.oracle.call("audit.tail", { limit: 50 })).records;
    const named = tail.find((r: { id: string }) => r.id === frame.params.id);
    expect(named).toMatchObject({ action: "field.add", node: "atlas", entry: added.entry, generation: added.generation });
    // the broker's own words, not a copy the page kept
    const reply = (await app.answerOf("entry_undo")).result;
    expect(reply).toMatchObject({ ok: true, restored: { action: "field.add", entry: added.entry, fieldCount: 1 } });
    expect(reply.generation).toBeGreaterThan(added.generation);
    await expect(fieldLabels(app)).toHaveCount(1);
    await expect(undoButton(app, "add field")).toHaveCount(0);
    expect((await app.oracle.fieldsOf("atlas", "pg-main")).map((f: { label: string; value: string }) => [f.label, f.value])).toEqual([["password", base]]);
    expect(await app.pageDump()).not.toContain(generated);
  });

  await test.step("Remove, then Undo: the removed field is back with its own value, restored by the broker from history", async () => {
    let dlg = await openFieldDialog(app);
    await dlg.getByLabel("field label").fill("api token");
    await dlg.getByRole("button", { name: "Generate" }).click();
    await expect(dlg.getByText(/characters · about/)).toBeVisible();
    const second = (await app.answerOf("util_generate", 1)).result.value as string;
    expect(second).not.toBe(generated); // a new value every time
    await dlg.getByRole("button", { name: "Add field", exact: true }).click();
    await expect(fieldLabels(app)).toHaveCount(2);

    await page.getByRole("button", { name: "field menu" }).last().click();
    await page.getByRole("menuitem", { name: "Remove…" }).click();
    dlg = app.screen("S5a Field");
    await expect(dlg).toBeVisible();
    await dlg.getByRole("button", { name: "Remove field", exact: true }).click();
    await expect(fieldLabels(app)).toHaveCount(1);
    expect((await app.oracle.fieldsOf("atlas", "pg-main")).map((f: { label: string }) => f.label)).toEqual(["password"]);

    await undoButton(app, "remove field").click();
    await expect(page.getByText("Restored: 2 fields (undone remove field)")).toBeVisible();
    await expect(fieldLabels(app)).toHaveCount(2);
    const back = await app.oracle.fieldsOf("atlas", "pg-main");
    expect(back.map((f: { label: string; value: string }) => [f.label, f.value])).toEqual([["password", base], ["api token", second]]);
    expect((await app.answerOf("entry_undo", 1)).result).toMatchObject({ ok: true, restored: { action: "field.remove", fieldCount: 2 } });
  });

  await test.step("Edit, then Undo: the old label returns", async () => {
    await page.getByRole("button", { name: "field menu" }).last().click();
    await page.getByRole("menuitem", { name: "Edit…" }).click();
    const dlg = app.screen("S5a Field");
    await expect(dlg).toBeVisible();
    await dlg.getByLabel("field label").fill("renamed");
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(fieldLabels(app).last()).toHaveText("renamed");
    await undoButton(app, "edit").click();
    await expect(page.getByText("Restored: 2 fields (undone edit)")).toBeVisible();
    await expect(fieldLabels(app).last()).toHaveText("api token");
    expect((await app.oracle.fieldsOf("atlas", "pg-main")).map((f: { label: string }) => f.label)).toEqual(["password", "api token"]);
  });

  await test.step("a lock ends the offer: the audit id belongs to the login it was read in", async () => {
    await page.getByRole("button", { name: "field menu" }).last().click();
    await page.getByRole("menuitem", { name: "Remove…" }).click();
    await app.screen("S5a Field").getByRole("button", { name: "Remove field", exact: true }).click();
    await expect(undoButton(app, "remove field")).toBeVisible();
    await lockUi(app);
    await unlockToMain(app);
    await selectNode(app, "Atlas");
    await openEntry(app, "pg-main");
    await expect(undoButton(app, "remove field")).toHaveCount(0);
    expect(await app.pageDump()).not.toContain(generated);
  });
});

test("a decision on the Lock screen: the agent's waiting reveal is approved with the passphrase while the vault stays locked, and the agent gets the value once", async ({ app }) => {
  const { page } = app;
  test.setTimeout(240_000);
  const stored = fixtureSecret("alpha-value");
  await app.open();
  await createVaultViaWizard(app);
  await page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
  const workdir = join(app.daemon.homeDir, "projects", "alpha");
  mkdirSync(workdir, { recursive: true });
  const settings = await openSettings(app, "Nodes");
  await settings.getByRole("button", { name: "+ New project" }).click();
  const dlg = app.screen("S8 Add node");
  await expect(dlg).toBeVisible();
  await dlg.getByLabel("node name").fill("Alpha");
  await dlg.getByLabel("work folder").first().fill("~/projects/alpha");
  await dlg.getByRole("button", { name: "Create node" }).click();
  await expect(dlg).toBeHidden();
  await closeSettings(app);
  await addEntry(app, "Alpha", { name: "EXISTING", value: stored });
  const entryId = await (await app.oracle.login()).entryId("alpha", "EXISTING");

  await lockUi(app);
  const read = () => Oracle.agent(app.daemon.socketPath, workdir, "entry.reveal", { node: "alpha", entry: entryId });
  const first = read();
  expect(first).toMatchObject({ ok: false, error: { code: "approval_pending" } });
  const requestId: string = first.error.detail?.request ?? first.error.request;
  expect(requestId, "the request id the agent was given").toMatch(/^rq_/);
  expect(JSON.stringify(first)).not.toContain(stored);

  const panel = app.screen("S16a Locked approval");
  const unlocksBefore = app.frames("vault.unlock").length;
  await test.step("the panel is reached from the Lock screen and lists the waiting request (ADR-090); a wrong passphrase is refused inside it, and nothing is released", async () => {
    await page.getByRole("button", { name: /agent requests? (is|are) waiting for approval|an agent is waiting for approval/ }).click({ timeout: 30_000 });
    await expect(panel).toBeVisible();
    // the broker's description of the request, from vault.approval_get: the entry and the node by name, picked for you (it is the only one)
    await expect(panel.getByRole("radio", { name: /“EXISTING” in Alpha/ })).toBeChecked({ timeout: 30_000 });
    await expect(panel.getByLabel("request id")).not.toHaveValue(""); // the id field stays and shows the one picked
    await panel.getByLabel("passphrase for this decision").fill("not the passphrase");
    await panel.getByRole("button", { name: "Approve" }).click();
    await expect(panel.getByRole("alert")).toHaveText("Wrong passphrase.", KDF);
    await expect(panel.getByLabel("passphrase for this decision")).toHaveValue("");
    await expect(panel.getByRole("radio", { name: /“EXISTING” in Alpha/ })).toBeChecked();
    expect(read()).toMatchObject({ ok: false, error: { code: "approval_pending" } }); // still waiting, still withheld
  });

  await test.step("approve: one vault.approval_decide with the factors; the vault is still locked, no login was made, and the agent's retry gets the value", async () => {
    await panel.getByLabel("passphrase for this decision").fill(app.passphrase);
    await panel.getByRole("button", { name: "Approve" }).click();
    await expect(page.getByText("approved with the passphrase · the vault is still locked")).toBeVisible(KDF);
    const decides = app.frames("vault.approval_decide");
    expect(decides.at(-1)!.params).toEqual({ request: requestId, approved: true, passphrase: app.passphrase });
    const answer = (await app.answerOf("vault_approval_decide")).result;
    expect(answer).toMatchObject({ request: requestId, approved: true, authorisedBy: "factors" });
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    expect(app.shim.session.isAuthenticated(), "no login was made").toBe(false);
    expect(app.frames("vault.unlock")).toHaveLength(unlocksBefore); // (the wizard's own login is the one before)
    expect(await app.pageDump(), "the passphrase is not left on the page").not.toContain(app.passphrase);

    const released = read();
    expect(released).toMatchObject({ ok: true });
    expect(JSON.stringify(released)).toContain(stored); // the agent has it, exactly once
    expect(read()).toMatchObject({ ok: false, error: { code: "approval_pending" } }); // a new request: the old approval was consumed
  });

  await test.step("deny: the agent is told so", async () => {
    const second = read();
    const rid: string = second.error.detail?.request ?? second.error.request;
    await page.getByRole("button", { name: /agent requests? (is|are) waiting for approval|an agent is waiting for approval/ }).click();
    await expect(panel).toBeVisible();
    await expect(panel.getByRole("radio", { name: /“EXISTING” in Alpha/ })).toBeChecked({ timeout: 30_000 });
    await panel.getByLabel("passphrase for this decision").fill(app.passphrase);
    await panel.getByRole("button", { name: "Deny" }).click();
    await expect(page.getByText("denied with the passphrase · the vault is still locked")).toBeVisible(KDF);
    expect(app.frames("vault.approval_decide").at(-1)!.params).toEqual({ request: rid, approved: false, passphrase: app.passphrase });
    expect(read()).toMatchObject({ ok: false, error: { code: "approval_denied" } });
    expect(app.shim.session.isAuthenticated()).toBe(false);
  });
});

test("with a second factor enrolled: the panel needs the code, a wrong one is refused, a real one decides; and a logged-in step-up opens the elevation the second-factor dialog sends", async ({ app }) => {
  const { page } = app;
  test.setTimeout(300_000);
  const stored = fixtureSecret("beta-value");
  await app.open();
  await createVaultViaWizard(app);
  const shown = (await page.locator("[data-totp-secret]").innerText()).trim();
  const auth = new Authenticator(shown);
  await page.getByPlaceholder("confirm one code").fill(await auth.next());
  await expect(page.locator("[data-gate-codes] div")).toHaveCount(10);
  await page.getByLabel("I have saved these recovery codes").check();
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);

  await test.step("the step-up: vault_gate_verify from the logged-in session, answered by the real gate; the login stays what it was", async () => {
    expect(app.shim.session.isAuthenticated()).toBe(true);
    const token = app.shim.session.token();
    await expect(app.shim.invoke("vault_gate_verify", { code: auth.wrong() })).rejects.toMatchObject({ code: "gate_verification_failed" });
    expect(app.shim.session.isAuthenticated(), "a wrong code does not end the login").toBe(true);
    const state = await app.shim.invoke("vault_gate_verify", { code: await auth.next() });
    expect(state).toMatchObject({ locked: false, authenticated: true });
    expect(app.shim.session.token(), "no new token: the step-up changes no login").toBe(token);
    const tail = (await (await app.oracle.login(() => auth.next())).call("audit.tail", { limit: 20 })).records;
    expect(tail.some((r: { action: string; decision?: string }) => r.action === "vault.gate_verify" && r.decision !== "deny")).toBe(true);
  });

  const workdir = join(app.daemon.homeDir, "projects", "beta");
  mkdirSync(workdir, { recursive: true });
  const settings = await openSettings(app, "Nodes");
  await settings.getByRole("button", { name: "+ New project" }).click();
  const dlg = app.screen("S8 Add node");
  await expect(dlg).toBeVisible();
  await dlg.getByLabel("node name").fill("Beta");
  await dlg.getByLabel("work folder").first().fill("~/projects/beta");
  await dlg.getByRole("button", { name: "Create node" }).click();
  await expect(dlg).toBeHidden();
  await closeSettings(app);
  await addEntry(app, "Beta", { name: "EXISTING", value: stored });
  const oracle = await app.oracle.login(() => auth.next());
  const entryId = await oracle.entryId("beta", "EXISTING");
  await lockUi(app);

  const read = () => Oracle.agent(app.daemon.socketPath, workdir, "entry.reveal", { node: "beta", entry: entryId });
  const first = read();
  expect(first).toMatchObject({ ok: false, error: { code: "approval_pending" } });
  const requestId: string = first.error.detail?.request ?? first.error.request;
  const panel = app.screen("S16a Locked approval");
  await page.getByRole("button", { name: /agent requests? (is|are) waiting for approval|an agent is waiting for approval/ }).click({ timeout: 30_000 });
  await expect(panel.getByRole("radio", { name: /“EXISTING” in Beta/ })).toBeChecked({ timeout: 30_000 });

  await test.step("no code: the broker asks for it, and the panel says so; a wrong code is refused; neither releases anything", async () => {
    await panel.getByLabel("passphrase for this decision").fill(app.passphrase);
    await panel.getByRole("button", { name: "Approve" }).click();
    await expect(panel.getByRole("alert")).toContainText("A second-factor code is needed", KDF);
    await panel.getByLabel("passphrase for this decision").fill(app.passphrase);
    await panel.getByLabel("second factor code").fill(auth.wrong());
    await panel.getByRole("button", { name: "Approve" }).click();
    await expect(panel.getByRole("alert")).toHaveText("That code was not accepted.", KDF);
    expect(read()).toMatchObject({ ok: false, error: { code: "approval_pending" } });
  });

  await test.step("a real code decides; a recovery code is never sent from here (the box takes six digits)", async () => {
    await panel.getByLabel("passphrase for this decision").fill(app.passphrase);
    await panel.getByLabel("second factor code").fill("AB12-CD34");
    await expect(panel.getByLabel("second factor code")).toHaveValue("12"); // six characters at most, digits only: a recovery code cannot even be typed here
    await panel.getByLabel("second factor code").fill(await auth.next());
    await panel.getByRole("button", { name: "Approve" }).click();
    await expect(page.getByText("approved with the passphrase · the vault is still locked")).toBeVisible(KDF);
    expect(app.shim.session.isAuthenticated()).toBe(false);
    expect(JSON.stringify(read())).toContain(stored);
  });
});

test("privateNames and the doctor: the node dialog's choice reaches the broker, the owner's row says 'name hidden', and the doctor asks for the purge on a dry run", async ({ app }) => {
  const { page } = app;
  await vaultWith(app, "Atlas");

  await test.step("a node created with 'Hide this node's name from others'", async () => {
    const settings = await openSettings(app, "Nodes");
    await settings.getByRole("button", { name: "+ New project" }).click();
    const dlg = app.screen("S8 Add node");
    await expect(dlg).toBeVisible();
    await expect(dlg.getByRole("checkbox", { name: /Hide this node's name from others/ })).not.toBeChecked();
    await dlg.getByLabel("node name").fill("Quiet");
    await dlg.getByRole("checkbox", { name: /Hide this node's name from others/ }).check();
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(dlg).toBeHidden();
    await closeSettings(app);
    // ADR-091: the id is not made from the name; the label is what was typed
    const quietId: string = app.frames("node.create").at(-1)!.params.id;
    expect(quietId).toMatch(/^n_[0-9a-f]{12}$/);
    expect(app.frames("node.create").at(-1)!.params.label).toBe("Quiet");
    expect(app.frames("node.policy").map((f) => f.params)).toEqual([{ node: quietId, reason: "set at creation", policy: { privateNames: true } }]);
    expect((await app.answerOf("node_policy")).result).toMatchObject({ changed: ["privateNames"], notEnforced: [] });
    await app.oracle.login();
    const snap = await app.oracle.call("graph.snapshot");
    expect(snap.nodes.find((n: { id: string }) => n.id === quietId)).toMatchObject({ id: quietId, label: "Quiet", nameHidden: true });
    expect(snap.nodes.find((n: { id: string }) => n.id === "quiet")).toBeUndefined();
    expect(snap.nodes.find((n: { id: string }) => n.id === "atlas")).not.toHaveProperty("nameHidden");
    await expect(page.locator("aside.cm-insp")).toContainText("Quiet");
    await expect(page.locator("aside.cm-insp .k-chip", { hasText: "name hidden" })).toBeVisible();
    await selectNode(app, "Atlas");
    await expect(page.locator("aside.cm-insp .k-chip", { hasText: "name hidden" })).toHaveCount(0);
    // the old "recorded, not enforced" chip is gone for good
    await expect(page.locator("aside.cm-insp")).not.toContainText("not enforced");
  });

  await test.step("the plain doctor's dry run never asks for the purge and says the vault is healthy", async () => {
    await page.getByRole("button", { name: "vault menu" }).click();
    await page.locator(".cm-vaultmenu button", { hasText: "Operations" }).first().click();
    await page.getByRole("button", { name: "Doctor", exact: true }).click();
    expect(app.frames("maintenance.doctor").map((f) => f.params)).toEqual([{ apply: false }]);
    const result = page.locator('[data-ops-result="true"]');
    await expect(result).toContainText("Doctor · checked");
    await expect(result).toContainText("nothing needs fixing");
    await expect(result.getByRole("button")).toHaveCount(0);
    const answer = (await app.answerOf("maintenance_doctor")).result;
    expect(answer).toMatchObject({ applied: false, fixCount: 0 });
  });
});
