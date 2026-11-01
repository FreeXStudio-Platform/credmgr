/**
 * The 2026-10-25 design drop's controls, driven against the fixture broker:
 *
 *   D10 Undo           after Add field / Edit / Remove the entry offers Undo; it sends entry.undo with the audit record the trail names and the
 *                      node's CURRENT generation, and says what the BROKER restored
 *   D11 Generate       Add field's Generate sends util.generate (the broker makes the value), shows it MASKED with its entropy, never as text,
 *                      and the value reaches the entry only through field.add
 *   D12 second factor  a reveal the broker answers two_factor_required opens the dialog; the code is sent as vault.gate_verify (the step-up) and
 *                      the refused call is repeated once; a node at level `always` also refuses lists, which the inspector says
 *   D13 approval       the Lock screen's panel decides an agent's waiting request with vault.approval_decide while the vault stays locked
 *   privateNames       the node dialog's checkbox goes to node.policy; the owner's row says "name hidden"
 *   doctor             the dry run asks for purgeExpiredSeals and lists what it would remove
 *
 * For each: the EXACT command and arguments, what the screen renders from the answer, and the refusals.  The flows that need a real broker are in
 * tests/real/gates.spec.ts.
 */
import { FIXTURE_GATE_CODE, FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import { dialogReady, fieldRow, fieldRows, openApp, openEntryOf, openMenu, PG, PG_VALUE, valueOf } from "./field-ui-helpers";
import { expect, test, type App } from "./harness";
import { lockAndUnlock, openAddNode, stateJson } from "./wp-c-util";
import { notice as noticeBy } from "./wp-b-helpers";
import { openOps } from "./wp-d-helpers";

const tfDialog = (app: App) => app.screen("S5c Second factor");
const undoButton = (app: App, what: string) => app.page.getByRole("button", { name: `Undo ${what}`, exact: true });

/** The audit record the fixture wrote last, by action. */
async function lastAudit(app: App, action: string): Promise<{ id: string; generation?: number }> {
  const state: any = await app.broker!.state();
  const rec = [...state.audit].reverse().find((r: any) => r.action === action);
  expect(rec, `no ${action} record in the trail`).toBeTruthy();
  return rec;
}

// ───────────────────────────── D10: Undo ─────────────────────────────

test.describe("Undo after a change to a field", () => {
  test("Add field: the link appears, sends entry.undo with the audit record and the CURRENT generation, and the entry is the broker's again", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await expect(undoButton(app, "add field")).toHaveCount(0); // nothing to undo yet
    await page.getByRole("button", { name: "+ Add field" }).click();
    const dlg = await dialogReady(app);
    await dlg.getByLabel("field label").fill("replica");
    await dlg.getByLabel("field value").fill("fixture-value-replica.example.test");
    await dlg.getByRole("button", { name: "Add field", exact: true }).click();
    await expect(fieldRows(app)).toHaveCount(6);
    await expect(undoButton(app, "add field")).toBeVisible();

    const added = await lastAudit(app, "field.add");
    expect(added.generation).toBe(2);
    await undoButton(app, "add field").click();

    // the audit id came from the change's own answer (ADR-091), so the trail was not read; then ONE entry.undo at the node's current generation
    expect(await broker.calls("audit_tail")).toEqual([]);
    expect(await broker.calls("entry_undo")).toEqual([{ cmd: "entry_undo", args: { node: "atlas", id: added.id, generation: 2 } }]);
    // the words are the broker's reply (the field count it restored), the entry is read again, and the link is gone
    await expect(page.getByText("Restored: 5 fields (undone add field)")).toBeVisible();
    await expect(fieldRows(app)).toHaveCount(5);
    await expect(undoButton(app, "add field")).toHaveCount(0);
    await expect(page.locator('[data-fields="true"]')).not.toContainText("replica");
    expect(await stateJson(app)).not.toContain("fixture-value-replica");
    expect(await app.storageDump()).not.toContain("fixture-value-replica");
  });

  test("Edit: undone, the field has its old label back; the old value is never shown on the way", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await (await openMenu(app, PG.note)).getByRole("menuitem", { name: "Edit…" }).click();
    const dlg = await dialogReady(app);
    await dlg.getByLabel("field label").fill("remarks");
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.locator('[data-fields="true"] [data-field-label="true"]').last()).toHaveText("remarks");
    await undoButton(app, "edit").click();
    await expect(page.locator('[data-fields="true"] [data-field-label="true"]').last()).toHaveText("note");
    await expect(page.getByText("Restored: 5 fields (undone edit)")).toBeVisible();
    const update = await lastAudit(app, "field.update");
    expect((await broker.calls("entry_undo"))[0].args).toMatchObject({ node: "atlas", id: update.id });
  });

  test("Remove: undone, the removed field is back, in its place", async ({ app }) => {
    const { page } = app;
    await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await (await openMenu(app, PG.user)).getByRole("menuitem", { name: "Remove…" }).click();
    const dlg = await dialogReady(app);
    await dlg.getByRole("button", { name: "Remove field", exact: true }).click();
    await expect(fieldRows(app)).toHaveCount(4);
    await expect(fieldRow(app, PG.user)).toHaveCount(0);
    await undoButton(app, "remove field").click();
    await expect(fieldRows(app)).toHaveCount(5);
    await expect(fieldRow(app, PG.user)).toBeVisible();
    await expect(valueOf(app, PG.user)).toHaveText(PG_VALUE.user);
    await expect(page.getByText("Restored: 5 fields (undone remove field)")).toBeVisible();
  });

  test("the link belongs to the entry it was made in, to this login, and to nothing else: another entry, a lock, a second change", async ({ app }) => {
    await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await (await openMenu(app, PG.note)).getByRole("menuitem", { name: "Remove…" }).click();
    await (await dialogReady(app)).getByRole("button", { name: "Remove field", exact: true }).click();
    await expect(undoButton(app, "remove field")).toBeVisible();
    // another entry: no link
    await openEntryOf(app, "atlas", "stripe-live");
    await expect(undoButton(app, "remove field")).toHaveCount(0);
    // a lock ends the login the audit id belongs to
    await openEntryOf(app, "atlas", "pg-main");
    await expect(undoButton(app, "remove field")).toBeVisible();
    await lockAndUnlock(app);
    await openEntryOf(app, "atlas", "pg-main");
    await expect(undoButton(app, "remove field")).toHaveCount(0);
    // a second change replaces the first: only the newest can be undone
    await (await openMenu(app, PG.port)).getByRole("menuitem", { name: "Remove…" }).click();
    await (await dialogReady(app)).getByRole("button", { name: "Remove field", exact: true }).click();
    await expect(undoButton(app, "remove field")).toHaveCount(1);
    await (await openMenu(app, PG.user)).getByRole("menuitem", { name: "Remove…" }).click();
    await (await dialogReady(app)).getByRole("button", { name: "Remove field", exact: true }).click();
    await expect(undoButton(app, "remove field")).toHaveCount(1);
  });

  test("a change that can no longer be undone (after seven days) or a node that moved on is refused in the broker's words and the link goes", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await (await openMenu(app, PG.note)).getByRole("menuitem", { name: "Remove…" }).click();
    await (await dialogReady(app)).getByRole("button", { name: "Remove field", exact: true }).click();
    await broker.set({ undoExpired: true });
    await undoButton(app, "remove field").click();
    await expect(noticeBy(app, "That can no longer be undone. Reloaded.")).toBeVisible();
    await expect(undoButton(app, "remove field")).toHaveCount(0);
    await expect(fieldRows(app)).toHaveCount(4); // nothing was put back, and the screen says what the broker holds
    await broker.set({ undoExpired: false });

    // a conflict: the node moved on between the change and the undo
    await (await openMenu(app, PG.port)).getByRole("menuitem", { name: "Remove…" }).click();
    await (await dialogReady(app)).getByRole("button", { name: "Remove field", exact: true }).click();
    await broker.script("entry_undo", { error: { code: "conflict", detail: { node: "atlas" } } });
    await undoButton(app, "remove field").click();
    await expect(noticeBy(app, "Changed elsewhere. Reloaded; try again.")).toBeVisible();
    await expect(undoButton(app, "remove field")).toHaveCount(0);
    await expect(page.locator("[data-notice]")).toHaveCount(1);
  });

  test("when the broker's answer carries no audit id there is no Undo, and nothing is guessed from the trail", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await broker.script("field_remove", { result: { node: "atlas", entry: PG.entry, generation: 2, fieldCount: 4, fieldIds: [] } });
    await (await openMenu(app, PG.note)).getByRole("menuitem", { name: "Remove…" }).click();
    await (await dialogReady(app)).getByRole("button", { name: "Remove field", exact: true }).click();
    await expect(undoButton(app, "remove field")).toHaveCount(0);
    expect(await broker.calls("entry_undo")).toEqual([]);
    expect(await broker.calls("audit_tail")).toEqual([]); // never searched for
  });
});

// ───────────────────────────── D11: Generate ─────────────────────────────

test.describe("Generate in Add field", () => {
  test("asks the broker, shows the value masked with its entropy and never as text, and the entry gets it through field.add only", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await page.getByRole("button", { name: "+ Add field" }).click();
    const dlg = await dialogReady(app);
    await expect(dlg.getByLabel("generated length")).toHaveValue("24");
    await expect(dlg.getByLabel("symbols")).toBeChecked();
    await expect(dlg.getByLabel("pronounceable")).not.toBeChecked();
    await dlg.getByLabel("field label").fill("token");
    await dlg.getByRole("button", { name: "Generate" }).click();

    expect(await broker.calls("util_generate")).toEqual([{ cmd: "util_generate", args: { length: 24, symbols: true, pronounceable: false } }]);
    await expect(dlg.getByText("24 characters · about 150 bits of entropy · shown masked, never copied")).toBeVisible();
    const box = dlg.getByLabel("field value");
    await expect(box).toHaveValue("•".repeat(24));
    await expect(box).toHaveJSProperty("readOnly", true);
    // the value is in no DOM, no state, no storage: the page holds it only as the form's value, which is not a binding
    expect(await page.content()).not.toContain("fixture-generated-");
    expect(await app.storageDump()).not.toContain("fixture-generated-");
    expect(await dlg.innerText()).not.toContain("fixture-generated-");

    await dlg.getByRole("button", { name: "Add field", exact: true }).click();
    await expect(dlg).toBeHidden();
    const sent = (await broker.calls("field_add"))[0].args as any;
    expect(sent.fields).toHaveLength(1);
    expect(sent.fields[0].label).toBe("token");
    expect(sent.fields[0].value).toMatch(/^fixture-generated-\d+-/); // the broker's value, byte for byte, with no trimming or masking on the way
    expect(sent.fields[0].value).toHaveLength(24);
    const held = ((await broker.state()).entries.atlas.find((e) => e.id === PG.entry) as any).fields.at(-1);
    expect(held.value).toBe(sent.fields[0].value);
    // the dialog's form is gone with it
    expect(await stateJson(app)).not.toContain("fixture-generated-");
    expect(await app.storageDump()).not.toContain("fixture-generated-");
    await expect(noticeBy(app, "Field added to “pg-main”.")).toBeVisible();
    await expect(noticeBy(app, /fixture-generated/)).toHaveCount(0);
  });

  test("length, symbols and pronounceable are what is sent; Clear gives back an empty, editable value", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await page.getByRole("button", { name: "+ Add field" }).click();
    const dlg = await dialogReady(app);
    await dlg.getByLabel("generated length").fill("40");
    await dlg.getByLabel("symbols").uncheck();
    await dlg.getByLabel("pronounceable").check();
    await expect(dlg.getByLabel("symbols")).not.toBeChecked();
    await dlg.getByRole("button", { name: "Generate" }).click();
    expect((await broker.calls("util_generate")).at(-1)).toEqual({ cmd: "util_generate", args: { length: 40, symbols: false, pronounceable: true } });
    await expect(dlg.getByText(/40 characters · about \d+ bits of entropy/)).toBeVisible();
    const box = dlg.getByLabel("field value");
    await expect(box).toHaveValue("•".repeat(32)); // bounded: the mask is not a ruler for the length
    // a generated value cannot be edited by typing: Clear first
    await dlg.getByRole("button", { name: "Clear", exact: true }).click();
    await expect(box).toHaveValue("");
    await expect(box).toHaveJSProperty("readOnly", false);
    await expect(dlg.getByRole("button", { name: "Add field", exact: true })).toBeDisabled();
    await box.fill("typed by hand");
    await expect(dlg.getByRole("button", { name: "Add field", exact: true })).toBeEnabled();
  });

  test("a length outside 8..128 is clamped before it is sent; a refusal is a notice and leaves the value empty", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await page.getByRole("button", { name: "+ Add field" }).click();
    const dlg = await dialogReady(app);
    await dlg.getByLabel("generated length").fill("3");
    await dlg.getByRole("button", { name: "Generate" }).click();
    expect((await broker.calls("util_generate")).at(-1)!.args).toMatchObject({ length: 8 });
    await dlg.getByRole("button", { name: "Clear", exact: true }).click();
    await dlg.getByLabel("generated length").fill("500");
    await dlg.getByRole("button", { name: "Generate" }).click();
    expect((await broker.calls("util_generate")).at(-1)!.args).toMatchObject({ length: 128 });
    await dlg.getByRole("button", { name: "Clear", exact: true }).click();
    await broker.script("util_generate", { error: { code: "capability_not_held", detail: { rule: "create or update is not granted" } } });
    await dlg.getByRole("button", { name: "Generate" }).click();
    await expect(noticeBy(app, "Not permitted (create or update is not granted).")).toBeVisible();
    await expect(dlg.getByLabel("field value")).toHaveValue("");
    await expect(dlg.getByRole("button", { name: "Add field", exact: true })).toBeDisabled();
  });

  test("Edit has no generator", async ({ app }) => {
    await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await (await openMenu(app, PG.note)).getByRole("menuitem", { name: "Edit…" }).click();
    const dlg = await dialogReady(app);
    await expect(dlg.getByRole("button", { name: "Generate" })).toHaveCount(0);
  });
});

// ───────────────────────────── D12: the second factor after the login ─────────────────────────────

async function openWithFactorGate(app: App, tfLevels: Record<string, string> = {}) {
  const broker = (await app.open({ broker: { locked: false, gate: true, gateCode: FIXTURE_GATE_CODE } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await broker.set({ factorGate: true, tfLevels });
  return broker;
}

test.describe("a node that requires a second factor", () => {
  test("a refused reveal opens the dialog; a wrong code is said inside it; the right one is sent as vault.gate_verify and the reveal is repeated ONCE", async ({ app }) => {
    const { page } = app;
    const broker = await openWithFactorGate(app);
    await openEntryOf(app, "atlas", "pg-main");
    const dlg = tfDialog(app);
    await expect(dlg).toBeVisible();
    await expect(dlg).toContainText("the node “atlas” requires a second factor to reveal");
    expect(await broker.calls("entry_reveal")).toHaveLength(1); // asked once, refused
    await expect(valueOf(app, PG.host)).not.toHaveText(PG_VALUE.host); // nothing is shown before the broker accepts a code

    const code = dlg.getByLabel("second factor code");
    await expect(code).toBeFocused();
    await expect(dlg.getByRole("button", { name: "Verify and reveal" })).toBeDisabled();
    await code.fill("123");
    await expect(dlg.getByRole("button", { name: "Verify and reveal" })).toBeDisabled(); // six digits, no fewer
    await code.fill("000000");
    await dlg.getByRole("button", { name: "Verify and reveal" }).click();
    await expect(dlg.getByRole("alert")).toHaveText("That code was not accepted.");
    await expect(code).toHaveValue(""); // a code is single-use: gone
    expect(await broker.calls("entry_reveal")).toHaveLength(1); // a wrong code repeats nothing

    await code.fill(FIXTURE_GATE_CODE);
    await dlg.getByRole("button", { name: "Verify and reveal" }).click();
    await expect(dlg).toBeHidden();
    expect((await broker.calls("vault_gate_verify")).map((c) => c.args)).toEqual([{ code: "000000" }, { code: FIXTURE_GATE_CODE }]);
    await expect(valueOf(app, PG.host)).toHaveText(PG_VALUE.host);
    expect(await broker.calls("entry_reveal")).toHaveLength(2); // the refused call, repeated once
    // no code in the page afterwards
    expect(await stateJson(app)).not.toContain(FIXTURE_GATE_CODE);
    expect(await app.storageDump()).not.toContain(FIXTURE_GATE_CODE);
    void page;
  });

  test("Cancel repeats nothing and sends nothing; the Reveal button asks again, and the right code reveals the field", async ({ app }) => {
    const { page } = app;
    const broker = await openWithFactorGate(app);
    await openEntryOf(app, "atlas", "pg-main");
    const dlg = tfDialog(app);
    await expect(dlg).toBeVisible();
    await dlg.getByRole("button", { name: "Cancel" }).click();
    await expect(dlg).toBeHidden();
    expect(await broker.calls("vault_gate_verify")).toEqual([]);
    expect(await broker.calls("entry_reveal")).toHaveLength(1); // no loop

    await fieldRow(app, PG.password).getByRole("button", { name: "reveal", exact: true }).click();
    await expect(dlg).toBeVisible();
    await dlg.getByLabel("second factor code").fill(FIXTURE_GATE_CODE);
    await dlg.getByRole("button", { name: "Verify and reveal" }).click();
    await expect(dlg).toBeHidden();
    await expect(valueOf(app, PG.password)).toHaveText(PG_VALUE.password);
    // the step-up holds: a second reveal does not ask again
    await fieldRow(app, PG.password).getByRole("button", { name: "hide" }).click();
    await fieldRow(app, PG.password).getByRole("button", { name: "reveal", exact: true }).click();
    await expect(valueOf(app, PG.password)).toHaveText(PG_VALUE.password);
    await expect(dlg).toBeHidden();
    expect(await broker.calls("vault_gate_verify")).toHaveLength(1);
    void page;
  });

  test("a rate limit is the broker's wait, said inside the dialog; a lost login ends at the Lock screen with the dialog gone", async ({ app }) => {
    const broker = await openWithFactorGate(app);
    await openEntryOf(app, "atlas", "pg-main");
    const dlg = tfDialog(app);
    await expect(dlg).toBeVisible();
    await broker.script("vault_gate_verify", { error: { code: "rate_limited", detail: { retryAfterSeconds: 30 } } });
    await dlg.getByLabel("second factor code").fill("123456");
    await dlg.getByRole("button", { name: "Verify and reveal" }).click();
    await expect(dlg.getByRole("alert")).toHaveText("Too many attempts. Try again in 30 s.");
    await broker.script("vault_gate_verify", { error: { code: "session_expired" } });
    await dlg.getByLabel("second factor code").fill("123456");
    await dlg.getByRole("button", { name: "Verify and reveal" }).click();
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    await expect(tfDialog(app)).toHaveCount(0);
    expect((await broker.calls("entry_reveal")).length).toBe(1); // the refused call never ran again
  });

  test("a node at level 'always' that refuses its list says so in the inspector, with a way to give the factor; the list is read again after it", async ({ app }) => {
    const { page } = app;
    const broker = (await app.open({ broker: { locked: false, gate: true, gateCode: FIXTURE_GATE_CODE } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    await page.locator(".cm-rail .k-tree-row", { hasText: "beacon" }).first().click();
    await expect(page.locator("aside.cm-insp button.k-entry", { hasText: "registry-token" })).toBeVisible();
    await broker.set({ factorGate: true, tfLevels: { beacon: "always" } });
    await page.evaluate(() => (window as any).__cm.model.refresh({ graph: true, nodes: ["beacon"] }));
    const panel = page.locator('[data-node-unreadable="two_factor_required"]');
    await expect(panel).toBeVisible();
    await expect(panel).toContainText("asks for a second factor before it lists its entries");
    await expect(panel).toContainText("not the same as having none");
    await expect(page.locator("aside.cm-insp button.k-entry", { hasText: "registry-token" })).toHaveCount(0);

    await panel.getByRole("button", { name: "Give second factor" }).click();
    const dlg = tfDialog(app);
    await expect(dlg).toBeVisible();
    await dlg.getByLabel("second factor code").fill(FIXTURE_GATE_CODE);
    await dlg.getByRole("button", { name: "Verify and reveal" }).click();
    await expect(dlg).toBeHidden();
    await expect(page.locator("aside.cm-insp button.k-entry", { hasText: "registry-token" })).toBeVisible();
    await expect(panel).toHaveCount(0);
  });

  test("the inspector shows the node's second-factor chip, and not the old 'not enforced' one", async ({ app }) => {
    await openApp(app);
    await app.page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
    await expect(app.page.locator("aside.cm-insp .k-chip", { hasText: "2fa · on reveal" })).toBeVisible();
    await expect(app.page.locator("aside.cm-insp").getByRole("button", { name: "Give second factor" })).toBeVisible();
    await expect(app.page.locator("aside.cm-insp")).not.toContainText("not enforced");
  });
});

// ───────────────────────────── D13: a decision while locked ─────────────────────────────

test.describe("an agent's waiting request, decided on the Lock screen", () => {
  async function lockedWithRequest(app: App, options: { gate?: boolean } = {}) {
    const broker = (await app.open({ broker: { locked: true, gate: options.gate, gateCode: FIXTURE_GATE_CODE, approvals: { rq_fixture0001: { node: "atlas", entry: "e-a1" } } } }))!;
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    return broker;
  }
  const panel = (app: App) => app.screen("S16a Locked approval");
  async function openPanel(app: App) {
    await app.page.getByRole("button", { name: "1 agent request is waiting for approval" }).click();
    await expect(panel(app)).toBeVisible();
  }

  test("approve: the listed request, the passphrase and the decision go in one vault.approval_decide; the vault is still locked and nothing was unlocked", async ({ app }) => {
    const { page } = app;
    const broker = await lockedWithRequest(app);
    await openPanel(app);
    // the request is listed by the names the broker gave; the id field only shows the one picked
    await expect(panel(app).getByRole("radio", { name: /“stripe-live” in atlas/ })).toBeChecked();
    await expect(panel(app).getByLabel("request id")).toHaveValue("rq_fixture0001");
    await expect(panel(app).getByRole("button", { name: "Approve" })).toBeDisabled(); // a request alone decides nothing
    await panel(app).getByLabel("passphrase for this decision").fill(FIXTURE_PASSPHRASE);
    await panel(app).getByRole("button", { name: "Approve" }).click();

    expect(await broker.calls("vault_approval_decide")).toEqual([{ cmd: "vault_approval_decide", args: { request: "rq_fixture0001", approved: true, passphrase: FIXTURE_PASSPHRASE } }]);
    await expect(page.getByText("approved with the passphrase · the vault is still locked")).toBeVisible();
    await expect(panel(app)).toHaveCount(0); // closed; the passphrase went with it
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    expect(await broker.calls("vault_unlock")).toEqual([]); // no login was made
    const state: any = await broker.state();
    expect(state.locked).toBe(true);
    expect(state.decisions).toEqual([{ request: "rq_fixture0001", approved: true, viaFactors: true }]);
    expect(state.audit.at(-1)).toMatchObject({ action: "vault.approval_decide", actor: "Factors" });
    expect(await stateJson(app)).not.toContain(FIXTURE_PASSPHRASE);
    expect(await page.content()).not.toContain(FIXTURE_PASSPHRASE);
    expect(await app.storageDump()).not.toContain(FIXTURE_PASSPHRASE);
  });

  test("deny: the same call with approved false", async ({ app }) => {
    const broker = await lockedWithRequest(app);
    await openPanel(app);
    await panel(app).getByLabel("passphrase for this decision").fill(FIXTURE_PASSPHRASE);
    await panel(app).getByRole("button", { name: "Deny" }).click();
    expect((await broker.calls("vault_approval_decide"))[0].args).toEqual({ request: "rq_fixture0001", approved: false, passphrase: FIXTURE_PASSPHRASE });
    await expect(app.page.getByText("denied with the passphrase · the vault is still locked")).toBeVisible();
  });

  test("a wrong passphrase is said inside the panel, the passphrase is gone, the request stays picked for another try; a request that is gone is said in the broker's words", async ({ app }) => {
    const broker = await lockedWithRequest(app);
    await openPanel(app);
    await panel(app).getByLabel("passphrase for this decision").fill("not the passphrase");
    await panel(app).getByRole("button", { name: "Approve" }).click();
    await expect(panel(app).getByRole("alert")).toHaveText("Wrong passphrase.");
    await expect(panel(app).getByLabel("passphrase for this decision")).toHaveValue("");
    await expect(panel(app).getByRole("radio", { name: /“stripe-live” in atlas/ })).toBeChecked();
    await expect(panel(app)).toBeVisible();
    expect((await broker.state() as any).decisions ?? []).toEqual([]);

    await broker.script("vault_approval_decide", { error: { code: "not_found" } });
    await panel(app).getByLabel("passphrase for this decision").fill(FIXTURE_PASSPHRASE);
    await panel(app).getByRole("button", { name: "Approve" }).click();
    await expect(panel(app).getByRole("alert")).toHaveText("There is no waiting approval with that request id.");
    expect((await broker.state() as any).locked).toBe(true);
  });

  test("with a second factor enrolled: no code is needed to type the panel, the broker asks, a wrong code is refused, the right one decides; a recovery-length code is never sent", async ({ app }) => {
    const broker = await lockedWithRequest(app, { gate: true });
    await openPanel(app);
    await panel(app).getByLabel("passphrase for this decision").fill(FIXTURE_PASSPHRASE);
    await panel(app).getByRole("button", { name: "Approve" }).click();
    await expect(panel(app).getByRole("alert")).toContainText("A second-factor code is needed");
    // a half code keeps the buttons off; six digits is the most the box takes
    await panel(app).getByLabel("passphrase for this decision").fill(FIXTURE_PASSPHRASE);
    await panel(app).getByLabel("second factor code").fill("12ab34");
    await expect(panel(app).getByLabel("second factor code")).toHaveValue("1234");
    await expect(panel(app).getByRole("button", { name: "Approve" })).toBeDisabled();
    await panel(app).getByLabel("second factor code").fill("000000");
    await panel(app).getByRole("button", { name: "Approve" }).click();
    await expect(panel(app).getByRole("alert")).toHaveText("That code was not accepted.");
    await panel(app).getByLabel("passphrase for this decision").fill(FIXTURE_PASSPHRASE);
    await panel(app).getByLabel("second factor code").fill(FIXTURE_GATE_CODE);
    await panel(app).getByRole("button", { name: "Approve" }).click();
    await expect(app.page.getByText("approved with the passphrase · the vault is still locked")).toBeVisible();
    expect((await broker.calls("vault_approval_decide")).map((c) => c.args.code)).toEqual([undefined, "000000", FIXTURE_GATE_CODE]); // (the first had none: the broker asked for it)
    expect((await broker.state() as any).decisions).toEqual([{ request: "rq_fixture0001", approved: true, viaFactors: true }]);
  });

  test("the panel is a link on the passphrase step; Close wipes what was typed; a lock after unlocking leaves it closed and empty", async ({ app }) => {
    await lockedWithRequest(app);
    await openPanel(app);
    await panel(app).getByLabel("passphrase for this decision").fill("typed but not sent");
    await panel(app).getByRole("button", { name: "Close" }).click();
    await expect(panel(app)).toHaveCount(0);
    await expect(app.page.getByRole("button", { name: "1 agent request is waiting for approval" })).toBeVisible();
    expect(await stateJson(app)).not.toContain("typed but not sent");
    await openPanel(app);
    await expect(panel(app).getByLabel("passphrase for this decision")).toHaveValue("");
    await app.page.getByRole("button", { name: "Close" }).click();
    await app.page.locator('input[type="password"]').fill(FIXTURE_PASSPHRASE);
    await app.page.getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(app.screen("S1 Main")).toBeVisible();
    await lockAndUnlock(app);
    await expect(app.screen("S1 Main")).toBeVisible();
  });
});

// ───────────────────────────── privateNames ─────────────────────────────

test.describe("privateNames", () => {
  test("the node dialog's checkbox goes to node.policy with the other narrowing choices; the owner's row says 'name hidden'", async ({ app }) => {
    const { page } = app;
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    const dlg = await openAddNode(app);
    const box = dlg.getByRole("checkbox", { name: /Hide this node's name from others/ });
    await expect(box).not.toBeChecked();
    await expect(dlg.getByRole("checkbox", { name: /Require second factor on reveal/ })).toBeChecked();
    await expect(dlg).not.toContainText("not yet enforced");
    await dlg.getByLabel("node name").fill("Quiet");
    await box.check();
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(dlg).toBeHidden();
    // ADR-091: the id is not made from the name; the label is what was typed
    const created = (await broker.calls("node_create"))[0].args as any;
    expect(created.id).toMatch(/^n_[0-9a-f]{12}$/);
    expect(created.label).toBe("Quiet");
    expect(await broker.calls("node_policy")).toEqual([{ cmd: "node_policy", args: { node: created.id, reason: "set at creation", policy: { privateNames: true } } }]);
    await expect(noticeBy(app, /were not applied/)).toHaveCount(0);
    const made = (await broker.state()).nodes.find((n) => n.id === created.id) as any;
    expect(made.policy.privateNames).toBe(true);
    // the snapshot row carries nameHidden:true, and the inspector says so
    await app.screen("S12 Settings").getByRole("button", { name: "Close", exact: true }).click();
    await expect(page.locator("aside.cm-insp")).toContainText("Quiet");
    await expect(page.locator("aside.cm-insp .k-chip", { hasText: "name hidden" })).toBeVisible();
    await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
    await expect(page.locator("aside.cm-insp .k-chip", { hasText: "name hidden" })).toHaveCount(0);
  });

  test("left unchecked it sends nothing; a refusal says the name stays visible, which is WIDER than chosen", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    let dlg = await openAddNode(app);
    await dlg.getByLabel("node name").fill("Plain");
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(dlg).toBeHidden();
    expect(await broker.calls("node_policy")).toEqual([]); // the defaults need no call
    await app.screen("S12 Settings").getByRole("button", { name: "Close", exact: true }).click();

    dlg = await openAddNode(app);
    await dlg.getByLabel("node name").fill("Shy");
    await dlg.getByRole("checkbox", { name: /Hide this node's name from others/ }).check();
    await broker.script("node_policy", { error: { code: "capability_not_held" } });
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(noticeBy(app, /hiding this node's name from others \(you chose on; it stays off\)/)).toBeVisible();
    await expect(noticeBy(app, /WIDER than you chose/)).toBeVisible();
  });
});

// ───────────────────────────── the doctor and expired seals ─────────────────────────────

test("Doctor with purge asks for the purge, lists what it would remove (node, when it was sealed), and Apply removes it for good", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await broker.set({ expiredSeals: [{ node: "old", sealedAt: 1750000000 }] });
  await openOps(app);
  await page.getByRole("button", { name: "Doctor with purge" }).click();
  const result = app.screen("S14 Operations");
  expect(await broker.calls("maintenance_doctor")).toEqual([{ cmd: "maintenance_doctor", args: { apply: false, purgeExpiredSeals: true } }]);
  await expect(result).toContainText("Doctor · purge expired seals");
  await expect(result).toContainText("1 fix would be applied");
  await expect(result).toContainText("old · would-purge-expired-seal");
  await expect(result).toContainText(/sealed 2025-06-1[56] \d\d:\d\d · the retained original would be removed for good/);
  await result.getByRole("button", { name: "Apply 1 fix" }).click();
  expect((await broker.calls("maintenance_doctor")).map((c) => c.args)).toEqual([{ apply: false, purgeExpiredSeals: true }, { apply: true, purgeExpiredSeals: true }]);
  await expect(result).toContainText("Doctor · applied");
  await expect(result).toContainText("old · purged-expired-seal");
  await expect(result).toContainText("the retained original was removed for good");
  expect((await broker.state() as any).expiredSeals).toEqual([]);
});
