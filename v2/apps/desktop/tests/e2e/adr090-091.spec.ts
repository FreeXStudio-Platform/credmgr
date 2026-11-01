/**
 * ADR-090 / ADR-091, driven against the fixture broker:
 *
 *   warnings        a name the broker accepted with `warnings: ["mixed_script_name"]` is said in the same notice, without blocking: entry, node, rename
 *   private ids     a node created with "Hide this node's name" gets an opaque id (n_ + 12 hex), never one made from the name; ordinary nodes keep their slug
 *   waiting list    the Lock screen lists the agent requests waiting for approval with the names the broker gave (the ids when a node's name is private),
 *                   picks one for you when there is only one, and gives the request-id field back when nothing is listed
 *   step-up         the chip on a node gives the second factor ON PURPOSE (the owner's login is exempt; the window it opens is for agents), and says so
 *   audit passthrough  Undo uses the audit id of the change's own answer
 *
 * The real-daemon proofs are in tests/real/adr090-091.spec.ts.
 */
import { FIXTURE_GATE_CODE, FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import { expect, test, type App } from "./harness";
import { fillBulk, fillSingle, notice, openAddEntry, openAddNode, selectNode } from "./wp-c-util";
import { openApp, openEntryOf, openMenu, dialogReady, PG, fieldRows } from "./field-ui-helpers";

const MIXED = "pаypal"; // a Latin name with one Cyrillic letter
const MIXED_TEXT = "This name mixes Latin with Greek or Cyrillic letters.";

// ───────────────────────────── warnings ─────────────────────────────

test.describe("a name that mixes scripts is accepted and said", () => {
  test("an entry: saved, with the warning in the same notice; a plain name has none", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    let dlg = await openAddEntry(app, "atlas");
    await fillSingle(dlg, { name: MIXED, value: "fixture-value-x" });
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(dlg).toBeHidden();
    await expect(notice(app)).toContainText("Saved 1 entry to atlas.");
    await expect(notice(app)).toContainText(MIXED_TEXT);
    expect((await broker.state()).entries.atlas.map((e: any) => e.name)).toContain(MIXED); // it was accepted, not refused

    dlg = await openAddEntry(app, "atlas");
    await fillSingle(dlg, { name: "plain-name", value: "fixture-value-y" });
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(notice(app)).toContainText("Saved 1 entry to atlas.");
    await expect(notice(app)).not.toContainText("mixes Latin");
  });

  test("a batch says it is a name in the batch", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    const dlg = await openAddEntry(app, "atlas");
    await fillBulk(dlg, "one: fixture-value-1\n///\ntwo: fixture-value-2");
    await dlg.getByLabel("split each /// segment into its own entry").check();
    // the broker's answer for a batch in which one name mixes scripts: the warning is the broker's, the notice is the window's
    await broker.script("entry_create_batch", { result: { node: "atlas", created: [{ name: "one", entry: "e-x1", pending: false, fieldCount: 1 }, { name: MIXED, entry: "e-x2", pending: false, fieldCount: 1 }], complete: true, failed: null, total: 2, generation: 9, warnings: ["mixed_script_name"] } });
    await dlg.getByRole("button", { name: "Save 2 entries" }).click();
    await expect(notice(app)).toContainText("Saved 2 entries to atlas.");
    await expect(notice(app)).toContainText("A name in this batch mixes Latin with Greek or Cyrillic letters.");
    expect((await broker.calls("entry_create_batch")).length).toBe(1);
  });

  test("a node: created, with the warning in the same notice", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    const dlg = await openAddNode(app);
    await dlg.getByLabel("node name").fill(MIXED);
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(dlg).toBeHidden();
    await expect(notice(app)).toContainText(`Node “${MIXED}” created.`);
    await expect(notice(app)).toContainText(MIXED_TEXT);
    expect((await broker.calls("node_create"))[0].args).toMatchObject({ label: MIXED });
  });

  test("a rename: renamed, with the warning in the same notice", async ({ app }) => {
    const { page } = app;
    await app.open({ broker: { locked: false } });
    await expect(app.screen("S1 Main")).toBeVisible();
    await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click({ button: "right" });
    await page.locator(".cm-ctxmenu").getByRole("button", { name: "Rename" }).click();
    const input = page.locator(".cm-rail input");
    await input.fill(MIXED);
    await input.press("Enter");
    await expect(notice(app)).toContainText("Renamed.");
    await expect(notice(app)).toContainText(MIXED_TEXT);
  });
});

// ───────────────────────────── private ids ─────────────────────────────

test.describe("a node whose name is private has an id that says nothing", () => {
  test("the id is n_ and twelve hex digits, the label is what was typed, and the dialog says so before it is created", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    const dlg = await openAddNode(app);
    await dlg.getByLabel("node name").fill("Acme Payroll");
    await expect(dlg).toContainText("node id: acme-payroll"); // an ordinary node keeps its slug
    await dlg.getByRole("checkbox", { name: /Hide this node's name from others/ }).check();
    await expect(dlg).toContainText("node id: chosen at random when it is created (the name is not part of it)");
    await expect(dlg).not.toContainText("acme-payroll");
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(dlg).toBeHidden();
    const created = (await broker.calls("node_create"))[0].args as any;
    expect(created).toMatchObject({ label: "Acme Payroll", parentId: "global" });
    expect(created.id).toMatch(/^n_[0-9a-f]{12}$/);
    expect(created.id).not.toMatch(/acme|payroll/i);
    const nodes = (await broker.state()).nodes as any[];
    expect(nodes.find((n) => n.id === "acme-payroll")).toBeUndefined();
    expect(nodes.find((n) => n.id === created.id)).toMatchObject({ label: "Acme Payroll" });
    // the node is selected by that id
    expect(await app.page.evaluate(() => (window as any).__cm.state.selected)).toBe(created.id);
  });

  test("two private nodes with the same name get two ids, and an ordinary node is still its slug", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    for (const _ of [1, 2]) {
      const dlg = await openAddNode(app);
      await dlg.getByLabel("node name").fill("Twin");
      await dlg.getByRole("checkbox", { name: /Hide this node's name from others/ }).check();
      await dlg.getByRole("button", { name: "Create node" }).click();
      await expect(dlg).toBeHidden();
      await app.screen("S12 Settings").getByRole("button", { name: "Close", exact: true }).click();
    }
    const ids = (await broker.calls("node_create")).map((c) => (c.args as any).id as string);
    expect(new Set(ids).size).toBe(2);
    const dlg = await openAddNode(app);
    await dlg.getByLabel("node name").fill("Open Book");
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(dlg).toBeHidden();
    expect((await broker.calls("node_create")).at(-1)!.args).toMatchObject({ id: "open-book", label: "Open Book" });
  });
});

// ───────────────────────────── the Lock screen's waiting list ─────────────────────────────

test.describe("agent requests waiting while the vault is locked", () => {
  const panel = (app: App) => app.screen("S16a Locked approval");

  test("the link says how many are waiting; the panel lists them by the names the broker gave and by id for a private node; picking decides that one", async ({ app }) => {
    const broker = (await app.open({
      broker: { locked: true, privateNodes: ["beacon"], approvals: { rq_one: { node: "atlas", entry: "e-a1" }, rq_two: { node: "beacon", entry: "e-b1" } } },
    }))!;
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    await app.page.getByRole("button", { name: "2 agent requests are waiting for approval" }).click();
    await expect(panel(app)).toBeVisible();
    const first = panel(app).getByRole("radio", { name: /“stripe-live” in atlas/ });
    const second = panel(app).getByRole("radio", { name: /an entry in a node whose name is private \(beacon\)/ });
    await expect(first).not.toBeChecked(); // two are waiting: the person picks
    await expect(second).not.toBeChecked();
    // a private node's names are never on the screen
    await expect(panel(app)).not.toContainText("registry-token");
    await expect(panel(app)).not.toContainText("“beacon”");
    expect(await app.page.content()).not.toContain("registry-token");
    await expect(panel(app).getByRole("button", { name: "Approve" })).toHaveCount(0); // the factors and the decision appear only once a request is chosen
    await second.check();
    await expect(panel(app).getByRole("button", { name: "Approve" })).toBeDisabled(); // and a request alone decides nothing
    await panel(app).getByLabel("passphrase for this decision").fill(FIXTURE_PASSPHRASE);
    await panel(app).getByRole("button", { name: "Approve" }).click();
    expect((await broker.calls("vault_approval_decide"))[0].args).toEqual({ request: "rq_two", approved: true, passphrase: FIXTURE_PASSPHRASE });
    await expect(app.page.getByText("approved with the passphrase · the vault is still locked")).toBeVisible();
    // the decided request leaves the list on the next look
    await expect(app.page.getByRole("button", { name: "1 agent request is waiting for approval" })).toBeVisible({ timeout: 8000 });
  });

  test("a request that arrives while the Lock screen is up is found by the next look (every five seconds), and the id field is the fallback when nothing is listed", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: true } }))!;
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    await expect(app.page.getByRole("button", { name: "an agent is waiting for approval?" })).toBeVisible();
    await app.page.getByRole("button", { name: "an agent is waiting for approval?" }).click();
    await expect(panel(app).getByLabel("request id")).toBeVisible(); // nothing listed: the id it was given
    await expect(panel(app)).toContainText("Enter the request id the agent printed."); // and the caption says so
    await broker.set({ approvals: { rq_late: { node: "atlas", entry: "e-a1" } } });
    await expect(panel(app).getByRole("radio", { name: /“stripe-live” in atlas/ })).toBeChecked({ timeout: 9000 }); // the only one is picked for you
    await expect(panel(app).getByLabel("request id")).toHaveValue("rq_late"); // the id field stays (a request not listed can be decided by its id); it shows the one picked
    expect((await broker.calls("vault_approval_get")).length).toBeGreaterThan(0);
    // and it stops when the screen changes: no more looks once the vault is unlocked
    await app.page.getByRole("button", { name: "Close" }).click();
    await app.page.locator('input[type="password"]').fill(FIXTURE_PASSPHRASE);
    await app.page.getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(app.screen("S1 Main")).toBeVisible();
    // count the page's own looks from here on: at most the one tick that notices the screen changed, then none
    await app.page.evaluate(() => { const c = (window as any).__cm; c.__ticks = 0; const orig = c.pollApprovals.bind(c); c.pollApprovals = () => { c.__ticks++; return orig(); }; });
    await app.page.waitForTimeout(11500);
    expect(await app.page.evaluate(() => (window as any).__cm.__ticks)).toBeLessThanOrEqual(1);
  });

  test("a rejected look leaves the list empty and the screen usable", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: true } }))!;
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    await broker.script("vault_approval_get", { error: { code: "internal" } });
    await broker.set({ approvals: { rq_x: { node: "atlas", entry: "e-a1" } } });
    await expect.poll(async () => (await broker.calls("vault_approval_get")).length, { timeout: 9000 }).toBeGreaterThan(0); // the look happened and was rejected
    await expect(app.page.getByRole("button", { name: "an agent is waiting for approval?" })).toBeVisible(); // nothing listed: the old link, not a count
    await app.page.locator('input[type="password"]').fill(FIXTURE_PASSPHRASE);
    await app.page.getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(app.screen("S1 Main")).toBeVisible();
  });
});

// ───────────────────────────── the second factor, given on purpose ─────────────────────────────

test.describe("the chip on a node gives the second factor on purpose", () => {
  test("it opens the dialog in its 'give' wording, sends the code as vault.gate_verify, repeats nothing, and says who it is for", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false, gate: true, gateCode: FIXTURE_GATE_CODE } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    await selectNode(app, "atlas");
    await expect(app.page.locator("aside.cm-insp .k-chip", { hasText: "2fa · on reveal" })).toBeVisible();
    await app.page.locator("aside.cm-insp").getByRole("button", { name: "Give second factor" }).click();
    const dlg = app.screen("S5c Second factor");
    await expect(dlg).toBeVisible();
    await expect(dlg).toContainText("Give second factor");
    await expect(dlg).toContainText("opens a 5-minute window for agents and other callers");
    await expect(dlg).toContainText("any agent, MCP or CLI caller passes the second factor on every node of this vault");
    await expect(dlg).not.toContainText("two_factor_required");
    await dlg.getByLabel("second factor code").fill("000000");
    await dlg.getByRole("button", { name: "Give second factor" }).click();
    await expect(dlg.getByRole("alert")).toHaveText("That code was not accepted.");
    await dlg.getByLabel("second factor code").fill(FIXTURE_GATE_CODE);
    await dlg.getByRole("button", { name: "Give second factor" }).click();
    await expect(dlg).toBeHidden();
    await expect(notice(app)).toContainText("Second factor accepted. For 5 minutes, agents and other tools can reveal from every node that asks for one.");
    expect((await broker.calls("vault_gate_verify")).map((c) => c.args)).toEqual([{ code: "000000" }, { code: FIXTURE_GATE_CODE }]);
    expect(await broker.calls("entry_reveal")).toEqual([]); // nothing was revealed, nothing was repeated
    expect(await app.page.content()).not.toContain(FIXTURE_GATE_CODE);
  });

  test("the Help legend says the chip protects the node against agents and other callers, and that the owner is past it", async ({ app }) => {
    await app.open({ broker: { locked: false } });
    await expect(app.screen("S1 Main")).toBeVisible();
    await app.page.getByRole("button", { name: "help", exact: true }).click();
    const help = app.screen("S21 Help");
    await expect(help).toContainText("asks every caller but you for a second factor on reveal");
    await expect(help).toContainText("You, logged in, are already past it");
  });
});

// ───────────────────────────── the page after a shell lock ─────────────────────────────

test("after the shell reloaded the page because it locked, the Lock screen says why, once, and nothing else the page could have stored is shown", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: { locked: true } });
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(page.locator('[data-lock-note="true"]')).toHaveCount(0);
  // what src-tauri/src/autolock.rs `reload_script` does: leave the reason, reload
  await page.evaluate(() => sessionStorage.setItem("cm.lockreason", "sleep"));
  await page.reload();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(page.locator('[data-lock-note="true"]')).toHaveText("Locked because this Mac went to sleep.");
  expect(await page.evaluate(() => sessionStorage.getItem("cm.lockreason"))).toBeNull(); // read once
  await page.reload();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(page.locator('[data-lock-note="true"]')).toHaveCount(0);
  // a word the shell never writes is never shown
  await page.evaluate(() => sessionStorage.setItem("cm.lockreason", "locked by <b>someone</b>"));
  await page.reload();
  expect(await page.evaluate(() => sessionStorage.getItem("cm.lockreason"))).toBeNull(); // read and deleted by the new page's boot
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect(page.locator('[data-lock-note="true"]')).toHaveCount(0);
});

// ───────────────────────────── audit passthrough ─────────────────────────────

test("Undo uses the audit id the change's own answer carried, and the trail is not read", async ({ app }) => {
  const broker = await openApp(app);
  await openEntryOf(app, "atlas", "pg-main");
  await (await openMenu(app, PG.note)).getByRole("menuitem", { name: "Remove…" }).click();
  await (await dialogReady(app)).getByRole("button", { name: "Remove field", exact: true }).click();
  await expect(fieldRows(app)).toHaveCount(4);
  await app.page.getByRole("button", { name: "Undo remove field", exact: true }).click();
  const undo = (await broker.calls("entry_undo"))[0].args as any;
  const state: any = await broker.state();
  const removed = [...state.audit].reverse().find((r: any) => r.action === "field.remove");
  expect(undo.id).toBe(removed.id);
  expect(await broker.calls("audit_tail")).toEqual([]);
});
