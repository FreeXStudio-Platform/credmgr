/**
 * ADR-090 / ADR-091 over the real broker: what the window shows and sends is checked at the vault by independent clients (the oracle, and
 * agents as separate processes), never only on screen.
 *
 *   private ids     a node created with "Hide this node's name" has an opaque id; an AGENT's view of the vault shows no name, only that id
 *   warnings        a mixed-script name is accepted with the broker's warning, said in the notice; a pure look-alike twin of an existing name is refused
 *   waiting list    the Lock screen lists the agent requests waiting for approval by the names the broker gives (the id for a private node), and a
 *                   decision made from the list releases exactly that request
 *   step-up         a gate-enrolled vault and an AGENT: its reveal is refused (two_factor_required), the owner's window gives the second factor on
 *                   purpose (vault.gate_verify), the agent's retry passes inside the window, and the window ends with a change to the node's policy.
 *                   The owner's own reveal is never asked (is_owner_session).  The 300-second clock itself is proven in the broker's tests
 *                   (part4_two_factor.rs, +60 s passes, +301 s is refused again); this journey does not wait five minutes.
 */
import { mkdirSync } from "node:fs";
import { join } from "node:path";

import { Oracle } from "./oracle.mjs";
import { expect, fixtureSecret, test, type RealApp } from "./harness";
import { addEntry, closeSettings, createVaultViaWizard, fillSingle, KDF, lockUi, MASKED_LABEL, notice, openAddEntry, openEntry, openSettings, railRow, revealOpenEntry, selectNode } from "./helpers";
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

/** A project bound to a folder the agent runs in; `hidden` ticks "Hide this node's name from others". */
async function addProject(app: RealApp, name: string, folder: string, hidden = false): Promise<string> {
  const workdir = join(app.daemon.homeDir, "projects", folder);
  mkdirSync(workdir, { recursive: true });
  const settings = await openSettings(app, "Nodes");
  await settings.getByRole("button", { name: "+ New project" }).click();
  const dlg = app.screen("S8 Add node");
  await expect(dlg).toBeVisible();
  await dlg.getByLabel("node name").fill(name);
  await dlg.getByLabel("work folder").first().fill(`~/projects/${folder}`);
  if (hidden) await dlg.getByRole("checkbox", { name: /Hide this node's name from others/ }).check();
  await dlg.getByRole("button", { name: "Create node" }).click();
  await expect(dlg).toBeHidden();
  await closeSettings(app);
  return workdir;
}

test("a node whose name is private has an opaque id, and an agent's view of the vault shows no name, only that id", async ({ app }) => {
  test.setTimeout(240_000);
  const stored = fixtureSecret("ledger-value");
  await vaultWith(app, "Atlas");
  const workdir = await addProject(app, "Quiet Ledger", "quiet", true);

  const create = app.frames("node.create").at(-1)!;
  const id: string = create.params.id;
  expect(id).toMatch(/^n_[0-9a-f]{12}$/);
  expect(create.params.label).toBe("Quiet Ledger");
  expect(id).not.toMatch(/quiet|ledger/i);
  expect(app.frames("node.policy").at(-1)!.params).toEqual({ node: id, reason: "set at creation", policy: { privateNames: true } });
  await addEntry(app, "Quiet Ledger", { name: "ledger-key", label: MASKED_LABEL, value: stored });

  const owner = await app.oracle.login();
  const ownerRow = (await owner.call("graph.snapshot")).nodes.find((n: { id: string }) => n.id === id);
  expect(ownerRow).toMatchObject({ id, label: "Quiet Ledger", nameHidden: true }); // the owner sees everything, with the badge

  await test.step("an agent (a process in the node's folder) sees the id and the shape of the graph, never the label or an entry's name", async () => {
    const snapshot = Oracle.agent(app.daemon.socketPath, workdir, "graph.snapshot");
    expect(snapshot).toMatchObject({ ok: true });
    const row = snapshot.value.nodes.find((n: { id: string }) => n.id === id);
    expect(row).toMatchObject({ id, nameHidden: true, label: null });
    const list = Oracle.agent(app.daemon.socketPath, workdir, "entry.list", { node: id });
    expect(list).toMatchObject({ ok: true });
    const nodes = Oracle.agent(app.daemon.socketPath, workdir, "node.list");
    for (const answer of [snapshot, list, nodes]) {
      const text = JSON.stringify(answer);
      expect(text, "no part of the name, in any answer an agent gets").not.toMatch(/quiet|ledger/i);
      expect(text).not.toContain(stored);
    }
    expect(JSON.stringify(nodes)).toContain(id);
  });
});

test("a name that mixes scripts is accepted with the broker's warning; a pure look-alike twin of an existing name is refused as a duplicate", async ({ app }) => {
  const { page } = app;
  test.setTimeout(240_000);
  await vaultWith(app, "Atlas");
  await addEntry(app, "Atlas", { name: "cap", value: fixtureSecret("cap-value") });
  const oracle = await app.oracle.login();

  await test.step("Latin with one Cyrillic letter: saved, and the notice says so", async () => {
    const mixed = "pаyroll";
    const dlg = await openAddEntry(app, "Atlas");
    await fillSingle(dlg, { name: mixed, value: fixtureSecret("payroll-value") });
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(notice(app, "Saved 1 entry to")).toBeVisible();
    await expect(notice(app, "This name mixes Latin with Greek or Cyrillic letters.")).toBeVisible();
    expect((await app.answerOf("entry_create", 1)).result).toMatchObject({ warnings: ["mixed_script_name"] });
    expect(Object.keys(await oracle.entries("atlas"))).toContain(mixed); // accepted, not refused
  });

  await test.step("an all-Cyrillic twin of 'cap' is not a new name: the existing duplicate error, and nothing was written", async () => {
    const twin = "сар";
    const dlg = await openAddEntry(app, "Atlas");
    await fillSingle(dlg, { name: twin, value: fixtureSecret("twin-value") });
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(dlg.getByRole("alert")).toContainText("An entry with that name already exists in this node.");
    await expect(dlg).toBeVisible();
    expect(Object.keys(await oracle.entries("atlas"))).not.toContain(twin);
    await dlg.getByRole("button", { name: "Cancel" }).click();
  });

  await test.step("a node named that way: created, with the same notice", async () => {
    const settings = await openSettings(app, "Nodes");
    await settings.getByRole("button", { name: "+ New project" }).click();
    const dlg = app.screen("S8 Add node");
    await dlg.getByLabel("node name").fill("Paуroll Team");
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(dlg).toBeHidden();
    await expect(notice(app, "This name mixes Latin with Greek or Cyrillic letters.")).toBeVisible();
    await closeSettings(app);
  });
  void page;
});

test("the Lock screen lists the waiting agent requests by name (by id for a private node) and a decision from the list releases that request", async ({ app }) => {
  const { page } = app;
  test.setTimeout(300_000);
  const openValue = fixtureSecret("open-value");
  const hiddenValue = fixtureSecret("hidden-value");
  await vaultWith(app, "Atlas");
  const openDir = await addProject(app, "Alpha", "alpha");
  const hiddenDir = await addProject(app, "Shadow", "shadow", true);
  await addEntry(app, "Alpha", { name: "OPEN_KEY", value: openValue });
  await addEntry(app, "Shadow", { name: "SHADOW_KEY", value: hiddenValue });
  const oracle = await app.oracle.login();
  const openEntryId = await oracle.entryId("alpha", "OPEN_KEY");
  const hiddenId: string = app.frames("node.create").at(-1)!.params.id;
  const hiddenEntryId = await oracle.entryId(hiddenId, "SHADOW_KEY");
  await lockUi(app);

  const readOpen = () => Oracle.agent(app.daemon.socketPath, openDir, "entry.reveal", { node: "alpha", entry: openEntryId });
  const readHidden = () => Oracle.agent(app.daemon.socketPath, hiddenDir, "entry.reveal", { node: hiddenId, entry: hiddenEntryId });
  const a = readOpen();
  const b = readHidden();
  expect(a).toMatchObject({ ok: false, error: { code: "approval_pending" } });
  expect(b).toMatchObject({ ok: false, error: { code: "approval_pending" } });
  const idA: string = a.error.request ?? a.error.detail?.request;
  const idB: string = b.error.request ?? b.error.detail?.request;

  await test.step("vault.status says how many (a bare count), the Lock screen finds them on its next look", async () => {
    // the broker's own count, by an independent client, and the same count as the shell hands the page
    expect(await oracle.call("vault.status")).toMatchObject({ locked: true, pendingApprovals: 2 });
    expect(JSON.stringify(await oracle.call("vault.status"))).not.toMatch(/alpha|shadow|OPEN_KEY|SHADOW_KEY/i);
    expect(await app.shim.invoke("vault_status")).toMatchObject({ locked: true, authenticated: false, pendingApprovals: 2 });
    await expect(page.getByRole("button", { name: "2 agent requests are waiting for approval" })).toBeVisible({ timeout: 20_000 });
    expect(app.frames("vault.approval_get").length).toBeGreaterThan(0);
    expect(app.frames("vault.approval_get").every((f) => Object.keys(f.params).length === 0)).toBe(true); // the list, not a guess at an id
    expect(app.shim.session.isAuthenticated()).toBe(false);
  });

  const panel = app.screen("S16a Locked approval");
  await test.step("the panel names the open one and hides the private one's names", async () => {
    await page.getByRole("button", { name: "2 agent requests are waiting for approval" }).click();
    await expect(panel).toBeVisible();
    await expect(panel.getByRole("radio", { name: /“OPEN_KEY” in Alpha/ })).toBeVisible();
    await expect(panel.getByRole("radio", { name: new RegExp(`an entry in a node whose name is private \\(${hiddenId}\\)`) })).toBeVisible();
    await expect(panel).not.toContainText("SHADOW_KEY");
    await expect(panel).not.toContainText("Shadow");
    expect(await page.content()).not.toContain("SHADOW_KEY");
  });

  await test.step("approving the private one releases that request and no other", async () => {
    await panel.getByRole("radio", { name: /whose name is private/ }).check();
    await panel.getByLabel("passphrase for this decision").fill(app.passphrase);
    await panel.getByRole("button", { name: "Approve" }).click();
    await expect(page.getByText("approved with the passphrase · the vault is still locked")).toBeVisible(KDF);
    expect(app.frames("vault.approval_decide").at(-1)!.params).toEqual({ request: idB, approved: true, passphrase: app.passphrase });
    expect(JSON.stringify(readHidden())).toContain(hiddenValue);
    expect(readOpen()).toMatchObject({ ok: false, error: { code: "approval_pending" } }); // the other is still waiting
    await expect(page.getByRole("button", { name: "1 agent request is waiting for approval" })).toBeVisible({ timeout: 20_000 });
    void idA;
  });
});

test("a gate-enrolled vault and an agent: the agent is refused, the owner gives the second factor on purpose, the agent passes inside the window, and a policy change ends it; the owner is never asked", async ({ app }) => {
  const { page } = app;
  test.setTimeout(360_000);
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
  const workdir = await addProject(app, "Beta", "beta");
  await addEntry(app, "Beta", { name: "EXISTING", label: MASKED_LABEL, value: stored });
  const oracle = await app.oracle.login(() => auth.next());
  const entryId = await oracle.entryId("beta", "EXISTING");
  const agentReads = () => Oracle.agent(app.daemon.socketPath, workdir, "entry.reveal", { node: "beta", entry: entryId });

  await test.step("the agent's reveal is refused with two_factor_required; the value is not in the answer", async () => {
    // Every login with a code opens the same five-minute window (ADR-085), so the window the logins above opened is ended first: any change
    // to a node's policy ends it, even one that changes no value.
    await oracle.call("node.policy", { node: "beta", reason: "start without an elevation", policy: { requireTwoFactor: "reveal" } });
    const refused = agentReads();
    expect(refused).toMatchObject({ ok: false, error: { code: "two_factor_required" } });
    expect(JSON.stringify(refused)).not.toContain(stored);
  });

  await test.step("the owner's own window is never asked: it reveals the same entry with no dialog", async () => {
    await selectNode(app, "Beta");
    await openEntry(app, "EXISTING");
    expect(await revealOpenEntry(app)).toBe(stored);
    await expect(app.screen("S5c Second factor")).toHaveCount(0);
  });

  await test.step("the owner gives the factor on purpose: the chip opens the dialog in its 'give' wording and sends vault.gate_verify", async () => {
    await page.getByRole("button", { name: /^← / }).click(); // leave the open entry: the node's header (and its chip) is what the inspector shows
    await page.locator("aside.cm-insp").getByRole("button", { name: "Give second factor" }).click();
    const dlg = app.screen("S5c Second factor");
    await expect(dlg).toBeVisible();
    await expect(dlg).toContainText("Give second factor");
    await expect(dlg).toContainText("opens a 5-minute window for agents and other callers");
    await dlg.getByLabel("second factor code").fill(auth.wrong());
    await dlg.getByRole("button", { name: "Give second factor" }).click();
    await expect(dlg.getByRole("alert")).toHaveText("That code was not accepted.", KDF);
    expect(agentReads()).toMatchObject({ ok: false, error: { code: "two_factor_required" } }); // a wrong code opens nothing
    const code = await auth.next();
    await dlg.getByLabel("second factor code").fill(code);
    await dlg.getByRole("button", { name: "Give second factor" }).click();
    await expect(dlg).toBeHidden(KDF);
    await expect(notice(app, "Second factor accepted. For 5 minutes, agents and other tools can reveal")).toBeVisible();
    expect(app.frames("vault.gate_verify").at(-1)!.params).toEqual({ code });
    expect((await app.answerOf("vault_gate_verify")).result).toMatchObject({ locked: false, authenticated: true });
    expect(await app.pageDump()).not.toContain(code);
  });

  await test.step("the agent's retry passes inside the window (the whole vault, every caller)", async () => {
    const passed = agentReads();
    expect(passed).toMatchObject({ ok: true });
    expect(JSON.stringify(passed)).toContain(stored);
  });

  await test.step("a change to the node's policy ends the window; the agent is refused again", async () => {
    await oracle.call("node.policy", { node: "beta", reason: "end the elevation", policy: { requireTwoFactor: "always" } });
    expect(agentReads()).toMatchObject({ ok: false, error: { code: "two_factor_required" } });
  });
});
