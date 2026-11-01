/**
 * The held-entry tray over the real broker: what is written while the vault or its node is locked is HELD, never applied, and
 * reaches a node only when the user accepts it.
 *
 *   A. an entry created in a locked node (the UI's own write) -> held; after a lock and an unlock the banner counts it; Accept needs
 *      the node open; Accept writes it, Discard writes nothing.
 *   B. an agent writing while the whole vault is locked (a separate process in a project's folder, no token) -> held; the user
 *      unlocks, sees it in the tray, accepts it.
 *
 * "Held" is checked at the vault, by the independent client: the entry is in the tray listing and NOT in the node.
 */
import { mkdirSync } from "node:fs";
import { join } from "node:path";

import { Oracle } from "./oracle.mjs";
import { expect, fixtureSecret, test, type RealApp } from "./harness";
import { addEntry, createVaultViaWizard, ctxMenu, fillSingle, inspector, KDF, lockUi, notice, openAddEntry, openSettings, closeSettings, railRow, unlockToMain } from "./helpers";

const banner = (app: RealApp) => app.screen("S20 Pending banner");
const tray = (app: RealApp) => app.screen("S20 Pending tray");
const heldRow = (app: RealApp, name: string) => tray(app).locator('[data-pending-row="true"]', { hasText: name });

/** Wizard with one project, `Cobalt`, then an ordinary entry in it. */
async function vaultWithProject(app: RealApp, label: string): Promise<void> {
  await app.open();
  await createVaultViaWizard(app);
  await app.page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await app.page.getByLabel("project name 1").fill(label);
  await app.page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
  await expect(railRow(app, label)).toBeVisible();
}

test("A. an entry created in a locked node is held, counted after the next unlock, and written only when accepted", async ({ app }) => {
  const { page } = app;
  const kept = fixtureSecret("kept");
  const first = fixtureSecret("held-one");
  const second = fixtureSecret("held-two");
  await vaultWithProject(app, "Cobalt");
  await addEntry(app, "Cobalt", { name: "shop-admin", value: kept });
  await app.oracle.login();

  await test.step("lock the node from its context menu: the broker locks that node, and the login survives", async () => {
    const menu = await ctxMenu(app, "Cobalt");
    await menu.getByRole("button", { name: "Lock now" }).click();
    await expect(notice(app, "Node locked.")).toBeVisible();
    await expect(railRow(app, "Cobalt")).toContainText("⌐");
    expect(app.frames("vault.node_lock").map((f) => f.params)).toEqual([{ node: "cobalt" }]);
    const snap = await app.oracle.call("graph.snapshot");
    expect(snap.nodes.find((n: { id: string }) => n.id === "cobalt").gate.locked).toBe(true);
    expect(snap.meta.vaultLocked, "the vault itself stays unlocked").toBe(false);
    await expect(app.screen("S1 Main")).toBeVisible();
  });

  await test.step("a write into the locked node says it will be held, and the broker holds it", async () => {
    const dlg = await openAddEntry(app, "Cobalt");
    await expect(dlg).toContainText("cobalt is locked");
    await fillSingle(dlg, { name: "held-one", value: first, label: "api token" });
    await dlg.getByRole("button", { name: "Hold for review", exact: true }).click();
    await expect(notice(app, "Held for review: cobalt is locked")).toBeVisible();
    await expect(page.getByRole("button", { name: "1 held" })).toBeVisible();

    const dlg2 = await openAddEntry(app, "Cobalt");
    await fillSingle(dlg2, { name: "held-two", value: second });
    await dlg2.getByRole("button", { name: "Hold for review", exact: true }).click();
    await expect(page.getByRole("button", { name: "2 held" })).toBeVisible();

    // at the vault: two items in the tray, listed by name, and nothing of them in the node's own list
    const pending = await app.oracle.pending("cobalt");
    expect(pending.map((p: { name: string }) => p.name).sort()).toEqual(["held-one", "held-two"]);
    expect(JSON.stringify(pending), "the tray listing carries no value").not.toMatch(new RegExp(`${first}|${second}`));
    expect(app.frames("entry.create").filter((f) => f.params.node === "cobalt").map((f) => f.params.name)).toEqual(["shop-admin", "held-one", "held-two"]);
    expect(await app.pageDump()).not.toContain(first);
  });

  await test.step("lock the vault and unlock it: the banner counts what is waiting; the node is still locked, so Accept is off", async () => {
    await lockUi(app);
    await unlockToMain(app);
    await expect(banner(app)).toContainText("2 entries are waiting for your review");
    await app.oracle.login(); // the lock revoked every login, the oracle's included
    await banner(app).getByRole("button", { name: "Review" }).click();
    await expect(tray(app)).toBeVisible();
    await expect(heldRow(app, "held-one")).toContainText("cobalt /");
    await expect(heldRow(app, "held-one")).toContainText("1 field");
    await expect(heldRow(app, "held-one")).toContainText("this node is locked");
    await expect(heldRow(app, "held-one").getByRole("button", { name: "Accept" })).toBeDisabled();
    await expect(heldRow(app, "held-one").getByRole("button", { name: "Discard" })).toBeDisabled();
    expect(app.frames("vault.pending_accept")).toEqual([]);
    expect(await app.pageDump(), "the tray never shows a value").not.toContain(first);
  });

  await test.step("unlock the node, refresh: Accept goes through and the value is in the node, exactly as typed", async () => {
    await page.keyboard.press("Escape");
    await expect(tray(app)).toBeHidden();
    const menu = await ctxMenu(app, "Cobalt");
    await menu.getByRole("button", { name: "Unlock node" }).click();
    await expect(notice(app, "Node unlocked.")).toBeVisible();
    await page.getByRole("button", { name: "2 held" }).click();
    await expect(tray(app)).toBeVisible();
    await tray(app).getByRole("button", { name: "Refresh" }).click();
    await expect(heldRow(app, "held-one").getByRole("button", { name: "Accept" })).toBeEnabled();

    const heldId = (await app.oracle.pending("cobalt")).find((p: { name: string }) => p.name === "held-one").entry;
    await heldRow(app, "held-one").getByRole("button", { name: "Accept" }).click();
    await expect(notice(app, "“held-one” accepted into cobalt.")).toBeVisible();
    expect(app.frames("vault.pending_accept").map((f) => f.params)).toEqual([{ node: "cobalt", entry: heldId }]);
    await expect(heldRow(app, "held-one")).toHaveCount(0);
    await app.oracle.login();
    expect(await app.oracle.entries("cobalt")).toEqual({ "shop-admin": kept, "held-one": first });
  });

  await test.step("discard writes nothing: the other held entry is gone from the tray and was never in the node", async () => {
    const heldId = (await app.oracle.pending("cobalt")).find((p: { name: string }) => p.name === "held-two").entry;
    await heldRow(app, "held-two").getByRole("button", { name: "Discard" }).click();
    await expect(notice(app, "“held-two” discarded.")).toBeVisible();
    expect(app.frames("vault.pending_discard").map((f) => f.params)).toEqual([{ node: "cobalt", entry: heldId }]);
    await expect(tray(app)).toContainText("Nothing is waiting.");
    await expect(page.getByRole("button", { name: /held$/ })).toHaveCount(0);
    expect(await app.oracle.pending("cobalt")).toEqual([]);
    expect(Object.keys(await app.oracle.entries("cobalt"))).toEqual(expect.not.arrayContaining(["held-two"]));
  });
});

test("B. an agent's write while the vault is locked is held in the tray, and the user accepts it after unlocking", async ({ app }) => {
  const { page } = app;
  const agentValue = fixtureSecret("agent-value");
  await app.open();
  await createVaultViaWizard(app);
  await page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);

  // a project bound to a folder: made through the UI's own dialog, the folder written the way a person writes it (`~/...`)
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
  await expect(railRow(app, "Alpha")).toBeVisible();
  // `~` was expanded by the shell (here, the shim) using the throwaway home, and the broker bound exactly that folder
  expect((await app.pluginCalls()).filter((c) => c.cmd === "plugin:path|resolve_directory")).toHaveLength(1);
  expect(app.frames("node.create").at(-1)!.params).toMatchObject({ id: "alpha", label: "Alpha", parentId: "global", workdirs: [workdir] });

  const existing = fixtureSecret("existing-value");
  await addEntry(app, "Alpha", { name: "EXISTING", value: existing });
  const existingId = await (await app.oracle.login()).entryId("alpha", "EXISTING");

  await lockUi(app);
  await test.step("an agent in that folder writes with no login: held, not applied; and it still cannot read a value out of the locked vault", async () => {
    const wrote = Oracle.agent(app.daemon.socketPath, workdir, "entry.create", { node: "alpha", name: "AGENT_KEY", value: agentValue });
    expect(wrote).toMatchObject({ ok: true, value: { node: "alpha", pending: true } });
    // held, not applied: the node's own list still has only what the user put there
    const listed = Oracle.agent(app.daemon.socketPath, workdir, "entry.list", { node: "alpha" });
    expect(listed).toMatchObject({ ok: true, value: { names: ["EXISTING"] } });
    // a locked vault gives no value to a process with no login. ADR-088 (4b): on a WHOLLY locked vault the broker records the
    // request (`approval_pending`) because a person can now decide it with the unlock factors; nothing is released until they do
    const read = Oracle.agent(app.daemon.socketPath, workdir, "entry.reveal", { node: "alpha", entry: existingId });
    expect(read).toMatchObject({ ok: false, error: { source: "broker", code: "approval_pending" } });
    expect(JSON.stringify([wrote, listed, read])).not.toContain(existing);
    expect(JSON.stringify([wrote, listed, read])).not.toContain(agentValue);
  });

  await test.step("unlock: the banner counts it, the tray shows name and node but no value, Accept writes it", async () => {
    await unlockToMain(app);
    await expect(banner(app)).toContainText("1 entry is waiting for your review");
    await banner(app).getByRole("button", { name: "Review" }).click();
    const row = heldRow(app, "AGENT_KEY");
    await expect(row).toContainText("alpha /");
    expect(await app.pageDump()).not.toContain(agentValue);
    await row.getByRole("button", { name: "Accept" }).click();
    await expect(notice(app, "“AGENT_KEY” accepted into alpha.")).toBeVisible();
    await app.oracle.login();
    expect(await app.oracle.entries("alpha")).toEqual({ EXISTING: existing, AGENT_KEY: agentValue });
    expect(await app.oracle.pending("alpha")).toEqual([]);
    await expect(inspector(app)).toBeVisible();
  });
});
