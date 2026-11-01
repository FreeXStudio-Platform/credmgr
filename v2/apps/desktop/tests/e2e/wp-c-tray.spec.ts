/**
 * Work package C, part 2: entries held for review (the S20 tray and its banner).
 *
 * What is held was written while the vault or its node was locked (by an agent, the CLI, or this window).  It reaches a node
 * only when the user ACCEPTS it; the tray lists node, name, type, sensitivity and when it was held, and never a value.
 */
import { FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import { expect, test, type App } from "./harness";
import { fillSingle, lockAndUnlock, notice, openAddEntry } from "./wp-c-util";

const HELD = "fixture-value-held";
const WHEN = /\d{4}-\d{2}-\d{2} \d{2}:\d{2}/;

function held(id: string, name: string, sensitivity: string, created: number) {
  return { id, name, type: "other", sensitivity, value: `${HELD}-${name}`, modified: created, rotatedAt: null, expiresAt: null, created };
}

const banner = (app: App) => app.screen("S20 Pending banner");
const tray = (app: App) => app.screen("S20 Pending tray");
const row = (app: App, name: string) => tray(app).locator('[data-pending-row="true"]', { hasText: name });

async function unlockWithPassphrase(app: App) {
  await app.page.locator('input[type="password"]').fill(FIXTURE_PASSPHRASE);
  await app.page.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible();
}

test("the tray is read on unlock, the banner shows the count, and opening the tray reads it again", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true } }))!;
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  // two entries were held while this window was locked
  await broker.set({ pending: { atlas: [held("p-a1", "a-held-1", "high", 1760000100)], beacon: [held("p-b1", "b-held-1", "low", 1760000200)] } });
  await unlockWithPassphrase(app);

  // on unlock: one vault.pending_list per node, a banner with the count, a chip in the header
  const nodes = ["atlas", "beacon", "cobalt", "global", "staging"];
  const listed = async () => (await broker.calls("vault_pending_list")).map((c) => c.args.node as string).sort();
  expect(await listed()).toEqual(nodes);
  await expect(banner(app)).toContainText("2 entries are waiting for your review");
  await expect(page.getByRole("button", { name: "2 held" })).toBeVisible();

  // on demand: Review opens the tray AND reads it again (and the graph, for the nodes' locks)
  const graphBefore = (await broker.calls("graph_snapshot")).length;
  await banner(app).getByRole("button", { name: "Review" }).click();
  await expect(tray(app)).toBeVisible();
  await expect(banner(app)).toBeHidden();
  await expect.poll(async () => (await listed()).length).toBe(nodes.length * 2);
  expect((await broker.calls("graph_snapshot")).length).toBe(graphBefore + 1);

  // each row: node, name, type, sensitivity, when it was held; never a value
  const rows = tray(app).locator('[data-pending-row="true"]');
  await expect(rows).toHaveCount(2);
  await expect(row(app, "a-held-1")).toContainText("atlas /");
  await expect(row(app, "a-held-1")).toContainText("1 field · other · high");
  await expect(row(app, "a-held-1")).toContainText(WHEN);
  await expect(row(app, "b-held-1")).toContainText("beacon /");
  await expect(row(app, "b-held-1")).toContainText("1 field · other · low");
  expect(await page.content()).not.toContain(HELD);
  expect(await app.viewJson()).not.toContain(HELD);

  // Accept is the only thing that writes: one call, node and entry under the bridge's keys, then fresh reads
  const atlasListsBefore = (await broker.calls("entry_list")).filter((c) => c.args.node === "atlas").length;
  await row(app, "a-held-1").getByRole("button", { name: "Accept" }).click();
  await expect(notice(app)).toContainText("“a-held-1” accepted into atlas.");
  expect(await broker.calls("vault_pending_accept")).toEqual([{ cmd: "vault_pending_accept", args: { node: "atlas", entry: "p-a1" } }]);
  await expect(row(app, "a-held-1")).toHaveCount(0);
  expect((await broker.calls("entry_list")).filter((c) => c.args.node === "atlas").length).toBe(atlasListsBefore + 1);
  expect((await broker.state()).entries.atlas.map((e) => e.name)).toContain("a-held-1");
  expect((await broker.state()).pending.atlas).toEqual([]);
  await expect(page.getByRole("button", { name: "1 held" })).toBeVisible();

  // Discard removes it and writes nothing
  await row(app, "b-held-1").getByRole("button", { name: "Discard" }).click();
  await expect(notice(app)).toContainText("“b-held-1” discarded.");
  expect(await broker.calls("vault_pending_discard")).toEqual([{ cmd: "vault_pending_discard", args: { node: "beacon", entry: "p-b1" } }]);
  expect((await broker.state()).entries.beacon.map((e) => e.name)).not.toContain("b-held-1");
  await expect(rows).toHaveCount(0);
  await expect(tray(app)).toContainText("Nothing is waiting.");
  await expect(page.getByRole("button", { name: /held$/ })).toHaveCount(0); // the chip goes with the last item
  expect(await broker.calls("vault_pending_accept")).toHaveLength(1);
});

test("a refused accept is shown and leaves the row; an item that is already gone is reloaded away", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true } }))!;
  await broker.set({ pending: { atlas: [held("p-a1", "a-held-1", "high", 1760000100), held("p-a2", "a-held-2", "low", 1760000300)] } });
  await unlockWithPassphrase(app);
  await banner(app).getByRole("button", { name: "Review" }).click();
  await expect(tray(app).locator('[data-pending-row="true"]')).toHaveCount(2);

  // 1. the name was taken in the node meanwhile: the broker says entry_exists, the row stays, nothing is accepted
  await broker.script("vault_pending_accept", { error: { code: "entry_exists", detail: { node: "atlas", name: "a-held-1" } } });
  await row(app, "a-held-1").getByRole("button", { name: "Accept" }).click();
  await expect(notice(app)).toContainText("An entry with that name already exists in this node.");
  await expect(row(app, "a-held-1")).toBeVisible();
  expect((await broker.state()).entries.atlas.map((e) => e.name)).not.toContain("a-held-1");
  await expect(row(app, "a-held-1").getByRole("button", { name: "Accept" })).toBeEnabled(); // the busy flag is released

  // 2. another process already discarded a-held-2: the broker says not_found, and the tray is re-read
  const st = await broker.state();
  await broker.set({ pending: { ...st.pending, atlas: st.pending.atlas.filter((p) => p.name !== "a-held-2") } });
  const listsBefore = (await broker.calls("vault_pending_list")).length;
  await row(app, "a-held-2").getByRole("button", { name: "Discard" }).click();
  await expect(notice(app)).toContainText("That no longer exists. Reloaded.");
  await expect(row(app, "a-held-2")).toHaveCount(0);
  expect((await broker.calls("vault_pending_list")).length).toBeGreaterThan(listsBefore);
  await expect(row(app, "a-held-1")).toBeVisible();

  // 3. the login is gone: the lock screen, and the tray is gone with it
  await broker.script("vault_pending_discard", { error: { code: "vault_locked" } });
  await row(app, "a-held-1").getByRole("button", { name: "Discard" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await page.content()).not.toContain("a-held-1");
});

test("the banner can be dismissed and leaves the chip; Refresh reads the tray on demand", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true } }))!;
  await broker.set({ pending: { beacon: [held("p-b1", "b-held-1", "low", 1760000200)] } });
  await unlockWithPassphrase(app);
  await expect(banner(app)).toContainText("1 entry is waiting for your review");
  await banner(app).getByRole("button", { name: "dismiss" }).click();
  await expect(banner(app)).toBeHidden();
  await page.getByRole("button", { name: "1 held" }).click(); // the chip opens the tray
  await expect(tray(app)).toBeVisible();

  // an agent holds a second entry while the tray is open; Refresh shows it
  const st = await broker.state();
  await broker.set({ pending: { ...st.pending, atlas: [held("p-a9", "agent-held", "high", 1760000900)] } });
  await expect(row(app, "agent-held")).toHaveCount(0);
  await tray(app).getByRole("button", { name: "Refresh" }).click();
  await expect(row(app, "agent-held")).toBeVisible();
  await expect(page.getByRole("button", { name: "2 held" })).toBeVisible();
});

test("an entry created in a locked node is held, the banner counts it after the next unlock, and it is accepted once the node is open", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();

  // "cobalt" is locked: the dialog says the entry will be held, and Save says so too
  const dlg = await openAddEntry(app, "cobalt");
  await expect(dlg).toContainText("cobalt is locked");
  await fillSingle(dlg, { name: "held-one", value: `${HELD}-held-one`, label: "api token" });
  const cobaltListsBefore = (await broker.calls("entry_list")).filter((c) => c.args.node === "cobalt").length;
  await dlg.getByRole("button", { name: "Hold for review", exact: true }).click();

  expect(await broker.calls("entry_create")).toEqual([{ cmd: "entry_create", args: { node: "cobalt", name: "held-one", fields: [{ label: "api token", value: `${HELD}-held-one` }] } }]);
  await expect(notice(app)).toContainText("Held for review: cobalt is locked");
  await expect(page.getByRole("button", { name: "1 held" })).toBeVisible();
  // a held entry changes the tray only: the node's own list is not re-read, and the node still shows its one entry
  expect((await broker.calls("entry_list")).filter((c) => c.args.node === "cobalt").length).toBe(cobaltListsBefore);
  expect((await broker.state()).entries.cobalt.map((e) => e.name)).toEqual(["shop-admin"]);
  const heldId = (await broker.state()).pending.cobalt[0].id;

  // lock, unlock: the banner counts what is waiting
  await lockAndUnlock(app);
  await expect(banner(app)).toContainText("1 entry is waiting for your review");
  await banner(app).getByRole("button", { name: "Review" }).click();

  // its node is still locked: the row says so and offers nothing it would be refused
  await expect(row(app, "held-one")).toContainText("this node is locked");
  await expect(row(app, "held-one").getByRole("button", { name: "Accept" })).toBeDisabled();
  await expect(row(app, "held-one").getByRole("button", { name: "Discard" })).toBeDisabled();
  expect(await broker.calls("vault_pending_accept")).toEqual([]);

  // the node is unlocked elsewhere; Refresh learns it and Accept goes through
  const st = await broker.state();
  await broker.set({ nodes: st.nodes.map((n) => (n.id === "cobalt" ? { ...n, gate: { ...n.gate, locked: false } } : n)) });
  await tray(app).getByRole("button", { name: "Refresh" }).click();
  await expect(row(app, "held-one").getByRole("button", { name: "Accept" })).toBeEnabled();
  await row(app, "held-one").getByRole("button", { name: "Accept" }).click();
  await expect(notice(app)).toContainText("“held-one” accepted into cobalt.");
  expect(await broker.calls("vault_pending_accept")).toEqual([{ cmd: "vault_pending_accept", args: { node: "cobalt", entry: heldId } }]);
  expect((await broker.state()).entries.cobalt.map((e) => e.name)).toEqual(["shop-admin", "held-one"]);
  expect(await app.viewJson()).not.toContain(HELD);
});

test("the vault menu's 'Pending writes' opens the tray and reads it again, like the chip and the banner do", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  // an agent holds an entry after this window last read the tray
  await broker.set({ pending: { atlas: [held("p-a9", "agent-held", "high", 1760000900)] } });
  const listsBefore = (await broker.calls("vault_pending_list")).length;
  await page.getByRole("button", { name: "vault menu" }).click();
  await page.locator(".cm-vaultmenu button", { hasText: "Pending writes" }).click();
  await expect(tray(app)).toBeVisible();
  await expect(row(app, "agent-held")).toBeVisible(); // the menu path showed the tray as the broker has it NOW, not the last read
  expect((await broker.calls("vault_pending_list")).length).toBeGreaterThan(listsBefore);
});
