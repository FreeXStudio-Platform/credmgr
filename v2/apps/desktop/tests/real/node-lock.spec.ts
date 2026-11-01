/**
 * A locked NODE is not a locked VAULT: the login survives it, the rest of the vault keeps working, and the locked node shows a
 * panel instead of a value. Against the real broker, from both directions:
 *
 *   1. locked from outside (the CLI, another window): the app's snapshot is stale, so the app asks, the broker refuses, the app
 *      re-reads and shows the panel; "Unlock node" opens it again
 *   2. locked from the app: the snapshot already says so, so no reveal is attempted; the lock survives a vault lock and unlock
 *   3. a TOTP entry in a locked node: the panel too, and no code is requested
 */
import { expect, fixtureSecret, fixtureTotpSeed, test, type RealApp } from "./harness";
import { addEntry, createVaultViaWizard, ctxMenu, KDF, lockUi, MASKED_LABEL, notice, openEntry, railRow, revealOpenEntry, selectNode, unlockToMain } from "./helpers";

const lockedPanel = (app: RealApp) => app.screen("S5 Entry detail — locked");

/** The entry's value sits in a MASKED field (label "password"), so the open entry offers the reveal control these journeys are about. */
async function vaultWithEntry(app: RealApp, value: string, entry = { name: "stripe-live", label: MASKED_LABEL as string | undefined }): Promise<void> {
  await app.open();
  await createVaultViaWizard(app);
  await app.page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await app.page.getByLabel("project name 1").fill("Atlas");
  await app.page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
  await addEntry(app, "Atlas", { name: entry.name, value, label: entry.label });
}

test("1. a node locked behind the app's back: the broker refuses the reveal, the app re-reads, shows the locked panel, and Unlock node opens it again without ending the login", async ({ app }) => {
  const { page } = app;
  const value = fixtureSecret("stripe-value");
  await vaultWithEntry(app, value);
  await selectNode(app, "Atlas");
  await openEntry(app, "stripe-live");
  await expect(lockedPanel(app)).toHaveCount(0);

  await app.oracle.login();
  expect(await app.oracle.call("vault.node_lock", { node: "atlas" })).toEqual({ node: "atlas", locked: true });
  const snapshots = app.frames("graph.snapshot").length;

  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(lockedPanel(app)).toBeVisible();
  await expect(lockedPanel(app)).toContainText("This node is locked");
  // the broker's own word for it, whichever of its two it uses; the panel is the answer, so no alarming notice on top of it
  const refusal = (await app.answerOf("entry_reveal")).error;
  expect(["node_locked", "approval_pending"], `the broker refused the reveal with ${refusal.code}`).toContain(refusal.code);
  await expect(notice(app)).toHaveCount(0);
  expect(app.frames("graph.snapshot").length, "the snapshot was read again").toBe(snapshots + 1);
  await expect(railRow(app, "Atlas")).toContainText("⌐");
  await expect(page.getByRole("button", { name: "reveal", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "copy", exact: true })).toHaveCount(0);
  await expect(inspectorValue(page)).toHaveCount(0);
  expect(await app.pageDump()).not.toContain(value);
  expect(app.shim.session.isAuthenticated(), "a node lock is not the end of the login").toBe(true);
  await expect(app.screen("S1 Main")).toBeVisible();

  // its note is not even asked for: the snapshot says the node is locked, so selecting it sends no notes.read for it
  const atlasNoteReads = () => app.frames("notes.read").filter((f) => f.params.node === "atlas").length;
  const before = atlasNoteReads();
  await selectNode(app, "Global");
  await selectNode(app, "Atlas");
  await expect(page.locator("[data-notes]")).toHaveText("locked — unlock the node to read its note");
  expect(atlasNoteReads()).toBe(before);

  await openEntry(app, "stripe-live");
  await lockedPanel(app).getByRole("button", { name: "Unlock node" }).click();
  expect(app.frames("vault.node_unlock").map((f) => f.params)).toEqual([{ node: "atlas" }]);
  await expect(lockedPanel(app)).toHaveCount(0);
  await expect(notice(app, "Node unlocked.")).toBeVisible();
  await expect(railRow(app, "Atlas")).not.toContainText("⌐");
  const snap = await app.oracle.call("graph.snapshot");
  expect(snap.nodes.find((n: { id: string }) => n.id === "atlas").gate.locked).toBe(false);
  expect(app.frames("vault.lock"), "never logged out").toEqual([]);
});

/** A node locked from the app's own menu and then opened again with "Unlock node", with an entry that was stored before. */
async function lockAndUnlockNodeInApp(app: RealApp): Promise<string> {
  const value = fixtureSecret("stripe-value");
  await vaultWithEntry(app, value);
  await selectNode(app, "Atlas");
  await openEntry(app, "stripe-live");
  const menu = await ctxMenu(app, "Atlas");
  await menu.getByRole("button", { name: "Lock now" }).click();
  await expect(lockedPanel(app)).toBeVisible();
  await lockedPanel(app).getByRole("button", { name: "Unlock node" }).click();
  await expect(lockedPanel(app)).toHaveCount(0);
  return value;
}

// 1b was a pinned backend defect (state.rs `lock_node` zeroised the node's hot key and `unlock_node` only cleared the flag, so every
// reveal after "Unlock node" answered not_found "envelope failed to open" until the vault was locked and unlocked). It is fixed:
// `unlock_node` re-derives the key from the resident root key first (state.rs, found by ADR-078's read-modify-write ops and the
// endpoint matrix). The pair of tests that pinned it is replaced by this one, which is the behaviour the pair was waiting for.
test("1b. after Unlock node the entry can be revealed again, with no vault lock in between, and the login is never ended", async ({ app }) => {
  const value = await lockAndUnlockNodeInApp(app);
  expect(app.frames("vault.node_unlock").map((f) => f.params)).toEqual([{ node: "atlas" }]);
  expect(await revealOpenEntry(app)).toBe(value);
  expect(app.shim.session.isAuthenticated(), "unlocking a node is not the end of the login").toBe(true);
  expect(app.frames("vault.lock"), "no vault lock in between").toEqual([]);
});

test("2. a node locked from the app: no reveal is attempted, what was revealed goes off the page, and the lock outlives a vault lock and unlock", async ({ app }) => {
  const { page } = app;
  const value = fixtureSecret("stripe-value");
  await vaultWithEntry(app, value);
  await selectNode(app, "Atlas");
  await openEntry(app, "stripe-live");
  expect(await revealOpenEntry(app)).toBe(value);
  expect(app.frames("entry.reveal")).toHaveLength(1);

  const menu = await ctxMenu(app, "Atlas");
  await menu.getByRole("button", { name: "Lock now" }).click();
  await expect(lockedPanel(app)).toBeVisible();
  expect(await app.pageDump(), "locking a node drops what was revealed from it").not.toContain(value);
  await expect(railRow(app, "Atlas")).toContainText("⌐");
  expect(app.frames("vault.node_lock").map((f) => f.params)).toEqual([{ node: "atlas" }]);
  expect(app.frames("entry.reveal"), "the panel is known from the snapshot: no second reveal was sent").toHaveLength(1);
  await app.oracle.login();
  await expect(app.oracle.call("notes.read", { node: "atlas" })).rejects.toMatchObject({ source: "broker", code: "node_locked" });

  // a vault lock and unlock is not a node unlock
  await lockUi(app);
  await unlockToMain(app);
  await expect(railRow(app, "Atlas")).toContainText("⌐");
  await selectNode(app, "Atlas");
  await openEntry(app, "stripe-live");
  await expect(lockedPanel(app)).toBeVisible();

  const reopen = await ctxMenu(app, "Atlas");
  await expect(reopen.getByRole("button", { name: "Lock now" })).toHaveCount(0);
  await reopen.getByRole("button", { name: "Unlock node" }).click();
  await expect(notice(app, "Node unlocked.")).toBeVisible();
  await expect(lockedPanel(app)).toHaveCount(0);
  expect(await revealOpenEntry(app)).toBe(value);
});

test("3. a TOTP entry in a locked node is the locked panel, and no code is asked for", async ({ app }) => {
  const { page } = app;
  const seed = fixtureTotpSeed();
  await vaultWithEntry(app, seed, { name: "deploy-otp", label: "totp" });
  await selectNode(app, "Atlas");
  const menu = await ctxMenu(app, "Atlas");
  await menu.getByRole("button", { name: "Lock now" }).click();
  await expect(notice(app, "Node locked.")).toBeVisible();
  await openEntry(app, "deploy-otp");
  await expect(lockedPanel(app)).toBeVisible();
  await expect(page.getByRole("button", { name: "show code" })).toHaveCount(0);
  expect(app.frames("totp.code")).toEqual([]);
  expect(await app.pageDump(), "the seed of a locked entry is not on the page").not.toContain(seed);
});

/** The field a revealed value would be in. */
const inspectorValue = (page: RealApp["page"]) => page.locator(".k-field-value");
