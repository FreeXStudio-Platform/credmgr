/**
 * The remaining wired controls, each against the real vault: rename a node, copy through the shell, Operations (verify, doctor,
 * back up), About, and sealing a node. Every one is checked at the vault by an independent client, never only on screen.
 *
 * Sealing used to be held to its intended behaviour in a test marked `test.fail`, with a twin that pinned the refusal: the broker
 * could not seal a node in a vault made by `vault.init_*` (K-7's remainder, no orphan key at init). ADR-079 closed that - `credmgr
 * init` now writes the orphan node and its cold key - so the pair is flipped: the intended test is the test, and the twin is gone.
 */
import { existsSync, readFileSync, statSync } from "node:fs";

import { expect, fixtureSecret, test, type Locator, type RealApp } from "./harness";
import { addEntry, closeSettings, createVaultViaWizard, ctxMenu, KDF, lockUi, MASKED_LABEL, notice, openEntry, openSettings, railRow, selectNode, unlockToMain } from "./helpers";

async function vaultWith(app: RealApp, project: string): Promise<void> {
  await app.open();
  await createVaultViaWizard(app);
  await app.page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await app.page.getByLabel("project name 1").fill(project);
  await app.page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
  await expect(railRow(app, project)).toBeVisible();
}

async function openFromMenu(app: RealApp, item: string): Promise<void> {
  await app.page.getByRole("button", { name: "vault menu" }).click();
  await app.page.locator(".cm-vaultmenu button", { hasText: item }).first().click();
}

test("rename sends the new label, the broker keeps it, and the node's id (what entries and grants hang off) never changes", async ({ app }) => {
  const { page } = app;
  await vaultWith(app, "Atlas");
  const menu = await ctxMenu(app, "Atlas");
  await menu.getByRole("button", { name: "Rename" }).click();
  const input = page.locator(".cm-rail input");
  await expect(input).toHaveValue("Atlas");
  await input.fill("  Atlas Prod  ");
  await input.press("Enter");
  await expect(railRow(app, "Atlas Prod")).toBeVisible();
  await expect(notice(app, "Renamed.")).toBeVisible();
  expect(app.frames("node.update").map((f) => f.params)).toEqual([{ node: "atlas", label: "Atlas Prod" }]); // trimmed, once
  await app.oracle.login();
  const snap = await app.oracle.call("graph.snapshot");
  expect(snap.nodes.find((n: { id: string }) => n.id === "atlas")).toMatchObject({ id: "atlas", label: "Atlas Prod" });
  // refused before any call: empty, and too long
  const again = await ctxMenu(app, "Atlas Prod");
  await again.getByRole("button", { name: "Rename" }).click();
  await page.locator(".cm-rail input").fill("x".repeat(121));
  await page.locator(".cm-rail input").press("Enter");
  await expect(notice(app, "1 to 120 characters")).toBeVisible();
  expect(app.frames("node.update")).toHaveLength(1);
});

test("copy goes through the shell: the value is on the (modelled) concealed pasteboard, never in the page, and locking takes it off", async ({ app }) => {
  const { page } = app;
  const value = fixtureSecret("copy-value");
  await vaultWith(app, "Atlas");
  // a MASKED field: the page holds none of its value (a field that is not masked is read and shown on open, which is not this test)
  await addEntry(app, "Atlas", { name: "stripe-live", label: MASKED_LABEL, value });
  await page.evaluate(() => {
    // anything the page itself tried to put on the clipboard would show up here
    (window as any).__clipWrites = [];
    try {
      Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: (t: string) => ((window as any).__clipWrites.push(t), Promise.resolve()), readText: () => Promise.resolve("") } });
    } catch {
      /* a browser that refuses the spy leaves the shell-side assertions below to carry the test */
    }
  });
  await selectNode(app, "Atlas");
  await openEntry(app, "stripe-live");
  await page.getByRole("button", { name: "copy", exact: true }).click();
  await expect(page.getByRole("button", { name: "copied" })).toBeVisible();

  // ADR-078: the page names the FIELD to copy, and the shell narrows its reveal to that field (`fieldIds`), so no other field's value
  // is ever read by the shell, let alone by the page
  const login = await app.oracle.login();
  const id = await login.entryId("atlas", "stripe-live");
  const [field, ...others] = await login.fieldsOf("atlas", "stripe-live");
  expect(others, "a one-field entry").toEqual([]);
  expect(app.calls("entry_copy").map((c) => c.args)).toEqual([{ node: "atlas", entry: id, field: field.id }]);
  expect(app.frames("entry.reveal"), "the shell revealed it Rust-side, for exactly that entry and that field").toEqual([{ op: "entry.reveal", params: { node: "atlas", entry: id, fieldIds: [field.id] } }]);
  expect(app.shim.clipboard).toMatchObject({ text: value, concealed: true });
  expect(app.shim.answers.find((a: any) => a.cmd === "entry_copy")).toEqual({ cmd: "entry_copy", result: { copied: true, clearAfterSeconds: 30 } });
  expect(await page.evaluate(() => (window as any).__clipWrites)).toEqual([]);
  expect(await app.pageDump(), "the value never reached the page").not.toContain(value);

  await lockUi(app);
  expect(app.shim.clipboard.text, "locking empties a secret the app copied").toBeNull();
  expect(app.shim.clipboard.history.map((h: { kind: string }) => h.kind)).toEqual(["secret", "clear"]);
});

test("Operations against the real vault: Verify says what the broker found, Doctor has nothing to fix, Back up writes an encrypted archive inside the vault directory", async ({ app }) => {
  const { page } = app;
  const value = fixtureSecret("backed-up-value");
  const backupPhrase = fixtureSecret("backup-phrase");
  await vaultWith(app, "Atlas");
  await addEntry(app, "Atlas", { name: "stripe-live", value });

  await openFromMenu(app, "Operations");
  await expect(app.screen("S14 Operations")).toBeVisible();
  const result = page.locator('[data-ops-result="true"]');
  await page.getByRole("button", { name: "Verify integrity" }).click();
  await expect(result).toContainText("ok · 2 nodes checked");
  expect(app.frames("maintenance.verify")).toHaveLength(1);

  await page.getByRole("button", { name: "Doctor", exact: true }).click();
  await expect(result).toContainText("Doctor · checked");
  expect(app.frames("maintenance.doctor").map((f) => f.params)).toEqual([{ apply: false }]); // a dry run first; a plain run never asks for the purge list
  await expect(result.getByRole("button")).toHaveCount(0); // nothing to apply on a healthy vault
  await page.keyboard.press("Escape");

  const settings = await openSettings(app, "Backup");
  await expect(page.locator(".k-chip", { hasText: "ok · 2 nodes checked" })).toBeVisible(); // the answer Operations just got
  await page.getByRole("button", { name: "Verify now" }).click();
  await expect.poll(() => app.frames("maintenance.verify").length).toBe(2);
  await expect(page.locator(".k-chip", { hasText: "ok · 2 nodes checked" })).toBeVisible();
  await page.getByRole("button", { name: "Back up now" }).click();
  const prompt = app.screen("Passphrase prompt");
  await prompt.getByLabel("backup passphrase", { exact: true }).fill(backupPhrase);
  await prompt.getByLabel("repeat the passphrase").fill(backupPhrase);
  await prompt.getByRole("button", { name: "Back up", exact: true }).click();
  await expect(prompt).toHaveCount(0, KDF); // the backup key is derived from the passphrase: memory-hard
  await expect(notice(app, "Backup written.")).toBeVisible();

  // the broker wrote exactly one archive, inside the throwaway vault, and the app shows where
  const [frame] = app.frames("maintenance.backup");
  expect(frame.params).toEqual({ passphrase: backupPhrase, retain: 14 });
  const answer = (await app.answerOf("maintenance_backup")).result;
  expect(answer.path.startsWith(app.daemon.vaultDir), `the archive is at ${answer.path}`).toBe(true);
  expect(existsSync(answer.path) && statSync(answer.path).size > 0).toBe(true);
  const shown = await settings.innerText();
  expect(shown).toMatch(/last backup this session: \S*backups\/credmgr-backup-\d+\.enc/);
  // an encrypted archive: neither the value nor the backup passphrase is readable in it
  const bytes = readFileSync(answer.path);
  expect(bytes.includes(Buffer.from(value))).toBe(false);
  expect(bytes.includes(Buffer.from(backupPhrase))).toBe(false);
  const dump = await app.pageDump();
  expect(dump).not.toContain(backupPhrase);
  expect(dump).not.toContain(value);
  await closeSettings(app);
});

async function backUpNow(app: RealApp): Promise<{ settings: Locator; answer: any }> {
  const { page } = app;
  const settings = await openSettings(app, "Backup");
  await page.getByRole("button", { name: "Back up now" }).click();
  const prompt = app.screen("Passphrase prompt");
  const phrase = fixtureSecret("backup-phrase");
  await prompt.getByLabel("backup passphrase", { exact: true }).fill(phrase);
  await prompt.getByLabel("repeat the passphrase").fill(phrase);
  await prompt.getByRole("button", { name: "Back up", exact: true }).click();
  await expect(notice(app, "Backup written.")).toBeVisible(KDF);
  return { settings, answer: (await app.answerOf("maintenance_backup")).result };
}

test("Back up: the broker answers the NAMES of the archives it pruned and the line under the button shows how many, as a number", async ({ app }) => {
  await vaultWith(app, "Atlas");
  const { settings, answer } = await backUpNow(app);
  expect(Array.isArray(answer.pruned), `maintenance.backup answered pruned as ${JSON.stringify(answer.pruned)}`).toBe(true);
  expect(answer.pruned).toEqual([]); // a first backup removes none
  expect(Object.keys(answer).sort()).toEqual(["path", "pruned", "retain"]);
  const line = (await settings.innerText()).match(/last backup this session:[^\n]*/)?.[0] ?? "";
  expect(line, "the line the person reads").toMatch(/· 0 older archives removed$/);
});

test("About shows the version the shell reports, and the donation address goes to the clipboard through the shell as plain text", async ({ app }) => {
  const { page } = app;
  await vaultWith(app, "Atlas");
  await openFromMenu(app, "About CredMgr");
  await expect(app.screen("S18 About")).toBeVisible();
  const conf = JSON.parse(readFileSync(new URL("../../src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  await expect(page.locator('[data-about-version="true"]')).toHaveText(conf.version);
  expect((await app.pluginCalls()).filter((c) => c.cmd === "plugin:app|version")).toHaveLength(1);

  // Donate: the address on screen is a published one (DONATE.md), and "copy address" hands exactly that text to the shell, as plain text
  await page.getByRole("link", { name: "Donate" }).click();
  const shown = (await app.screen("S18 About").locator("div[style*='user-select']").first().innerText()).trim();
  expect(readFileSync(new URL("../../../../DONATE.md", import.meta.url), "utf8")).toContain(shown);
  await page.evaluate(() => {
    (window as any).__written = [];
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: (t: string) => ((window as any).__written.push(t), Promise.resolve()), readText: () => Promise.resolve("") } });
  });
  await page.getByRole("button", { name: "copy address" }).click();
  await expect(page.getByRole("button", { name: /copied/ })).toBeVisible();
  expect(app.calls("copy_text")).toEqual([{ cmd: "copy_text", args: { text: shown } }]);
  expect(app.shim.clipboard).toMatchObject({ text: shown, concealed: false });
  expect(app.calls("entry_copy"), "an address is not a secret: the concealed copy is for entries").toEqual([]);
  expect(await page.evaluate(() => (window as any).__written), "the page never writes the clipboard itself").toEqual([]);
});

test.describe("sealing a node", () => {
  async function openSeal(app: RealApp, label: string) {
    await app.page.locator(".cm-rail .k-tree-row", { hasText: label }).first().click({ button: "right" });
    await app.page.getByRole("button", { name: "Remove node…", exact: true }).click();
    const dlg = app.screen("S9 Seal node");
    await expect(dlg).toBeVisible();
    await dlg.getByLabel("type the node name to confirm").fill(label);
    return dlg;
  }

  test("sealing moves the node's entries to Orphaned (names stay, values do not), and the node can be restored within 7 days", async ({ app }) => {
    const { page } = app;
    const value = fixtureSecret("sealed-value");
    await vaultWith(app, "Atlas");
    await addEntry(app, "Atlas", { name: "stripe-live", value });
    const dlg = await openSeal(app, "Atlas");
    await dlg.getByRole("button", { name: "Seal node" }).click();
    expect(app.frames("node.seal").map((f) => f.params)).toEqual([{ node: "atlas" }]);
    await expect(notice(app, "Node “atlas” sealed. Restore it from Settings → Nodes within 7 days.")).toBeVisible();
    await expect(page.locator(".cm-rail .k-tree-row", { hasText: "Atlas" })).toHaveCount(0);
    await app.oracle.login();
    // the node is gone from the ordinary view, and Orphaned is native + presence only (R0): an ordinary login cannot even list it, and
    // there is no unseal operation (ADR-079) - so nothing here can read the sealed entry's name or value
    expect((await app.oracle.call("entry.list", { node: "atlas" })).names, "the sealed node lists nothing any more").toEqual([]);
    await expect(app.oracle.call("entry.list", { node: "orphan" })).rejects.toMatchObject({ source: "broker", code: "node_access_denied", detail: { rule: "R0" } });
    expect((await app.oracle.call("maintenance.verify")).ok, "a seal leaves a vault that verifies").toBe(true);

    const settings = await openSettings(app, "Nodes");
    await settings.getByRole("button", { name: "Restore node" }).click();
    await expect(notice(app, "Node “atlas” restored.")).toBeVisible();
    await closeSettings(app);
    await expect(railRow(app, "Atlas")).toBeVisible();
    await lockUi(app);
    await unlockToMain(app);
    await app.oracle.login();
    expect(await app.oracle.entries("atlas")).toEqual({ "stripe-live": value });
  });

  test("J8: a sealed node is still listed, with its real window, after a lock, an unlock and a daemon restart, and Restore brings it back", async ({ app }) => {
    const { page } = app;
    const value = fixtureSecret("sealed-restart-value");
    await vaultWith(app, "Atlas");
    await addEntry(app, "Atlas", { name: "stripe-live", value });
    const dlg = await openSeal(app, "Atlas");
    await dlg.getByRole("button", { name: "Seal node" }).click();
    await expect(notice(app, "Node “atlas” sealed.")).toBeVisible();
    await expect(page.locator(".cm-rail .k-tree-row", { hasText: "Atlas" })).toHaveCount(0);

    await lockUi(app);
    await unlockToMain(app); // (the session's own memory of what it sealed is gone with the lock)
    await lockUi(app);
    await app.restartDaemon(); // SIGTERM + start again on the same vault: the broker's memory is gone too, only the vault remains
    await unlockToMain(app);
    const settings = await openSettings(app, "Nodes");
    const row = settings.locator(".is-sealed");
    await expect(row).toHaveCount(1);
    await expect(row).toContainText("Atlas");
    await expect(row).toContainText(/restorable until \d{4}-\d{2}-\d{2} \d{2}:\d{2}/); // the broker's own window, not the rule
    await expect(row).not.toContainText("restorable for 7 days after sealing");
    await row.getByRole("button", { name: "Restore node" }).click();
    await expect(notice(app, "Node “atlas” restored.")).toBeVisible();
    expect(app.frames("node.restore").map((f) => f.params)).toEqual([{ node: "atlas" }]);
    await closeSettings(app);
    await expect(railRow(app, "Atlas")).toBeVisible();
    await app.oracle.login();
    expect(await app.oracle.entries("atlas")).toEqual({ "stripe-live": value });
  });
});
