/**
 * The whole path, against a real daemon on a throwaway vault:
 *
 *   first run (init) -> node -> entries (single, bulk) -> reveal -> search -> notes -> lock -> unlock
 *   -> daemon restart -> unlock -> the data is still there
 *
 * Every step is checked twice: what the app shows, and what the vault holds, read by an independent client (the oracle: its own
 * login, the socket protocol directly). A screen that claims "Saved" while the broker holds nothing, or a reveal that shows a
 * value the broker never gave, fails here.
 */
import { readFileSync } from "node:fs";

import { expect, fixtureSecret, test } from "./harness";
import { createVaultViaWizard, fillBulk, inspector, lockUi, notice, openAddEntry, openEntry, railRow, revealOpenEntry, selectNode, unlockToMain, addEntry } from "./helpers";

test("first run to a restarted daemon: the vault, a project, entries, reveal, search, notes, lock, unlock, restart, and the data is still there", async ({ app }) => {
  const { page } = app;
  const billing = fixtureSecret("billing-value");
  const bulkKey = fixtureSecret("bulk-api-key");
  const mergedPassword = fixtureSecret("merged-password");
  const noteBody = "first line of a longer value\nsecond line";
  const runbook = "# Runbook\nrotate the billing key monthly";
  await app.open();

  await test.step("first run: a machine with no vault is routed to the wizard, which creates a real one", async () => {
    await expect(app.screen("S17 First run")).toBeVisible();
    expect(app.commands()).toEqual(["vault_status"]);
    expect(app.frames()).toEqual([{ op: "vault.status", params: {} }]);
    expect(app.daemon.vaultFiles().some((f) => f.endsWith("registry.json")), "no vault exists before first run").toBe(false);

    const recovery = await createVaultViaWizard(app);
    const [begin] = app.calls("vault_init_begin");
    expect(begin.args).toEqual({ passphrase: app.passphrase });
    expect(app.calls("vault_init_confirm").map((c) => c.args)).toEqual([{ recoveryCode: recovery }]);
    // the vault now exists on disk, made by the broker (not by the page), and the wizard logged in
    const files = app.daemon.vaultFiles().map((f) => f.slice(app.daemon.root.length));
    for (const needed of ["/v/registry.json", "/v/registry.sig", "/v/keys/root.wrap.pass", "/v/keys/root.wrap.recovery", "/v/keys/nodes/global.key"]) {
      expect(files, `the broker wrote ${needed}`).toContain(needed);
    }
    expect(app.commands().slice(0, 4)).toEqual(["vault_status", "vault_init_begin", "vault_init_confirm", "vault_unlock"]);
    expect(app.shim.session.isAuthenticated(), "the shim holds the login").toBe(true);
    // neither the passphrase nor the recovery code is left on the page
    const dump = await app.pageDump();
    expect(dump).not.toContain(app.passphrase);
    expect(dump).not.toContain(recovery);

    await page.getByRole("button", { name: "Enrol later", exact: true }).click();
    await expect(page.getByText("first run · step 4 of 4")).toBeVisible();
    await page.getByLabel("project name 1").fill("Shop Front");
    await page.getByRole("button", { name: "Open the vault", exact: true }).click();
    await expect(app.screen("S1 Main")).toBeVisible();
    expect(app.frames("node.create").map((f) => f.params)).toEqual([{ id: "shop-front", label: "Shop Front", parentId: "global" }]);
    await expect(railRow(app, "Shop Front")).toBeVisible();
    await app.oracle.login();
    expect((await app.oracle.nodeIds()).sort()).toEqual(["global", "shop-front"]);
  });

  await test.step("one entry through the form: the broker has exactly what was typed", async () => {
    await addEntry(app, "Shop Front", { name: "billing-token", label: "api token", value: billing });
    // ADR-078: the form always sends the field list, even for one field. `value` and `fields` are alternatives, and the label is the field's own.
    expect(app.frames("entry.create").map((f) => f.params)).toEqual([{ node: "shop-front", name: "billing-token", fields: [{ label: "api token", value: billing }] }]);
    expect(await app.oracle.entries("shop-front")).toEqual({ "billing-token": billing });
    const [field, ...others] = await app.oracle.fieldsOf("shop-front", "billing-token");
    expect(others).toEqual([]);
    expect(field).toMatchObject({ label: "api token", value: billing, type: "api-key", masked: true }); // typed by the broker's inference, from the label
    await expect(inspector(app).locator("button.k-entry")).toHaveCount(1);
    expect(await app.pageDump(), "the typed value is nowhere on the page once the dialog is closed").not.toContain(billing);
  });

  await test.step("a bulk paste with the split box ticked is ONE broker batch: one entry per /// segment, each field kept with its label", async () => {
    const dlg = await openAddEntry(app, "Shop Front");
    await fillBulk(dlg, `host: db.internal.example\nuser: deploy\n///\napi key: ${bulkKey}\n///\nnotes:\n${noteBody}`, { split: true });
    const rows = dlg.locator('[data-preview-row="true"]');
    await expect(rows).toHaveCount(4); // one row per FIELD: host, user | api key | notes
    await expect(rows.nth(2)).not.toContainText(bulkKey); // masked in the preview
    await dlg.getByRole("button", { name: "Save 3 entries" }).click();
    await expect(notice(app, "Saved 3 entries to shop-front.")).toBeVisible();
    const batches = app.frames("entry.create_batch");
    expect(batches).toHaveLength(1);
    // each entry is named from the first label of its segment; its fields are what the preview showed, label and value verbatim, nothing pinned
    expect(batches[0].params.entries).toEqual([
      { name: "host", fields: [{ label: "host", value: "db.internal.example" }, { label: "user", value: "deploy" }] },
      { name: "api key", fields: [{ label: "api key", value: bulkKey }] },
      { name: "notes", fields: [{ label: "notes", value: noteBody }] },
    ]);
    expect(app.frames("entry.create")).toHaveLength(1); // still only the single entry from before
    expect(await app.oracle.entries("shop-front")).toEqual({
      "billing-token": billing,
      host: [{ label: "host", value: "db.internal.example" }, { label: "user", value: "deploy" }],
      "api key": bulkKey,
      notes: noteBody,
    });
    await expect(railRow(app, "Shop Front").locator(".k-tree-count")).toHaveText("4");
  });

  await test.step("a bulk paste as it comes (not split) is ONE entry holding every field in order, typed by the broker's own inference", async () => {
    const dlg = await openAddEntry(app, "Shop Front");
    await fillBulk(dlg, `host: cache.internal.example\nport: 6379\npassword: ${mergedPassword}`);
    await dlg.getByLabel("entry name").fill("cache");
    await expect(dlg.locator('[data-preview-row="true"]')).toHaveCount(3);
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(notice(app, "Saved 1 entry to shop-front.")).toBeVisible();
    await expect(dlg).toBeHidden(); // closes when the broker has taken it - the next step's notice reads the same, so this is what tells them apart
    expect(app.frames("entry.create").at(-1)!.params).toEqual({
      node: "shop-front",
      name: "cache",
      fields: [{ label: "host", value: "cache.internal.example" }, { label: "port", value: "6379" }, { label: "password", value: mergedPassword }],
    });
    expect(app.frames("entry.create_batch"), "one entry is not a batch").toHaveLength(1);
    const fields = await app.oracle.fieldsOf("shop-front", "cache");
    expect(fields.map((f: { label: string; value: string; type: string; masked: boolean }) => [f.label, f.value, f.type, f.masked])).toEqual([
      ["host", "cache.internal.example", "host", false],
      ["port", "6379", "port", false],
      ["password", mergedPassword, "password", true],
    ]);
    await expect(railRow(app, "Shop Front").locator(".k-tree-count")).toHaveText("5");
  });

  await test.step("reveal asks the broker for that entry and shows its value; leaving the entry takes it off the page", async () => {
    await openEntry(app, "billing-token");
    const shown = await revealOpenEntry(app);
    expect(shown).toBe(billing);
    const id = await app.oracle.entryId("shop-front", "billing-token");
    const [field] = await app.oracle.fieldsOf("shop-front", "billing-token");
    // ADR-078: the reveal names the field it wants (`fieldIds`), so an entry with several fields never gives up the others' values
    expect(app.frames("entry.reveal")).toEqual([{ op: "entry.reveal", params: { node: "shop-front", entry: id, fieldIds: [field.id] } }]);
    expect(await app.storageDump()).not.toContain(billing);
    await page.getByRole("button", { name: /^← Shop Front/ }).click();
    expect(await app.pageDump(), "a revealed value does not outlive the entry detail").not.toContain(billing);
  });

  await test.step("search asks the broker once for what was typed, and a hit opens its entry", async () => {
    const box = page.locator(".cm-searchinput");
    await box.click();
    await box.pressSequentially("billing", { delay: 5 });
    const drop = app.screen("S7 Search");
    const hit = drop.getByRole("button", { name: /billing-token/ });
    await expect(hit).toBeVisible();
    await expect(hit).toContainText("Shop Front");
    expect(app.frames("search").map((f) => f.params)).toEqual([{ term: "billing" }]);
    await hit.click();
    await expect(app.screen("S5 Entry detail")).toBeVisible();
    await expect(inspector(app)).toContainText("billing-token");
    await page.getByRole("button", { name: /^← Shop Front/ }).click();
  });

  await test.step("notes: a note written elsewhere (the CLI's way) is read from the broker when the node is selected; a '+ New note' is a labelled entry", async () => {
    await app.oracle.setNote("shop-front", runbook);
    await selectNode(app, "Global");
    await expect(page.locator("[data-notes]")).toHaveText("No note.");
    await selectNode(app, "Shop Front");
    await expect(page.locator("[data-notes]")).toHaveText(runbook);
    expect(app.frames("notes.read").at(-1)).toEqual({ op: "notes.read", params: { node: "shop-front" } });

    const dlg = await openAddEntry(app, "Shop Front", true);
    await expect(dlg.getByLabel("label (optional)")).toHaveValue("note");
    await dlg.getByLabel("entry name").fill("release-checklist");
    await dlg.getByLabel("value", { exact: true }).fill("ship on thursday\nnot on friday");
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(notice(app, "Saved 1 entry to shop-front.")).toBeVisible();
    await expect(dlg).toBeHidden(); // the previous step's notice reads the same: the dialog closing is the broker having taken THIS save
    expect((await app.oracle.entries("shop-front"))["release-checklist"]).toBe("ship on thursday\nnot on friday");
    await expect(railRow(app, "Shop Front").locator(".k-tree-count")).toHaveText("6");
  });

  const expected = {
    "billing-token": billing,
    host: [{ label: "host", value: "db.internal.example" }, { label: "user", value: "deploy" }],
    "api key": bulkKey,
    notes: noteBody,
    cache: [{ label: "host", value: "cache.internal.example" }, { label: "port", value: "6379" }, { label: "password", value: mergedPassword }],
    "release-checklist": "ship on thursday\nnot on friday",
  };

  await test.step("lock: the broker really locks, the login is dead, and the page forgets the vault", async () => {
    await lockUi(app);
    expect(app.frames("vault.lock")).toHaveLength(1);
    expect(app.shim.session.isAuthenticated()).toBe(false);
    // the oracle's own login died with the vault: a revoked token is refused as session_expired (ADR-068)
    await expect(app.oracle.call("entry.list", { node: "shop-front" })).rejects.toMatchObject({ source: "broker", code: "session_expired" });
    const dump = await app.pageDump();
    for (const gone of ["billing-token", "Shop Front", billing, bulkKey, mergedPassword, "release-checklist", runbook]) expect(dump, `${gone} is still on the Lock screen`).not.toContain(gone);
  });

  await test.step("unlock again: everything is back, from the broker", async () => {
    await unlockToMain(app);
    await expect(railRow(app, "Shop Front").locator(".k-tree-count")).toHaveText("6");
    expect(app.frames("vault.unlock")).toHaveLength(2); // the wizard's, and this one
  });

  await test.step("restart the daemon (SIGTERM, same vault): lock, unlock, and every value is still there", async () => {
    const pidBefore = app.daemon.pid;
    await lockUi(app);
    await app.restartDaemon();
    expect(app.daemon.pid).not.toBe(pidBefore);
    await unlockToMain(app);
    await expect(railRow(app, "Shop Front").locator(".k-tree-count")).toHaveText("6");
    await selectNode(app, "Shop Front");
    await expect(page.locator("[data-notes]")).toHaveText(runbook);
    await openEntry(app, "billing-token");
    expect(await revealOpenEntry(app)).toBe(billing);
    await page.getByRole("button", { name: /^← Shop Front/ }).click();
    // and by the independent route, on a brand-new login against the restarted process
    await app.oracle.login();
    expect(await app.oracle.entries("shop-front")).toEqual(expected);
    expect((await app.oracle.call("maintenance.verify")).ok, "the vault verifies clean after the restart").toBe(true);
  });

  await test.step("on disk: no plaintext value, no passphrase, no session token anywhere under the vault", async () => {
    const needles = [billing, bulkKey, mergedPassword, noteBody, runbook, "db.internal.example", "cache.internal.example", app.passphrase];
    const offenders: string[] = [];
    for (const file of app.daemon.vaultFiles()) {
      const bytes = readFileSync(file);
      const text = bytes.toString("latin1");
      for (const n of needles) if (bytes.includes(Buffer.from(n)) || text.includes(n)) offenders.push(`${file.slice(app.daemon.root.length)} holds ${n.slice(0, 12)}...`);
      if (/cmt_[0-9a-f]{8,}/i.test(text)) offenders.push(`${file.slice(app.daemon.root.length)} holds a session token`);
    }
    expect(offenders).toEqual([]);
  });
});
