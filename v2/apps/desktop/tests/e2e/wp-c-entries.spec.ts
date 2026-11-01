/**
 * Work package C, part 1: adding entries (several fields, a note, one paste -> one entry, a paste split by `///`).
 *
 * Every test asserts the EXACT bridge command and arguments the app sends, what the screens render from the answer, and the
 * refusal paths.  A typed value must be in the DOM of the open dialog only: never in the view, the logic's state after the
 * dialog closes, storage, or a notice.  What the preview shows is the SHELL's answer (`fields_preview`, local: no broker call, no
 * audit record), and what is saved is that preview verbatim: the page keeps no parser and no inference of its own.
 */
import { expect, test } from "./harness";
import { addRow, fillBulk, fillRow, fillSingle, foreignEntry, notice, openAddEntry, previewRows, stateJson } from "./wp-c-util";

const VALUE = "fixture-value-billing-9f2c";

test("an entry of several fields sends exactly one entry_create with those fields, re-reads the list, and no value is left anywhere", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");
  await dlg.getByLabel("entry name").fill("billing");
  await fillRow(dlg, 1, { label: "host", value: "billing.example.test" });
  await addRow(dlg);
  await fillRow(dlg, 2, { label: "api token", value: VALUE });

  // the preview is the shell's: one row per field, in order; what it believes is secret is masked, and the value is never shown
  const rows = previewRows(dlg);
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(0)).toContainText("host");
  await expect(rows.nth(0)).toContainText("billing.example.test");
  await expect(rows.nth(1)).toContainText("api token");
  await expect(rows.nth(1)).toContainText("••••");
  await expect(rows.nth(1)).not.toContainText(VALUE);
  await expect(dlg.locator('[data-preview-summary="true"]')).toContainText("2 fields · 1 masked");

  // typing asked the SHELL, never the broker: no entry call, no audit record, and the secret never went over the socket
  expect((await broker.calls()).map((c) => c.cmd).filter((c) => c.startsWith("entry_") && c !== "entry_list")).toEqual([]);
  expect((await broker.calls("fields_preview")).length).toBeGreaterThan(0);
  expect((await broker.state()).audit).toEqual([]);

  const graphBefore = (await broker.calls("graph_snapshot")).length;
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(notice(app)).toContainText("Saved 1 entry to atlas.");
  await expect(dlg).toBeHidden();

  // the exact command: `fields` instead of a value, the previewed label and value verbatim, and NO pin (nothing was chosen, so nothing is pinned)
  expect(await broker.calls("entry_create")).toEqual([
    { cmd: "entry_create", args: { node: "atlas", name: "billing", fields: [{ label: "host", value: "billing.example.test" }, { label: "api token", value: VALUE }] } },
  ]);
  expect(await broker.calls("entry_create_batch")).toEqual([]);

  // no optimistic write: the counts and the list come from fresh reads
  expect((await broker.calls("graph_snapshot")).length).toBe(graphBefore + 1);
  const listCalls = (await broker.calls("entry_list")).filter((c) => c.args.node === "atlas");
  expect(listCalls.length).toBe(2); // once when the vault loaded, once after the write
  await expect(page.locator("aside.cm-insp button.k-entry")).toHaveCount(4);
  await expect(page.locator("aside.cm-insp button.k-entry", { hasText: "billing" })).toBeVisible();
  await expect(page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first()).toContainText("4");

  // the value is in the broker and nowhere else
  expect((await broker.state()).entries.atlas.map((e) => e.name)).toContain("billing");
  expect(await app.viewJson()).not.toContain(VALUE);
  expect(await stateJson(app)).not.toContain(VALUE); // the form and the preview were wiped when the dialog closed
  expect(await app.storageDump()).not.toContain(VALUE);
  expect(await page.content()).not.toContain(VALUE);
  await expect(notice(app)).not.toContainText(VALUE);
});

test("a one-field entry is the same call with one field in it: the label is kept, not thrown away", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");
  await fillSingle(dlg, { name: "billing-token", label: "api token", value: VALUE });
  await expect(previewRows(dlg)).toHaveCount(1);
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(notice(app)).toContainText("Saved 1 entry to atlas.");
  expect(await broker.calls("entry_create")).toEqual([{ cmd: "entry_create", args: { node: "atlas", name: "billing-token", fields: [{ label: "api token", value: VALUE }] } }]);
});

test("a note is an entry of type note whose one field is free text", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "beacon", true);
  await expect(dlg.locator("#dlg-addentry-title")).toHaveText("New note");
  await expect(dlg.getByLabel("label (optional)")).toHaveValue("note");
  await expect(dlg.getByLabel("entry type")).toHaveValue("note");
  await dlg.getByLabel("entry name").fill("release-checklist");
  await dlg.getByLabel("value", { exact: true }).fill("fixture note body, line one\nline two");
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(notice(app)).toContainText("Saved 1 entry to beacon.");
  // the pin is sent because the user's own button (+ New note) chose it; a plain entry sends none
  expect(await broker.calls("entry_create")).toEqual([
    { cmd: "entry_create", args: { node: "beacon", name: "release-checklist", fields: [{ label: "note", value: "fixture note body, line one\nline two" }], entryType: "note" } },
  ]);
  expect((await broker.state()).entries.beacon.find((e) => e.name === "release-checklist")).toMatchObject({ type: "note" });
});

test("the entry type is sent only when the user picks one; 'auto' sends nothing", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "beacon");
  await fillSingle(dlg, { name: "typed-one", label: "host", value: "box.example.test" });
  await expect(dlg.getByLabel("entry type")).toHaveValue("auto");
  await dlg.getByLabel("entry type").selectOption("login");
  await dlg.getByRole("button", { name: "Save and add another" }).click();
  await expect(notice(app)).toContainText("Saved 1 entry to beacon.");
  // the form is empty again, and the pin did not follow the user into the next entry
  await expect(dlg.getByLabel("entry type")).toHaveValue("auto");
  await fillSingle(dlg, { name: "untyped-one", label: "host", value: "other.example.test" });
  await dlg.getByLabel("entry type").selectOption("login");
  await dlg.getByLabel("entry type").selectOption("auto");
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(dlg).toBeHidden();
  const calls = await broker.calls("entry_create");
  expect(calls.map((c) => c.args.entryType)).toEqual(["login", undefined]);
});

test("pinning a field's type asks the shell again, shows ITS answer, and sends the pin on that field only", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");
  await dlg.getByLabel("entry name").fill("pinned");
  await fillRow(dlg, 1, { label: "contact", value: "ops@fixture.test" });
  await addRow(dlg);
  await fillRow(dlg, 2, { label: "memo", value: "fixture-value-memo" });
  await expect(previewRows(dlg)).toHaveCount(2);
  const typeOf = (n: number) => dlg.getByLabel(`type of ${n === 1 ? "contact" : "memo"}`);
  await expect(typeOf(2)).toHaveValue("auto");
  await expect(previewRows(dlg).nth(1)).toContainText("fixture-value-memo"); // inferred as text: shown

  const previewsBefore = (await broker.calls("fields_preview")).length;
  await typeOf(2).selectOption("password");
  await expect(previewRows(dlg).nth(1)).toContainText("••••"); // the shell re-answered: a pinned password is masked
  await expect(previewRows(dlg).nth(1)).not.toContainText("fixture-value-memo");
  expect((await broker.calls("fields_preview")).length).toBeGreaterThan(previewsBefore);
  const last = (await broker.calls("fields_preview")).at(-1)!;
  expect(last.args).toEqual({ fields: [{ label: "contact", value: "ops@fixture.test" }, { label: "memo", value: "fixture-value-memo", type: "password" }] });

  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(notice(app)).toContainText("Saved 1 entry to atlas.");
  expect(await broker.calls("entry_create")).toEqual([
    { cmd: "entry_create", args: { node: "atlas", name: "pinned", fields: [{ label: "contact", value: "ops@fixture.test" }, { label: "memo", value: "fixture-value-memo", type: "password" }] } },
  ]);
});

test("removing a field row removes it from the preview and from what is sent", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");
  await dlg.getByLabel("entry name").fill("two-rows");
  await fillRow(dlg, 1, { label: "keep", value: "fixture-value-keep" });
  await addRow(dlg);
  await fillRow(dlg, 2, { label: "drop", value: "fixture-value-drop" });
  await expect(previewRows(dlg)).toHaveCount(2);
  await dlg.getByRole("button", { name: "remove field 2" }).click();
  await expect(previewRows(dlg)).toHaveCount(1);
  await expect(dlg.getByRole("button", { name: "remove field 1" })).toHaveCount(0); // the last row cannot go
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(notice(app)).toContainText("Saved 1 entry to atlas.");
  expect((await broker.calls("entry_create"))[0].args).toMatchObject({ fields: [{ label: "keep", value: "fixture-value-keep" }] });
  expect(JSON.stringify(await broker.calls("entry_create"))).not.toContain("fixture-value-drop");
});

test("a name that already exists is refused before any call, and the broker's own entry_exists is shown next to the name", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");

  // 1. the screen knows the name is taken: a message, Save disabled, nothing sent
  await fillSingle(dlg, { name: "stripe-live", value: VALUE });
  await expect(dlg.getByRole("alert")).toContainText("already exists in atlas");
  await expect(dlg.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  expect(await broker.calls("entry_create")).toEqual([]);

  // 2. another process creates "race-name" after this screen last read the node: the broker refuses, and says so
  const st = await broker.state();
  await broker.set({ entries: { ...st.entries, atlas: [...st.entries.atlas, foreignEntry("e-race", "race-name")] } });
  await dlg.getByLabel("entry name").fill("race-name");
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(dlg.getByRole("alert")).toContainText("An entry with that name already exists in this node.");
  await expect(dlg).toBeVisible(); // still open, and what was typed is still there
  await expect(dlg.getByLabel("value", { exact: true })).toHaveValue(VALUE);
  expect(await broker.calls("entry_create")).toEqual([{ cmd: "entry_create", args: { node: "atlas", name: "race-name", fields: [{ label: "", value: VALUE }] } }]);
  expect((await broker.state()).entries.atlas.filter((e) => e.name === "race-name")).toHaveLength(1);
  await expect(page.getByRole("alert").filter({ hasText: VALUE })).toHaveCount(0);

  // typing a new name clears the refusal and the entry can be saved
  await dlg.getByLabel("entry name").fill("race-name-2");
  await expect(dlg.getByRole("alert")).toHaveCount(0);
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(notice(app)).toContainText("Saved 1 entry to atlas.");
});

test("Save and add another keeps the dialog open on the same node with an empty form and the cursor in the name", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");
  await fillSingle(dlg, { name: "first-of-two", value: VALUE });
  await dlg.getByRole("button", { name: "Save and add another" }).click();
  await expect(notice(app)).toContainText("Saved 1 entry to atlas.");
  await expect(dlg).toBeVisible();
  await expect(dlg.getByLabel("entry name")).toHaveValue("");
  await expect(dlg.getByLabel("value", { exact: true })).toHaveValue("");
  await expect(dlg.getByLabel("entry location (node)")).toHaveValue("atlas");
  await expect(dlg.getByRole("button", { name: "Save", exact: true })).toBeDisabled(); // nothing to save yet
  await expect(dlg.getByLabel("entry name")).toBeFocused();
  expect(await stateJson(app)).not.toContain(VALUE);

  await fillSingle(dlg, { name: "second-of-two", value: VALUE + "-2" });
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(dlg).toBeHidden();
  expect((await broker.calls("entry_create")).map((c) => c.args.name)).toEqual(["first-of-two", "second-of-two"]);
  await expect(page.locator("aside.cm-insp button.k-entry")).toHaveCount(5);
});

const PASTE = "host: db.internal.example\nuser: deploy\n///\napi key: fixture-value-bulk-key\n///\nnotes:\nfirst line of a longer value\nsecond line";

test("one paste is ONE multi-field entry: every field in order, named by the name field, saved with one entry_create", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");
  await fillBulk(dlg, PASTE);

  // the shell was asked once for the whole paste, not split
  await expect(previewRows(dlg)).toHaveCount(4);
  expect((await broker.calls("fields_preview")).at(-1)!.args).toEqual({ text: PASTE, split: false });
  await expect(previewRows(dlg).nth(0)).toContainText("host");
  await expect(previewRows(dlg).nth(1)).toContainText("user");
  await expect(previewRows(dlg).nth(2)).toContainText("api key");
  await expect(previewRows(dlg).nth(2)).not.toContainText("fixture-value-bulk-key");
  await expect(previewRows(dlg).nth(3)).toContainText("notes");
  await expect(dlg.locator('[data-preview-summary="true"]')).toContainText("4 fields · 1 masked");

  // one entry needs a name; the paste does not supply one
  await expect(dlg.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  await dlg.getByLabel("entry name").fill("prod-box");
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(notice(app)).toContainText("Saved 1 entry to atlas.");

  expect(await broker.calls("entry_create_batch")).toEqual([]);
  expect(await broker.calls("entry_create")).toEqual([
    {
      cmd: "entry_create",
      args: {
        node: "atlas",
        name: "prod-box",
        fields: [
          { label: "host", value: "db.internal.example" },
          { label: "user", value: "deploy" },
          { label: "api key", value: "fixture-value-bulk-key" },
          { label: "notes", value: "first line of a longer value\nsecond line" },
        ],
      },
    },
  ]);
  expect(await app.viewJson()).not.toContain("fixture-value-bulk-key");
  expect(await stateJson(app)).not.toContain("fixture-value-bulk-key");
});

test("split by /// makes one entry per segment in ONE entry_create_batch, each named by its first label", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");
  await fillBulk(dlg, PASTE);
  await dlg.getByLabel("split each /// segment into its own entry").check();

  // the name field is not used while splitting, and the shell was asked to split
  await expect(dlg.getByLabel("entry name")).toBeDisabled();
  await expect(dlg.locator('[data-preview-entry="true"]')).toHaveCount(3);
  expect((await broker.calls("fields_preview")).at(-1)!.args).toEqual({ text: PASTE, split: true });
  await expect(dlg.getByRole("button", { name: "Save 3 entries" })).toBeEnabled();
  await dlg.getByRole("button", { name: "Save 3 entries" }).click();
  await expect(notice(app)).toContainText("Saved 3 entries to atlas.");

  expect(await broker.calls("entry_create")).toEqual([]);
  expect(await broker.calls("entry_create_batch")).toEqual([
    {
      cmd: "entry_create_batch",
      args: {
        node: "atlas",
        entries: [
          { name: "host", fields: [{ label: "host", value: "db.internal.example" }, { label: "user", value: "deploy" }] },
          { name: "api key", fields: [{ label: "api key", value: "fixture-value-bulk-key" }] },
          { name: "notes", fields: [{ label: "notes", value: "first line of a longer value\nsecond line" }] },
        ],
      },
    },
  ]);
  const names = (await broker.state()).entries.atlas.map((e) => e.name);
  expect(names).toEqual(expect.arrayContaining(["host", "api key", "notes"]));
});

test("split: repeated first labels are numbered apart, and a segment with no label is 'untitled n'", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "beacon");
  await fillBulk(dlg, "token: fixture-value-one\n///\ntoken: fixture-value-two\n///\njust a value with no label");
  await dlg.getByLabel("split each /// segment into its own entry").check();
  await dlg.getByRole("button", { name: "Save 3 entries" }).click();
  await expect(notice(app)).toContainText("Saved 3 entries to beacon.");
  const args = (await broker.calls("entry_create_batch"))[0].args as { entries: Array<{ name: string }> };
  expect(args.entries.map((e) => e.name)).toEqual(["token", "token 2", "untitled 3"]);
});

test("a refused split paste writes nothing: the broker checks every name first, and the paste stays for the user to fix", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");
  await fillBulk(dlg, "host: db.internal.example\n///\nuser: deploy\n///\napi key: fixture-value-bulk-key");
  await dlg.getByLabel("split each /// segment into its own entry").check();
  await expect(dlg.getByRole("button", { name: "Save 3 entries" })).toBeEnabled();

  // another process creates "user" after this screen last read the node
  const st = await broker.state();
  const before = [...st.entries.atlas.map((e) => e.name), "user"];
  await broker.set({ entries: { ...st.entries, atlas: [...st.entries.atlas, foreignEntry("e-race", "user")] } });

  await dlg.getByRole("button", { name: "Save 3 entries" }).click();
  await expect(dlg.getByRole("alert")).toContainText("An entry with that name already exists in this node. Nothing was written.");
  await expect(dlg).toBeVisible();
  await expect(dlg.getByLabel("bulk paste")).toHaveValue(/api key: fixture-value-bulk-key/);

  expect((await broker.calls("entry_create_batch")).length).toBe(1);
  expect((await broker.state()).entries.atlas.map((e) => e.name)).toEqual(before); // not even the entries that were fine
  await expect(page.locator("aside.cm-insp button.k-entry", { hasText: "host" })).toHaveCount(0);
});

test("a split paste that clashes with an existing name is flagged in the preview and cannot be saved", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");
  await fillBulk(dlg, "stripe-live: fixture-value-x\n///\nfresh-one: fixture-value-y");
  await dlg.getByLabel("split each /// segment into its own entry").check();
  await expect(dlg.locator('[data-preview-entry="true"]').first()).toContainText("already exists");
  await expect(dlg.getByRole("alert")).toContainText("“stripe-live” already exists in atlas");
  await expect(dlg.getByRole("button", { name: "Save 2 entries" })).toBeDisabled();
  expect(await broker.calls("entry_create_batch")).toEqual([]);
});

test("a batch that stops part-way says what was saved and what was not", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "beacon");
  await fillBulk(dlg, "alpha: fixture-value-1\n///\nbeta: fixture-value-2");
  await dlg.getByLabel("split each /// segment into its own entry").check();
  await broker.script("entry_create_batch", {
    result: { node: "beacon", created: [{ name: "alpha", entry: "e-p1", pending: false, fieldCount: 1 }], complete: false, failed: { index: 1, name: "beta", error: "internal" }, total: 2, generation: 3 },
  });
  await dlg.getByRole("button", { name: "Save 2 entries" }).click();
  await expect(notice(app)).toContainText("Saved 1 entry of 2 in beacon; stopped at “beta”. The rest were not written.");
  await expect(dlg).toBeHidden();
});

test("a block of lines with no labels is one field, and the hint offers to make each line its own", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "beacon");
  await fillBulk(dlg, "alpha\nbravo\ncharlie");
  await expect(previewRows(dlg)).toHaveCount(1);
  const hint = dlg.locator('[data-blob-hint="true"]');
  await expect(hint).toContainText("one block");
  await hint.getByRole("button", { name: "Make each line its own field" }).click();
  await expect(dlg.getByLabel("bulk paste")).toHaveValue("alpha\n///\nbravo\n///\ncharlie");
  await expect(previewRows(dlg)).toHaveCount(3);
  await expect(hint).toHaveCount(0);
  expect((await broker.calls("fields_preview")).at(-1)!.args).toEqual({ text: "alpha\n///\nbravo\n///\ncharlie", split: false });
});

test("a paste the shell cannot preview says so and cannot be saved", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "beacon");
  await dlg.getByLabel("entry name").fill("unpreviewable");
  await broker.script("fields_preview", { error: { code: "invalid_fields", source: "bridge" } });
  await fillBulk(dlg, "a: b");
  await expect(dlg.getByText("That text could not be previewed")).toBeVisible();
  await expect(dlg.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  expect(await broker.calls("entry_create")).toEqual([]);
});

test("a refusal that is not about a name is shown, not swallowed", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "beacon");
  await fillSingle(dlg, { name: "x-token", value: VALUE });
  await broker.script("entry_create", { error: { code: "capability_not_held", detail: { rule: "create is not granted to this node" } } });
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(dlg.getByRole("alert")).toContainText("Not permitted (create is not granted to this node).");
  await expect(dlg).toBeVisible();
});

test("a lost login while saving goes to the lock screen and the typed value does not survive it", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "atlas");
  await fillSingle(dlg, { name: "late-one", value: VALUE });
  await expect(dlg.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
  await broker.script("entry_create", { error: { code: "vault_locked" } });
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await expect.poll(() => stateJson(app)).not.toContain(VALUE);
  expect(await page.content()).not.toContain(VALUE);
});

test("closing the dialog any way at all leaves no typed value behind, in the form or in the preview", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: { locked: false } });
  await expect(app.screen("S1 Main")).toBeVisible();
  for (const how of ["Cancel", "Escape", "scrim"] as const) {
    const dlg = await openAddEntry(app, "beacon");
    await fillSingle(dlg, { name: "abandoned", value: VALUE });
    await expect(previewRows(dlg)).toHaveCount(1); // the preview holds the value too: it must go with the form
    if (how === "Cancel") await dlg.getByRole("button", { name: "Cancel" }).click();
    else if (how === "Escape") await page.keyboard.press("Escape");
    else await page.mouse.click(5, 5);
    await expect(dlg).toBeHidden();
    await expect.poll(() => stateJson(app), how).not.toContain(VALUE);
  }
});

test("a preview that arrives after the dialog closed puts nothing back", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "beacon");
  await broker.script("fields_preview", { delayMs: 600 });
  await dlg.getByLabel("value", { exact: true }).fill(VALUE);
  await page.waitForTimeout(250); // the debounce has fired and the shell's answer is on its way
  await page.keyboard.press("Escape");
  await expect(dlg).toBeHidden();
  await page.waitForTimeout(900);
  expect(await stateJson(app)).not.toContain(VALUE);
});

test("saves ask the broker nothing in a page with no shell", async ({ app }) => {
  // no Tauri shell at all: the app runs on its demo data and has no broker to write to, and says so
  await app.open({ broker: false });
  await expect(app.screen("S1 Main")).toBeVisible();
  const dlg = await openAddEntry(app, "linux");
  await fillSingle(dlg, { name: "demo-one", value: VALUE });
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(notice(app)).toContainText("Writing needs the CredMgr app");
  await expect(dlg).toBeVisible();
});
