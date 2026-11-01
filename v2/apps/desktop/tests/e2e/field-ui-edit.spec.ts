/**
 * Field UI, part 2: changing an entry's fields - the ⋮ menu, "+ Add field", Edit, Move up / Move down and Remove.
 *
 * For every control: the EXACT command and arguments it sends (field.add / update / remove / reorder, each with the node's generation as the
 * list last said it), what the screen renders from the re-read, and at least one refusal.  What the user types lives in the dialog's DOM and the
 * logic's state only while the dialog is open: it is in no notice, no storage and no state afterwards.
 */
import { MASK, notice } from "./wp-b-helpers";
import { expect, test } from "./harness";
import { dialogReady, fieldDialog, fieldRow, fieldRows, openApp, openEntryOf, openMenu, PG, PG_VALUE, valueOf } from "./field-ui-helpers";
import { stateJson } from "./wp-c-util";

const labels = (app: Parameters<typeof fieldRows>[0]) => app.page.locator('[data-fields="true"] [data-field-label="true"]');

test.describe("the field menu", () => {
  test("offers Edit, Move up, Move down and Remove; the first field cannot move up, the last cannot move down", async ({ app }) => {
    await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    const first = await openMenu(app, PG.host);
    await expect(first.getByRole("menuitem")).toHaveText(["Edit…", "Move up", "Move down", "Remove…"]);
    await expect(first.getByRole("menuitem", { name: "Move up" })).toBeDisabled();
    await expect(first.getByRole("menuitem", { name: "Move down" })).toBeEnabled();
    await expect(first.getByRole("menuitem", { name: "Remove…" })).toBeEnabled();
    // it is a menu: the first enabled item has the focus, and the arrow keys walk the enabled ones (a disabled item is skipped)
    await expect(first.getByRole("menuitem", { name: "Edit…" })).toBeFocused();
    await app.page.keyboard.press("ArrowDown");
    await expect(first.getByRole("menuitem", { name: "Move down" })).toBeFocused(); // "Move up" is disabled for the first field
    await app.page.keyboard.press("ArrowDown");
    await expect(first.getByRole("menuitem", { name: "Remove…" })).toBeFocused();
    await app.page.keyboard.press("ArrowDown");
    await expect(first.getByRole("menuitem", { name: "Edit…" })).toBeFocused(); // wraps
    await app.page.keyboard.press("ArrowUp");
    await expect(first.getByRole("menuitem", { name: "Remove…" })).toBeFocused();
    await app.page.keyboard.press("Escape");
    await expect(app.page.locator(".cm-fieldmenu")).toHaveCount(0);

    const last = await openMenu(app, PG.note);
    await expect(last.getByRole("menuitem", { name: "Move down" })).toBeDisabled();
    await expect(last.getByRole("menuitem", { name: "Move up" })).toBeEnabled();
    // a click anywhere else closes it; so does opening another field's menu
    await app.page.locator("aside.cm-insp").getByText("every reveal and copy writes an audit record").click();
    await expect(app.page.locator(".cm-fieldmenu")).toHaveCount(0);
    // (a menu hangs below its row, so open the lower one first: an open menu covers the buttons under it, as a popover does)
    await openMenu(app, PG.note);
    await openMenu(app, PG.host);
    await expect(app.page.locator(".cm-fieldmenu")).toHaveCount(1);
    await expect(app.page.locator(".cm-fieldmenu")).toHaveAttribute("aria-label", "actions for host");
  });

  test("an entry's only field cannot be removed: the item is disabled and says why", async ({ app }) => {
    await openApp(app);
    await openEntryOf(app, "atlas", "stripe-live");
    const menu = await openMenu(app, "f_00000000");
    const remove = menu.getByRole("menuitem", { name: "Remove…" });
    await expect(remove).toBeDisabled();
    await expect(remove).toHaveAttribute("title", "an entry keeps at least one field");
    await expect(menu.getByRole("menuitem", { name: "Move up" })).toBeDisabled();
    await expect(menu.getByRole("menuitem", { name: "Move down" })).toBeDisabled();
  });

  test("a locked node offers none of it", async ({ app }) => {
    await openApp(app);
    await openEntryOf(app, "cobalt", "shop-admin");
    await expect(app.page.getByRole("button", { name: "field menu" })).toHaveCount(0);
    await expect(app.page.getByRole("button", { name: "+ Add field" })).toHaveCount(0);
  });
});

test.describe("+ Add field", () => {
  test("appends one field with the label and value typed, echoing the node's generation, then reads the entry again", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    await page.getByRole("button", { name: "+ Add field" }).click();
    const dlg = await dialogReady(app);
    await expect(dlg).toBeVisible();
    await expect(dlg.locator("#dlg-field-title")).toHaveText("Add a field");
    await expect(dlg).toContainText("pg-main");
    const add = dlg.getByRole("button", { name: "Add field", exact: true });
    await expect(add).toBeDisabled(); // nothing to add yet
    await expect(dlg.getByLabel("field label")).toBeFocused();
    await dlg.getByLabel("field label").fill("replica");
    await expect(add).toBeDisabled(); // a label alone is not a field
    await dlg.getByLabel("field value").fill("fixture-value-replica.example.test");
    await expect(add).toBeEnabled();

    const getsBefore = (await broker.calls("entry_get")).length;
    const listsBefore = (await broker.calls("entry_list")).filter((c) => c.args.node === "atlas").length;
    await add.click();
    await expect(notice(app, "Field added to “pg-main”.")).toBeVisible();
    await expect(dlg).toBeHidden();

    // the exact command: the previous generation, one field, no pin, no position (appended)
    expect(await broker.calls("field_add")).toEqual([
      { cmd: "field_add", args: { node: "atlas", entry: PG.entry, generation: 1, fields: [{ label: "replica", value: "fixture-value-replica.example.test" }] } },
    ]);
    // nothing is guessed: the entry's fields, the node's list and the graph are read again
    expect((await broker.calls("entry_get")).length).toBe(getsBefore + 1);
    expect((await broker.calls("entry_list")).filter((c) => c.args.node === "atlas").length).toBe(listsBefore + 1);
    await expect(fieldRows(app)).toHaveCount(6);
    await expect(labels(app).last()).toHaveText("replica");
    await expect(app.screen("S5 Entry detail")).toContainText("6 fields");
    // its value is shown (the broker inferred a host: not masked), fetched in ONE read of the fields not yet held
    await expect(fieldRows(app).last().locator(".k-field-value")).toHaveText("fixture-value-replica.example.test");
    expect((await broker.state()).entries.atlas.find((e) => e.id === PG.entry)).toMatchObject({ fields: expect.arrayContaining([expect.objectContaining({ label: "replica" })]) });
    expect((await broker.calls("entry_reveal")).at(-1)!.args.fieldIds).toHaveLength(1);
    expect(await stateJson(app)).not.toContain("fixture-value-replica");
    expect(await app.storageDump()).not.toContain("fixture-value-replica");
  });

  test("a stale generation is conflict: the entry is reloaded, the notice says so, the form keeps what was typed, and a retry goes through", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await app.page.getByRole("button", { name: "+ Add field" }).click();
    const dlg = await dialogReady(app);
    await dlg.getByLabel("field label").fill("late");
    await dlg.getByLabel("field value").fill("fixture-value-late");
    const getsBefore = (await broker.calls("entry_get")).length;
    await broker.script("field_add", { error: { code: "conflict", detail: { node: "atlas", expectedGeneration: 1, currentGeneration: 4 } } });
    await dlg.getByRole("button", { name: "Add field", exact: true }).click();
    await expect(notice(app, "Changed elsewhere. Reloaded; try again.")).toBeVisible();
    await expect(dlg).toBeVisible();
    await expect(dlg.getByLabel("field value")).toHaveValue("fixture-value-late");
    await expect.poll(async () => (await broker.calls("entry_get")).length).toBeGreaterThan(getsBefore); // the one entry it was working on, not only the node
    expect(await broker.state().then((s) => s.entries.atlas.find((e) => e.id === PG.entry)!)).not.toMatchObject({ fields: expect.arrayContaining([expect.objectContaining({ label: "late" })]) });

    await dlg.getByRole("button", { name: "Add field", exact: true }).click();
    await expect(notice(app, "Field added to “pg-main”.")).toBeVisible();
    expect((await broker.calls("field_add")).length).toBe(2);
    await expect(labels(app).last()).toHaveText("late");
  });

  test("a field the broker does not accept is said next to the form, which stays open", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await app.page.getByRole("button", { name: "+ Add field" }).click();
    const dlg = await dialogReady(app);
    await dlg.getByLabel("field label").fill("odd");
    await dlg.getByLabel("field value").fill("fixture-value-odd");
    await broker.script("field_add", { error: { code: "malformed_request" } });
    await dlg.getByRole("button", { name: "Add field", exact: true }).click();
    await expect(dlg.getByRole("alert")).toContainText("The broker did not accept that field.");
    await expect(dlg).toBeVisible();
    await expect(app.page.locator("[data-notice]")).toHaveCount(0); // said once, next to the form, not twice
    await expect(fieldRows(app)).toHaveCount(5);
    // typing clears it
    await dlg.getByLabel("field label").fill("odd2");
    await expect(dlg.getByRole("alert")).toHaveCount(0);
  });

  test("a label over 200 characters is refused on the form, before any call", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await app.page.getByRole("button", { name: "+ Add field" }).click();
    const dlg = await dialogReady(app);
    await dlg.getByLabel("field label").fill("x".repeat(201));
    await dlg.getByLabel("field value").fill("fixture-value-long-label");
    await expect(dlg.getByRole("alert")).toContainText("A label is at most 200 characters.");
    await expect(dlg.getByRole("button", { name: "Add field", exact: true })).toBeDisabled();
    expect(await broker.calls("field_add")).toEqual([]);
    await dlg.getByLabel("field label").fill("x".repeat(200));
    await expect(dlg.getByRole("button", { name: "Add field", exact: true })).toBeEnabled();
  });

  test("a label that holds a line break is made one line", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await app.page.getByRole("button", { name: "+ Add field" }).click();
    const dlg = await dialogReady(app);
    await dlg.getByLabel("field label").fill("two\nlines");
    await dlg.getByLabel("field value").fill("fixture-value-two-lines");
    await dlg.getByRole("button", { name: "Add field", exact: true }).click();
    await expect(notice(app, "Field added to “pg-main”.")).toBeVisible();
    expect((await broker.calls("field_add"))[0].args.fields).toEqual([{ label: "two lines", value: "fixture-value-two-lines" }]);
  });
});

test.describe("Edit", () => {
  const openEdit = async (app: Parameters<typeof openMenu>[0], id: string) => {
    const menu = await openMenu(app, id);
    await menu.getByRole("menuitem", { name: "Edit…" }).click();
    return dialogReady(app);
  };

  test("starts from what the broker said, never from the value; Save stays off until something changes", async ({ app }) => {
    await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    const dlg = await openEdit(app, PG.note);
    await expect(dlg.locator("#dlg-field-title")).toHaveText("Edit a field");
    await expect(dlg.getByLabel("field label")).toHaveValue("note");
    await expect(dlg.getByLabel("new field value")).toHaveValue(""); // the current value is not shown here
    await expect(dlg.getByLabel("new field value")).toHaveAttribute("placeholder", "leave empty to keep the current value");
    await expect(dlg.getByLabel("field type")).toHaveValue("text"); // this field's type is the user's pin
    await expect(dlg.getByLabel("field masking")).toHaveValue("auto");
    await expect(dlg.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
    expect(await app.page.content()).not.toContain("value=\"" + PG_VALUE.note); // not in any input
    // a field whose type is inferred starts on "auto"
    await app.page.keyboard.press("Escape");
    const dlg2 = await openEdit(app, PG.host);
    await expect(dlg2.getByLabel("field type")).toHaveValue("auto");
  });

  test("a label change sends the label and nothing else", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    const dlg = await openEdit(app, PG.note);
    await dlg.getByLabel("field label").fill("remarks");
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(notice(app, "Field updated in “pg-main”.")).toBeVisible();
    expect(await broker.calls("field_update")).toEqual([
      { cmd: "field_update", args: { node: "atlas", entry: PG.entry, generation: 1, field: PG.note, patch: { label: "remarks" } } },
    ]);
    await expect(labels(app).nth(4)).toHaveText("remarks");
    await expect(dlg).toBeHidden();
  });

  test("a new value, a type and a masking each travel as their own key, only the keys that changed; the old value is dropped at once", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    const dlg = await openEdit(app, PG.note);
    await dlg.getByLabel("new field value").fill("fixture-value-new-note");
    await dlg.getByLabel("field type").selectOption("password");
    await dlg.getByLabel("field masking").selectOption("hidden");
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(notice(app, "Field updated in “pg-main”.")).toBeVisible();
    expect(await broker.calls("field_update")).toEqual([
      { cmd: "field_update", args: { node: "atlas", entry: PG.entry, generation: 1, field: PG.note, patch: { value: "fixture-value-new-note", type: "password", masked: true } } },
    ]);
    // it is a hidden password now: masked, and neither the old value nor the new one is on the page or in the state
    await expect(valueOf(app, PG.note)).toHaveText(MASK);
    await expect(fieldRow(app, PG.note).locator("[data-field-type]")).toHaveText("password");
    for (const v of [PG_VALUE.note, "fixture-value-new-note"]) {
      expect(await page.content(), v).not.toContain(v);
      expect(await stateJson(app), v).not.toContain(v);
      expect(await app.storageDump(), v).not.toContain(v);
    }
    // the others kept their values (re-read in one call, since the wipe dropped them with the old one)
    await expect(valueOf(app, PG.host)).toHaveText(PG_VALUE.host);
    // and "auto" clears a pin
    const again = await openEdit(app, PG.note);
    await expect(again.getByLabel("field type")).toHaveValue("password");
    await again.getByLabel("field type").selectOption("auto");
    await again.getByLabel("field masking").selectOption("auto");
    await again.getByRole("button", { name: "Save", exact: true }).click();
    await expect(notice(app, "Field updated in “pg-main”.")).toBeVisible();
    expect((await broker.calls("field_update")).at(-1)!.args.patch).toEqual({ type: "auto", masked: "auto" });
  });

  test("a field that is gone closes the form and reloads: nothing is left to apply it to", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    const dlg = await openEdit(app, PG.note);
    await dlg.getByLabel("field label").fill("remarks");
    await broker.script("field_update", { error: { code: "not_found" } });
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(notice(app, "That no longer exists. Reloaded.")).toBeVisible();
    await expect(dlg).toBeHidden();
    expect(await stateJson(app)).not.toContain("remarks");
  });

  test("a stale generation reloads the entry and keeps the form for a retry", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    const dlg = await openEdit(app, PG.note);
    await dlg.getByLabel("field label").fill("remarks");
    await broker.set({ generation: { atlas: 9 } }); // another process changed the node
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(notice(app, "Changed elsewhere. Reloaded; try again.")).toBeVisible();
    await expect(dlg).toBeVisible();
    await expect(dlg.getByLabel("field label")).toHaveValue("remarks");
    // the retry carries the generation the reload learned
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(notice(app, "Field updated in “pg-main”.")).toBeVisible();
    expect((await broker.calls("field_update")).map((c) => c.args.generation)).toEqual([1, 9]);
  });

  test("a refused update is said next to the form and changes nothing on screen", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    const dlg = await openEdit(app, PG.note);
    await dlg.getByLabel("new field value").fill("fixture-value-refused");
    await broker.script("field_update", { error: { code: "malformed_request" } });
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(dlg.getByRole("alert")).toContainText("The broker did not accept that field.");
    await expect(dlg).toBeVisible();
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note); // untouched
  });

  test("closing the form any way at all leaves the typed value nowhere", async ({ app }) => {
    const { page } = app;
    await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    for (const how of ["Cancel", "Escape", "scrim"] as const) {
      const dlg = await openEdit(app, PG.password);
      await dlg.getByLabel("new field value").fill("fixture-value-abandoned");
      if (how === "Cancel") await dlg.getByRole("button", { name: "Cancel" }).click();
      else if (how === "Escape") await page.keyboard.press("Escape");
      else await page.mouse.click(5, 5);
      await expect(dlg).toBeHidden();
      await expect.poll(() => stateJson(app), how).not.toContain("fixture-value-abandoned");
    }
  });

  test("a lock with the form open leaves no typed value behind", async ({ app }) => {
    const { page } = app;
    await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    const dlg = await openEdit(app, PG.password);
    await dlg.getByLabel("new field value").fill("fixture-value-mid-lock");
    await page.keyboard.press("Control+l");
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    await expect.poll(() => stateJson(app)).not.toContain("fixture-value-mid-lock");
    expect(await page.content()).not.toContain("fixture-value-mid-lock");
  });
});

test.describe("Remove", () => {
  test("asks first; Cancel sends nothing; confirming sends field.remove for that field, and the row is gone after the re-read", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    const menu = await openMenu(app, PG.port);
    await menu.getByRole("menuitem", { name: "Remove…" }).click();
    const dlg = fieldDialog(app);
    await expect(dlg.locator("#dlg-field-title")).toHaveText("Remove a field");
    await expect(dlg).toContainText("Remove the field “port” from “pg-main”? The entry keeps its other fields.");
    await dlg.getByRole("button", { name: "Cancel" }).click();
    await expect(dlg).toBeHidden();
    expect(await broker.calls("field_remove")).toEqual([]);
    await expect(fieldRows(app)).toHaveCount(5);

    await (await openMenu(app, PG.port)).getByRole("menuitem", { name: "Remove…" }).click();
    await expect(dlg).toBeVisible();
    await dlg.getByRole("button", { name: "Remove field", exact: true }).click();
    await expect(notice(app, "Field removed from “pg-main”.")).toBeVisible();
    expect(await broker.calls("field_remove")).toEqual([{ cmd: "field_remove", args: { node: "atlas", entry: PG.entry, generation: 1, field: PG.port } }]);
    await expect(fieldRows(app)).toHaveCount(4);
    await expect(labels(app)).toHaveText(["host", "username", "password", "note"]);
    await expect(app.screen("S5 Entry detail")).toContainText("4 fields");
  });

  test("the last field is refused by the broker with its own words (a stale screen can still ask)", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await (await openMenu(app, PG.port)).getByRole("menuitem", { name: "Remove…" }).click();
    await broker.script("field_remove", { error: { code: "malformed_request" } });
    await fieldDialog(app).getByRole("button", { name: "Remove field", exact: true }).click();
    await expect(notice(app, "An entry keeps at least one field. Remove the entry instead. Nothing was changed.")).toBeVisible();
    await expect(fieldRows(app)).toHaveCount(5);
  });

  test("a field that was already removed elsewhere closes the form and reloads", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await (await openMenu(app, PG.port)).getByRole("menuitem", { name: "Remove…" }).click();
    await broker.script("field_remove", { error: { code: "not_found" } });
    await fieldDialog(app).getByRole("button", { name: "Remove field", exact: true }).click();
    await expect(notice(app, "That no longer exists. Reloaded.")).toBeVisible();
    await expect(fieldDialog(app)).toBeHidden();
  });

  test("a lost login while removing goes to the lock screen", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await (await openMenu(app, PG.port)).getByRole("menuitem", { name: "Remove…" }).click();
    await broker.script("field_remove", { error: { code: "vault_locked" } });
    await fieldDialog(app).getByRole("button", { name: "Remove field", exact: true }).click();
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    expect(await app.secretCount()).toBe(0);
  });
});

test.describe("Move up and Move down", () => {
  test("Move up sends field.reorder with every id in the new order, and the rows follow the re-read; held values stay", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    const revealsBefore = (await broker.calls("entry_reveal")).length;
    await (await openMenu(app, PG.port)).getByRole("menuitem", { name: "Move up" }).click();
    await expect(labels(app)).toHaveText(["port", "host", "username", "password", "note"]);
    expect(await broker.calls("field_reorder")).toEqual([
      { cmd: "field_reorder", args: { node: "atlas", entry: PG.entry, generation: 1, order: [PG.port, PG.host, PG.user, PG.password, PG.note] } },
    ]);
    // the ids did not change, so nothing was dropped and nothing is read again
    await expect(valueOf(app, PG.host)).toHaveText(PG_VALUE.host);
    expect((await broker.calls("entry_reveal")).length).toBe(revealsBefore);
  });

  test("Move down is the same call the other way, one place", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await (await openMenu(app, PG.host)).getByRole("menuitem", { name: "Move down" }).click();
    await expect(labels(app)).toHaveText(["port", "host", "username", "password", "note"]);
    expect((await broker.calls("field_reorder"))[0].args.order).toEqual([PG.port, PG.host, PG.user, PG.password, PG.note]);
  });

  test("a stale generation is conflict: the screen reloads, says so, and the retry carries the new generation", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await broker.set({ generation: { atlas: 9 } }); // another process changed the node behind the screen's back
    await (await openMenu(app, PG.port)).getByRole("menuitem", { name: "Move up" }).click();
    await expect(notice(app, "Changed elsewhere. Reloaded; try again.")).toBeVisible();
    await expect(labels(app)).toHaveText(["host", "port", "username", "password", "note"]); // unchanged
    await (await openMenu(app, PG.port)).getByRole("menuitem", { name: "Move up" }).click();
    await expect(labels(app)).toHaveText(["port", "host", "username", "password", "note"]);
    expect((await broker.calls("field_reorder")).map((c) => c.args.generation)).toEqual([1, 9]);
  });

  test("a refused reorder is said and the order on screen stays what the broker last said", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await broker.script("field_reorder", { error: { code: "malformed_request" } });
    await (await openMenu(app, PG.user)).getByRole("menuitem", { name: "Move up" }).click();
    await expect(notice(app, "The fields could not be reordered because the entry changed. Reloaded; try again.")).toBeVisible();
    await expect(labels(app)).toHaveText(["host", "port", "username", "password", "note"]);
  });
});

test.describe("a page with no shell", () => {
  test("shows the example vault's fields, and a change says it needs the app and sends nothing", async ({ app }) => {
    const { page } = app;
    await app.open({ broker: false });
    await expect(app.screen("S1 Main")).toBeVisible();
    await page.locator(".cm-rail .k-tree-row", { hasText: "linux" }).first().click();
    await page.locator("aside.cm-insp button.k-entry", { hasText: "vps-root" }).first().click();
    await expect(app.screen("S5 Entry detail")).toBeVisible();
    await expect(page.locator('[data-fields="true"] .k-field').first()).toBeVisible();
    const rows = await page.locator('[data-fields="true"] .k-field').count();
    expect(rows).toBeGreaterThan(1);

    // Move down: said, nothing changed
    await page.locator('[data-fields="true"] .k-field').first().getByRole("button", { name: "field menu" }).click();
    await page.locator(".cm-fieldmenu").getByRole("menuitem", { name: "Move down" }).click();
    await expect(notice(app, "Changing a field needs the CredMgr app")).toBeVisible();

    // Edit: the same, after typing
    await page.locator('[data-fields="true"] .k-field').nth(1).getByRole("button", { name: "field menu" }).click();
    await page.locator(".cm-fieldmenu").getByRole("menuitem", { name: "Edit…" }).click();
    const dlg = await dialogReady(app);
    await dlg.getByLabel("field label").fill("renamed");
    await dlg.getByRole("button", { name: "Save", exact: true }).click();
    await expect(notice(app, "Changing a field needs the CredMgr app")).toBeVisible();
    await expect(dlg).toBeVisible();
    await expect(page.locator('[data-fields="true"] .k-field')).toHaveCount(rows);
  });
});
