/**
 * Field UI, part 1: the entry detail (S5) renders an entry's fields from the broker and nothing else, and its per-field controls.
 *
 * What is asserted, for every control: the EXACT command and arguments it sends (`entry_get`, `entry_reveal` with `fieldIds`, `entry_copy`
 * and `totp_code` with `field`), what the screen renders from the answer, and one refusal path.  A plaintext value is allowed in exactly one
 * place: the DOM of the field it belongs to, while it is shown.  Never the view, the logic's state, storage, a notice or a log.
 */
import { MASK, notice } from "./wp-b-helpers";
import { expect, test } from "./harness";
import { fieldRow, fieldRows, multi, openApp, openEntryOf, openWithExtra, PG, PG_SECRETS, PG_VALUE, valueOf } from "./field-ui-helpers";

test.describe("the fields come from entry.get", () => {
  test("a multi-field entry is one row per field in the broker's order, labelled and typed as the broker said, and no field is invented", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");

    await expect(fieldRows(app)).toHaveCount(5);
    await expect(page.locator('[data-fields="true"] [data-field-label="true"]')).toHaveText(["host", "port", "username", "password", "note"]);
    await expect(page.locator('[data-fields="true"] [data-field-type="true"]')).toHaveText(["host", "port", "username", "password", "text"]);
    await expect(app.screen("S5 Entry detail")).toContainText("server");
    await expect(app.screen("S5 Entry detail")).toContainText("5 fields");

    // one metadata read of the entry, and nothing else about it: the list rows carry no labels
    expect(await broker.calls("entry_get")).toEqual([{ cmd: "entry_get", args: { node: "atlas", entry: PG.entry } }]);

    // the labels and ids live in the model's detail, not in the view the screens replace wholesale
    const view = await app.viewJson();
    for (const bad of ["f_00a2", "username", "password"]) expect(view, bad).not.toContain(bad);
  });

  test("the fields that are not masked show without a click, from ONE reveal of exactly those fields; the masked one stays masked", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");

    await expect(valueOf(app, PG.host)).toHaveText(PG_VALUE.host);
    await expect(valueOf(app, PG.port)).toHaveText(PG_VALUE.port);
    await expect(valueOf(app, PG.user)).toHaveText(PG_VALUE.user);
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    await expect(valueOf(app, PG.password)).toHaveText(MASK);
    await expect(valueOf(app, PG.password)).toHaveAttribute("data-masked", "true");
    await expect(valueOf(app, PG.host)).toHaveAttribute("data-masked", "false");

    // one reveal, narrowed to the unmasked fields in stored order: the password's value was never asked for
    expect(await broker.calls("entry_reveal")).toEqual([{ cmd: "entry_reveal", args: { node: "atlas", entry: PG.entry, fieldIds: [PG.host, PG.port, PG.user, PG.note] } }]);
    expect(await app.secretCount()).toBe(4);
    expect(await page.content()).not.toContain(PG_VALUE.password);
    await expect(fieldRow(app, PG.host).getByRole("button", { name: "reveal" })).toHaveCount(0); // nothing to reveal: it is showing
    await expect(fieldRow(app, PG.password).getByRole("button", { name: "reveal", exact: true })).toBeVisible();
  });

  test("a refused read of the unmasked fields says so, shows no value, and does not ask again by itself", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await broker.script("entry_reveal", { error: { code: "capability_not_held", detail: { rule: "reveal is not granted here" } } });
    await openEntryOf(app, "atlas", "pg-main");
    await expect(notice(app, "Not permitted (reveal is not granted here).")).toBeVisible();
    await expect(valueOf(app, PG.host)).toHaveText("—");
    await expect(valueOf(app, PG.note)).toHaveText("—");
    await page.waitForTimeout(700); // a render loop would show as more calls
    expect((await broker.calls("entry_reveal")).length).toBe(1);
    expect(await app.secretCount()).toBe(0);

    // a masked field still reveals: the refusal was about that one read
    await fieldRow(app, PG.password).getByRole("button", { name: "reveal", exact: true }).click();
    await expect(valueOf(app, PG.password)).toHaveText(PG_VALUE.password);
  });

  test("a lost login during the read of the unmasked fields goes to the lock screen and leaves nothing of the entry", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await broker.script("entry_reveal", { error: { code: "vault_locked" } });
    await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
    await page.locator("aside.cm-insp button.k-entry", { hasText: "pg-main" }).first().click();
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    expect(await app.secretCount()).toBe(0);
    const html = await page.content();
    for (const v of PG_SECRETS) expect(html, v).not.toContain(v);
    expect(html).not.toContain("pg-main");
    expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  });

  test("an entry written before the field model is one field with no label: the screen numbers it, and it is masked until revealed", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "stripe-live");
    await expect(fieldRows(app)).toHaveCount(1);
    await expect(page.locator('[data-field-label="true"]')).toHaveText("field 1");
    await expect(valueOf(app, "f_00000000")).toHaveText(MASK);
    expect(await broker.calls("entry_get")).toEqual([{ cmd: "entry_get", args: { node: "atlas", entry: "e-a1" } }]);
    expect(await broker.calls("entry_reveal")).toEqual([]); // nothing unmasked, so nothing is revealed by opening it
  });

  test("when entry.get fails the detail says so and offers Try again, which reads again", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await broker.script("entry_get", { error: { code: "internal" } });
    await openEntryOf(app, "atlas", "pg-main");
    const failed = page.locator('[data-fields-state="failed"]');
    await expect(failed).toContainText("The fields of this entry could not be read.");
    await expect(fieldRows(app)).toHaveCount(0);
    await failed.getByRole("button", { name: "Try again" }).click();
    await expect(fieldRows(app)).toHaveCount(5);
    expect((await broker.calls("entry_get")).length).toBe(2);
  });

  test("an entry that is gone says so, and the node is reloaded", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await broker.script("entry_get", { error: { code: "not_found" } });
    const listsBefore = (await broker.calls("entry_list")).filter((c) => c.args.node === "atlas").length;
    await openEntryOf(app, "atlas", "pg-main");
    await expect(page.locator('[data-fields-state="failed"]')).toContainText("This entry no longer exists.");
    await expect(notice(app, "That no longer exists. Reloaded.")).toBeVisible();
    await expect.poll(async () => (await broker.calls("entry_list")).filter((c) => c.args.node === "atlas").length).toBeGreaterThan(listsBefore);
  });

  test("while the fields are being read the detail says so, and shows no field", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await broker.script("entry_get", { delayMs: 500 });
    await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
    await page.locator("aside.cm-insp button.k-entry", { hasText: "pg-main" }).first().click();
    await expect(page.locator('[data-fields-state="loading"]')).toBeVisible();
    await expect(fieldRows(app)).toHaveCount(0);
    await expect(fieldRows(app)).toHaveCount(5);
    await expect(page.locator('[data-fields-state="loading"]')).toHaveCount(0);
  });
});

test.describe("reveal and copy are per field", () => {
  test("reveal sends entry.reveal narrowed to that field, shows it, counts down, re-masks and holds nothing afterwards", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await page.evaluate(() => (window as any).__cm.setState({ revealWindowSecs: 2 }));
    await openEntryOf(app, "atlas", "pg-main");
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    expect(await app.secretCount()).toBe(4);

    await fieldRow(app, PG.password).getByRole("button", { name: "reveal", exact: true }).click();
    await expect(valueOf(app, PG.password)).toHaveText(PG_VALUE.password);
    await expect(valueOf(app, PG.password)).toHaveAttribute("data-masked", "false");
    await expect(fieldRow(app, PG.password).getByText(/re-masks in [12]s/)).toBeVisible();
    expect((await broker.calls("entry_reveal")).at(-1)).toEqual({ cmd: "entry_reveal", args: { node: "atlas", entry: PG.entry, fieldIds: [PG.password] } });
    expect(await app.secretCount()).toBe(5);
    expect(await app.viewJson()).not.toContain(PG_VALUE.password);
    expect(await app.storageDump()).not.toContain(PG_VALUE.password);

    // it re-masks by itself; the unmasked ones stay (they are not secrets of the window, they are what the entry shows)
    await expect(valueOf(app, PG.password)).toHaveText(MASK);
    expect(await page.content()).not.toContain(PG_VALUE.password);
    expect(await app.secretCount()).toBe(4);
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    expect((await broker.calls("entry_reveal")).length).toBe(2); // re-masking asked the broker for nothing
  });

  test("hide puts the mask back at once", async ({ app }) => {
    const { page } = app;
    await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await fieldRow(app, PG.password).getByRole("button", { name: "reveal", exact: true }).click();
    await expect(valueOf(app, PG.password)).toHaveText(PG_VALUE.password);
    await fieldRow(app, PG.password).getByRole("button", { name: "hide", exact: true }).click();
    await expect(valueOf(app, PG.password)).toHaveText(MASK);
    expect(await page.content()).not.toContain(PG_VALUE.password);
  });

  test("a refused reveal of one field is shown with the broker's rule and leaves that field masked", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    await broker.script("entry_reveal", { error: { code: "capability_not_held", detail: { rule: "reveal is not granted here" } } });
    await fieldRow(app, PG.password).getByRole("button", { name: "reveal", exact: true }).click();
    await expect(notice(app, "Not permitted (reveal is not granted here).")).toBeVisible();
    await expect(valueOf(app, PG.password)).toHaveText(MASK);
    expect(await app.secretCount()).toBe(4);
  });

  test("copy goes through the shell narrowed to that field; the value never reaches the page; the button says copied", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    const revealsBefore = (await broker.calls("entry_reveal")).length;

    await fieldRow(app, PG.password).getByRole("button", { name: "copy", exact: true }).click();
    await expect(fieldRow(app, PG.password).getByRole("button", { name: "copied" })).toBeVisible();
    expect(await broker.calls("entry_copy")).toEqual([{ cmd: "entry_copy", args: { node: "atlas", entry: PG.entry, field: PG.password } }]);
    expect((await broker.calls("entry_reveal")).length).toBe(revealsBefore); // the page did not fetch the value to copy it
    await expect(valueOf(app, PG.password)).toHaveText(MASK);
    expect(await page.content()).not.toContain(PG_VALUE.password);
    expect(await app.viewJson()).not.toContain(PG_VALUE.password);
    // the fixture's pasteboard holds that one field's value, concealed, and the receipt the page saw names no value
    const board = await page.evaluate(() => (window as any).__brokerFixture.pasteboard);
    expect(board).toMatchObject({ field: PG.password, concealed: true });
  });

  test("a clipboard the shell cannot write is said, and nothing is reported as copied", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await broker.script("entry_copy", { error: { code: "clipboard_failed", source: "bridge" } });
    await fieldRow(app, PG.host).getByRole("button", { name: "copy", exact: true }).click();
    await expect(notice(app, "The clipboard could not be written. Nothing was copied.")).toBeVisible();
    await expect(fieldRow(app, PG.host).getByRole("button", { name: "copied" })).toHaveCount(0);
  });

  test("each field has its own copy button, and each asks for its own field", async ({ app }) => {
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    for (const id of [PG.host, PG.user]) await fieldRow(app, id).getByRole("button", { name: "copy", exact: true }).click();
    await expect.poll(async () => (await broker.calls("entry_copy")).length).toBe(2);
    expect((await broker.calls("entry_copy")).map((c) => c.args.field)).toEqual([PG.host, PG.user]);
  });
});

test.describe("a TOTP seed field", () => {
  const VPN = multi("e-m1", "vpn", [
    { id: "f_00c10001", label: "username", value: "fixture-value-vpn-user" },
    { id: "f_00c10002", label: "2fa seed", value: "JBSWY3DPEHPK3PXP" },
  ]);

  test("shows its CODE instead of a reveal, asks for it by field, has no copy button, and never has its seed read", async ({ app }) => {
    const { page } = app;
    const broker = await openWithExtra(app, "atlas", [VPN]);
    await openEntryOf(app, "atlas", "vpn");
    await expect(valueOf(app, "f_00c10001")).toHaveText("fixture-value-vpn-user");
    // the unmasked read names the username only: the seed is not an unmasked field to be read, whatever its masking says
    expect(await broker.calls("entry_reveal")).toEqual([{ cmd: "entry_reveal", args: { node: "atlas", entry: "e-m1", fieldIds: ["f_00c10001"] } }]);

    const seed = fieldRow(app, "f_00c10002");
    await expect(seed.getByRole("button", { name: "copy" })).toHaveCount(0);
    await seed.getByRole("button", { name: "show code" }).click();
    await expect(valueOf(app, "f_00c10002")).toHaveText("123 456");
    expect(await broker.calls("totp_code")).toEqual([{ cmd: "totp_code", args: { node: "atlas", entry: "e-m1", field: "f_00c10002" } }]);
    expect((await broker.calls("entry_reveal")).length).toBe(1);
    expect(await page.content()).not.toContain("JBSWY3DPEHPK3PXP");
    await seed.getByRole("button", { name: "hide" }).click();
    await expect(valueOf(app, "f_00c10002")).toHaveText(MASK);
  });

  test("show seed is asked for by field and refused for want of presence; nothing is shown", async ({ app }) => {
    const { page } = app;
    const broker = await openWithExtra(app, "atlas", [VPN]);
    await openEntryOf(app, "atlas", "vpn");
    await fieldRow(app, "f_00c10002").getByRole("button", { name: "show seed" }).click();
    await expect(notice(app, "Needs presence (Touch ID), which this beta cannot attest yet. Nothing was changed. (totp.seed)")).toBeVisible();
    expect(await broker.calls("totp_seed")).toEqual([{ cmd: "totp_seed", args: { node: "atlas", entry: "e-m1", field: "f_00c10002" } }]);
    await expect(valueOf(app, "f_00c10002")).toHaveText(MASK);
    expect(await page.content()).not.toContain("JBSWY3DPEHPK3PXP");
  });

  test("a code the broker refuses is said, and nothing is kept", async ({ app }) => {
    const broker = await openWithExtra(app, "atlas", [VPN]);
    await openEntryOf(app, "atlas", "vpn");
    await broker.script("totp_code", { error: { code: "malformed_request" } });
    await fieldRow(app, "f_00c10002").getByRole("button", { name: "show code" }).click();
    await expect(notice(app, /does not hold a usable TOTP seed/)).toBeVisible();
    await expect(valueOf(app, "f_00c10002")).toHaveText(MASK);
    expect(await app.secretCount()).toBe(1); // only the username
  });
});

test.describe("leaving, locking and the locked node", () => {
  test("leaving the entry wipes every value; opening it again reads its fields afresh", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    await fieldRow(app, PG.password).getByRole("button", { name: "reveal", exact: true }).click();
    await expect(valueOf(app, PG.password)).toHaveText(PG_VALUE.password);
    expect(await app.secretCount()).toBe(5);

    await page.getByRole("button", { name: /^← atlas/ }).click();
    expect(await app.secretCount()).toBe(0);
    expect(await page.content()).not.toContain(PG_VALUE.password);
    expect(await page.content()).not.toContain(PG_VALUE.note);

    await page.locator("aside.cm-insp button.k-entry", { hasText: "pg-main" }).click();
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    await expect(valueOf(app, PG.password)).toHaveText(MASK);
    expect((await broker.calls("entry_get")).length).toBe(2);
    expect((await broker.calls("entry_reveal")).filter((c) => (c.args.fieldIds as string[]).length === 4).length).toBe(2);
  });

  test("a hidden window wipes every value (auto-lock off), and the window coming back reads the unmasked fields again", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await page.evaluate(() => (window as any).__cm.setState({ autoLockMins: 0 }));
    await openEntryOf(app, "atlas", "pg-main");
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    await fieldRow(app, PG.password).getByRole("button", { name: "reveal", exact: true }).click();
    await expect(valueOf(app, PG.password)).toHaveText(PG_VALUE.password);

    await page.evaluate(() => {
      Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await expect.poll(() => app.secretCount()).toBe(0);
    await expect(valueOf(app, PG.host)).toHaveText("—"); // nothing is shown, and nothing is read while the window is hidden
    await expect(valueOf(app, PG.password)).toHaveText(MASK);
    for (const v of [...PG_SECRETS]) expect(await page.content(), v).not.toContain(v);
    expect((await broker.calls("entry_reveal")).length).toBe(2); // the open of the entry, and the password; none since

    const revealsBefore = (await broker.calls("entry_reveal")).length;
    await page.evaluate(() => {
      Object.defineProperty(document, "hidden", { configurable: true, get: () => false });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    expect((await broker.calls("entry_reveal")).length).toBe(revealsBefore + 1);
    expect((await broker.calls("entry_reveal")).at(-1)!.args.fieldIds).toEqual([PG.host, PG.port, PG.user, PG.note]);
    await expect(valueOf(app, PG.password)).toHaveText(MASK); // the one that was revealed does not come back by itself
  });

  test("a value does not follow the user to another node", async ({ app }) => {
    const { page } = app;
    await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    await page.locator(".cm-rail .k-tree-row", { hasText: "beacon" }).first().click();
    expect(await app.secretCount()).toBe(0);
    for (const v of PG_SECRETS) expect(await page.content(), v).not.toContain(v);
  });

  test("a lock leaves no field, label or value anywhere, and the unlocked entry asks again", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "atlas", "pg-main");
    await expect(valueOf(app, PG.note)).toHaveText(PG_VALUE.note);
    await page.getByRole("button", { name: "vault menu" }).click();
    await page.locator(".cm-vaultmenu button", { hasText: "Lock vault" }).click();
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    expect(await app.secretCount()).toBe(0);
    const html = await page.content();
    for (const v of PG_SECRETS) expect(html, v).not.toContain(v);
    expect(html).not.toContain(PG.password);
    expect(await app.storageDump()).not.toContain(PG_VALUE.note);
    expect((await broker.state()).locked).toBe(true);
  });

  test("a locked node is the locked panel from the snapshot: neither entry.get nor entry.reveal is attempted", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await openEntryOf(app, "cobalt", "shop-admin");
    await expect(app.screen("S5 Entry detail — locked")).toContainText("This node is locked");
    await expect(fieldRows(app)).toHaveCount(0);
    await expect(page.getByRole("button", { name: "+ Add field" })).toHaveCount(0);
    expect(await broker.calls("entry_get")).toEqual([]);
    expect(await broker.calls("entry_reveal")).toEqual([]);
  });

  test("node_locked from entry.get on a node the snapshot did not know was locked: the snapshot is re-read and the panel follows", async ({ app }) => {
    const { page } = app;
    const broker = await openApp(app);
    await page.locator(".cm-rail .k-tree-row", { hasText: "atlas" }).first().click();
    await page.evaluate(() => ((window as any).__brokerFixture.node("atlas").gate.locked = true)); // locked behind the app's back
    const reads = (await broker.calls("graph_snapshot")).length;
    await page.locator("aside.cm-insp button.k-entry", { hasText: "pg-main" }).click();
    await expect(app.screen("S5 Entry detail — locked")).toContainText("This node is locked");
    expect((await broker.calls("entry_get")).length).toBe(1);
    expect((await broker.calls("graph_snapshot")).length).toBe(reads + 1);
    expect(await broker.calls("entry_reveal")).toEqual([]);
  });
});
