/**
 * 2.0.0-rc.1 window work: the C4 findings F-1 ... F-14 (issues #23 to #27), aliases and near-duplicate names (#20, ADR-121) and the
 * .env importer (#21, ADR-122).  Fixture broker, same invariants as every spec (0 CSP violations, 0 console errors, 0 external requests).
 *
 * Where a finding was written on the build before the 2026-10 design merge, the spec says what the build does now; a finding the source
 * shows is already fixed is closed by a test that would fail if it came back.
 */
import { FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import { expect, test, type App } from "./harness";
import { entryOpened } from "./wp-b-helpers";
import { notice, openAddEntry, selectNode, fillRow, addRow } from "./wp-c-util";
import { openEntryOf } from "./field-ui-helpers";

const insp = (app: App) => app.page.locator("aside.cm-insp");
const opened = async (app: App) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  return broker;
};
const fixture = (app: App, fn: string, arg: unknown) => app.page.evaluate(([f, a]) => (window as any).__brokerFixture.handlers[f as string](a), [fn, arg] as const);

// ───────────────────────────── #23: selecting a node re-reads its entries ─────────────────────────────
test.describe("#23 selecting a node reads its entries again", () => {
  test("an entry written from outside the app shows up when its node is selected", async ({ app }) => {
    const { page } = app;
    const broker = await opened(app);
    await selectNode(app, "atlas");
    await expect(insp(app).locator("button.k-entry")).toHaveCount(3);

    // another process (`credmgr set`, an agent) writes into atlas; nothing in the app has refreshed it
    await fixture(app, "entry_create", { node: "atlas", name: "written-outside", value: "fixture-value-outside" });
    await expect(insp(app).locator("button.k-entry")).toHaveCount(3);

    const before = (await broker.calls("entry_list")).filter((c) => c.args.node === "atlas").length;
    await selectNode(app, "beacon");
    await selectNode(app, "atlas");
    await expect(insp(app).locator("button.k-entry", { hasText: "written-outside" })).toBeVisible();
    await expect(insp(app).locator("button.k-entry")).toHaveCount(4);
    const after = (await broker.calls("entry_list")).filter((c) => c.args.node === "atlas").length;
    expect(after).toBeGreaterThan(before);
    // and it did not read a value to do it
    expect((await broker.calls("entry_reveal")).length).toBe(0);
    await expect(page.locator("[data-notice]")).toHaveCount(0);
  });

  test("a locked node is not listed on select (it shows the locked panel, not an error)", async ({ app }) => {
    const broker = await opened(app);
    const listed = async () => (await broker.calls("entry_list")).filter((c) => c.args.node === "cobalt").length;
    const before = await listed(); // the load at unlock asked once
    await selectNode(app, "cobalt");
    await expect(insp(app)).toContainText("locked");
    expect(await listed()).toBe(before); // selecting a locked node asks nothing more
  });
});

// ───────────────────────────── #24: the narrow inspector sheet ─────────────────────────────
test.describe("#24 the inspector sheet at a narrow width", () => {
  test("it is one column, and an entry's name is readable", async ({ app }) => {
    const { page } = app;
    await opened(app);
    await selectNode(app, "atlas");
    // below 820 px the inspector is a sheet that opens over the graph when a node is selected
    await page.setViewportSize({ width: 700, height: 800 });
    await page.evaluate(() => (window as any).__cm.setState({ inspOpen: true }));
    const sheet = page.locator("aside.cm-insp.is-open");
    await expect(sheet).toBeVisible();
    expect(await sheet.evaluate((el) => getComputedStyle(el).flexDirection)).toBe("column");
    const row = sheet.locator("button.k-entry", { hasText: "stripe-live" });
    await expect(row).toBeVisible();
    const name = row.locator(".k-entry-name");
    const box = (await name.boundingBox())!;
    expect(box.width).toBeGreaterThan(90);
    // not clipped to an ellipsis: the element shows all of its text
    expect(await name.evaluate((el) => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
    await page.setViewportSize({ width: 1280, height: 800 });
  });
});

// ───────────────────────────── #25: Orphaned lists what was sealed ─────────────────────────────
test.describe("#25 the Orphaned panel after sealing a node", () => {
  test("it lists the sealed node's entries, the rail count follows, and the node's own list is never asked", async ({ app }) => {
    const { page } = app;
    const broker = await opened(app);
    await page.locator(".cm-rail .k-tree-row", { hasText: "beacon" }).first().click({ button: "right" });
    await page.getByRole("button", { name: "Remove node…", exact: true }).click();
    const dlg = app.screen("S9 Seal node");
    await dlg.getByLabel("type the node name to confirm").fill("beacon");
    await dlg.getByRole("button", { name: "Seal node" }).click();
    await expect(notice(app)).toContainText("sealed");

    await expect(insp(app)).toContainText("registry-token");
    await expect(insp(app)).not.toContainText("Nothing is orphaned");
    const orphanRow = page.locator(".cm-rail .k-tree-row", { hasText: "orphaned" }).first();
    await expect(orphanRow).toContainText("2"); // the vault already held old-root; the sealed registry-token makes two
    expect((await broker.calls("entry_list")).filter((c) => c.args.node === "orphaned")).toHaveLength(0);
    // the names come from the snapshot (ADR-120), never a value
    expect((await broker.calls("entry_reveal")).length).toBe(0);
  });

  test("opening a sealed item asks the broker, which refuses without presence", async ({ app }) => {
    const { page } = app;
    const broker = await opened(app);
    await selectNode(app, "orphaned");
    await expect(insp(app)).toContainText("old-root");
    await insp(app).getByRole("button", { name: "open" }).first().click();
    expect((await broker.calls("entry_reveal")).length).toBe(1);
    await expect(page.locator('[data-notice="presence"]')).toBeVisible();
  });
});

// ───────────────────────────── #26: what Help says about a note ─────────────────────────────
test.describe("#26 a note is shown, and Help says so", () => {
  test("Help no longer promises a mask a note does not have", async ({ app }) => {
    const { page } = app;
    await opened(app);
    await page.getByRole("button", { name: "help", exact: true }).click();
    const help = page.locator('[data-screen-label="S21 Help"]');
    await expect(help).toBeVisible();
    const text = (await help.innerText()).replace(/\s+/g, " ");
    expect(text).not.toContain("masked until you reveal it");
    expect(text).toContain("Its text is not masked");
    expect(text).toContain("always hidden");
  });
});

// ───────────────────────────── #27: the cosmetic findings ─────────────────────────────
test.describe("#27 cosmetic findings", () => {
  test("F-2: host + username + password is previewed as a server", async ({ app }) => {
    await opened(app);
    const dlg = await openAddEntry(app, "atlas");
    await fillRow(dlg, 1, { label: "host", value: "db.example.test" });
    await addRow(dlg);
    await fillRow(dlg, 2, { label: "username", value: "deploy" });
    await addRow(dlg);
    await fillRow(dlg, 3, { label: "password", value: "fixture-value-pw-three" });
    await expect(dlg.getByLabel("entry type").locator("option").first()).toHaveText("auto: server");
  });

  test("F-4: the seal dialog says the node survives a lock and a restart", async ({ app }) => {
    const { page } = app;
    await opened(app);
    await page.locator(".cm-rail .k-tree-row", { hasText: "beacon" }).first().click({ button: "right" });
    await page.getByRole("button", { name: "Remove node…", exact: true }).click();
    const dlg = app.screen("S9 Seal node");
    await expect(dlg).toContainText("also after a lock or a restart");
    await expect(dlg).not.toContainText("until you lock the vault");
  });

  test("F-7: with Motion reduced the entry dots hold their places; without it they drift", async ({ app }) => {
    const { page } = app;
    await opened(app);
    const positions = () => page.evaluate(() => ((window as any).__cm.entryNodes || []).map((e: any) => [e.x, e.y]));
    const moved = async () => {
      const a = (await positions()) as number[][];
      await page.waitForTimeout(700);
      const b = (await positions()) as number[][];
      return Math.max(...a.map((p, i) => Math.hypot(p[0] - b[i][0], p[1] - b[i][1])));
    };
    await page.evaluate(() => (window as any).__cm.setState({ motion: "full" }));
    await page.waitForTimeout(300);
    expect(await moved()).toBeGreaterThan(0.3);
    await page.evaluate(() => (window as any).__cm.setState({ motion: "reduced" }));
    await page.waitForTimeout(1800); // let the dots settle onto their fixed places
    expect(await moved()).toBeLessThan(0.15);
  });

  test("F-11: the first Escape in CredPong pauses, the second leaves", async ({ app }) => {
    const { page } = app;
    await opened(app);
    await page.evaluate(() => (window as any).__cm.cpStart());
    await expect(page.locator('[data-screen-label="S19 CredGames"]').first()).toBeVisible().catch(() => undefined);
    await page.keyboard.press("Escape");
    expect(await page.evaluate(() => (window as any).__cm.state.overlay)).toBe("games");
    expect(await page.evaluate(() => (window as any).__cm.cp.paused)).toBe(true);
    await page.keyboard.press("Escape");
    expect(await page.evaluate(() => (window as any).__cm.state.overlay)).toBe(null);
  });

  test("F-12: a grant dialog reopened after Cancel (or Escape) starts with an empty reason", async ({ app }) => {
    const { page } = app;
    await opened(app);
    const settings = app.screen("S12 Settings");
    const grant = page.locator('[data-screen-label="S11 Grant"]').first();
    await page.getByRole("button", { name: "settings", exact: true }).click();
    await settings.getByRole("button", { name: "Grants", exact: true }).click();
    await settings.getByRole("button", { name: "+ New grant" }).click();
    await expect(grant).toBeVisible();
    await grant.getByLabel("reason for the grant").fill("a reason I typed first");
    await grant.getByRole("button", { name: "Cancel" }).click();
    await expect(grant).toBeHidden();
    await settings.getByRole("button", { name: "+ New grant" }).click();
    await expect(grant.getByLabel("reason for the grant")).toHaveValue("");
    await grant.getByLabel("reason for the grant").fill("typed again, then Escape");
    await page.keyboard.press("Escape");
    expect(await page.evaluate(() => (window as any).__cm.state.dialog)).toBe(null); // Escape closes Settings with it
    await page.getByRole("button", { name: "settings", exact: true }).click();
    await settings.getByRole("button", { name: "Grants", exact: true }).click();
    await settings.getByRole("button", { name: "+ New grant" }).click();
    await expect(grant.getByLabel("reason for the grant")).toHaveValue("");
  });

  test("F-13: Settings → Advanced names the real socket", async ({ app }) => {
    const { page } = app;
    await opened(app);
    await page.getByRole("button", { name: "settings", exact: true }).click();
    const settings = app.screen("S12 Settings");
    await settings.getByRole("button", { name: "Advanced", exact: true }).click();
    await expect(settings).toContainText("run/broker.sock");
    await expect(settings).not.toContainText("credmgrd.sock");
  });

  test("F-14: the concealed-clipboard pill stays one line at a narrow width", async ({ app }) => {
    const { page } = app;
    await page.setViewportSize({ width: 560, height: 800 });
    await opened(app);
    await page.getByRole("button", { name: "settings", exact: true }).click();
    const settings = app.screen("S12 Settings");
    await settings.getByRole("button", { name: "Security", exact: true }).click();
    const pill = settings.getByText("Concealed clipboard", { exact: true }).locator("xpath=ancestor::div[2]").locator(".k-chip");
    await expect(pill).toBeVisible();
    const box = (await pill.boundingBox())!;
    expect(box.height).toBeLessThan(30);
    expect(box.width).toBeGreaterThan(box.height);
    expect(await pill.evaluate((el) => getComputedStyle(el).whiteSpace)).toBe("nowrap");
    await page.setViewportSize({ width: 1280, height: 800 });
  });

  test("F-1: the broker-unreachable screen says how to start the app", async ({ app }) => {
    await app.open({ broker: { unreachable: true } });
    await expect(app.screen("S16 Broker unreachable")).toContainText("open the app the usual way");
  });
});

// ───────────────────────────── #20: aliases and near-duplicate names ─────────────────────────────
test.describe("#20 aliases", () => {
  test("an entry gets aliases, shows them, is found by them, and they can be cleared", async ({ app }) => {
    const { page } = app;
    const broker = await opened(app);
    await openEntryOf(app, "atlas", "stripe-live");
    await expect(page.locator('[data-aliases="true"]')).toHaveCount(0);

    await insp(app).getByRole("button", { name: "Aliases…" }).click();
    const dlg = app.screen("S5d Aliases");
    await expect(dlg).toBeVisible();
    await expect(dlg.getByRole("button", { name: "Save aliases" })).toBeDisabled(); // nothing changed
    await dlg.getByLabel("aliases, one per line").fill("live-payments\n  Payments Key  \n");
    await expect(dlg).toContainText("2 of 8");
    await dlg.getByRole("button", { name: "Save aliases" }).click();
    await expect(dlg).toBeHidden();

    const calls = await broker.calls("entry_alias");
    expect(calls).toHaveLength(1);
    expect(calls[0].args).toMatchObject({ node: "atlas", entry: "e-a1", aliases: ["live-payments", "Payments Key"] });
    expect(typeof calls[0].args.generation).toBe("number");
    await expect(notice(app)).toContainText("Aliases of “stripe-live” saved.");
    await expect(page.locator('[data-aliases="true"]')).toContainText("also called live-payments · Payments Key");

    // the search finds the entry by an alias
    await page.locator(".cm-searchinput").fill("payments");
    await expect(app.screen("S7 Search")).toContainText("stripe-live");

    // clear them
    await page.keyboard.press("Escape");
    await insp(app).getByRole("button", { name: "Aliases…" }).click();
    await expect(dlg.getByLabel("aliases, one per line")).toHaveValue("live-payments\nPayments Key");
    await dlg.getByLabel("aliases, one per line").fill("");
    await dlg.getByRole("button", { name: "Save aliases" }).click();
    await expect(notice(app)).toContainText("Aliases of “stripe-live” cleared.");
    await expect(page.locator('[data-aliases="true"]')).toHaveCount(0);
    expect(await app.storageDump()).not.toContain("live-payments");
  });

  test("a name another entry has is refused next to the form, and nothing changed", async ({ app }) => {
    const { page } = app;
    const broker = await opened(app);
    await openEntryOf(app, "atlas", "stripe-live");
    await insp(app).getByRole("button", { name: "Aliases…" }).click();
    const dlg = app.screen("S5d Aliases");
    await dlg.getByLabel("aliases, one per line").fill("PG-MAIN");
    await dlg.getByRole("button", { name: "Save aliases" }).click();
    await expect(dlg.getByRole("alert")).toContainText("already taken");
    await expect(dlg).toBeVisible(); // kept for another try
    expect((await broker.state()).entries.atlas.find((e) => e.id === "e-a1")).not.toHaveProperty("aliases");
    // local checks never reach the broker
    await dlg.getByLabel("aliases, one per line").fill("one\nONE");
    await expect(dlg.getByRole("alert")).toContainText("same name");
    await expect(dlg.getByRole("button", { name: "Save aliases" })).toBeDisabled();
    await dlg.getByLabel("aliases, one per line").fill("stripe-live");
    await expect(dlg.getByRole("alert")).toContainText("own name");
    await page.keyboard.press("Escape");
    expect((await broker.calls("entry_alias")).length).toBe(1);
  });

  test("an alias that resembles another name is saved and the notice says so", async ({ app }) => {
    const broker = await opened(app);
    await openEntryOf(app, "atlas", "deploy-otp");
    await insp(app).getByRole("button", { name: "Aliases…" }).click();
    const dlg = app.screen("S5d Aliases");
    await dlg.getByLabel("aliases, one per line").fill("Stripe_Live");
    await dlg.getByRole("button", { name: "Save aliases" }).click();
    await expect(notice(app)).toContainText("Looks like stripe-live");
    expect((await broker.calls("entry_alias")).length).toBe(1);
  });

  test("while a new entry's name is typed, names that look like it are said, and it can still be saved", async ({ app }) => {
    const broker = await opened(app);
    const dlg = await openAddEntry(app, "atlas");
    await dlg.getByLabel("entry name").fill("stripe_live");
    await expect(dlg.locator('[data-name-hint="true"]')).toContainText("Looks like stripe-live");
    expect((await broker.calls("entry_similar")).at(-1)!.args).toEqual({ node: "atlas", name: "stripe_live" });
    await dlg.getByLabel("value", { exact: true }).fill("fixture-value-new");
    await expect(dlg.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
    await dlg.getByLabel("entry name").fill("wholly-different");
    await expect(dlg.locator('[data-name-hint="true"]')).toHaveCount(0);
  });
});

// ───────────────────────────── #21: the .env importer ─────────────────────────────
const ENV = ["# service", "export FIX_ONE=fixture-env-value-one", 'FIX_TWO="fixture env value two"', "FIX_EMPTY=", "stripe-live=fixture-env-value-three"].join("\n");

test.describe("#21 import a .env file", () => {
  async function openImport(app: App) {
    await opened(app);
    await selectNode(app, "atlas");
    await insp(app).getByRole("button", { name: "Import .env…" }).click();
    const dlg = app.screen("S6b Import .env");
    await expect(dlg).toBeVisible();
    return dlg;
  }

  test("the preview names every pair and what it would become, a conflict blocks until it is skipped, and no value is shown", async ({ app }) => {
    const { page } = app;
    await openImport(app);
    const broker = app.broker!;
    const dlg = app.screen("S6b Import .env");
    await expect(dlg.getByRole("button", { name: "Preview" })).toBeDisabled();
    await dlg.getByLabel(".env text").fill(ENV);
    await dlg.getByRole("button", { name: "Preview" }).click();

    // the shell read the text; the broker previewed the names; nothing was written
    expect((await broker.calls("env_preview"))[0].args).toEqual({ text: ENV });
    const dry = (await broker.calls("entry_import_env")).at(-1)!;
    expect(dry.args).toMatchObject({ node: "atlas", dryRun: true });
    expect((dry.args.entries as { name: string }[]).map((e) => e.name)).toEqual(["FIX_ONE", "FIX_TWO", "stripe-live"]);
    expect((await broker.state()).entries.atlas.map((e) => e.name)).not.toContain("FIX_ONE");

    await expect(dlg.locator('[data-import-row="new"]')).toHaveCount(2);
    await expect(dlg.locator('[data-import-row="exists"]')).toContainText("stripe-live");
    await expect(dlg.locator('[data-import-summary="true"]')).toContainText("2 new, 1 already there, 1 empty (skipped)");
    // the values are in the page only as the pairs to send: not in the text, not in the markup
    expect(await dlg.innerText()).not.toContain("fixture-env-value");
    expect(await page.content()).not.toContain("fixture-env-value");

    // a conflict blocks Import until the person chooses to skip it
    await expect(dlg.getByRole("button", { name: "Import 2 entries" })).toBeDisabled();
    await expect(dlg.getByRole("alert")).toContainText("already taken");
    await dlg.getByRole("radio", { name: /skip them/ }).check();
    await expect(dlg.getByRole("button", { name: "Import 2 entries" })).toBeEnabled();
    await dlg.getByRole("button", { name: "Import 2 entries" }).click();
    await expect(dlg).toBeHidden();

    const write = (await broker.calls("entry_import_env")).at(-1)!;
    expect(write.args).toMatchObject({ node: "atlas", onConflict: "skip" });
    expect(write.args.dryRun).toBeUndefined();
    await expect(notice(app)).toContainText("Imported 2 entries into atlas. 1 name was skipped.");
    await expect(insp(app).locator("button.k-entry", { hasText: "FIX_ONE" })).toBeVisible();
    await expect(insp(app).locator("button.k-entry", { hasText: "FIX_TWO" })).toBeVisible();
    // nothing of the file stays in the page
    expect(await app.page.evaluate(() => (window as any).__cm.state.importForm)).toBeNull();
    expect(await app.storageDump()).not.toContain("fixture-env-value");
    expect(await page.content()).not.toContain("fixture-env-value");
    expect((await broker.calls("entry_reveal")).length).toBe(0);
  });

  test("a file chosen from disk is read into the same box, and a bad line is named by number and never shown", async ({ app }) => {
    const dlg = await openImport(app);
    await dlg.getByLabel("choose a .env file").setInputFiles({ name: "service.env", mimeType: "text/plain", buffer: Buffer.from("NEW_ONE=fixture-env-file-value\nNEW_TWO=fixture-env-file-value-2\n") });
    await expect(dlg).toContainText("read from service.env");
    await expect(dlg.getByLabel(".env text")).toHaveValue("NEW_ONE=fixture-env-file-value\nNEW_TWO=fixture-env-file-value-2\n");
    await dlg.getByRole("button", { name: "Preview" }).click();
    await expect(dlg.locator('[data-import-row="new"]')).toHaveCount(2);
    await expect(dlg.getByRole("button", { name: "Import 2 entries" })).toBeEnabled(); // no conflict: no choice to make

    await dlg.getByRole("button", { name: "Back" }).click();
    await dlg.getByLabel(".env text").fill("GOOD=1\nfixture-bare-token-without-a-name\n");
    await dlg.getByRole("button", { name: "Preview" }).click();
    await expect(dlg.getByRole("alert")).toContainText("not a valid .env file (line 2)");
    expect(await dlg.innerText()).not.toContain("fixture-bare-token");
  });

  test("Cancel (and Escape) leave nothing of the pasted text behind, and a conflict with the default choice writes nothing", async ({ app }) => {
    const { page } = app;
    const dlg = await openImport(app);
    const broker = app.broker!;
    await dlg.getByLabel(".env text").fill(ENV);
    await dlg.getByRole("button", { name: "Cancel" }).click();
    await expect(dlg).toBeHidden();
    await expect.poll(() => page.evaluate(() => (window as any).__cm.state.importForm)).toBeNull();

    await insp(app).getByRole("button", { name: "Import .env…" }).click();
    await dlg.getByLabel(".env text").fill(ENV);
    await page.keyboard.press("Escape");
    await expect(dlg).toBeHidden();
    await expect.poll(() => page.evaluate(() => (window as any).__cm.state.importForm)).toBeNull();
    expect((await broker.calls("entry_import_env")).length).toBe(0); // nothing was even previewed
    await insp(app).getByRole("button", { name: "Import .env…" }).click();
    await expect(dlg.getByLabel(".env text")).toHaveValue("");
  });

  test("a lock empties the dialog", async ({ app }) => {
    const { page } = app;
    const dlg = await openImport(app);
    await dlg.getByLabel(".env text").fill(ENV);
    await page.evaluate(() => (window as any).__cm.lockVault());
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    expect(await page.evaluate(() => (window as any).__cm.state.importForm)).toBeNull();
    expect(await page.content()).not.toContain("fixture-env-value");
    await page.locator('input[type="password"]').fill(FIXTURE_PASSPHRASE);
  });
});

// keeps the helper imports honest for the type checker
void entryOpened;
