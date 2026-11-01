/**
 * Work package B, part 2: what the user DOES with an entry or a node.  Reveal (and the re-mask), the refusals a reveal can meet
 * (a locked node above all), a TOTP entry's code, Copy through the shell, renaming a node and locking or unlocking it from the
 * context menu.  Each control is asserted by the exact bridge command and arguments it sends and by what it renders from the answer,
 * with at least one refusal per control.  A plaintext value or code must never be anywhere but on screen while it is revealed.
 */
import { expect, test, type App } from "./harness";
import { MASK, notice, openEntry, openNodeEntry, openWith, railRow, valueOf } from "./wp-b-helpers";

const STRIPE = valueOf("stripe-live");
const open = async (app: App) => (await app.open({ broker: { locked: false } }))!;

/** The fixture vault's own node, edited behind the app's back (so the app's snapshot is stale). */
const lockBehindTheApp = (app: App, node: string) => app.page.evaluate((id) => ((window as any).__brokerFixture.node(id).gate.locked = true), node);

async function ctxMenu(app: App, nodeLabel: string) {
  await railRow(app, nodeLabel).click({ button: "right" });
  const menu = app.page.locator(".cm-ctxmenu");
  await expect(menu).toBeVisible();
  return menu;
}

test.describe("reveal", () => {
  test("shows the broker's value, counts down, re-masks by itself and leaves nothing behind", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await expect(app.screen("S1 Main")).toBeVisible();
    await page.evaluate(() => (window as any).__cm.setState({ revealWindowSecs: 2 }));
    await openNodeEntry(app, "atlas", "stripe-live");
    const field = page.locator(".k-field-value");
    await expect(field).toHaveText(MASK);
    await expect(field).toHaveAttribute("data-masked", "true");

    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(field).toHaveText(STRIPE);
    await expect(field).toHaveAttribute("data-masked", "false");
    await expect(page.getByText(/re-masks in [12]s/)).toBeVisible();
    expect(await broker.calls("entry_reveal")).toEqual([{ cmd: "entry_reveal", args: { node: "atlas", entry: "e-a1", fieldIds: ["f_00000000"] } }]);
    expect(await app.secretCount()).toBe(1);
    expect(await app.viewJson()).not.toContain(STRIPE);
    expect(await app.storageDump()).not.toContain(STRIPE);

    // the window closes by itself: masked on screen AND gone from the model
    await expect(field).toHaveText(MASK);
    await expect(field).toHaveAttribute("data-masked", "true");
    expect(await app.secretCount()).toBe(0);
    expect(await page.content()).not.toContain(STRIPE);
    expect((await broker.calls("entry_reveal")).length).toBe(1); // re-masking asked the broker for nothing
  });

  test("hide puts the mask back at once; a second click while the request is in flight does not ask twice", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await openNodeEntry(app, "atlas", "stripe-live");
    const field = page.locator(".k-field-value");
    await broker.script("entry_reveal", { delayMs: 400 }); // the real handler answers, late
    const button = page.getByRole("button", { name: "reveal", exact: true });
    await button.click({ noWaitAfter: true });
    await button.click({ noWaitAfter: true, timeout: 2000 }).catch(() => {}); // it may already have turned into "hide"; either way no second request
    await expect(field).toHaveText(STRIPE);
    expect((await broker.calls("entry_reveal")).length).toBe(1);
    await page.getByRole("button", { name: "hide", exact: true }).click();
    await expect(field).toHaveText(MASK);
    expect(await app.secretCount()).toBe(0);
    expect((await broker.calls("entry_reveal")).length).toBe(1);
  });

  test("a revealed value does not follow the user to another node, or out of the entry", async ({ app }) => {
    const { page } = app;
    await open(app);
    await openNodeEntry(app, "atlas", "stripe-live");
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(page.locator(".k-field-value")).toHaveText(STRIPE);
    await page.getByRole("button", { name: /^← atlas/ }).click(); // leaving the detail
    expect(await app.secretCount()).toBe(0);
    await openEntry(app, "stripe-live");
    await expect(page.locator(".k-field-value")).toHaveText(MASK);

    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(page.locator(".k-field-value")).toHaveText(STRIPE);
    expect(await app.secretCount()).toBe(1);
    await railRow(app, "beacon").click(); // another node
    expect(await app.secretCount()).toBe(0);
    expect(await page.content()).not.toContain(STRIPE);
  });

  test("a refusal that is not about the lock is shown with the broker's rule", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await openNodeEntry(app, "atlas", "stripe-live");
    await broker.script("entry_reveal", { error: { code: "capability_not_held", detail: { rule: "reveal is not granted here" } } });
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(notice(app, "Not permitted (reveal is not granted here).")).toBeVisible();
    await expect(page.locator(".k-field-value")).toHaveText(MASK);
    expect(await app.secretCount()).toBe(0);
    await expect(app.screen("S5 Entry detail — locked")).toHaveCount(0);
  });
});

test.describe("a locked node", () => {
  test("is the locked panel, known from the snapshot: no reveal is attempted, and Unlock node opens it", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await openNodeEntry(app, "cobalt", "shop-admin");
    const panel = app.screen("S5 Entry detail — locked");
    await expect(panel).toContainText("This node is locked");
    await expect(page.getByRole("button", { name: "reveal", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "copy", exact: true })).toHaveCount(0);
    await expect(page.locator(".k-field-value")).toHaveCount(0);
    await expect(page.locator("aside.cm-insp")).toContainText("shop-admin"); // the name stays visible
    expect(await broker.calls("entry_reveal")).toEqual([]);

    await panel.getByRole("button", { name: "Unlock node" }).click();
    expect(await broker.calls("vault_node_unlock")).toEqual([{ cmd: "vault_node_unlock", args: { node: "cobalt" } }]);
    await expect(app.screen("S5 Entry detail — locked")).toHaveCount(0);
    await expect(notice(app, "Node unlocked.")).toBeVisible();
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(page.locator(".k-field-value")).toHaveText(valueOf("shop-admin"));
    await expect(railRow(app, "cobalt")).not.toContainText("⌐");
    await expect(app.screen("S1 Main")).toBeVisible(); // never logged out
    expect(await broker.calls("vault_lock")).toEqual([]);
  });

  test("approval_pending on a node the snapshot did not know was locked: the snapshot is re-read and the panel follows", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await openNodeEntry(app, "atlas", "stripe-live");
    await lockBehindTheApp(app, "atlas"); // locked from elsewhere (the CLI, another window)
    const reads = (await broker.calls("graph_snapshot")).length;
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(app.screen("S5 Entry detail — locked")).toContainText("This node is locked");
    expect(await broker.calls("entry_reveal")).toEqual([{ cmd: "entry_reveal", args: { node: "atlas", entry: "e-a1", fieldIds: ["f_00000000"] } }]);
    expect((await broker.calls("graph_snapshot")).length).toBe(reads + 1);
    await expect(railRow(app, "atlas")).toContainText("⌐");
    await expect(page.locator("[data-notice]")).toHaveCount(0); // the panel IS the answer; no "waiting for approval" on top of it
    expect(await app.secretCount()).toBe(0);
    await expect(app.screen("S1 Main")).toBeVisible();
    expect(await broker.calls("vault_lock")).toEqual([]);
  });

  test("node_locked, the broker's own word, gives the same panel", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await openNodeEntry(app, "atlas", "stripe-live");
    await lockBehindTheApp(app, "atlas");
    await broker.script("entry_reveal", { error: { code: "node_locked", detail: { node: "atlas" } } });
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(app.screen("S5 Entry detail — locked")).toBeVisible();
    await expect(app.screen("S1 Main")).toBeVisible();
    expect(await broker.calls("vault_lock")).toEqual([]);
  });

  test("approval_pending from a node that is not locked is just a notice (there is nothing to unlock)", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await openNodeEntry(app, "atlas", "stripe-live");
    await broker.script("entry_reveal", { error: { code: "approval_pending", detail: { request: "r1", node: "atlas" } } });
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(notice(app, "Waiting for approval.")).toBeVisible();
    await expect(app.screen("S5 Entry detail — locked")).toHaveCount(0);
    await expect(page.locator(".k-field-value")).toHaveText(MASK);
  });

  test("a refused unlock says so and the panel stays", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await openNodeEntry(app, "cobalt", "shop-admin");
    await broker.script("vault_node_unlock", { error: { code: "node_access_denied", detail: { rule: "R2" } } });
    await app.screen("S5 Entry detail — locked").getByRole("button", { name: "Unlock node" }).click();
    await expect(notice(app, "Not permitted (R2).")).toBeVisible();
    await expect(app.screen("S5 Entry detail — locked")).toBeVisible();
    await expect(railRow(app, "cobalt")).toContainText("⌐");
    expect(page.url()).toContain("tauri.localhost");
  });

  test("the node's own inspector offers the unlock too, and its note is not read", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await railRow(app, "cobalt").click();
    await expect(page.locator("aside.cm-insp")).toContainText("⌐ locked");
    expect((await broker.calls("notes_read")).filter((c) => c.args.node === "cobalt")).toEqual([]);
    await page.locator("aside.cm-insp").getByRole("button", { name: "Unlock node" }).click();
    expect(await broker.calls("vault_node_unlock")).toEqual([{ cmd: "vault_node_unlock", args: { node: "cobalt" } }]);
    await expect(page.locator("aside.cm-insp")).not.toContainText("⌐ locked");
    // unlocking makes the note readable, so it is read
    await expect.poll(async () => (await broker.calls("notes_read")).filter((c) => c.args.node === "cobalt").length).toBeGreaterThan(0);
  });
});

test.describe("a TOTP entry", () => {
  test("shows its current code instead of a reveal, counts down, never fetches the value, and hides", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await openNodeEntry(app, "atlas", "deploy-otp");
    await expect(page.getByRole("button", { name: "reveal", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "copy", exact: true })).toHaveCount(0); // a code is shown, not copied
    const field = page.locator(".k-field-value");
    await expect(field).toHaveText(MASK);

    await page.getByRole("button", { name: "show code" }).click();
    await expect(field).toHaveText("123 456");
    expect(await broker.calls("totp_code")).toEqual([{ cmd: "totp_code", args: { node: "atlas", entry: "e-a3", field: "f_00000000" } }]);
    expect((await broker.calls("entry_reveal")).length).toBe(0); // the seed is never fetched
    const left = await page.getByText(/re-masks in \d+s/).innerText();
    expect(Number(left.match(/(\d+)s/)![1])).toBeLessThanOrEqual(20);
    expect(await app.secretCount()).toBe(1);
    expect(await app.viewJson()).not.toContain("123456");
    expect(await app.storageDump()).not.toContain("123456");
    expect(await page.content()).not.toContain("123456"); // shown as "123 456" only

    await page.getByRole("button", { name: "hide", exact: true }).click();
    await expect(field).toHaveText(MASK);
    expect(await app.secretCount()).toBe(0);
  });

  test("show seed is asked for and refused for want of presence; nothing is shown", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await openNodeEntry(app, "atlas", "deploy-otp");
    await page.getByRole("button", { name: "show seed" }).click();
    await expect(notice(app, "Needs presence (Touch ID)")).toBeVisible();
    await expect(notice(app, "(totp.seed)")).toBeVisible();
    expect(await broker.calls("totp_seed")).toEqual([{ cmd: "totp_seed", args: { node: "atlas", entry: "e-a3", field: "f_00000000" } }]);
    await expect(page.locator(".k-field-value")).toHaveText(MASK);
    expect(await app.secretCount()).toBe(0);
  });

  test("a seed the broker cannot compute a code from is explained, not reported as a bug", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await openNodeEntry(app, "atlas", "deploy-otp");
    await broker.script("totp_code", { error: { code: "malformed_request", message: "the stored TOTP seed is shorter than 80 bits" } });
    await page.getByRole("button", { name: "show code" }).click();
    await expect(notice(app, "does not hold a usable TOTP seed")).toBeVisible();
    // the floor the broker enforces (MIN_TOTP_SECRET_LEN, ADR-077): 80 bits.  Not 128 (a stricter number it never asked for).
    await expect(notice(app, "at least 80 bits")).toBeVisible();
    await expect(notice(app, "128")).toHaveCount(0);
    await expect(notice(app, /unexpected/i)).toHaveCount(0);
    expect(await app.secretCount()).toBe(0);
  });

  test("a code that arrives after the window was hidden is discarded, not shown", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await openNodeEntry(app, "atlas", "deploy-otp");
    await broker.script("totp_code", { delayMs: 800 }); // the real handler answers, late
    await page.getByRole("button", { name: "show code" }).click({ noWaitAfter: true });
    await expect.poll(async () => (await broker.calls("totp_code")).length).toBe(1);
    expect(await broker.emit("credmgr://window-inactive", "hidden")).toBeGreaterThan(0); // the window is hidden while the broker is still answering
    await page.waitForTimeout(1300); // the answer has arrived by now
    expect(await app.secretCount()).toBe(0); // dropped on arrival: held nowhere
    await expect(page.locator(".k-field-value")).toHaveText(MASK);
    await expect(page.getByRole("button", { name: "show code" })).toBeVisible(); // and the screen did not claim it was showing
    expect(await page.content()).not.toContain("123 456");
  });

  test("a TOTP entry in a locked node is the locked panel; no code is asked for", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await lockBehindTheApp(app, "atlas");
    await page.evaluate(() => (window as any).__cm.model.refresh({ graph: true })); // the app learns of it
    await railRow(app, "atlas").click();
    await openEntry(app, "deploy-otp");
    await expect(app.screen("S5 Entry detail — locked")).toBeVisible();
    await expect(page.getByRole("button", { name: "show code" })).toHaveCount(0);
    expect(await broker.calls("totp_code")).toEqual([]);
  });

  test("a code is dropped when the user moves to another node", async ({ app }) => {
    const { page } = app;
    await open(app);
    await openNodeEntry(app, "atlas", "deploy-otp");
    await page.getByRole("button", { name: "show code" }).click();
    await expect(page.locator(".k-field-value")).toHaveText("123 456");
    await railRow(app, "beacon").click();
    expect(await app.secretCount()).toBe(0);
  });
});

test.describe("copy", () => {
  async function spyOnClipboard(app: App) {
    await app.page.addInitScript(() => {
      (window as any).__clipWrites = [];
      Object.defineProperty(navigator, "clipboard", { value: { writeText: (t: string) => ((window as any).__clipWrites.push(t), Promise.resolve()), readText: () => Promise.resolve("") }, configurable: true });
    });
  }

  test("when the shell cannot write the clipboard: the user is told, nothing is reported as copied, and the value is never fetched into the page", async ({ app }) => {
    const { page } = app;
    await spyOnClipboard(app);
    const broker = await open(app);
    await openNodeEntry(app, "atlas", "stripe-live");
    await broker.script("entry_copy", { error: { code: "clipboard_failed" } });
    await page.getByRole("button", { name: "copy", exact: true }).click();
    await expect(notice(app, "The clipboard could not be written. Nothing was copied.")).toBeVisible();
    expect(await broker.calls("entry_copy")).toEqual([{ cmd: "entry_copy", args: { node: "atlas", entry: "e-a1", field: "f_00000000" } }]);
    expect((await broker.calls("entry_reveal")).length).toBe(0); // it did not reveal the value in order to copy it from the page
    expect(await page.evaluate(() => (window as any).__clipWrites)).toEqual([]); // and never touched navigator.clipboard
    expect(await page.evaluate(() => (window as any).__brokerFixture.pasteboard)).toBeUndefined();
    expect(await app.secretCount()).toBe(0);
    await expect(page.getByRole("button", { name: "copied" })).toHaveCount(0);
  });

  test("through the shell: one entry_copy call with node and entry, the button says copied, and the value never reaches the page", async ({ app }) => {
    const { page } = app;
    await spyOnClipboard(app);
    const broker = await open(app);
    await openNodeEntry(app, "atlas", "stripe-live");
    await page.getByRole("button", { name: "copy", exact: true }).click();
    await expect(page.getByRole("button", { name: "copied" })).toBeVisible();
    expect(await broker.calls("entry_copy")).toEqual([{ cmd: "entry_copy", args: { node: "atlas", entry: "e-a1", field: "f_00000000" } }]);
    expect((await broker.calls("entry_reveal")).length).toBe(0);
    expect(await page.evaluate(() => (window as any).__clipWrites)).toEqual([]);
    expect(await page.evaluate(() => (window as any).__brokerFixture.pasteboard)).toMatchObject({ value: STRIPE, concealed: true }); // the shell's pasteboard has it
    expect(await app.secretCount()).toBe(0);
    expect(await page.content()).not.toContain(STRIPE);
    expect(await app.viewJson()).not.toContain(STRIPE);
    expect(await app.storageDump()).not.toContain(STRIPE);
  });

  test("through the shell, a refusal is routed like a reveal's: a locked node the snapshot missed is the panel", async ({ app }) => {
    const { page } = app;
    await spyOnClipboard(app);
    await open(app);
    await openNodeEntry(app, "atlas", "stripe-live");
    await lockBehindTheApp(app, "atlas");
    await page.getByRole("button", { name: "copy", exact: true }).click();
    await expect(app.screen("S5 Entry detail — locked")).toBeVisible();
    expect(await page.evaluate(() => (window as any).__brokerFixture.pasteboard)).toBeUndefined();
  });
});

test.describe("rename (node.update)", () => {
  test("sends the node and the new label, shows what the broker kept, and never changes the id", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    const menu = await ctxMenu(app, "atlas");
    await menu.getByRole("button", { name: "Rename" }).click();
    const input = page.locator(".cm-rail input");
    await expect(input).toHaveValue("atlas");
    await input.fill("  Atlas Prod  ");
    await input.press("Enter");
    await expect(railRow(app, "Atlas Prod")).toBeVisible();
    expect(await broker.calls("node_update")).toEqual([{ cmd: "node_update", args: { node: "atlas", label: "Atlas Prod" } }]); // trimmed, once (Enter and the blur after it make one request)
    await expect(notice(app, "Renamed.")).toBeVisible();
    await expect(page.locator(".cm-rail input")).toHaveCount(0);
    // the id is what children, grants and entries hang off: untouched
    expect(await page.evaluate(() => (window as any).__cm.vault.nodes.map((n: any) => `${n.id}:${n.label}`).filter((s: string) => s.startsWith("atlas") || s.startsWith("staging")))).toEqual(["atlas:Atlas Prod", "staging:staging"]);
    expect(await page.evaluate(() => (window as any).__cm.gd.nodes.find((n: any) => n.id === "atlas").label)).toBe("Atlas Prod"); // and the graph
    await railRow(app, "Atlas Prod").click();
    await expect(page.locator("aside.cm-insp")).toContainText("node · Atlas Prod");
  });

  test("clicking away commits it, once; Escape and an unchanged or empty name send nothing", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    let menu = await ctxMenu(app, "beacon");
    await menu.getByRole("button", { name: "Rename" }).click();
    await page.locator(".cm-rail input").fill("Beacon East");
    await page.locator("header.k-head").click({ position: { x: 3, y: 3 } }); // blur
    await expect(railRow(app, "Beacon East")).toBeVisible();
    expect((await broker.calls("node_update")).length).toBe(1);

    for (const [name, act] of [
      ["Escape", async (i: ReturnType<App["page"]["locator"]>) => { await i.fill("Something Else"); await i.press("Escape"); }],
      ["unchanged", async (i: ReturnType<App["page"]["locator"]>) => { await i.press("Enter"); }],
      ["empty", async (i: ReturnType<App["page"]["locator"]>) => { await i.fill("   "); await i.press("Enter"); }],
    ] as const) {
      menu = await ctxMenu(app, "Beacon East");
      await menu.getByRole("button", { name: "Rename" }).click();
      await act(page.locator(".cm-rail input"));
      await expect(page.locator(".cm-rail input"), name).toHaveCount(0);
      await expect(railRow(app, "Beacon East"), name).toBeVisible();
    }
    expect((await broker.calls("node_update")).length).toBe(1); // none of those three asked the broker
  });

  test("a name longer than 120 characters is not sent", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    const menu = await ctxMenu(app, "beacon");
    await menu.getByRole("button", { name: "Rename" }).click();
    await page.locator(".cm-rail input").fill("x".repeat(121));
    await page.locator(".cm-rail input").press("Enter");
    await expect(notice(app, "1 to 120 characters")).toBeVisible();
    expect(await broker.calls("node_update")).toEqual([]);
    await expect(railRow(app, "beacon")).toBeVisible();
  });

  test("a refusal is shown and the label stays what the broker last said", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    await broker.script("node_update", { error: { code: "node_access_denied", detail: { rule: "R2" } } });
    const menu = await ctxMenu(app, "beacon");
    await menu.getByRole("button", { name: "Rename" }).click();
    await page.locator(".cm-rail input").fill("Nope");
    await page.locator(".cm-rail input").press("Enter");
    await expect(notice(app, "Not permitted (R2).")).toBeVisible();
    await expect(railRow(app, "beacon")).toBeVisible();
    await expect(page.locator(".cm-rail")).not.toContainText("Nope");
    expect(await page.evaluate(() => (window as any).__cm.vault.nodes.find((n: any) => n.id === "beacon").label)).toBe("beacon");
  });

  test("the global and orphaned nodes cannot be renamed, so the menu does not offer it; the broker's refusal is the backstop", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    const global = await ctxMenu(app, "global");
    await expect(global.getByRole("button")).toHaveText(["Open", "New entry", "New project", "Grant access…", "Lock now"]); // no Rename, no Remove node
    await page.keyboard.press("Escape");
    // (the rail never opens a menu for the orphaned row; the graph canvas does, which a DOM test reaches through the state it sets)
    await page.evaluate(() => (window as any).__cm.setState({ ctx: { node: "__orphan", x: 200, y: 200 } }));
    await expect(page.locator(".cm-ctxmenu").getByRole("button")).toHaveText(["Open orphaned"]);
    await page.keyboard.press("Escape");
    // a sub-node can't have children (the tree stops at depth 2)
    const sub = await ctxMenu(app, "staging");
    await expect(sub.getByRole("button", { name: "New sub-node" })).toHaveCount(0);
    await expect(sub.getByRole("button", { name: "Rename" })).toBeVisible();
    await page.keyboard.press("Escape");
    // the backstop: the broker refuses the global node with malformed_request, shown as an unexpected error, label untouched
    const r = await page.evaluate(() => (window as any).__cm.routeReadError({ source: "broker", code: "malformed_request", message: "x" }, { op: "node.update", node: "global" }));
    expect(r.route).toBe("notice");
    expect(await broker.calls("node_update")).toEqual([]);
  });
});

test.describe("node lock and unlock from the context menu", () => {
  test("Lock now sends the node, the rail shows the lock, and the menu then offers Unlock node", async ({ app }) => {
    const { page } = app;
    const broker = await open(app);
    let menu = await ctxMenu(app, "atlas");
    await menu.getByRole("button", { name: "Lock now" }).click();
    expect(await broker.calls("vault_node_lock")).toEqual([{ cmd: "vault_node_lock", args: { node: "atlas" } }]);
    await expect(railRow(app, "atlas")).toContainText("⌐");
    await expect(notice(app, "Node locked.")).toBeVisible();
    expect((await broker.state()).nodes.find((n) => n.id === "atlas")!.gate.locked).toBe(true);
    await expect(page.locator(".cm-ctxmenu")).toHaveCount(0);

    menu = await ctxMenu(app, "atlas");
    await expect(menu.getByRole("button", { name: "Lock now" })).toHaveCount(0);
    await menu.getByRole("button", { name: "Unlock node" }).click();
    expect(await broker.calls("vault_node_unlock")).toEqual([{ cmd: "vault_node_unlock", args: { node: "atlas" } }]);
    await expect(railRow(app, "atlas")).not.toContainText("⌐");
    await expect(notice(app, "Node unlocked.")).toBeVisible();
    await expect(app.screen("S1 Main")).toBeVisible(); // the login survived both
    expect(await broker.calls("vault_lock")).toEqual([]);
  });

  test("locking a node drops what was revealed from it and turns the open entry into the locked panel", async ({ app }) => {
    const { page } = app;
    await open(app);
    await openNodeEntry(app, "atlas", "stripe-live");
    await page.getByRole("button", { name: "reveal", exact: true }).click();
    await expect(page.locator(".k-field-value")).toHaveText(STRIPE);
    expect(await app.secretCount()).toBe(1);
    const menu = await ctxMenu(app, "atlas");
    await menu.getByRole("button", { name: "Lock now" }).click();
    await expect(app.screen("S5 Entry detail — locked")).toBeVisible();
    expect(await app.secretCount()).toBe(0);
    expect(await page.content()).not.toContain(STRIPE);
  });

  test("a refused lock is shown and the node stays unlocked", async ({ app }) => {
    const broker = await open(app);
    await broker.script("vault_node_lock", { error: { code: "capability_not_held", detail: { capability: "admin" } } });
    const menu = await ctxMenu(app, "atlas");
    await menu.getByRole("button", { name: "Lock now" }).click();
    await expect(notice(app, "Not permitted")).toBeVisible();
    await expect(railRow(app, "atlas")).not.toContainText("⌐");
    expect((await broker.state()).nodes.find((n) => n.id === "atlas")!.gate.locked).toBe(false);
  });

  test("losing the login during a lock goes to the Lock screen", async ({ app }) => {
    const broker = await open(app);
    await broker.script("vault_node_lock", { error: { code: "vault_locked" } });
    const menu = await ctxMenu(app, "atlas");
    await menu.getByRole("button", { name: "Lock now" }).click();
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  });
});
