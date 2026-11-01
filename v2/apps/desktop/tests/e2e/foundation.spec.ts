/**
 * The foundation: the app, the model and the bridge talking to a fixture broker, under the production CSP.
 *
 * Proves the path every wiring package builds on - boot, unlock, list, reveal, lock - by asserting the EXACT bridge commands
 * and argument keys that go out and what the screens render from the answers, plus the refusal paths (a wrong passphrase, a
 * refused reveal, a node lock that must not log the user out, a lost login, a second factor, an unreachable broker).
 */
import { FIXTURE_GATE_CODE, FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import { expect, test, type App } from "./harness";
import { entryOpened } from "./wp-b-helpers";

const VALUE = "fixture-value-stripe-live";
const MASK = "••••••••••••";

/** Fill the passphrase and press Unlock (bridge mode opens straight onto the passphrase step). */
async function unlock(app: App, passphrase = FIXTURE_PASSPHRASE) {
  await app.page.locator('input[type="password"]').fill(passphrase);
  await app.page.getByRole("button", { name: "Unlock", exact: true }).click();
}

/** Select a node in the rail and open its first entry. */
async function openFirstEntry(app: App, node: string) {
  await app.page.locator(".cm-rail .k-tree-row", { hasText: node }).first().click();
  await app.page.locator("aside.cm-insp button.k-entry").first().click();
  await entryOpened(app);
}

test("boot asks the broker once, shows the lock screen, and unlock -> list -> reveal sends exactly these commands", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true } }))!;

  // boot
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await broker.calls()).toEqual([{ cmd: "vault_status", args: {} }]);

  // unlock: one call with the passphrase under the key the bridge uses, then the whole vault is read
  await unlock(app);
  await expect(app.screen("S1 Main")).toBeVisible();
  const calls = await broker.calls();
  expect(calls[1]).toEqual({ cmd: "vault_unlock", args: { passphrase: FIXTURE_PASSPHRASE } });
  const after = calls.slice(2);
  const named = (cmd: string) => after.filter((c) => c.cmd === cmd).map((c) => c.args);
  const byNode = (cmd: string) => named(cmd).map((a) => a.node).sort();
  expect(named("graph_snapshot")).toEqual([{}]);
  expect(named("grant_list")).toEqual([{}]);
  // every node's entries (and the orphaned node's items) and every node's review tray
  expect(byNode("entry_list")).toEqual(["atlas", "beacon", "cobalt", "global", "orphaned", "staging"]);
  expect(byNode("vault_pending_list")).toEqual(["atlas", "beacon", "cobalt", "global", "staging"]);
  expect(calls.map((c) => c.cmd)).not.toContain("entry_reveal"); // nothing is revealed by loading

  // the rail renders what the broker said: node labels and entry counts, the orphaned node as its own row
  const rows = page.locator(".cm-rail .k-tree-row");
  await expect(rows).toHaveCount(6);
  await expect(rows.filter({ hasText: "atlas" }).first()).toContainText("3");
  // the orphaned row is the last one, drawn with its label (it used to show the count alone) and its count
  await expect(rows.last()).toContainText("orphaned");
  await expect(rows.last().locator(".k-tree-count")).toHaveText("1");

  // list: select a node, open an entry
  await rows.filter({ hasText: "atlas" }).first().click();
  const entries = page.locator("aside.cm-insp button.k-entry");
  await expect(entries).toHaveCount(3);
  await expect(entries.first()).toContainText("stripe-live");
  await entries.first().click();
  await entryOpened(app);
  const field = page.locator(".k-field-value");
  await expect(field).toHaveText(MASK);
  await expect(field).toHaveAttribute("data-masked", "true");
  expect(await broker.calls("entry_reveal")).toEqual([]);

  // reveal: one call, node and entry ids under the bridge's keys, and the value on screen (only)
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(field).toHaveText(VALUE);
  expect(await broker.calls("entry_reveal")).toEqual([{ cmd: "entry_reveal", args: { node: "atlas", entry: "e-a1", fieldIds: ["f_00000000"] } }]);
  expect(await app.secretCount()).toBe(1);
  expect(await app.viewJson()).not.toContain(VALUE); // the view holds names and counts, never a value
  expect(await app.storageDump()).not.toContain(VALUE);

  // hide: the value leaves the screen and the model, with no new call
  await page.getByRole("button", { name: "hide", exact: true }).click();
  await expect(field).toHaveText(MASK);
  expect(await app.secretCount()).toBe(0);
  expect((await broker.calls("entry_reveal")).length).toBe(1);

  // lock: the bridge is told, the screen is the lock screen, and nothing the session held is left anywhere
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(field).toHaveText(VALUE);
  await page.getByRole("button", { name: "vault menu" }).click();
  await page.locator(".cm-vaultmenu button", { hasText: "Lock vault" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await broker.calls("vault_lock")).toEqual([{ cmd: "vault_lock", args: {} }]);
  expect(await app.secretCount()).toBe(0);
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  expect(await page.content()).not.toContain(VALUE);
  expect(await page.content()).not.toContain("stripe-live");
});

test("a wrong passphrase is shown, not swallowed, and nothing is loaded", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true } }))!;
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await unlock(app, "not-the-passphrase");
  await expect(page.getByRole("alert")).toContainText("Wrong passphrase.");
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await broker.commands()).toEqual(["vault_status", "vault_unlock"]);
  await expect(page.locator('input[type="password"]')).toHaveValue(""); // the secret is not left in the field
});

test("a refused reveal is shown with the broker's rule, and the value never appears", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await openFirstEntry(app, "atlas");
  await broker.script("entry_reveal", { error: { code: "capability_not_held", detail: { rule: "reveal is not granted to this node" } } });
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(page.getByRole("status").or(page.getByRole("alert")).filter({ hasText: "Not permitted (reveal is not granted to this node)." })).toBeVisible();
  await expect(page.locator(".k-field-value")).toHaveText(MASK);
  expect(await app.secretCount()).toBe(0);
  await expect(app.screen("S1 Main")).toBeVisible(); // still logged in
});

test("a locked NODE shows the per-node locked panel and does not log them out (node_locked is not vault_locked)", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await openFirstEntry(app, "cobalt");
  // the snapshot already says cobalt is locked, so there is no reveal to refuse: the panel is the detail (wp-b-entries.spec.ts covers it in full)
  await expect(app.screen("S5 Entry detail — locked")).toContainText("This node is locked");
  await expect(page.getByRole("button", { name: "reveal", exact: true })).toHaveCount(0);
  expect(await broker.calls("entry_reveal")).toEqual([]);
  await expect(app.screen("S1 Main")).toBeVisible();
  expect(await broker.calls("vault_lock")).toEqual([]);
});

test("losing the login mid-session (vault_locked) goes to the lock screen, empties the model and drops a value that was on screen", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  await openFirstEntry(app, "atlas");
  await page.getByRole("button", { name: "reveal", exact: true }).click();
  await expect(page.locator(".k-field-value")).toHaveText(VALUE);
  expect(await app.secretCount()).toBe(1);

  // another entry (a single masked field, in beacon): this time the broker says the login is gone
  await page.getByRole("button", { name: /^← atlas/ }).click();
  await page.locator(".cm-rail .k-tree-row", { hasText: "beacon" }).first().click();
  await page.locator("aside.cm-insp button.k-entry").first().click();
  await entryOpened(app);
  await broker.script("entry_reveal", { error: { code: "vault_locked" } });
  await page.getByRole("button", { name: "reveal", exact: true }).click();

  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  expect(await app.secretCount()).toBe(0); // the value revealed before is gone from the model, not just from the screen
  expect(await page.content()).not.toContain(VALUE);
  expect(await page.content()).not.toContain("stripe-live");
});

test("a second factor: unlock asks for the code, a wrong one is refused, the right one opens the vault", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true, gate: true } }))!;
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await unlock(app);
  const code = page.getByPlaceholder("______");
  await expect(code).toBeVisible();
  expect(await broker.commands()).toEqual(["vault_status", "vault_unlock"]); // nothing is loaded before the second factor

  await code.fill("000000");
  await expect(page.getByRole("alert")).toContainText("That code was not accepted.");
  await expect(app.screen("S16 Lock screen")).toBeVisible();

  await code.fill(FIXTURE_GATE_CODE);
  await expect(app.screen("S1 Main")).toBeVisible();
  expect(await broker.calls("vault_gate_verify")).toEqual([
    { cmd: "vault_gate_verify", args: { code: "000000" } },
    { cmd: "vault_gate_verify", args: { code: FIXTURE_GATE_CODE } },
  ]);
  expect((await broker.commands()).filter((c) => c === "vault_unlock").length).toBe(1); // the passphrase was sent once
});

test("an unreachable broker is a screen with a Retry, not a blank window", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true, unreachable: true } }))!;
  await expect(app.screen("S16 Broker unreachable")).toBeVisible();
  await broker.set({ unreachable: false });
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await broker.commands()).toEqual(["vault_status", "vault_status"]);
});

test("a first run (no vault yet) is routed to the first-run screen", async ({ app }) => {
  await app.open({ broker: { initialized: false } });
  await expect(app.screen("S17 First run")).toBeVisible();
});

test("an already-open broker session is loaded without asking for a passphrase", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const cmds = await broker.commands();
  expect(cmds.slice(0, 3)).toEqual(["vault_status", "graph_snapshot", "grant_list"]);
  expect(cmds).not.toContain("vault_unlock");
});

test("unlocked by another process (status says open, but this process holds no login) still shows the lock screen", async ({ app }) => {
  const broker = (await app.open({ broker: { locked: true }, script: { vault_status: [{ result: { locked: false, authenticated: false, initialized: true } }] } }))!;
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(await broker.commands()).toEqual(["vault_status"]);
});
