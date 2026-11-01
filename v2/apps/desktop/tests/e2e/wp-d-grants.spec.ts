/**
 * Settings -> Grants and the grant dialog, against the fixture broker.
 *
 * Asserts the exact bridge commands and arguments, what the screens render from the answers, and the refusal paths:
 *   - the list shows what grant.list says, and Revoke sends grant.revoke with the grant's id and reads the list again;
 *   - a revoke the broker refuses leaves the grant on screen and says why;
 *   - a revoke of a grant that is already gone reloads the list;
 *   - grant.create is sent for real and the broker's presence_required is shown honestly (nothing changes);
 *   - a request the broker rejects as malformed is shown, not swallowed.
 */
import { expect, test, type App } from "./harness";
import { notice, openSettings } from "./wp-d-helpers";

const ROW = '[data-grant-row="true"]';

async function open(app: App) {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  return broker;
}

test("the grant list shows what the broker holds, and Revoke sends grant.revoke with the grant's id and reads the list again", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Grants");

  const rows = page.locator(ROW);
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText("beacon ⇢ atlas");
  await expect(rows.first()).toContainText("read · never expires");
  await expect(rows.first()).toContainText("fixture grant");
  await expect(rows.first()).not.toContainText("last used"); // the broker does not report it, so the screen does not claim it
  const listedBefore = (await broker.calls("grant_list")).length;

  await rows.first().getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByText("No grants. Isolation is the default")).toBeVisible();
  expect(await broker.calls("grant_revoke")).toEqual([{ cmd: "grant_revoke", args: { id: "g-f1" } }]);
  expect((await broker.calls("grant_list")).length).toBe(listedBefore + 1); // the list on screen is the broker's, not an edit of ours
  expect((await broker.state()).grants).toEqual([]);
  await expect(notice(app)).toContainText("Grant revoked.");
  // and the graph's dashed edge went with it
  expect(JSON.parse(await app.viewJson()).links.filter((l: { kind: string }) => l.kind === "grant")).toEqual([]);
});

test("a revoke the broker refuses leaves the grant on screen and says why", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Grants");
  await broker.script("grant_revoke", { error: { code: "capability_not_held", detail: { rule: "revoke needs admin on the exposed node" } } });
  await page.locator(ROW).first().getByRole("button", { name: "Revoke" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Not permitted (revoke needs admin on the exposed node)." })).toBeVisible();
  await expect(page.locator(ROW)).toHaveCount(1);
  expect((await broker.state()).grants.length).toBe(1);
  await expect(app.screen("S12 Settings")).toBeVisible(); // still logged in, still here
});

test("revoking a grant that is already gone says so and reloads the list", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Grants");
  await broker.set({ grants: [] }); // revoked elsewhere (the CLI), after this list was read
  const listedBefore = (await broker.calls("grant_list")).length;
  await page.locator(ROW).first().getByRole("button", { name: "Revoke" }).click();
  await expect(notice(app).filter({ hasText: "That no longer exists. Reloaded." })).toBeVisible();
  await expect(page.getByText("No grants. Isolation is the default")).toBeVisible();
  expect((await broker.calls("grant_list")).length).toBeGreaterThan(listedBefore);
});

test("creating a grant sends grant.create and shows the broker's presence_required; nothing changes", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Grants");
  await page.getByRole("button", { name: "+ New grant" }).click();
  const dialog = app.screen("S11 Grant");
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("Creating a grant needs presence");
  await expect(dialog.locator('input[placeholder="2FA code"]')).toHaveCount(0); // presence guards it, not a typed code
  await expect(dialog.getByText("expiry")).toHaveCount(0); // the broker takes no expiry

  const create = dialog.getByRole("button", { name: "Create grant" });
  await expect(create).toBeDisabled(); // no reason yet
  await dialog.getByLabel("grant from node").selectOption("beacon");
  await dialog.getByLabel("grant to node").selectOption("atlas");
  await dialog.getByLabel("reveal values").check();
  await dialog.getByLabel("reason for the grant").fill("short");
  await expect(create).toBeDisabled(); // under 8 characters
  await dialog.getByLabel("reason for the grant").fill("the build needs the registry token");
  await expect(create).toBeEnabled();
  await create.click();

  await expect(page.getByRole("alert").filter({ hasText: "Needs presence (Touch ID)" })).toContainText("(grant.create)");
  expect(await broker.calls("grant_create")).toEqual([
    { cmd: "grant_create", args: { from: "beacon", to: { kind: "node", nodeId: "atlas" }, scope: ["read", "reveal"], reason: "the build needs the registry token" } },
  ]);
  await expect(dialog).toBeVisible(); // the dialog stays, so what the user typed is not lost
  expect((await broker.state()).grants.length).toBe(1);
  expect(await broker.calls("grant_list")).toHaveLength(1); // nothing succeeded, so nothing was reloaded
});

test("a grant request the broker rejects is shown, and the dialog keeps what was typed", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await openSettings(app, "Grants");
  await page.getByRole("button", { name: "+ New grant" }).click();
  const dialog = app.screen("S11 Grant");
  await dialog.getByLabel("reason for the grant").fill("a perfectly good reason");
  await broker.script("grant_create", { error: { code: "node_access_denied", detail: { rule: "admin on the target node is required" } } });
  await dialog.getByRole("button", { name: "Create grant" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Not permitted (admin on the target node is required)." })).toBeVisible();
  await expect(dialog.getByLabel("reason for the grant")).toHaveValue("a perfectly good reason");
});

test("Lite mode: grants can be listed and revoked but not created", async ({ app }) => {
  const { page } = app;
  const broker = await open(app);
  await page.evaluate(() => (window as any).__cm.setState({ mode: "lite", overlay: "settings", setSection: "grants" }));
  await expect(page.locator(ROW)).toHaveCount(1);
  await expect(page.getByRole("button", { name: "+ New grant" })).toHaveCount(0);
  await page.locator(ROW).first().getByRole("button", { name: "Revoke" }).click(); // revoking is safety: always reachable
  await expect(page.getByText("No grants. Isolation is the default")).toBeVisible();
  expect(await broker.calls("grant_revoke")).toHaveLength(1);
});
