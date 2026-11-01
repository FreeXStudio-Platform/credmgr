/**
 * Controls the broker will not perform without presence (Touch ID, which a bridge session cannot attest): the app must send them
 * for real, say plainly that presence is missing, and change NOTHING.
 *
 *   grant creation, the full audit record, root-key rotation, the TOTP seed, and the "widening" node choices.
 *
 * Each is asserted three ways: the exact frame the app put on the wire, the notice the person sees (with the broker's own operation
 * name in it), and the vault afterwards, read by an independent client, unchanged. The broker also writes the refusal to its audit
 * trail; that trail is read back through the app's Audit section, and no session token may be on it.
 */
import { expect, fixtureSecret, fixtureTotpSeed, test, type RealApp } from "./harness";
import { addEntry, closeSettings, createVaultViaWizard, KDF, lockUi, notice, openEntry, openSettings, railRow, selectNode, unlockToMain } from "./helpers";
import { codeAt, base32Decode } from "./totp.mjs";

/** Generated per run: a TOTP seed written into a spec is a secret-shaped literal in a tracked file. */
const SEED = fixtureTotpSeed();

async function vaultWith(app: RealApp, project: string): Promise<void> {
  await app.open();
  await createVaultViaWizard(app);
  await app.page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await app.page.getByLabel("project name 1").fill(project);
  await app.page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
  await expect(railRow(app, project)).toBeVisible();
}

const presenceAlert = (app: RealApp, op: string) => app.page.getByRole("alert").filter({ hasText: "Needs presence (Touch ID)" }).filter({ hasText: `(${op})` });

test("grant creation, root-key rotation, the audit record, the TOTP seed and a widening node choice are each sent, each met with presence_required, and none changes the vault", async ({ app }) => {
  const { page } = app;
  const otpValue = fixtureSecret("plain-value");
  await vaultWith(app, "Atlas");
  await addEntry(app, "Atlas", { name: "deploy-otp", label: "totp", value: SEED });
  await addEntry(app, "Atlas", { name: "plain-one", value: otpValue });
  await app.oracle.login();
  const before = {
    nodes: (await app.oracle.nodeIds()).sort(),
    entries: await app.oracle.entries("atlas"),
    grants: (await app.oracle.call("grant.list")).grants,
  };
  expect(before.grants).toEqual([]);

  await test.step("a new grant: the dialog says why it will be refused, the request goes out, nothing is granted", async () => {
    const settings = await openSettings(app, "Grants");
    await settings.getByRole("button", { name: "+ New grant" }).click();
    const dialog = app.screen("S11 Grant");
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText("Creating a grant needs presence");
    const create = dialog.getByRole("button", { name: "Create grant" });
    await expect(create).toBeDisabled(); // no reason yet
    await dialog.getByLabel("grant from node").selectOption("atlas");
    await dialog.getByLabel("grant to node").selectOption("global");
    await dialog.getByLabel("reason for the grant").fill("the build needs the registry token");
    await create.click();
    await expect(presenceAlert(app, "grant.create")).toBeVisible();
    expect(app.frames("grant.create").map((f) => f.params)).toEqual([{ from: "atlas", to: { kind: "node", nodeId: "global" }, scope: ["read"], reason: "the build needs the registry token" }]);
    await expect(dialog).toBeVisible(); // stays open: what was typed is not lost
    expect((await app.oracle.call("grant.list")).grants, "the refused grant was not created").toEqual([]);
    await dialog.getByRole("button", { name: "Cancel" }).click();
  });

  await test.step("rotate root key: the vault passphrase is asked and sent, presence is missing, no recovery code appears, the vault is untouched", async () => {
    await openSettings(app, "Advanced");
    await page.getByRole("button", { name: "Rotate…" }).click();
    const prompt = app.screen("Passphrase prompt");
    await expect(prompt).toContainText("needs presence (Touch ID)");
    await prompt.getByLabel("vault passphrase").fill(app.passphrase);
    await prompt.getByRole("button", { name: "Rotate", exact: true }).click();
    await expect(presenceAlert(app, "maintenance.rotate_root")).toBeVisible();
    expect(app.frames("maintenance.rotate_root").map((f) => f.params)).toEqual([{ passphrase: app.passphrase }]);
    await expect(prompt).toHaveCount(0);
    await expect(app.screen("New recovery code")).toHaveCount(0);
    expect(await app.pageDump(), "the passphrase is not left on the page").not.toContain(app.passphrase);
    // the vault is exactly as it was: same files can still be verified, and the same passphrase still opens it
    expect((await app.oracle.call("maintenance.verify")).ok).toBe(true);
  });

  await test.step("the audit trail, read back from the broker, records the refusals and carries no session token", async () => {
    await openSettings(app, "Audit");
    const rows = page.locator('[data-audit-row="true"]');
    await expect(rows.first()).toBeVisible();
    await expect(page.getByText(/\d+ records, newest first/)).toBeVisible();
    const text = await page.locator(".cm-settings").innerText();
    expect(text).toContain("maintenance.rotate_root");
    expect(text).toContain("grant.create");
    expect(text).not.toMatch(/cmt_[0-9a-f]{8}/i);
    expect(await app.pageDump()).not.toMatch(/cmt_[0-9a-f]{8}/i);
    // the broker's trail agrees with what the screen shows, independently
    const tail = (await app.oracle.call("audit.tail", { limit: 50 })).records;
    expect(tail.some((r: any) => r.action === "grant.create" && r.decision === "deny" && r.detail === "presence_required")).toBe(true);
    expect(tail.some((r: any) => r.action === "maintenance.rotate_root" && r.decision === "deny")).toBe(true);
    expect(JSON.stringify(tail)).not.toMatch(/cmt_[0-9a-f]{8}/i);
    // opening one record is audit.get, which is also presence-gated
    await rows.first().click();
    await expect(presenceAlert(app, "audit.get")).toBeVisible();
    expect(app.frames("audit.get")).toHaveLength(1);
    await closeSettings(app);
  });

  await test.step("a TOTP entry shows the broker's real code (the same one an authenticator would show), and 'show seed' is refused for presence", async () => {
    await selectNode(app, "Atlas");
    await openEntry(app, "deploy-otp");
    const field = page.locator(".k-field-value").first();
    await page.getByRole("button", { name: "show code" }).click();
    await expect(field).toHaveText(/^\d{3} \d{3}$/);
    const shown = (await field.innerText()).replace(/\s/g, "");
    const step = Math.floor(Date.now() / 1000 / 30);
    const mine = [step - 1, step, step + 1].map((s) => codeAt(base32Decode(SEED), s));
    expect(mine, "the code on screen is a valid RFC 6238 code for the stored seed").toContain(shown);
    expect(app.frames("totp.code")).toHaveLength(1);
    expect(app.frames("entry.reveal"), "showing a code never fetches the seed").toEqual([]);
    expect(await app.pageDump()).not.toContain(shown);
    await page.getByRole("button", { name: "hide", exact: true }).click();
    await expect(field).toHaveText("••••••••••••");

    await page.getByRole("button", { name: "show seed" }).click();
    await expect(presenceAlert(app, "totp.seed")).toBeVisible();
    expect(app.frames("totp.seed")).toHaveLength(1);
    expect(await app.pageDump(), "no seed was shown").not.toContain(SEED);
  });

  await test.step("a node created with a widening choice is created, but the widening is refused, said plainly, and not applied", async () => {
    const settings = await openSettings(app, "Nodes");
    await settings.getByRole("button", { name: "+ New project" }).click();
    const dlg = app.screen("S8 Add node");
    await expect(dlg).toBeVisible();
    await dlg.getByLabel("node name").fill("Payments API");
    await dlg.getByLabel("This node can read its children").check();
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(dlg).toBeHidden();
    await expect(notice(app)).toHaveCount(1);
    await expect(notice(app)).toContainText("Node “Payments API” was created, but these choices were not applied");
    await expect(notice(app)).toContainText("presence (Touch ID)");
    expect(app.frames("node.create").at(-1)!.params).toMatchObject({ id: "payments-api", label: "Payments API", parentId: "global" });
    expect(app.frames("node.policy").map((f) => f.params)).toEqual([{ node: "payments-api", reason: "set at creation", policy: { descendantRead: true } }]);
    expect((await app.oracle.nodeIds()).sort()).toEqual([...before.nodes, "payments-api"].sort());
    // ...and the choice is not applied AT THE VAULT, read by an independent client. node.policy is the only op that reports a node's
    // policy, so a patch that sets a field to the value it already has (a no-op) is the read: it answers the whole stored policy.
    const stored = await app.oracle.call("node.policy", { node: "payments-api", reason: "read-back: a no-op patch to read the stored policy", policy: { privateNames: false } });
    expect(stored.policy.descendantRead, "the node still cannot read its children: the widening was not applied").toBe(false);
    expect(stored.policy.siblingVisibility, "and its other choices are the defaults").toBe("shared");
  });

  await test.step("nothing else changed: the entries are as they were, no grant exists, and the vault verifies clean after a lock and an unlock", async () => {
    await closeSettings(app);
    await lockUi(app);
    await unlockToMain(app);
    await app.oracle.login();
    expect(await app.oracle.entries("atlas")).toEqual(before.entries);
    expect((await app.oracle.call("grant.list")).grants).toEqual([]);
    expect((await app.oracle.call("maintenance.verify")).ok).toBe(true);
  });
});
