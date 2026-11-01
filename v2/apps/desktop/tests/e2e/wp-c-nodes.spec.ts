/**
 * Work package C, part 3: adding a node (with its work folders and policy), sealing a node, restoring it.
 *
 * Policy is applied after the node exists, in two kinds of call: the choices that narrow or keep reach go together; the ones
 * that WIDEN reach go alone, because the broker answers `presence_required` to them in this beta and a refusal must not
 * discard the rest.  Every call carries a reason.
 */
import { expect, test, type App } from "./harness";
import { dialogFocusSettled, notice, openAddNode, openSettingsNodes } from "./wp-c-util";

const rail = (app: App, label: string) => app.page.locator(".cm-rail .k-tree-row", { hasText: label });

/** Right-click a rail row and choose an item of its menu; a dialog it opens is waited for until its focus has settled. */
async function nodeMenu(app: App, label: string, item: string) {
  await rail(app, label).first().click({ button: "right" });
  await app.page.getByRole("button", { name: item, exact: true }).click();
  if (item === "Remove node…") await dialogFocusSettled(app.screen("S9 Seal node").getByLabel("type the node name to confirm"));
}

async function closeSettings(app: App) {
  await app.screen("S12 Settings").getByRole("button", { name: "Close", exact: true }).click();
  await expect(app.screen("S12 Settings")).toBeHidden();
}

test.describe("add node", () => {
  test("creates the node with its work folder (~ expanded), then applies the policy choices: narrowing together, widening alone, each with a reason", async ({ app }) => {
    const { page } = app;
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    const dlg = await openAddNode(app);

    await dlg.getByLabel("node name").fill("Payments API");
    await expect(dlg).toContainText("node id: payments-api");
    await dlg.getByLabel("work folder").first().fill("~/projects/alpha");
    // the advanced choices (pro mode): 2FA on reveal off narrows nothing it must ask for; reading children widens reach
    await dlg.getByLabel("Require second factor on reveal").uncheck();
    await dlg.getByLabel("This node can read its children").check();
    await dlg.getByLabel("agent access").selectOption("read-only");
    await dlg.getByRole("button", { name: "Create node" }).click();

    // the folder was expanded by the shell's path API, then ONE node_create
    await expect(dlg).toBeHidden();
    expect(await broker.calls("plugin:path|resolve_directory")).toHaveLength(1);
    expect(await broker.calls("node_create")).toEqual([
      { cmd: "node_create", args: { id: "payments-api", label: "Payments API", parentId: "global", workdirs: ["/opt/fixture-home/projects/alpha"] } },
    ]);
    // two policy calls, in this order, each with a reason; the widening one is alone
    expect(await broker.calls("node_policy")).toEqual([
      { cmd: "node_policy", args: { node: "payments-api", reason: "set at creation", policy: { requireTwoFactor: "never", agentAccess: "read-only" } } },
      { cmd: "node_policy", args: { node: "payments-api", reason: "set at creation", policy: { descendantRead: true } } },
    ]);

    // the broker refused the widening part for lack of presence: said plainly, with what was and was not done
    await expect(notice(app)).toHaveCount(1); // ONE notice for the whole account of the node
    await expect(notice(app)).toContainText("Node “Payments API” was created, but these choices were not applied");
    await expect(notice(app)).toContainText("this node reading its children (you chose on; it stays off)");
    await expect(notice(app)).toContainText("presence (Touch ID)");
    await expect(notice(app)).toContainText("Applied: second factor on reveal, agent access.");
    await expect(notice(app)).toContainText("The node is no wider than you chose.");
    const made = (await broker.state()).nodes.find((n) => n.id === "payments-api") as any;
    expect(made.workdirs).toEqual(["/opt/fixture-home/projects/alpha"]);
    expect(made.policy).toMatchObject({ requireTwoFactor: "never", agentAccess: "read-only", descendantRead: false });

    // fresh reads: the node is in the rail and selected
    await closeSettings(app);
    await expect(rail(app, "Payments API").first()).toBeVisible();
    await expect(page.locator("aside.cm-insp")).toContainText("Payments API");
  });

  test("a policy call the broker refuses for a reason other than presence is reported as that, ONE notice names every refusal, and a node left WIDER than chosen says so", async ({ app }) => {
    const { page } = app;
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    const dlg = await openAddNode(app);
    await dlg.getByLabel("node name").fill("Locked down");
    await dlg.getByLabel("Sub-nodes see each other").uncheck(); // chosen: isolated      (narrowing call)
    await dlg.getByLabel("agent access").selectOption("none"); // chosen: agents locked out (narrowing call)
    await dlg.getByLabel("This node can read its children").check(); // chosen: widening, which the fixture refuses for presence
    // the narrowing call is refused for a reason that is NOT presence; the widening one falls through to the fixture's own presence refusal
    await broker.script("node_policy", { error: { code: "capability_not_held" } });
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(dlg).toBeHidden();

    expect((await broker.calls("node_policy")).map((c) => Object.keys((c.args as any).policy))).toEqual([["siblingVisibility", "agentAccess"], ["descendantRead"]]);
    // one notice, not two: the second refusal did not replace the first
    await expect(notice(app)).toHaveCount(1);
    const text = (await notice(app).innerText()).replace(/\s+/g, " ");
    expect(text).toContain("Node “Locked down” was created, but these choices were not applied");
    expect(text).toContain("sub-nodes seeing each other (you chose isolated; it stays shared)");
    expect(text).toContain("agent access (you chose none; it stays read-write)");
    expect(text).toContain("this node reading its children (you chose on; it stays off)");
    expect(text).toContain("not allowed to change the node's settings"); // the real reason of the first refusal, not "Unexpected error" and not a bare "Not permitted"
    expect(text).toContain("presence (Touch ID)");
    expect(text).toContain("The node is WIDER than you chose");
    expect(text).toContain("credmgr node policy locked-down --reason");
    await expect(notice(app)).toHaveAttribute("data-notice", /error/);
    // and the node really is as wide as the report says
    const made = (await broker.state()).nodes.find((n) => n.id === "locked-down") as any;
    expect(made.policy).toMatchObject({ siblingVisibility: "shared", agentAccess: "read-write", descendantRead: false });
    await page.keyboard.press("Escape");
  });

  test("a node left at the defaults sends node_create and nothing else", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    const dlg = await openAddNode(app);
    await dlg.getByLabel("node name").fill("plain");
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(notice(app)).toContainText("Node “plain” created.");
    expect(await broker.calls("node_create")).toEqual([{ cmd: "node_create", args: { id: "plain", label: "plain", parentId: "global" } }]);
    expect(await broker.calls("node_policy")).toEqual([]);
    expect(await broker.calls("plugin:path|resolve_directory")).toEqual([]); // nothing to expand
  });

  test("advanced choices do not carry over from one node to the next, however the dialog was left", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    let dlg = await openAddNode(app);
    // loosen things, type a name and a folder, then walk away
    await dlg.getByLabel("node name").fill("walked-away");
    await dlg.getByLabel("work folder").first().fill("~/projects/beta");
    await dlg.getByLabel("Require second factor on reveal").uncheck();
    await dlg.getByLabel("Sub-nodes see each other").uncheck();
    await dlg.getByRole("button", { name: "Cancel" }).click();
    await expect(dlg).toBeHidden();

    // the next node starts from the defaults: nothing typed, nothing loosened, so no policy call at all
    dlg = app.screen("S8 Add node");
    await app.screen("S12 Settings").getByRole("button", { name: "+ New project" }).click();
    await expect(dlg).toBeVisible();
    await expect(dlg.getByLabel("node name")).toHaveValue("");
    await expect(dlg.getByLabel("work folder").first()).toHaveValue("");
    await expect(dlg.getByLabel("Require second factor on reveal")).toBeChecked();
    await expect(dlg.getByLabel("Sub-nodes see each other")).toBeChecked();
    await dlg.getByLabel("node name").fill("fresh");
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(notice(app)).toContainText("Node “fresh” created.");
    expect(await broker.calls("node_create")).toEqual([{ cmd: "node_create", args: { id: "fresh", label: "fresh", parentId: "global" } }]);
    expect(await broker.calls("node_policy")).toEqual([]);
  });

  test("a sub-node goes under the chosen project", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    const dlg = await openAddNode(app);
    await dlg.getByLabel("node name").fill("canary");
    await dlg.getByLabel("parent node").selectOption("beacon");
    await dlg.getByLabel("Sub-nodes see each other").uncheck(); // narrowing: isolated
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(notice(app)).toContainText("Node “canary” created.");
    expect((await broker.calls("node_create"))[0].args).toEqual({ id: "canary", label: "canary", parentId: "beacon" });
    expect(await broker.calls("node_policy")).toEqual([{ cmd: "node_policy", args: { node: "canary", reason: "set at creation", policy: { siblingVisibility: "isolated" } } }]);
    expect(((await broker.state()).nodes.find((n) => n.id === "canary") as any).depth).toBe(2);
  });

  test("a name that cannot be a node is refused before any call", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    const dlg = await openAddNode(app);
    const create = dlg.getByRole("button", { name: "Create node" });
    const name = dlg.getByLabel("node name");

    await expect(create).toBeDisabled(); // empty
    await name.fill("atlas");
    await expect(dlg.getByRole("alert")).toContainText('a node called "atlas" already exists');
    await expect(create).toBeDisabled();
    await name.fill("Global");
    await expect(dlg.getByRole("alert")).toContainText("“global” is reserved");
    await expect(create).toBeDisabled();
    await name.fill("!!!");
    await expect(dlg.getByRole("alert")).toContainText("needs at least one letter or digit");
    await expect(create).toBeDisabled();
    await name.fill("../escape"); // the id becomes a folder name: only letters, digits and dashes survive
    await expect(dlg).toContainText("node id: escape");
    await name.fill("fine");
    await dlg.getByLabel("work folder").first().fill("relative/path");
    await expect(dlg.getByRole("alert")).toContainText("Work folders must be absolute paths");
    await expect(create).toBeDisabled();
    expect(await broker.calls("node_create")).toEqual([]);
  });

  test("a folder the broker cannot use leaves the dialog open, says what to check, and creates nothing", async ({ app }) => {
    const { page } = app;
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    const dlg = await openAddNode(app);
    await dlg.getByLabel("node name").fill("doomed");
    await dlg.getByLabel("work folder").first().fill("/opt/fixture-home/projects/does-not-exist");
    await dlg.getByRole("button", { name: "Create node" }).click();
    await expect(dlg.getByRole("alert")).toContainText("The broker did not accept this node. Check the name, the parent, and that every work folder is an existing directory.");
    await expect(notice(app)).toContainText("Unexpected error (malformed_request). Nothing was changed.");
    await expect(dlg).toBeVisible();
    expect(await broker.calls("node_create")).toHaveLength(1);
    expect(await broker.calls("node_policy")).toEqual([]);
    expect((await broker.state()).nodes.map((n) => n.id)).not.toContain("doomed");
    await expect(page.locator(".cm-rail .k-tree-row", { hasText: "doomed" })).toHaveCount(0);
  });
});

test.describe("seal and restore", () => {
  test("seal sends node_seal, re-reads graph, grants and the tray, and the node's entries show up under Orphaned", async ({ app }) => {
    const { page } = app;
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    await nodeMenu(app, "beacon", "Remove node…");
    const dlg = app.screen("S9 Seal node");
    await expect(dlg).toBeVisible();

    // what the dialog promises is what the broker does
    await expect(dlg).toContainText("1 entries (0 2FA) move to ORPHANED");
    await expect(dlg).toContainText("1 grant touching this node is revoked");
    await expect(dlg).toContainText("you can restore the node for 7 days");
    await expect(dlg.getByRole("button", { name: "Seal node" })).toBeDisabled(); // until the name is typed
    await dlg.getByLabel("type the node name to confirm").fill("beac");
    await expect(dlg.getByRole("button", { name: "Seal node" })).toBeDisabled();
    await dlg.getByLabel("type the node name to confirm").fill("beacon");

    const reads = async () => ({
      graph: (await broker.calls("graph_snapshot")).length,
      grants: (await broker.calls("grant_list")).length,
      pending: (await broker.calls("vault_pending_list")).length,
    });
    const before = await reads();
    await dlg.getByRole("button", { name: "Seal node" }).click();
    await expect(notice(app)).toContainText("Node “beacon” sealed. Restore it from Settings → Nodes within 7 days.");

    expect(await broker.calls("node_seal")).toEqual([{ cmd: "node_seal", args: { node: "beacon" } }]);
    const after = await reads();
    expect(after.graph).toBe(before.graph + 1);
    expect(after.grants).toBe(before.grants + 1); // the grant on beacon was revoked by the broker
    expect(after.pending).toBe(before.pending + 4); // every node still there is read again
    expect((await broker.state()).grants).toEqual([]);

    await expect(rail(app, "beacon")).toHaveCount(0);
    await expect(page.locator("aside.cm-insp")).toContainText("registry-token"); // selected: Orphaned, with the node's entry in it
    expect((await broker.state()).entries.orphaned.map((e) => e.name)).toContain("registry-token");
  });

  test("a sealed node is restored from Settings → Nodes with node_restore, and its entries come back", async ({ app }) => {
    const { page } = app;
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    await nodeMenu(app, "beacon", "Remove node…");
    await app.screen("S9 Seal node").getByLabel("type the node name to confirm").fill("beacon");
    await app.screen("S9 Seal node").getByRole("button", { name: "Seal node" }).click();
    await expect(rail(app, "beacon")).toHaveCount(0);

    const settings = await openSettingsNodes(app);
    await expect(settings).toContainText("sealed nodes · restorable for 7 days after sealing");
    await settings.getByRole("button", { name: "Restore node" }).click();
    await expect(notice(app)).toContainText("Node “beacon” restored.");
    expect(await broker.calls("node_restore")).toEqual([{ cmd: "node_restore", args: { node: "beacon" } }]);
    await expect(settings.getByRole("button", { name: "Restore node" })).toHaveCount(0); // no longer offered

    await closeSettings(app);
    await expect(rail(app, "beacon").first()).toBeVisible();
    await expect(page.locator("aside.cm-insp button.k-entry", { hasText: "registry-token" })).toBeVisible();
    expect((await broker.state()).entries.orphaned.map((e) => e.name)).not.toContain("registry-token");
  });

  test("a restore after the 7-day window is refused, said so, and no longer offered", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    await nodeMenu(app, "beacon", "Remove node…");
    await app.screen("S9 Seal node").getByLabel("type the node name to confirm").fill("beacon");
    await app.screen("S9 Seal node").getByRole("button", { name: "Seal node" }).click();
    await expect(rail(app, "beacon")).toHaveCount(0);

    await broker.set({ sealedExpired: true });
    const settings = await openSettingsNodes(app);
    await settings.getByRole("button", { name: "Restore node" }).click();
    await expect(notice(app)).toContainText("That can no longer be undone. Reloaded.");
    expect(await broker.calls("node_restore")).toHaveLength(1);
    await expect(settings.getByRole("button", { name: "Restore node" })).toHaveCount(0);
    await closeSettings(app);
    await expect(rail(app, "beacon")).toHaveCount(0);
  });

  test("a node that still has sub-nodes is not offered for sealing, and nothing is sent", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    await nodeMenu(app, "atlas", "Remove node…"); // atlas holds "staging"
    const dlg = app.screen("S9 Seal node");
    await expect(dlg.getByRole("alert")).toContainText("Seal its sub-nodes first (staging)");
    await dlg.getByLabel("type the node name to confirm").fill("atlas");
    await expect(dlg.getByRole("button", { name: "Seal node" })).toBeDisabled();
    expect(await broker.calls("node_seal")).toEqual([]);
  });

  test("a locked node is not offered for sealing either (sealing needs its key)", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    await nodeMenu(app, "cobalt", "Remove node…");
    const dlg = app.screen("S9 Seal node");
    await expect(dlg.getByRole("alert")).toContainText("This node is locked. Unlock it first");
    await dlg.getByLabel("type the node name to confirm").fill("cobalt");
    await expect(dlg.getByRole("button", { name: "Seal node" })).toBeDisabled();
    expect(await broker.calls("node_seal")).toEqual([]);
  });

  test("a refusal from the broker is shown and the node stays", async ({ app }) => {
    const broker = (await app.open({ broker: { locked: false } }))!;
    await expect(app.screen("S1 Main")).toBeVisible();
    await nodeMenu(app, "beacon", "Remove node…");
    const dlg = app.screen("S9 Seal node");
    await dlg.getByLabel("type the node name to confirm").fill("beacon");
    await broker.script("node_seal", { error: { code: "node_access_denied", detail: { rule: "R8" } } });
    await dlg.getByRole("button", { name: "Seal node" }).click();
    // an inline-class refusal is shown as a notice here (the dialog has no field for it) and the dialog stays for another try
    await expect(notice(app)).toContainText("Not permitted (R8).");
    await expect(dlg).toBeVisible();
    await expect(rail(app, "beacon").first()).toBeVisible();
    expect((await broker.state()).nodes.map((n) => n.id)).toContain("beacon");
  });
});
