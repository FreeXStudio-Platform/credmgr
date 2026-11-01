/**
 * Work package B, part 1: what the user BROWSES.  The rail, the tree and the graph are drawn from the broker's snapshot, grant list
 * and entry lists and from nothing else; a node's note is read lazily as plain text; the orphaned node's items are listed from the
 * broker; header search asks the broker for entry names.  Each control is asserted by the exact bridge command and arguments it
 * sends and by what it renders from the answer, including a refusal.
 *
 * The vault here is seeded with names the design has never shipped (quartz, ember, ...), so nothing can pass on remembered demo data.
 */
import { expect, test } from "./harness";
import { entryOpened, notice, openWith, railRow, seedVault, unlockUi, type SeedVault } from "./wp-b-helpers";

const VAULT: SeedVault = {
  nodes: [
    { id: "global", kind: "global", parentId: null },
    { id: "quartz", label: "Quartz", kind: "project", parentId: "global" },
    { id: "quartz-ci", label: "Quartz CI", kind: "sub", parentId: "quartz" },
    { id: "ember", label: "Ember", kind: "project", parentId: "global", twofa: "required" },
    { id: "ember-eu", label: "Ember EU", kind: "sub", parentId: "ember" },
    { id: "ember-us", label: "Ember US", kind: "sub", parentId: "ember" },
    { id: "lone", label: "Lone", kind: "project", parentId: "global" },
    { id: "vaulted", label: "Vaulted", kind: "project", parentId: "global", locked: true },
    { id: "sealed", label: "sealed", kind: "orphan", parentId: "global" },
  ],
  entries: {
    global: [{ id: "g1", name: "licence-key", type: "api", sensitivity: "low" }],
    quartz: [
      { id: "q1", name: "signing-key", type: "api", sensitivity: "critical", rotatedAt: 1751241600 },
      { id: "q2", name: "ci-token", type: "api", sensitivity: "high" },
      { id: "q3", name: "release-otp", type: "totp", sensitivity: "high" },
    ],
    "quartz-ci": [{ id: "qc1", name: "runner-secret", type: "api", sensitivity: "medium" }],
    ember: [
      { id: "m1", name: "queue-password", type: "login", sensitivity: "high" },
      { id: "m2", name: "queue-admin", type: "login", sensitivity: "medium" },
    ],
    "ember-eu": [],
    "ember-us": [{ id: "mu1", name: "us-token", type: "api", sensitivity: "low" }],
    lone: [],
    vaulted: [{ id: "v1", name: "behind-the-lock", type: "api", sensitivity: "high" }],
    sealed: [
      { id: "o1", name: "old-root", type: "server", sensitivity: "critical" },
      { id: "o2", name: "old-cert", type: "certificate", sensitivity: "high" },
    ],
  },
  notes: { global: "Root note", quartz: "Release notes\n<b>not bold</b>\nline three" },
  grants: [{ id: "gr1", from: "ember", to: { kind: "node", nodeId: "quartz" }, direction: "one-way", scope: ["read"], expiresAt: null, reason: "ci reads the signing key" }],
};

const DEMO_NAMES = ["vps-root", "deploy-key", "grafana-admin", "pg-primary", "backup-b2", "wireguard-peer", "tailscale-auth"];

test("the rail, the tree and the graph are drawn from the broker's data and nothing else", async ({ app }) => {
  const { page } = app;
  const broker = await openWith(app, VAULT);

  // ---- rail: labels (not ids), entry counts, lock and second-factor badges, the orphaned node last
  const rows = page.locator(".cm-rail .k-tree-row");
  await expect(rows).toHaveCount(9);
  const labels = ["global", "Quartz", "Quartz CI", "Ember", "Ember EU", "Ember US", "Lone", "Vaulted", "orphaned"];
  for (let i = 0; i < labels.length; i++) await expect(rows.nth(i)).toContainText(labels[i]);
  await expect(rows.locator(".k-tree-count")).toHaveText(["1", "3", "1", "2", "0", "1", "0", "1", "2"]);
  await expect(rows.nth(3)).toContainText("‖"); // Ember: second factor on reveal
  await expect(rows.nth(7)).toContainText("⌐"); // Vaulted: locked
  await expect(rows.nth(1)).not.toContainText("⌐");
  // the id is not the label: a node called "Quartz" must not be drawn as "quartz"
  await expect(page.locator(".cm-rail")).not.toContainText("quartz-ci");

  // ---- the reads that built it: one snapshot, one grant list, every node's entries (and the orphan's), no value
  const reads = (cmd: string) => broker.calls(cmd);
  expect((await reads("graph_snapshot")).length).toBe(1);
  expect((await reads("grant_list")).length).toBe(1);
  expect((await reads("entry_list")).map((c) => c.args.node).sort()).toEqual(["ember", "ember-eu", "ember-us", "global", "lone", "quartz", "quartz-ci", "sealed", "vaulted"]);
  expect((await reads("entry_reveal")).length).toBe(0);

  // ---- tree view: the same nodes with their counts
  await page.getByRole("button", { name: "tree", exact: true }).click();
  const tree = app.screen("S2 Worktree view");
  await expect(tree).toBeVisible();
  await expect(tree).toContainText("3 entries · 1 2FA"); // Quartz: 3 entries, one of them TOTP
  await expect(tree).toContainText("Ember US");
  await expect(tree).not.toContainText("ember-us");
  for (const demo of DEMO_NAMES) await expect(page.locator("body")).not.toContainText(demo);
  await page.getByRole("button", { name: "graph", exact: true }).click();

  // ---- graph: nodes, structural links, the grant edge and the entry dots, from the view
  const g = await page.evaluate(() => {
    const cm = (window as any).__cm;
    const gd = cm.gd;
    return {
      nodes: gd.nodes.map((n: any) => ({ id: n.id, label: n.label, x: n.x, y: n.y })),
      links: gd.links.map((l: any) => ({ kind: l.kind, source: l.source.id, target: l.target.id })),
      dots: (cm.entryNodes || []).map((e: any) => ({ id: e.id, parent: e.parentId })),
      painted: (window as any).__cmPaint > 0,
    };
  });
  expect(g.nodes.map((n: { id: string }) => n.id).sort()).toEqual(["__orphan", "ember", "ember-eu", "ember-us", "global", "lone", "quartz", "quartz-ci", "vaulted"]);
  expect(g.nodes.find((n: { id: string }) => n.id === "ember").label).toBe("Ember");
  expect(g.links.filter((l: { kind: string }) => l.kind === "structural").length).toBe(7); // every node but global and the orphan has a parent
  expect(g.links.filter((l: { kind: string }) => l.kind === "grant")).toEqual([{ kind: "grant", source: "ember", target: "quartz" }]);
  expect(g.dots.length).toBe(1 + 3 + 1 + 2 + 1 + 1); // global, quartz, quartz-ci, ember, ember-us, vaulted; the orphan's items are not dots
  expect(g.dots.every((d: { parent: string }) => g.nodes.some((n: { id: string }) => n.id === d.parent))).toBe(true);
  const spots = new Set(g.nodes.map((n: { x: number; y: number }) => `${Math.round(n.x)},${Math.round(n.y)}`));
  expect(spots.size).toBe(g.nodes.length); // no two nodes on one spot
  expect(g.nodes.every((n: { x: number; y: number }) => Number.isFinite(n.x) && Number.isFinite(n.y))).toBe(true);
  expect(g.painted).toBe(true);
  const ink = await page.evaluate(() => {
    const cv = document.querySelector(".cm-main canvas") as HTMLCanvasElement;
    const data = cv.getContext("2d")!.getImageData(0, 0, cv.width, cv.height).data;
    let n = 0;
    for (let i = 3; i < data.length; i += 4) if (data[i] > 0) n++;
    return n;
  });
  expect(ink, "the canvas has something drawn on it").toBeGreaterThan(500);

  // a node the user moved keeps its place across a refresh (a rename re-reads the graph)
  const before = await page.evaluate(() => (window as any).__cm.gd.nodes.find((n: any) => n.id === "lone"));
  await page.evaluate(() => (window as any).__cm.model.refresh({ graph: true }));
  const after = await page.evaluate(() => (window as any).__cm.gd.nodes.find((n: any) => n.id === "lone"));
  expect([Math.round(after.x), Math.round(after.y)]).toEqual([Math.round(before.x), Math.round(before.y)]);
});

test("clicking an entry dot on the canvas opens that entry in ITS node, not in whichever node was selected", async ({ app }) => {
  const { page } = app;
  await openWith(app, VAULT); // global is selected
  // where the dot of Quartz's "ci-token" is on screen, once the dots have stopped drifting
  const spot = () =>
    page.evaluate(() => {
      const cm = (window as any).__cm;
      const dot = cm.entryNodes.find((e: any) => e.id === "q2");
      const r = cm.gcv.getBoundingClientRect();
      return { x: r.left + dot.x * cm.gv.k + cm.gv.tx, y: r.top + dot.y * cm.gv.k + cm.gv.ty };
    });
  let a = await spot();
  await expect
    .poll(async () => {
      const b = await spot();
      const moved = Math.hypot(a.x - b.x, a.y - b.y);
      a = b;
      return moved;
    }, { intervals: [150], timeout: 6000 })
    .toBeLessThan(0.4);
  await expect(page.locator("aside.cm-insp")).toContainText("node · global");
  await page.mouse.click(a.x, a.y);
  await entryOpened(app);
  await expect(page.locator("aside.cm-insp")).toContainText("ci-token");
  await expect(page.locator("aside.cm-insp")).toContainText("← Quartz"); // the node followed the dot
  await expect(railRow(app, "Quartz")).toHaveAttribute("aria-current", "true");
});

test("a node the broker will not list is shown as unreadable, not as empty, and the rest of the vault still renders", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true } }))!;
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await seedVault(app, VAULT);
  await broker.script("entry_list", { error: { code: "node_access_denied", detail: { rule: "R8" } } }); // the first node read is refused
  await unlockUi(app);
  await expect(app.screen("S1 Main")).toBeVisible();
  await expect(app.screen("S16 Lock screen")).toHaveCount(0); // a per-node refusal is not a lost login
  // the first list the app asked for was refused; that node says so (its count in the rail is the snapshot's, and unchanged), and does
  // NOT say "No entries in this node": the entries are there, out of this login's reach
  const refused = (await broker.calls("entry_list"))[0].args.node as string;
  const label = VAULT.nodes.find((n) => n.id === refused)!.label ?? refused;
  await railRow(app, label).click();
  await expect(page.locator("aside.cm-insp [data-node-unreadable]")).toHaveAttribute("data-node-unreadable", "node_access_denied");
  await expect(page.locator("aside.cm-insp")).toContainText("This login is not allowed to read this node");
  await expect(page.locator("aside.cm-insp")).not.toContainText("No entries in this node");
  expect((await broker.calls("entry_list")).filter((c) => c.args.node === refused).length).toBe(1);
  // every other node is as the broker said
  await railRow(app, "Quartz").click();
  await expect(page.locator("aside.cm-insp button.k-entry")).toHaveCount(3);
  await railRow(app, "Ember US").click();
  await expect(page.locator("aside.cm-insp button.k-entry")).toHaveCount(1);
});

test("a graph snapshot that says the vault is locked sends the user to the Lock screen, with nothing loaded", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: true } }))!;
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await seedVault(app, VAULT);
  // the login succeeds, then the snapshot (which is served even while locked) reports the idle lock having already fired
  await broker.script("graph_snapshot", { result: { nodes: [], links: [], meta: { generatedAt: 1, vaultLocked: true } } });
  await unlockUi(app);
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  expect(await page.content()).not.toContain("signing-key");
  expect((await broker.calls("entry_list")).length).toBe(0); // nothing past the snapshot was read
});

test("a node's inspector lists its entries with what the broker knows of them, and no value", async ({ app }) => {
  const { page } = app;
  await openWith(app, VAULT);
  await railRow(app, "Quartz").click();
  const entries = page.locator("aside.cm-insp button.k-entry");
  await expect(page.locator("aside.cm-insp")).toContainText("node · Quartz");
  await expect(page.locator("aside.cm-insp")).toContainText("3 entries · 1 2FA");
  await expect(entries).toHaveCount(3);
  await expect(entries.nth(0)).toContainText("signing-key");
  await expect(entries.nth(0)).toContainText("api");
  await expect(entries.nth(2)).toContainText("release-otp");
  await expect(entries.nth(2)).toContainText("2FA"); // a TOTP entry is marked as one
  // critical entries have the heavy danger border, low ones the hairline
  await expect(entries.nth(0)).toHaveCSS("border-left-width", "3px");
  // the second-factor policy of Ember is on its inspector, an empty node says so
  await railRow(app, "Ember").click();
  await expect(page.locator("aside.cm-insp")).toContainText("2fa · on reveal");
  await railRow(app, "Lone").click();
  await expect(page.locator("aside.cm-insp")).toContainText("No entries in this node");
  expect(await app.viewJson()).not.toContain("fixture-value");
  for (const demo of DEMO_NAMES) await expect(page.locator("body")).not.toContainText(demo);
});

test("a node's note is read when the node is selected, shown as plain text, and an unreadable one is a dash", async ({ app }) => {
  const { page } = app;
  const broker = await openWith(app, VAULT);
  const note = page.locator("[data-notes]");

  // the node that is selected when the vault opens has its note read without a click
  await expect(note).toHaveText("Root note");
  expect(await broker.calls("notes_read")).toEqual([{ cmd: "notes_read", args: { node: "global" } }]);

  // selecting a node reads its note: the exact command, and the text exactly as stored
  await railRow(app, "Quartz").click();
  await expect(note).toHaveText("Release notes\n<b>not bold</b>\nline three");
  expect((await broker.calls("notes_read")).at(-1)).toEqual({ cmd: "notes_read", args: { node: "quartz" } });
  expect(await note.locator("b").count()).toBe(0); // markup in a note is text, never markup
  expect(await note.evaluate((el) => getComputedStyle(el).whiteSpace)).toBe("pre-wrap"); // line breaks survive

  // a node with no note
  await railRow(app, "Lone").click();
  await expect(note).toHaveText("No note.");

  // the notes capability is not implied by read: the broker refuses, the note is a dash, the screen carries on
  await broker.script("notes_read", { error: { code: "capability_not_held", detail: { capability: "notes" } } });
  await railRow(app, "Ember").click();
  await expect(note).toHaveText("—");
  await expect(page.locator("[data-notice]")).toHaveCount(0); // nothing to alarm the user with

  // a locked node's note is not even asked for
  const asked = (await broker.calls("notes_read")).length;
  await railRow(app, "Vaulted").click();
  await expect(note).toHaveText("locked — unlock the node to read its note");
  expect((await broker.calls("notes_read")).length).toBe(asked);

  // selecting a node again reads its note again (it may have changed since)
  await railRow(app, "Quartz").click();
  await expect(note).toHaveText(/Release notes/);
  expect((await broker.calls("notes_read")).filter((c) => c.args.node === "quartz").length).toBe(2);
});

test("a note read that finds the login gone goes to the Lock screen", async ({ app }) => {
  const { page } = app;
  const broker = await openWith(app, VAULT);
  await broker.script("notes_read", { error: { code: "vault_locked" } });
  await railRow(app, "Quartz").click();
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  expect(await page.content()).not.toContain("signing-key");
});

test("the orphaned node lists its items from the broker; opening one is refused for want of presence", async ({ app }) => {
  const { page } = app;
  const broker = await openWith(app, VAULT);
  await railRow(app, "orphaned").click();
  const panel = app.screen("S10 Orphaned");
  await expect(panel).toBeVisible();
  await expect(panel).toContainText("orphaned · 2 items · sealed");
  await expect(panel).toContainText("old-root");
  await expect(panel).toContainText("old-cert");
  await expect(panel).not.toContainText(/from |Restore|Destroy/); // the design's "from"/date columns, restore and destroy have no broker op behind them
  await expect(panel.getByRole("button", { name: "open" })).toHaveCount(2);

  // "open" asks the broker for the item; the broker refuses (R0: native + presence only) and the user gets the standard presence notice, nothing shown
  await panel.getByRole("button", { name: "open" }).first().click();
  await expect(notice(app, "Needs presence (Touch ID), which this beta cannot attest yet. Nothing was changed. (entry.reveal)")).toBeVisible();
  await expect(app.page.locator('[data-notice="presence"]')).toBeVisible();
  expect(await broker.calls("entry_reveal")).toEqual([{ cmd: "entry_reveal", args: { node: "sealed", entry: "o1" } }]);
  expect(await app.secretCount()).toBe(0);
  expect(await page.content()).not.toContain("fixture-value-old-root");
  await expect(app.screen("S10 Orphaned")).toBeVisible();

  // if the broker ever did answer, the item opens like an entry, the value is on screen only while revealed, and leaving wipes it
  await broker.script("entry_reveal", { result: { node: "sealed", entry: "o2", fields: [{ id: "f_00000000", label: "", value: "sealed-value-xyz", type: "text", masked: true }], value: "sealed-value-xyz" } });
  await panel.getByRole("button", { name: "open" }).nth(1).click();
  await expect(app.screen("S5 Entry detail")).toBeVisible();
  await expect(page.locator(".k-field-value")).toHaveText("sealed-value-xyz");
  await expect(page.getByRole("button", { name: "copy" })).toHaveCount(0); // a sealed item is opened, never copied
  expect(await app.secretCount()).toBe(1);
  await page.getByRole("button", { name: /^← orphaned/ }).click();
  expect(await app.secretCount()).toBe(0);
  expect(await page.content()).not.toContain("sealed-value-xyz");
});

test.describe("search", () => {
  const box = (app: { page: import("@playwright/test").Page }) => app.page.locator(".cm-searchinput");
  const drop = (app: { screen: (l: string) => import("@playwright/test").Locator }) => app.screen("S7 Search");

  test("asks the broker for entry names once typing pauses, with one call for what was typed, and a hit opens the entry", async ({ app }) => {
    const { page } = app;
    const broker = await openWith(app, VAULT);
    await box(app).click();
    await box(app).pressSequentially("sig", { delay: 5 });
    await expect(drop(app).getByRole("button", { name: /signing-key/ })).toBeVisible();
    // three keystrokes inside the debounce window made ONE request, for the whole term, under the bridge's key
    expect(await broker.calls("search")).toEqual([{ cmd: "search", args: { term: "sig" } }]);
    await expect(drop(app).getByRole("button", { name: /signing-key/ })).toContainText("Quartz"); // the node's label, not its id

    await drop(app).getByRole("button", { name: /signing-key/ }).click();
    await expect(app.screen("S5 Entry detail")).toBeVisible();
    await expect(page.locator("aside.cm-insp")).toContainText("signing-key");
    await expect(page.locator("aside.cm-insp")).toContainText("← Quartz");
    await expect(drop(app)).toHaveCount(0);
    expect(await app.viewJson()).not.toContain("fixture-value");
  });

  test("a node is found by its label from the view, and selecting it opens its inspector without a broker call", async ({ app }) => {
    const { page } = app;
    const broker = await openWith(app, VAULT);
    await box(app).click();
    await box(app).fill("ember");
    const hit = drop(app).getByRole("button", { name: /Ember US/ });
    await expect(hit).toBeVisible();
    await expect(hit).toContainText("node");
    await hit.click();
    await expect(page.locator("aside.cm-insp")).toContainText("node · Ember US");
    // (the broker was asked for entry names too, which is its job; the node row did not wait for it)
    expect((await broker.calls("search")).every((c) => c.args.term === "ember")).toBe(true);
  });

  test("a term nothing matches says so once the broker has answered, not before", async ({ app }) => {
    const broker = await openWith(app, VAULT);
    await broker.script("search", { delayMs: 400, result: { results: [] } });
    await box(app).click();
    await box(app).fill("zzzz");
    await app.page.waitForTimeout(250);
    await expect(drop(app)).toBeVisible();
    await expect(drop(app)).not.toContainText("Nothing matches"); // the answer has not come yet
    await expect(drop(app)).toContainText("Nothing matches");
  });

  test("an answer for an older term is dropped when the user has typed on, and does not take the current answer's place", async ({ app }) => {
    const broker = await openWith(app, VAULT);
    // the request for "sig" is slow and its answer arrives AFTER the answer for "sign"
    await broker.script("search", { delayMs: 700, result: { results: [{ node: "quartz", id: "q2", name: "late-answer" }] } });
    await box(app).click();
    await box(app).fill("sig");
    await app.page.waitForTimeout(250); // the first request is now in flight
    await box(app).fill("sign");
    await expect(drop(app).getByRole("button", { name: /signing-key/ })).toBeVisible(); // the current term's answer (the real handler) came first
    await app.page.waitForTimeout(900); // now the stale one has arrived
    await expect(drop(app)).not.toContainText("late-answer");
    await expect(drop(app).getByRole("button", { name: /signing-key/ })).toBeVisible(); // and the stale answer did not replace it
    expect((await broker.calls("search")).map((c) => c.args.term)).toEqual(["sig", "sign"]);
  });

  test("a sealed item is found from the orphaned node's own list, and the broker's copy of the hit is not shown twice", async ({ app }) => {
    const broker = await openWith(app, VAULT);
    await broker.script("search", { result: { results: [{ node: "sealed", id: "o1", name: "old-root" }] } });
    await box(app).click();
    await box(app).fill("old-r");
    const hits = drop(app).getByRole("button", { name: /old-root/ });
    await expect(hits).toHaveCount(1);
    await expect(hits).toContainText("orphaned · sealed");
    await hits.click();
    await expect(app.screen("S10 Orphaned")).toBeVisible();
  });

  test("a refusal is shown, not swallowed, and the node matches still work", async ({ app }) => {
    const broker = await openWith(app, VAULT);
    await broker.script("search", { error: { code: "capability_not_held", detail: { rule: "list" } } });
    await box(app).click();
    await box(app).fill("quartz");
    await expect(notice(app, "Not permitted")).toBeVisible();
    await expect(drop(app).getByRole("button", { name: /Quartz/ }).first()).toBeVisible();
    await expect(drop(app)).not.toContainText("Nothing matches");
  });

  test("losing the login during a search goes to the Lock screen", async ({ app }) => {
    const broker = await openWith(app, VAULT);
    await broker.script("search", { error: { code: "vault_locked" } });
    await box(app).click();
    await box(app).fill("sig");
    await expect(app.screen("S16 Lock screen")).toBeVisible();
    expect(JSON.parse(await app.viewJson()).nodes).toEqual([]);
  });

  test("a value is never searched: only names go out, and a hit shows no value", async ({ app }) => {
    const { page } = app;
    const broker = await openWith(app, VAULT);
    await box(app).click();
    await box(app).fill("sig");
    await expect(drop(app).getByRole("button", { name: /signing-key/ })).toBeVisible();
    expect(JSON.stringify(await broker.calls("search"))).not.toContain("fixture-value");
    expect(await page.content()).not.toContain("fixture-value");
    await expect(page.locator(".k-field-value")).toHaveCount(0);
  });
});
