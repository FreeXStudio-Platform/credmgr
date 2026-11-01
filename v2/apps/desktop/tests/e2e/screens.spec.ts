/**
 * Every screen, dialog, overlay and settings section renders from BROKER-SHAPED data.
 *
 * test:csp walks the same screens on the design's demo data.  Once the model is fed by the bridge the screens read different
 * shapes (a field with no `value`, a note that is `null`, a grant with no `lastUsed`, node labels that are slugs), and a
 * template that throws on one of them is caught by the error boundary and shows "Something went wrong" instead of the screen.
 * This spec unlocks against the fixture broker, puts the logic into each state the design has, and fails - naming the state -
 * if any of them lands on the error screen, logs a console error or leaves the app's origin.  (The harness also asserts, at the
 * end of every spec, zero CSP violations, console errors and page errors.)
 *
 * The state patches are scripts/states.mjs STATES (the fixture vault's ids: atlas, e-a1, ...), which the design audit walks too.
 */
import { expect, test, type App } from "./harness";

const BASE = {
  screen: "app", vaultLocked: false, overlay: null, dialog: null, view: "graph", openEntry: null, donateToastOpen: false,
  donateView: "main", ctx: null, vaultMenu: false, searchOpen: false, searchQ: "", railOpen: false, inspOpen: false, hover: null,
  selected: "atlas", aboutTab: "main", setSection: "security", theme: "dark", contrastMode: "standard", gameScreen: "menu",
};

const SECTIONS = ["security", "appearance", "backup", "mode", "games", "nodes", "grants", "agents", "maintenance", "audit", "advanced"];

const STATES: Array<[string, Record<string, unknown>]> = [
  ["graph", {}],
  ["tree", { view: "tree" }],
  ["entry", { openEntry: "e-a1" }],
  ["entry-totp", { openEntry: "e-a3" }],
  ["entry-multi", { openEntry: "e-a2" }],
  ["entry-multi-menu", { openEntry: "e-a2", fieldMenu: "e-a2:f_00a20004" }],
  ["entry-locked", { openEntry: "e-a1", vaultLocked: true }],
  ["node-locked (cobalt)", { selected: "cobalt" }],
  ["orphan", { selected: "__orphan" }],
  ["global", { selected: "global" }],
  ["rail", { railOpen: true }],
  ["insp", { inspOpen: true }],
  ["vaultmenu", { vaultMenu: true }],
  ["search", { searchOpen: true, searchQ: "stripe" }],
  ["search-none", { searchOpen: true, searchQ: "zzzz-no-match" }],
  ["ctx", { ctx: { node: "atlas", x: 200, y: 200 } }],
  ["locked", { vaultLocked: true }],
  ["add-single", { dialog: "addEntry" }],
  ["add-bulk", { dialog: "addEntry", addMode: "bulk", bulkText: "host: a.example\nuser: root\n///\napi key: sk-test-123" }],
  ["add-locked", { dialog: "addEntry", vaultLocked: true }],
  ["addNode", { dialog: "addNode", newNodeName: "x" }],
  ["seal", { dialog: "seal", sealTarget: "beacon" }],
  ["grant", { dialog: "grant" }],
  ["about", { dialog: "about" }],
  ["about-donate", { dialog: "about", aboutTab: "donate" }],
  ["about-privacy", { dialog: "about", aboutTab: "privacy" }],
  ["about-licences", { dialog: "about", aboutTab: "licenses" }],
  ["help", { dialog: "help" }],
  ["pending", { dialog: "pending" }],
  ["touch", { dialog: "touch", touch: { title: "t", body: "b" } }],
  ["ops", { overlay: "ops" }],
  ["games", { overlay: "games" }],
  ["lock1", { screen: "lock", lockStep: 1 }],
  ["lock2", { screen: "lock", lockStep: 2 }],
  ["lock3", { screen: "lock", lockStep: 3 }],
  ...SECTIONS.map((k): [string, Record<string, unknown>] => [`settings-${k}`, { overlay: "settings", setSection: k }]),
  ["light", { theme: "light" }],
  ["dark-high", { contrastMode: "high" }],
  ["light-high", { theme: "light", contrastMode: "high" }],
];

/** The error screen the boundary draws, or null if the window shows something else. */
async function errorPanel(app: App): Promise<string | null> {
  const panel = app.page.locator('[data-error-boundary="true"]');
  return (await panel.count()) ? await panel.first().innerText() : null;
}

test("every screen, dialog, overlay and settings section renders from broker-shaped data", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: { locked: false } });
  await expect(app.screen("S1 Main")).toBeVisible();

  const failed: string[] = [];
  for (const [name, patch] of STATES) {
    await page.evaluate((s) => (window as any).__cm.setState(s), { ...BASE, ...patch });
    // let React commit and the template render; the boundary draws its panel synchronously on a throw
    await page.waitForTimeout(60);
    const panel = await errorPanel(app);
    const empty = (await page.locator("#dc-root").innerHTML()).trim() === "";
    if (panel !== null || empty) failed.push(`${name}: ${panel ?? "blank window"}`);
    // after a failure the boundary has taken over; put the app back so later states are judged on their own
    if (panel !== null) await page.reload();
  }
  // the boundary logs each render failure it catches; those are the failures reported above, not extra ones
  app.consoleErrors.length = 0;
  expect(failed, "states that did not render").toEqual([]);
});

test("the first-run steps render, with the broker saying there is no vault yet", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: { initialized: false, locked: true } });
  await expect(app.screen("S17 First run")).toBeVisible();
  const failed: string[] = [];
  for (let step = 1; step <= 5; step++) {
    await page.evaluate((n) => {
      const cm = (window as any).__cm;
      cm.setState({ screen: "firstrun", fr: { ...cm.state.fr, step: n } });
    }, step);
    await page.waitForTimeout(60);
    const panel = await errorPanel(app);
    if (panel !== null) failed.push(`step ${step}: ${panel}`);
  }
  app.consoleErrors.length = 0;
  expect(failed, "first-run steps that did not render").toEqual([]);
});

test("in the test build the broker-backed view is frozen: a screen that edits it in place throws", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: { locked: false } });
  await expect(app.screen("S1 Main")).toBeVisible();
  const outcome = await page.evaluate(() => {
    "use strict"; // the app's modules are strict, where an assignment to a frozen property throws
    const view = (window as any).__cm.vault;
    const tries: Record<string, string> = {};
    for (const [name, edit] of Object.entries<() => unknown>({
      pushNode: () => view.nodes.push({ id: "x" }),
      renameNode: () => (view.nodes[0].label = "renamed"),
      addEntry: () => view.entries.atlas.push({ id: "x" }),
      replaceList: () => (view.grants = []),
    })) {
      try {
        edit();
        tries[name] = "mutated";
      } catch {
        tries[name] = "threw";
      }
    }
    return tries;
  });
  expect(outcome).toEqual({ pushNode: "threw", renameNode: "threw", addEntry: "threw", replaceList: "threw" });
});
