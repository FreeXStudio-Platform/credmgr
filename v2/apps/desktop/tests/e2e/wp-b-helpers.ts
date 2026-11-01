/**
 * Shared by the read-path specs (wp-b-*.spec.ts).  Not a spec itself (the name does not end in .spec.ts).
 *
 * `seedVault` replaces the fixture broker's vault BEFORE the app unlocks, so a spec can use names the design has never
 * shipped: if anything on screen still came from the design's own data, it would not match.
 */
import { FIXTURE_PASSPHRASE } from "../fixtures/broker/index";
import { expect, type App, type Locator } from "./harness";

export const MASK = "••••••••••••";

export interface SeedNode {
  id: string;
  label?: string;
  kind: "global" | "project" | "sub" | "orphan";
  parentId: string | null;
  locked?: boolean;
  twofa?: "none" | "enrolled" | "required";
}
export interface SeedEntry {
  id: string;
  name: string;
  type: string;
  sensitivity: "low" | "medium" | "high" | "critical";
  rotatedAt?: number;
}
export interface SeedVault {
  nodes: SeedNode[];
  entries: Record<string, SeedEntry[]>;
  notes?: Record<string, string>;
  grants?: Array<{ id: string; from: string; to: { kind: "node"; nodeId: string }; direction: "one-way"; scope: string[]; expiresAt: null; reason: string }>;
}

/** The value the fixture broker holds for an entry called `name`. */
export const valueOf = (name: string): string => `fixture-value-${name}`;

export async function seedVault(app: App, vault: SeedVault): Promise<void> {
  await app.page.evaluate((v) => {
    const S = (window as any).__brokerFixture.S;
    S.nodes = v.nodes.map((n) => ({
      id: n.id,
      label: n.label ?? n.id,
      kind: n.kind,
      depth: n.kind === "global" ? 0 : n.kind === "sub" ? 2 : 1,
      parentId: n.parentId,
      gate: { locked: !!n.locked, twofa: n.twofa ?? "none" },
    }));
    S.entries = {};
    for (const [node, list] of Object.entries(v.entries)) {
      S.entries[node] = list.map((e) => ({ id: e.id, name: e.name, type: e.type, sensitivity: e.sensitivity, value: "fixture-value-" + e.name, modified: 1760000000, rotatedAt: e.rotatedAt ?? null, expiresAt: null }));
    }
    S.notes = v.notes ?? {};
    S.grants = v.grants ?? [];
    S.pending = {};
    S.generation = {};
  }, vault);
}

/** Type the fixture passphrase on the lock screen and press Unlock. */
export async function unlockUi(app: App): Promise<void> {
  await app.page.locator('input[type="password"]').fill(FIXTURE_PASSPHRASE);
  await app.page.getByRole("button", { name: "Unlock", exact: true }).click();
}

/** Open the app on a locked fixture vault, put `vault` in it, unlock through the real lock screen, and wait for the main screen. */
export async function openWith(app: App, vault: SeedVault): Promise<NonNullable<Awaited<ReturnType<App["open"]>>>> {
  const broker = (await app.open({ broker: { locked: true } }))!;
  await expect(app.screen("S16 Lock screen")).toBeVisible();
  await seedVault(app, vault);
  await unlockUi(app);
  await expect(app.screen("S1 Main")).toBeVisible();
  return broker;
}

/** A rail row, by what it shows (the label the broker sent). */
export function railRow(app: App, label: string | RegExp): Locator {
  return app.page.locator(".cm-rail .k-tree-row", { hasText: label }).first();
}

/** The notice the app raised (any kind), by what it says. */
export function notice(app: App, text: string | RegExp): Locator {
  return app.page.locator("[data-notice]").filter({ hasText: text });
}

/**
 * The entry detail is open AND has finished loading its fields.  They come from `entry.get`, one read after the click, so a spec that acts on
 * a field (or changes the world behind the app's back) must wait for them first, or it races that read.  The detail ends in one of three
 * states, and this waits for whichever it is: the fields, "could not be read", or the locked-node panel.
 */
export async function entryOpened(app: App): Promise<void> {
  await expect(app.screen("S5 Entry detail")).toBeVisible();
  await expect(app.page.locator('[data-fields="true"], [data-fields-state="failed"], [data-screen-label="S5 Entry detail — locked"]').first()).toBeVisible();
}

/** Open an entry of the selected node's inspector by its name. */
export async function openEntry(app: App, name: string): Promise<void> {
  await app.page.locator("aside.cm-insp button.k-entry", { hasText: name }).first().click();
  await entryOpened(app);
}

/** Select a node in the rail, then open one of its entries. */
export async function openNodeEntry(app: App, nodeLabel: string | RegExp, entryName: string): Promise<void> {
  await railRow(app, nodeLabel).click();
  await openEntry(app, entryName);
}
