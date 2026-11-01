// Binding coverage: every identifier the compiled template reads must be a key of renderVals(), in every state the headless gates
// walk (scripts/states.mjs).  A renamed or removed key would otherwise render nothing, silently.
//
// The logic runs here exactly as it does in the app: the model reads through the real bridge client, and the Tauri shell's
// `invoke` is the fixture broker (tests/fixtures/broker), loaded into a fake `window` the way the Playwright specs load it
// into a page.  So the vault the states are drawn from has the broker's shapes, not the design's old demo data.
import { afterEach, describe, expect, it } from "vitest";

import { bindings } from "../../src/design/app.template.html?dc";
import Component from "../../src/design/logic/core.js";
import { STATES } from "../../scripts/states.mjs";
import { brokerScript } from "../fixtures/broker/script.mjs";

/**
 * The number of names the template reads.  PINNED: every change to a screen that adds or removes a binding changes this on
 * purpose, in the same commit.  (A loose "more than 300" let a lane drop bindings without a test noticing.)
 */
const BINDING_COUNT = 630; // measured on the merged tree; tests/unit/compile.test.ts pins the same number from the compiler

const BASE = { screen: "app", vaultLocked: false, overlay: null, dialog: null, view: "graph", openEntry: null, ctx: null, vaultMenu: false, searchOpen: false, searchQ: "", railOpen: false, inspOpen: false };

const g = globalThis as unknown as { window?: unknown };

/** A fake page: the fixture broker installed on it, an open vault behind it. */
function fixtureWindow(options: Record<string, unknown> = { locked: false }): void {
  const win = {};
  g.window = win;
  new Function("window", brokerScript(options))(win);
}

afterEach(() => {
  delete g.window;
});

/** A logic instance in `state`, with the model booted (the fixture answers in memory, so this is a few microtasks). */
async function logicIn(state: Record<string, unknown>) {
  fixtureWindow();
  const logic = new (Component as any)({ mode: "pro" });
  await logic.model.boot();
  expect(logic.model.kind).toBe("bridge");
  expect(logic.model.status).toBe("unlocked");
  const patch: Record<string, unknown> = { ...BASE, selected: "atlas", ...state };
  if (patch.__fr) {
    patch.fr = { ...logic.state.fr, step: patch.__fr };
    delete patch.__fr;
  }
  logic.state = { ...logic.state, ...patch };
  return logic;
}

describe("renderVals() against the compiled template", () => {
  it("the template binds exactly the pinned number of names, each once, and the compiler found them all", () => {
    expect(new Set(bindings).size).toBe(bindings.length);
    expect(bindings.length).toBe(BINDING_COUNT);
  });

  for (const [name, patch] of STATES as [string, Record<string, unknown>][]) {
    it(`covers every binding in state "${name}"`, async () => {
      const vals = (await logicIn(patch)).renderVals();
      const missing = bindings.filter((b) => !(b in vals));
      expect(missing).toEqual([]);
    });
  }

  it("has no key that two areas both define (each key has one home)", async () => {
    const logic = await logicIn({});
    const c = logic.rvBase();
    const seen = new Map<string, string>();
    const dup: string[] = [];
    for (const area of ["Common", "Session", "Notice", "Main", "Inspector", "Search", "Write", "Settings", "Games"]) {
      for (const k of Object.keys(logic[`rv${area}`](c))) {
        if (seen.has(k)) dup.push(`${k}: ${seen.get(k)} and ${area}`);
        seen.set(k, area);
      }
    }
    expect(dup).toEqual([]);
  });

  it("renders before the model has loaded anything (the blank 'starting' screen must not throw)", () => {
    fixtureWindow();
    const logic = new (Component as any)({ mode: "pro" });
    expect(logic.vault.nodes).toEqual([]);
    const vals = logic.renderVals();
    expect(bindings.filter((b) => !(b in vals))).toEqual([]);
  });

  it("reads the vault only through the model", () => {
    fixtureWindow();
    const logic = new (Component as any)({ mode: "pro" });
    expect(logic.vault).toBe(logic.model.view);
    expect(() => {
      logic.vault = {};
    }).toThrow();
  });
});
