/**
 * No screen carries a "mock" marker.
 *
 * The design drew a dashed badge ("mock", "notes.* not built") next to every control whose operation did not exist yet.  Every one of
 * those controls is now either wired to the broker or gone.  This walks every state of scripts/states.mjs (screens, dialogs,
 * overlays, every settings section, the lock and first-run steps) with a vault that has data in all the places a badge hid
 * (a held entry, a grant, an audit record, an operation result), and fails, naming the state, on anything a user could read as
 * "this is not real": the word "mock", "not built", "not wired", a dashed type pill (the design's badge style), a tooltip that says
 * so, or an accessible name that does.
 *
 * It can fail: the last test injects each marker into a rendered screen and requires the walk's check to see it.
 */
import { SETTINGS_SECTIONS, STATES } from "../../scripts/states.mjs";
import { expect, test, type App } from "./harness";

const BASE = {
  screen: "app", vaultLocked: false, overlay: null, dialog: null, view: "graph", openEntry: null, donateToastOpen: false, donateView: "main",
  ctx: null, vaultMenu: false, searchOpen: false, searchQ: "", railOpen: false, inspOpen: false, hover: null, selected: "atlas",
  aboutTab: "main", setSection: "security", theme: "dark", contrastMode: "standard", gameScreen: "menu",
};

/** The words a user could read as "this control is not real".  Matched on visible text, tooltips and accessible names. */
const MARKER = /\bmock(?:ed|s|ing)?\b|\bnot\s+(?:built|wired|implemented|available yet)\b|\bnot\s+yet\s+(?:built|wired|implemented)\b|\bplaceholder data\b|\bTODO\b|\bstub(?:bed)?\b/i;

interface Finding {
  state: string;
  what: string;
}

/** Everything a user could read in the app's root right now that says "not real": text, titles, aria labels, dashed pills. */
async function scan(app: App, state: string): Promise<Finding[]> {
  return app.page.evaluate(
    ([name, source]) => {
      const marker = new RegExp(source, "i");
      const out: Array<{ state: string; what: string }> = [];
      const root = document.querySelector("#dc-root");
      if (!root) return [{ state: name, what: "no #dc-root" }];
      const visible = (el: Element): boolean => {
        const r = (el as HTMLElement).getBoundingClientRect();
        const cs = getComputedStyle(el);
        return r.width > 0 && r.height > 0 && cs.visibility !== "hidden" && cs.display !== "none" && cs.opacity !== "0";
      };
      for (const el of root.querySelectorAll("*")) {
        if (!visible(el)) continue;
        const own = [...el.childNodes].filter((n) => n.nodeType === 3).map((n) => n.textContent || "").join(" ").replace(/\s+/g, " ").trim();
        if (own && marker.test(own)) out.push({ state: name, what: `text "${own.slice(0, 80)}" in <${el.localName}>` });
        for (const attr of ["title", "aria-label", "alt", "aria-description"]) {
          const v = el.getAttribute(attr);
          if (v && marker.test(v)) out.push({ state: name, what: `${attr}="${v.slice(0, 80)}" on <${el.localName}>` });
        }
        // The ONE sanctioned stand-in (owner decision O4, ADR-082): the supporter extras' app-icon picker is preview only until the shell has `app.icon.set`;
        // its pill names that op in its title.  Any other dashed pill, or this one without the op's name, is still a finding.
        const sanctioned = el.getAttribute("title")?.startsWith("app.icon.set:") && (el.textContent || "").trim() === "not in beta.1";
        if (el.classList.contains("k-type") && getComputedStyle(el).borderTopStyle === "dashed" && !sanctioned) out.push({ state: name, what: `a dashed k-type pill (the design's mock badge) reading "${(el.textContent || "").trim().slice(0, 40)}"` });
      }
      return out;
    },
    [state, MARKER.source] as const,
  );
}

test("no screen, dialog, overlay or settings section shows a mock badge, a 'not built' tooltip or a dashed stand-in pill", async ({ app }) => {
  const { page } = app;
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  const now = Math.floor(Date.now() / 1000);
  // data in every place a badge used to hide: a held entry (the tray), an audit record, a sealed node's restore row
  await broker.set({
    pending: { atlas: [{ id: "p-a1", name: "held-one", type: "other", sensitivity: "high", value: "fixture-value-held-one", modified: now, rotatedAt: null, expiresAt: null, created: now }] },
    audit: [{ id: "a_1", timestamp: now - 60, actor: "HumanUi:s_0123456789abcdef", action: "entry.reveal", node: "atlas", entry: "e-a1", decision: "allow", detail: null, generation: null }],
  });
  await page.evaluate(() => (window as any).__cm.model.refresh({ pending: true }));
  await page.evaluate(async () => {
    const cm = (window as any).__cm;
    await cm.loadAudit(); // the Audit section's rows
    await cm.doVerify(); // the Operations overlay's result panel
  });
  await page.evaluate(() => (window as any).__cm.model.rememberSealed({ id: "old-node", label: "old-node", node: { id: "old-node", label: "old-node" }, kids: [], date: "2026-10-01" }));

  const found: Finding[] = [];
  let walked = 0;
  for (const [name, patch] of STATES as Array<[string, Record<string, unknown>]>) {
    const state: Record<string, unknown> = { ...BASE, ...patch };
    if (state.__fr) {
      state.fr = await page.evaluate((n) => ({ ...(window as any).__cm.state.fr, step: n }), state.__fr);
      delete state.__fr;
    }
    await page.evaluate((s) => (window as any).__cm.setState(s), state);
    await page.waitForTimeout(60);
    found.push(...(await scan(app, name)));
    walked++;
  }
  // the settings sections once more, now that the audit rows, the operation result and a sealed node exist
  for (const section of SETTINGS_SECTIONS) {
    await page.evaluate((s) => (window as any).__cm.setState(s), { ...BASE, overlay: "settings", setSection: section });
    await page.waitForTimeout(40);
    found.push(...(await scan(app, `settings-${section} (second pass)`)));
    walked++;
  }
  app.consoleErrors.length = 0; // a state that does not render is screens.spec.ts's finding, not this one's
  expect(walked, "the walk covered the states").toBeGreaterThan(50);
  expect(found, "things on screen that read as 'not real'").toEqual([]);
});

test("the walk's check can fail: each marker it looks for is seen when it is on screen", async ({ app }) => {
  const { page } = app;
  await app.open({ broker: { locked: false } });
  await expect(app.screen("S1 Main")).toBeVisible();
  expect(await scan(app, "clean")).toEqual([]);
  // Planted through the DOM, no eval: the page runs under the production policy, which would (rightly) refuse it.
  type Plant = { kind: "text"; text: string } | { kind: "title"; title: string } | { kind: "aria"; label: string } | { kind: "dashed-pill"; text: string };
  const plants: Array<[string, Plant]> = [
    ["the word mock in text", { kind: "text", text: "mock" }],
    ["'notes.* not built' in text", { kind: "text", text: "notes.* not built" }],
    ["a tooltip that says not wired", { kind: "title", title: "this is not wired yet" }],
    ["an accessible name that says mock", { kind: "aria", label: "mock control" }],
    ["a dashed k-type pill", { kind: "dashed-pill", text: "soon" }],
  ];
  for (const [label, plant] of plants) {
    await page.evaluate((p) => {
      const root = document.querySelector("#dc-root")!;
      const holder = document.createElement("div");
      holder.id = "planted";
      let el: HTMLElement;
      if (p.kind === "text") {
        el = document.createElement("span");
        el.textContent = p.text;
      } else if (p.kind === "title" || p.kind === "aria") {
        el = document.createElement("button");
        el.textContent = "x";
        if (p.kind === "title") el.title = p.title;
        else el.setAttribute("aria-label", p.label);
      } else {
        el = document.createElement("span");
        el.className = "k-type";
        el.textContent = p.text;
        el.style.borderStyle = "dashed";
        el.style.borderWidth = "1px";
        el.style.display = "inline-block";
      }
      holder.append(el);
      root.append(holder);
    }, plant);
    const seen = await scan(app, label);
    await page.evaluate(() => document.getElementById("planted")?.remove());
    expect(seen.length, `the check did not see: ${label}`).toBeGreaterThan(0);
  }
  expect(await scan(app, "clean again")).toEqual([]);
});
