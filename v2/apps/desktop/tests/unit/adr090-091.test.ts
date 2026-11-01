// ADR-090 / ADR-091 at the logic layer: the Lock screen's list of waiting agent requests, the deliberate second factor, the node dialog's private
// name, the reload reason, and the audit passthrough list the fixture broker and the Rust shell must agree on.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { nextApprovalState } from "../../src/design/logic/gates.js";
import { LOCK_PHRASE } from "../../src/design/logic/session.js";
import { PAGE_LOCK_NOTE_KEY, RELOAD_REASON_KEY, rememberPageLockNote, takeReloadLockNote } from "../../src/vault/shell-events";

async function logic(state: Record<string, unknown> = {}, props: Record<string, unknown> = { mode: "pro" }) {
  const l = new (Component as any)(props);
  await l.model.boot();
  l.state = { ...l.state, ...state };
  l.__host = {
    setLogicState: (u: unknown, cb?: () => void) => {
      const next = typeof u === "function" ? (u as (s: unknown) => unknown)(l.state) : u;
      if (next) l.state = { ...l.state, ...(next as object) };
      cb?.();
    },
    forceUpdate: () => {},
  };
  return l;
}
const waiting = (request: string, title: string) => ({ request, node: "atlas", entry: "e_1", title, expiresAt: Date.now() + 60_000 });

describe("the Lock screen lists the waiting agent requests (ADR-090)", () => {
  it("lists what is waiting, always offers the request id field (worded for not-listed when a list is shown), and shows the factors only once a request is chosen", async () => {
    const l = await logic({ screen: "lock", lockStep: LOCK_PHRASE, aprOpen: true });
    let v = l.renderVals();
    expect(v).toMatchObject({ aprListShow: false, aprCount: 0, aprIdCaption: "Enter the request id the agent printed.", aprSelShow: false, aprLinkText: "an agent is waiting for approval?" });
    l.state = { ...l.state, aprWaiting: [waiting("rq_a", "“API_KEY” in Atlas")] };
    v = l.renderVals();
    expect(v).toMatchObject({ aprListShow: true, aprCount: 1, aprIdCaption: "Not listed? Enter the request id the agent printed.", aprLinkText: "1 agent request is waiting for approval" });
    expect(v.aprWaiting).toHaveLength(1);
    expect(v.aprWaiting[0]).toMatchObject({ title: "“API_KEY” in Atlas", picked: false });
    expect(v.aprWaiting[0].sub).toMatch(/^asked to reveal · \d+ s left$/);
    expect(v.aprIntro).toMatch(/Pick the request/);
    l.state = { ...l.state, aprWaiting: [waiting("rq_a", "a"), waiting("rq_b", "b")] };
    expect(l.renderVals().aprLinkText).toBe("2 agent requests are waiting for approval");
  });

  it("picking a request is what Approve and Deny send, and the button waits for the passphrase", async () => {
    const l = await logic({ screen: "lock", lockStep: LOCK_PHRASE, aprOpen: true, aprWaiting: [waiting("rq_a", "a"), waiting("rq_b", "b")] });
    expect(l.renderVals().aprDisabled).toBe(true);
    l.renderVals().aprWaiting[1].pick();
    expect(l.state.aprReq).toBe("rq_b");
    expect(l.renderVals().aprWaiting.map((w: any) => w.picked)).toEqual([false, true]);
    l.renderVals().onAprPass({ target: { value: "a passphrase" } });
    expect(l.renderVals().aprDisabled).toBe(false);
  });

  it("does not poll without a broker, and a lock screen with nothing to poll leaves the list empty", async () => {
    const l = await logic({ screen: "lock" });
    l.startApprovalPoll();
    expect(l._aprT).toBeUndefined();
    expect(l.state.aprWaiting).toEqual([]);
  });

  it("a lock wipes the list with the rest of the panel", async () => {
    const l = await logic({ screen: "app", aprWaiting: [waiting("rq_a", "a")], aprReq: "rq_a" });
    l.showLock("");
    expect(l.state).toMatchObject({ aprWaiting: [], aprReq: "" });
  });
});

describe("the second factor is given on purpose (S5c, as the broker does it)", () => {
  it("the inspector's chip opens the dialog in its 'give' wording: it is for agents, not for the owner who is already past it", async () => {
    const l = await logic({ screen: "app" });
    l.askSecondFactor({ node: "atlas", give: true });
    const v = l.renderVals();
    expect(v).toMatchObject({ dlgTf: true, tfTitle: "Give second factor", tfVerifyLabel: "Give second factor" });
    expect(v.tfSub).toBe("opens a 5-minute window for agents and other callers");
    expect(v.tfIntro).toMatch(/any agent, MCP or CLI caller passes the second factor on every node of this vault/);
    expect(v.tfIntro).toMatch(/You are not asked when you reveal a value yourself/);
    expect(v.tfNote).toMatch(/whole vault and for every caller, 300 s/);
    expect(v.tfNote).toMatch(/ends early when the vault locks or any node policy changes/);
  });

  it("a refused call that asks for the factor keeps the wording it always had", async () => {
    const l = await logic({ screen: "app" });
    l.askSecondFactor({ node: "atlas", retry: () => {} });
    const v = l.renderVals();
    expect(v).toMatchObject({ tfTitle: "Second factor needed", tfVerifyLabel: "Verify and reveal", tfSub: "the node “atlas” requires a second factor to reveal" });
    expect(v.tfIntro).toMatch(/two_factor_required/);
  });
});

describe("a node whose name is private (ADR-091)", () => {
  const adv = (pn: boolean) => ({ subShare: true, twofa: true, childRead: false, agentAccess: "read-write", pn });

  it("has no id until it is created (a slug of the name would give the name away), and the name's slug is not checked", async () => {
    const l = await logic({ screen: "app", dialog: "addNode", newNodeName: "Acme Prod", addNodeAdv: adv(true) });
    expect(l.addNodeInfo()).toMatchObject({ priv: true, id: "", label: "Acme Prod", problem: "", disabled: false });
    const v = l.renderVals();
    expect(v.newNodeIdShow).toBe(true);
    expect(v.newNodeIdNote).toBe("node id: chosen at random when it is created (the name is not part of it)");
    expect(v.newNodeIdNote).not.toMatch(/acme/i);
    // even a name that has no letters or digits can be private: the label is what the person typed
    l.state = { ...l.state, newNodeName: "★★★" };
    expect(l.addNodeInfo()).toMatchObject({ priv: true, problem: "", disabled: false });
  });

  it("keeps the name's slug for an ordinary node", async () => {
    const l = await logic({ screen: "app", dialog: "addNode", newNodeName: "Acme Prod", addNodeAdv: adv(false) });
    expect(l.addNodeInfo()).toMatchObject({ priv: false, id: "acme-prod", problem: "" });
    expect(l.renderVals().newNodeIdNote).toBe("node id: acme-prod");
    l.state = { ...l.state, newNodeName: "★★★" };
    expect(l.addNodeInfo().problem).toBe("the name needs at least one letter or digit");
  });

  it("still refuses a name that is too long or has control characters", async () => {
    const l = await logic({ screen: "app", dialog: "addNode", newNodeName: "x".repeat(121), addNodeAdv: adv(true) });
    expect(l.addNodeInfo().problem).toMatch(/1 to 120 characters/);
  });

  it("is only a pro-mode choice: the checkbox is not shown outside pro, so a leftover tick is ignored", async () => {
    const l = await logic({ screen: "app", dialog: "addNode", newNodeName: "Acme Prod", addNodeAdv: adv(true) }, { mode: "simple" });
    expect(l.addNodeInfo()).toMatchObject({ priv: false, id: "acme-prod" });
  });
});

describe("the page after the shell reloaded it because it locked (ADR-091)", () => {
  beforeEach(() => sessionStorage.clear());
  afterEach(() => sessionStorage.clear());

  it("shows the reason the shell left, once, in the event's own words", () => {
    sessionStorage.setItem(RELOAD_REASON_KEY, "sleep");
    expect(takeReloadLockNote()).toBe("Locked because this Mac went to sleep.");
    expect(takeReloadLockNote()).toBe("");
    expect(sessionStorage.getItem(RELOAD_REASON_KEY)).toBeNull();
  });

  it("accepts the six fixed words and nothing else", () => {
    for (const w of ["sleep", "screens_sleep", "session_resign", "screen_locked", "tray", "window_closed"]) {
      sessionStorage.setItem(RELOAD_REASON_KEY, w);
      expect(takeReloadLockNote()).not.toBe("");
    }
    sessionStorage.setItem(RELOAD_REASON_KEY, "<img src=x onerror=alert(1)>");
    expect(takeReloadLockNote()).toBe(""); // never shown, only deleted
    expect(sessionStorage.getItem(RELOAD_REASON_KEY)).toBeNull();
    expect(takeReloadLockNote()).toBe("");
  });

  it("is the key the shell writes (src-tauri/src/autolock.rs)", () => {
    const rust = readFileSync(resolve(__dirname, "../../src-tauri/src/autolock.rs"), "utf8");
    expect(rust).toContain(`RELOAD_REASON_KEY: &str = "${RELOAD_REASON_KEY}"`);
  });
});

describe("the audit passthrough (ADR-091)", () => {
  const rustList = (): string[] => {
    const rust = readFileSync(resolve(__dirname, "../../src-tauri/src/commands.rs"), "utf8");
    const block = /pub const AUDIT_PASSTHROUGH: &\[&str\] = &\[([\s\S]*?)\];/.exec(rust)![1];
    return [...block.matchAll(/"([a-z_.]+)"/g)].map((m) => m[1]);
  };

  it("lists the same ops in the Rust shell and in the fixture broker", async () => {
    const { brokerScript } = await import("../fixtures/broker/index");
    expect(brokerScript).toBeTruthy();
    const js = readFileSync(resolve(__dirname, "../fixtures/broker/core.js"), "utf8");
    const block = /B\.AUDITED = \[([\s\S]*?)\];/.exec(js)![1];
    const fixture = [...block.matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
    expect(fixture.sort()).toEqual(rustList().map((op) => op.replace(/\./g, "_")).sort());
    expect(fixture.length).toBe(24);
  });

  it("the real-daemon shim carries the same list", () => {
    const shim = readFileSync(resolve(__dirname, "../real/shim/shim.mjs"), "utf8");
    const block = /AUDIT_PASSTHROUGH = new Set\(\[([\s\S]*?)\]\)/.exec(shim)![1];
    const ops = [...block.matchAll(/"([a-z_.]+)"/g)].map((m) => m[1]);
    expect(ops.sort()).toEqual(rustList().sort());
  });
});

describe("the Lock screen's pick of a waiting request is never changed under the person", () => {
  const w = (...ids: string[]) => ids.map((request) => ({ request, node: "atlas", entry: "e", title: request, expiresAt: 1 }));

  it("fills an empty pick only when exactly one is waiting", () => {
    expect(nextApprovalState({ aprReq: "" }, w("rq_A", "rq_B"))).toEqual({ aprWaiting: w("rq_A", "rq_B"), aprReq: "" });
    expect(nextApprovalState({ aprReq: "" }, w("rq_A"))).toMatchObject({ aprReq: "rq_A" });
    expect(nextApprovalState({ aprReq: "" }, []).aprReq).toBe("");
  });

  it("keeps a pick that is still waiting, even when it becomes the only one", () => {
    expect(nextApprovalState({ aprReq: "rq_A" }, w("rq_A", "rq_B")).aprReq).toBe("rq_A");
    expect(nextApprovalState({ aprReq: "rq_A" }, w("rq_A")).aprReq).toBe("rq_A");
  });

  it("[A,B] picked A, A expires, [B] remains: the pick AND the typed passphrase and code are dropped; B is not picked in their place", () => {
    const r: any = nextApprovalState({ aprReq: "rq_A", aprPass: "typed for A", aprCode: "123456" }, w("rq_B"));
    expect(r).toMatchObject({ aprReq: "", aprPass: "", aprCode: "" });
    expect(r.aprErr).toMatch(/no longer waiting/);
  });

  it("when nothing is listed any more the request-id field keeps what was typed in it", () => {
    expect(nextApprovalState({ aprReq: "rq_typed", aprPass: "p" }, [])).toEqual({ aprWaiting: [] });
  });

  it("the poll does not run while an unlock or a decision is in flight", async () => {
    const l = await logic({ screen: "lock", lockBusy: true });
    await l.pollApprovals();
    expect(l._aprPolling).toBeFalsy();
    expect(l.state.aprWaiting).toEqual([]);
  });
});

describe("the page's own lock note survives the reload the shell now does after it (ADR-091 amendment)", () => {
  beforeEach(() => { sessionStorage.clear(); });
  it("leaves the idle-timer sentence for the next boot, once", () => {
    rememberPageLockNote("Locked after 5 minutes without activity.");
    expect(sessionStorage.getItem(PAGE_LOCK_NOTE_KEY)).toBe("Locked after 5 minutes without activity.");
    expect(takeReloadLockNote()).toBe("Locked after 5 minutes without activity.");
    expect(takeReloadLockNote()).toBe("");
    rememberPageLockNote("Locked after 1 minute without activity.");
    expect(takeReloadLockNote()).toBe("Locked after 1 minute without activity.");
  });
  it("keeps the hidden-window sentence too (the page's third own lock)", () => {
    rememberPageLockNote("Locked because the window was hidden.");
    expect(takeReloadLockNote()).toBe("Locked because the window was hidden.");
    expect(takeReloadLockNote()).toBe("");
  });
  it("leaves nothing for the user's own lock, and nothing a page could have stored is ever shown", () => {
    rememberPageLockNote("");
    expect(sessionStorage.getItem(PAGE_LOCK_NOTE_KEY)).toBeNull();
    rememberPageLockNote("<img src=x onerror=alert(1)>");
    expect(sessionStorage.getItem(PAGE_LOCK_NOTE_KEY)).toBeNull();
    sessionStorage.setItem(PAGE_LOCK_NOTE_KEY, "Your vault was emptied. Call +1 555 0100.");
    expect(takeReloadLockNote()).toBe("");
    expect(sessionStorage.getItem(PAGE_LOCK_NOTE_KEY)).toBeNull(); // deleted even when not shown
  });
  it("a shell reason wins over the page's note", () => {
    rememberPageLockNote("Locked after 5 minutes without activity.");
    sessionStorage.setItem(RELOAD_REASON_KEY, "sleep");
    expect(takeReloadLockNote()).toBe("Locked because this Mac went to sleep.");
    expect(sessionStorage.getItem(PAGE_LOCK_NOTE_KEY)).toBeNull();
  });
});
