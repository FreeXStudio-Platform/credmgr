// ADR-164, the desktop half: the "Agent tokens" section of Settings > Agents and its Issue dialog.  The logic runs through the real
// bridge client against the fixture broker (tests/fixtures/broker/agent_tokens.js), with the shell's `invoke` wrapped so the command names
// and argument keys the real bridge sends are the ones asserted here.  The token never reaches the page: the shell (and the fixture,
// which answers as the shell does) puts it on the concealed clipboard and answers `copied`, so no answer, state or render holds it.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { expiresIn, TOKEN_CAPS, TOKEN_EXPIRIES, utcMinute } from "../../src/design/logic/agents.js";
import Component from "../../src/design/logic/core.js";
import { redactTokens } from "../../src/vault/actions/admin";
import { brokerScript } from "../fixtures/broker/script.mjs";

const ROOT = resolve(__dirname, "../..");
const read = (rel: string) => readFileSync(resolve(ROOT, rel), "utf8");
const g = globalThis as unknown as { window?: any };

interface Call {
  cmd: string;
  args: Record<string, unknown>;
}

function fixture(options: Record<string, unknown> = {}) {
  const win: any = {};
  g.window = win;
  new Function("window", brokerScript({ locked: false, ...options }))(win);
  const calls: Call[] = [];
  const failNext: Record<string, string> = {};
  const inner = win.__TAURI_INTERNALS__.invoke;
  win.__TAURI_INTERNALS__.invoke = async (cmd: string, args: Record<string, unknown> = {}) => {
    calls.push({ cmd, args: JSON.parse(JSON.stringify(args)) });
    if (failNext[cmd]) {
      const code = failNext[cmd];
      delete failNext[cmd];
      throw { source: "broker", code, message: code };
    }
    return inner(cmd, args);
  };
  return { win, calls, failNext };
}

const flush = async (n = 6) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0));
};

/** A logic instance on Settings > Agents with the vault open.  `touchId` makes the fixture's Touch ID prompt succeed. */
async function agentsScreen(options: Record<string, unknown> = { touchId: true }) {
  const fx = fixture(options);
  const logic: any = new (Component as any)({ mode: "pro" });
  logic.__host = {
    setLogicState(update: any, cb?: () => void) {
      const patch = typeof update === "function" ? update(logic.state) : update;
      if (patch) logic.state = { ...logic.state, ...patch };
      cb?.();
    },
    forceUpdate() {},
  };
  const notes: [string, string][] = [];
  logic.notify = (k: string, t: string) => notes.push([k, t]);
  logic.focusLater = () => {};
  await logic.model.boot();
  logic.state = { ...logic.state, screen: "app", selected: "atlas", overlay: "settings", setSection: "agents", dialog: null };
  await logic.loadAgentTokens();
  await flush();
  return { logic, notes, ...fx };
}

const tokenCalls = (calls: Call[]) => calls.filter((c) => c.cmd.startsWith("agent_token_"));
const vals = (logic: any) => logic.renderVals();

afterEach(() => {
  delete g.window;
});

describe("helpers", () => {
  it("prints times in UTC to the minute and the time left in words", () => {
    expect(utcMinute(Date.UTC(2026, 10, 14, 9, 5) / 1000)).toBe("2026-11-14 09:05 UTC");
    expect(utcMinute(NaN as unknown as number)).toBe("");
    expect(expiresIn(1000, 1000)).toBe("expired");
    expect(expiresIn(1000 + 600, 1000)).toBe("in 10 min");
    expect(expiresIn(1000 + 3 * 3600, 1000)).toBe("in 3 h");
    expect(expiresIn(1000 + 6 * 86400, 1000)).toBe("in 6 days");
  });
  it("offers only the five agent capabilities and expiries within the broker's bounds", () => {
    expect(TOKEN_CAPS.map((c) => c.id)).toEqual(["list", "read", "reveal", "create", "update"]);
    for (const x of TOKEN_EXPIRIES) expect(x.secs >= 60 && x.secs <= 604800).toBe(true);
  });
  it("redacts an agent token as it redacts a login in anything shown from a record", () => {
    expect(redactTokens("actor cma_0123456789abcdef0123 did it")).toBe("actor [redacted-token] did it");
    expect(redactTokens("cmt_deadbeefdeadbeef")).toBe("[redacted-token]");
  });
});

describe("the list", () => {
  it("reads agent_token_status once when the section loads and says when none is live", async () => {
    const { logic, calls } = await agentsScreen();
    expect(tokenCalls(calls)).toEqual([{ cmd: "agent_token_status", args: {} }]);
    const v = vals(logic);
    expect(v.atEmpty).toBe(true);
    expect(v.atRows).toEqual([]);
    expect(v.atCount).toBe("0 of 32 live");
  });

  it("lists a token's label, node, capabilities, expiry and use, and never a secret", async () => {
    const { logic, win } = await agentsScreen();
    win.__brokerFixture.handlers.agent_token_issue({ node: "atlas", label: "api agent", capabilities: ["list", "read"] });
    await logic.loadAgentTokens();
    const v = vals(logic);
    expect(v.atRows).toHaveLength(1);
    const row = v.atRows[0];
    expect(row.label).toBe("api agent");
    expect(row.node).toBe("atlas");
    expect(row.caps).toBe("list, read");
    expect(row.expires).toMatch(/^expires in (23|24) h · \d{4}-\d\d-\d\d \d\d:\d\d UTC$/);
    expect(row.used).toBe("never used");
    expect(JSON.stringify(logic.state.atList)).not.toMatch(/cma_/);
  });

  it("says a refusal in words instead of showing an empty list", async () => {
    const { logic, failNext } = await agentsScreen();
    failNext.agent_token_status = "capability_not_held";
    await logic.loadAgentTokens();
    const v = vals(logic);
    expect(v.atErrShow).toBe(true);
    expect(v.atErr).toBe("Only your own login can see agent tokens.");
    expect(v.atEmpty).toBe(false);
  });
});

describe("issuing", () => {
  it("opens on the selected node with list and read ticked and one day, and sends exactly what the form says", async () => {
    const { logic, calls } = await agentsScreen();
    logic.openAgentTokenDlg();
    let v = vals(logic);
    expect(v.dlgAgentToken).toBe(true);
    expect(v.atFormShow).toBe(true);
    expect(v.atNodeVal).toBe("atlas");
    expect(v.atNodes.map((n: any) => n.id)).not.toContain("orphaned");
    expect(v.atCaps.filter((c: any) => c.on).map((c: any) => c.id)).toEqual(["list", "read"]);
    expect(v.atExpiresVal).toBe("86400");
    v.onAtLabel({ target: { value: "  claude on api  " } });
    vals(logic).atCaps.find((c: any) => c.id === "reveal").toggle();
    vals(logic).onAtExpires({ target: { value: "28800" } });
    calls.length = 0;
    await vals(logic).issueAgentToken();
    await flush();
    expect(tokenCalls(calls)[0]).toEqual({
      cmd: "agent_token_issue",
      args: { node: "atlas", label: "claude on api", capabilities: ["list", "read", "reveal"], expiresIn: 28800 },
    });
    v = vals(logic);
    expect(v.atFormShow).toBe(false);
    expect(v.atIssuedShow).toBe(true);
    expect(v.atIssuedWhat).toContain("on node atlas: list, read, reveal");
    expect(v.atCopiedShow).toBe(true);
    expect(v.atCopiedText).toContain("CREDMGR_AGENT_TOKEN within 30 seconds");
    expect(v.atNotCopiedShow).toBe(false);
    // the list is read again and shows the new token
    expect(tokenCalls(calls).map((c) => c.cmd)).toContain("agent_token_status");
    expect(v.atRows).toHaveLength(1);
  });

  it("never holds the token: it is on the concealed clipboard, not in the answer, the state or the render", async () => {
    const { logic, win } = await agentsScreen();
    logic.openAgentTokenDlg();
    vals(logic).onAtLabel({ target: { value: "agent" } });
    await logic.issueAgentToken();
    const pasted = win.__brokerFixture.pasteboard;
    expect(pasted.concealed).toBe(true);
    expect(pasted.value).toMatch(/^cma_[0-9a-f]{64}$/);
    const rendered = JSON.stringify(vals(logic), (_k, x) => (typeof x === "function" ? undefined : x));
    expect(rendered).not.toContain(pasted.value);
    expect(rendered).not.toMatch(/cma_/);
    expect(JSON.stringify(logic.state)).not.toMatch(/cma_/);
  });

  // ADR-164 review P2-6: the test above passes even if the page kept the whole answer, because the fixture (like the shell)
  // never puts the token in it.  Here the answer does carry a token-shaped value, as a broken shell would: the page must
  // take only the fields it shows, so the value reaches neither its state nor its render.
  it("keeps nothing but the fields it shows, even when an answer carries a token", async () => {
    const leaked = "cma_" + "5e".repeat(32);
    const { logic, win } = await agentsScreen();
    const handlers = win.__brokerFixture.handlers;
    const real = handlers.agent_token_issue;
    handlers.agent_token_issue = (a: any) => ({ ...real(a), token: leaked, shownOnce: true });
    // The fixture does leak, so this test can fail: the raw answer carries the value.
    const raw = await win.__TAURI_INTERNALS__.invoke("agent_token_issue", { node: "atlas", label: "probe", capabilities: ["list"], expiresIn: null });
    expect(raw.token).toBe(leaked);
    logic.openAgentTokenDlg();
    vals(logic).onAtLabel({ target: { value: "agent" } });
    await logic.issueAgentToken();
    await flush();
    expect(vals(logic).atIssuedShow).toBe(true);
    const rendered = JSON.stringify(vals(logic), (_k, x) => (typeof x === "function" ? undefined : x));
    expect(rendered).not.toContain(leaked);
    expect(JSON.stringify(logic.state)).not.toContain(leaked);
  });

  it("the shell keeps a token it could not copy or revoke and revokes it at the next unlock, and the dialog says so", async () => {
    const { logic, win } = await agentsScreen();
    const issue = win.__brokerFixture.handlers.agent_token_issue;
    win.__brokerFixture.handlers.agent_token_issue = (a: any) => {
      const r = issue(a);
      delete r.clearAfterSeconds;
      return { ...r, copied: false, revoked: false, revokePending: true };
    };
    logic.openAgentTokenDlg();
    vals(logic).onAtLabel({ target: { value: "agent three" } });
    await logic.issueAgentToken();
    const v = vals(logic);
    expect(v.atNotCopiedShow).toBe(true);
    expect(v.atNotCopiedText).toMatch(/will revoke “agent three” as soon as you unlock/);
  });

  it("offers no Global: the broker issues a token only for a project", async () => {
    const { logic, calls } = await agentsScreen();
    logic.state = { ...logic.state, selected: "global" };
    logic.openAgentTokenDlg();
    const v = vals(logic);
    expect(v.atNodes.map((n: any) => n.id)).not.toContain("global");
    expect(v.atNodeVal).not.toBe("global");
    calls.length = 0;
    await expect((globalThis as any).window.__TAURI_INTERNALS__.invoke("agent_token_issue", { node: "global", label: "x", capabilities: ["list"], expiresIn: null })).rejects.toMatchObject({ code: "malformed_request" });
  });

  it("a token the clipboard could not take is revoked by the shell, and the dialog says so", async () => {
    const { logic, win } = await agentsScreen();
    const issue = win.__brokerFixture.handlers.agent_token_issue;
    win.__brokerFixture.handlers.agent_token_issue = (a: any) => {
      const r = issue(a);
      delete r.clearAfterSeconds;
      return { ...r, copied: false, revoked: true };
    };
    logic.openAgentTokenDlg();
    vals(logic).onAtLabel({ target: { value: "agent" } });
    await logic.issueAgentToken();
    let v = vals(logic);
    expect(v.atCopiedShow).toBe(false);
    expect(v.atNotCopiedShow).toBe(true);
    expect(v.atNotCopiedText).toMatch(/has been revoked/);
    win.__brokerFixture.handlers.agent_token_issue = (a: any) => ({ ...issue(a), copied: false, revoked: false });
    vals(logic).closeAgentToken();
    logic.openAgentTokenDlg();
    vals(logic).onAtLabel({ target: { value: "agent two" } });
    await logic.issueAgentToken();
    v = vals(logic);
    expect(v.atNotCopiedText).toMatch(/Revoke “agent two” from the list now/);
  });

  it("checks the form before any call: a node, a name, at least one capability", async () => {
    const { logic, calls } = await agentsScreen();
    logic.openAgentTokenDlg();
    calls.length = 0;
    await logic.issueAgentToken();
    expect(vals(logic).atFormErr).toBe("Name the agent that will hold the token.");
    vals(logic).onAtLabel({ target: { value: "agent" } });
    for (const id of ["list", "read"]) vals(logic).atCaps.find((c: any) => c.id === id).toggle();
    await logic.issueAgentToken();
    expect(vals(logic).atFormErr).toBe("Tick at least one thing the agent may do.");
    expect(tokenCalls(calls)).toEqual([]);
  });

  it("without Touch ID the broker refuses, nothing is shown and the presence notice explains", async () => {
    const { logic, notes, win } = await agentsScreen({});
    logic.openAgentTokenDlg();
    vals(logic).onAtLabel({ target: { value: "agent" } });
    await logic.issueAgentToken();
    await flush();
    const v = vals(logic);
    expect(v.atIssuedShow).toBe(false);
    expect(win.__brokerFixture.pasteboard).toBeFalsy();
    expect(notes.some(([k, t]) => k === "presence" && t.includes("agent.token_issue"))).toBe(true);
  });

  it("a capability the node does not give agents is refused in the dialog's own words", async () => {
    const { logic, win } = await agentsScreen();
    win.__brokerFixture.node("atlas").policy = { agentAccess: "read-only" };
    logic.openAgentTokenDlg();
    vals(logic).onAtLabel({ target: { value: "agent" } });
    vals(logic).atCaps.find((c: any) => c.id === "update").toggle();
    await logic.issueAgentToken();
    const v = vals(logic);
    expect(v.atIssuedShow).toBe(false);
    expect(v.atFormErr).toMatch(/agent access/);
  });

  it("makes no clipboard call of its own: the shell already copied the token", async () => {
    const { logic, calls } = await agentsScreen();
    logic.openAgentTokenDlg();
    vals(logic).onAtLabel({ target: { value: "agent" } });
    calls.length = 0;
    await logic.issueAgentToken();
    await flush();
    expect(calls.filter((c) => /copy/.test(c.cmd))).toEqual([]);
  });

  it("drops the dialog's state when it closes, by Done or by any other way", async () => {
    const { logic } = await agentsScreen();
    logic.openAgentTokenDlg();
    vals(logic).onAtLabel({ target: { value: "agent" } });
    await logic.issueAgentToken();
    expect(logic.state.atIssued.copied).toBe(true);
    vals(logic).closeAgentToken();
    expect(logic.state.atIssued).toBeNull();
    expect(logic.state.atForm).toBeNull();

    // Escape (or a lock) clears `dialog` without the dialog's own handler: the next render wipes the token.
    logic.openAgentTokenDlg();
    vals(logic).onAtLabel({ target: { value: "agent two" } });
    await logic.issueAgentToken();
    expect(logic.state.atIssued).toBeTruthy();
    logic.state = { ...logic.state, dialog: null };
    vals(logic);
    await flush();
    expect(logic.state.atIssued).toBeNull();
    expect(logic.state.atForm).toBeNull();
  });
});

describe("revoking", () => {
  it("sends one agent_token_revoke with the id, says so, and reads the list again", async () => {
    const { logic, calls, notes, win } = await agentsScreen();
    const made = win.__brokerFixture.handlers.agent_token_issue({ node: "atlas", label: "old agent", capabilities: ["list"] });
    await logic.loadAgentTokens();
    calls.length = 0;
    await vals(logic).atRows[0].revoke();
    await flush();
    expect(tokenCalls(calls)).toEqual([
      { cmd: "agent_token_revoke", args: { id: made.id } },
      { cmd: "agent_token_status", args: {} },
    ]);
    expect(notes).toContainEqual(["success", "Revoked “old agent”. The next request with it is refused."]);
    expect(vals(logic).atRows).toEqual([]);
  });

  it("a token that had already ended is said plainly", async () => {
    const { logic, notes, win, failNext } = await agentsScreen();
    win.__brokerFixture.handlers.agent_token_issue({ node: "atlas", label: "gone", capabilities: ["list"] });
    await logic.loadAgentTokens();
    failNext.agent_token_revoke = "not_found";
    await vals(logic).atRows[0].revoke();
    expect(notes).toContainEqual(["info", "That token had already ended."]);
  });
});

describe("the templates", () => {
  it("the section and the dialog are wired, the dialog is included before Settings, and the scrim does not close it", () => {
    const section = read("src/design/screens/S21-agents.html");
    expect(section).toContain('data-screen-label="S21c Agent tokens"');
    expect(section).toContain("{{openAgentToken}}");
    const dlg = read("src/design/screens/dlg-agent-token.html");
    expect(dlg).toContain("{{atCopiedText}}");
    expect(dlg).toContain("{{atNotCopiedText}}");
    expect(dlg).not.toMatch(/atToken|copyAgentToken/);
    expect(dlg).not.toContain("{{scrimClose}}");
    const app = read("src/design/app.template.html");
    expect(app.indexOf("dlg-agent-token.html")).toBeGreaterThan(-1);
    expect(app.indexOf("dlg-agent-token.html")).toBeLessThan(app.indexOf("S12-settings.html"));
  });
});
