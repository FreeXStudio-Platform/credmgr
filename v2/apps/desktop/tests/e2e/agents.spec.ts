/**
 * ADR-140 and ADR-143: Settings -> Agents (connect a coding assistant) and the node's security level.
 *
 * The shell is the fixture broker (tests/fixtures/broker/admin.js), which models src-tauri/src/agents.rs: it "reads" five assistants'
 * config files, draws a diff, and writes only when the token from the plan is sent back from the dialog's Write button.
 */
import { expect, test, type App } from "./harness";
import { notice, selectNode } from "./wp-c-util";
import { openSettings } from "./wp-d-helpers";
import { railRow } from "./wp-b-helpers";

async function open(app: App) {
  const broker = (await app.open({ broker: { locked: false } }))!;
  await expect(app.screen("S1 Main")).toBeVisible();
  return broker;
}

const section = (app: App) => app.screen("S21 Agents");
const row = (app: App, client: string) => app.page.locator(`[data-agent-row="${client}"]`);
const dialog = (app: App) => app.page.getByRole("dialog", { name: /connect|disconnect/i });

test("the Agents section lists what the shell found, in plain words", async ({ app }) => {
  await open(app);
  await openSettings(app, "Agents");
  await expect(section(app)).toBeVisible();
  await expect(row(app, "cursor")).toContainText("not connected");
  await expect(row(app, "claude-desktop")).toContainText("connected");
  await expect(row(app, "vscode")).toContainText("not found");
  await expect(row(app, "windsurf")).toContainText("unreadable");
  await expect(row(app, "windsurf")).toContainText("not valid JSON");
  // Claude Code's state file is never edited: a command to copy, and no Connect button.
  await expect(row(app, "claude-code").getByRole("button", { name: /Connect/ })).toHaveCount(0);
  await expect(row(app, "claude-code").getByRole("button", { name: /copy the command for Claude Code/ })).toHaveText("Copy command");
  // Only a found, unconnected assistant can be connected; only a connected one can be disconnected.
  await expect(row(app, "cursor").getByRole("button", { name: /review connecting Cursor/ })).toBeVisible();
  await expect(row(app, "claude-desktop").getByRole("button", { name: /review disconnecting/ })).toBeVisible();
  await expect(row(app, "vscode").getByRole("button", { name: /review connecting/ })).toHaveCount(0);
  await expect(row(app, "windsurf").getByRole("button", { name: /review connecting/ })).toHaveCount(0);
  app.assertClean();
});

test("copying hands the exact configuration to the shell's clipboard, and writes nothing", async ({ app }) => {
  const broker = await open(app);
  await openSettings(app, "Agents");
  await row(app, "cursor").getByRole("button", { name: /copy the configuration/ }).click();
  await expect(row(app, "cursor").getByRole("button", { name: /copy the configuration/ })).toHaveText("copied ✓");
  const copied = (await broker.calls("copy_text")).map((c) => (c.args as any).text as string);
  expect(copied).toHaveLength(1);
  expect(JSON.parse(copied[0]).mcpServers.credmgr).toEqual({ command: "/opt/homebrew/bin/credmgr", args: ["mcp"] });
  await row(app, "claude-code").getByRole("button", { name: /copy the command/ }).click();
  const second = (await broker.calls("copy_text")).map((c) => (c.args as any).text as string);
  expect(second[1]).toBe("claude mcp add --scope user credmgr -- /opt/homebrew/bin/credmgr mcp");
  expect(await broker.calls("agent_apply")).toEqual([]);
  app.assertClean();
});

test("Connect shows the change first; Cancel writes nothing; Write writes once with the token it was shown", async ({ app }) => {
  const broker = await open(app);
  await openSettings(app, "Agents");

  await row(app, "cursor").getByRole("button", { name: /review connecting Cursor/ }).click();
  await expect(dialog(app)).toBeVisible();
  const diff = app.page.locator("[data-agent-diff]");
  await expect(diff).toContainText('"credmgr": {');
  await expect(diff).toContainText("/opt/homebrew/bin/credmgr");
  await expect(dialog(app)).toContainText("Everything else in the file stays exactly as it is");
  await expect(dialog(app)).toContainText("mcp.json.credmgr-backup-");
  expect(await broker.calls("agent_apply")).toEqual([]); // looking is not doing

  await app.page.locator("[data-agent-cancel]").click();
  await expect(dialog(app)).toHaveCount(0);
  expect(await broker.calls("agent_apply")).toEqual([]);

  await row(app, "cursor").getByRole("button", { name: /review connecting Cursor/ }).click();
  await app.page.locator("[data-agent-write]").click();
  await expect(dialog(app)).toHaveCount(0);
  expect(await broker.calls("agent_apply")).toEqual([
    { cmd: "agent_apply", args: { client: "cursor", action: "connect", token: "tok-cursor-connect-ready" } },
  ]);
  await expect(notice(app)).toContainText("Cursor is connected");
  await expect(notice(app)).toContainText("Restart it");
  await expect(row(app, "cursor")).toContainText("connected");
  await expect(row(app, "cursor").getByRole("button", { name: /review disconnecting Cursor/ })).toBeVisible();
  app.assertClean();
});

test("if the file moved after the diff was drawn, nothing is written and the person is told", async ({ app }) => {
  const broker = await open(app);
  await openSettings(app, "Agents");
  await row(app, "cursor").getByRole("button", { name: /review connecting Cursor/ }).click();
  await broker.set({ agentMoved: true });
  await app.page.locator("[data-agent-write]").click();
  await expect(dialog(app)).toHaveCount(0);
  await expect(notice(app)).toContainText("changed since the diff was shown");
  await expect(row(app, "cursor")).toContainText("not connected");
  app.assertClean();
});

test("the vault prompt is built from the selected node's names and level, never a value", async ({ app }) => {
  const broker = await open(app);
  await selectNode(app, "atlas");
  await openSettings(app, "Agents");
  await section(app).getByRole("button", { name: "Copy prompt" }).click();
  const prompts = await broker.calls("agent_prompt");
  expect(prompts).toHaveLength(1);
  const a = prompts[0].args as any;
  expect(a.node).toBe("atlas");
  expect(a.reachable).toContain("global");
  expect(a.level).toBe("guarded");
  expect(a.format).toBe("prompt");
  app.assertClean();
});

test("a node's security level: the inspector says it in consequences, raising is one click, lowering needs Touch ID", async ({ app }) => {
  const broker = await open(app);
  await selectNode(app, "atlas");
  const panel = app.screen("S4a Security level");
  await expect(panel).toBeVisible();
  await expect(panel.getByRole("button", { name: "Guarded" })).toHaveAttribute("aria-pressed", "true");
  await expect(panel.locator("[data-lvl-caption]")).toContainText("a high or critical value waits for your one-tap approval");

  // ADR-152: the strictest level reads "Strict" for people; the word "seal" stays with sealing a node into Orphaned.
  await expect(panel.getByRole("button", { name: "Strict" })).toBeVisible();
  await expect(panel.getByRole("button", { name: /sealed/i })).toHaveCount(0);
  await expect(panel).not.toContainText(/sealed/i);
  await panel.getByRole("button", { name: "Strict" }).click();
  await expect(notice(app)).toContainText("Security level is now strict");
  expect((await broker.calls("node_policy")).map((c) => (c.args as any).policy)).toEqual([{ securityLevel: "sealed" }]);
  await expect(panel.getByRole("button", { name: "Strict" })).toHaveAttribute("aria-pressed", "true");
  await expect(panel.locator("[data-lvl-caption]")).toContainText("Every value waits for your approval");

  // Lowering widens what an agent may do: the broker wants presence, the app says so and the level does not change.
  await panel.getByRole("button", { name: "Open" }).click();
  await expect(notice(app)).toContainText("Needs Touch ID");
  await expect(panel.getByRole("button", { name: "Strict" })).toHaveAttribute("aria-pressed", "true");
  app.assertClean();
});

test("ADR-152: the level reads Strict, and sealing a node into Orphaned keeps the word Seal", async ({ app }) => {
  await open(app);
  await selectNode(app, "atlas");
  const panel = app.screen("S4a Security level");
  await expect(panel.getByRole("button")).toHaveText(["Open", "Guarded", "Strict"]);
  await expect(panel).not.toContainText(/sealed/i);
  await railRow(app, "beacon").click({ button: "right" });
  await app.page.getByRole("button", { name: "Remove node…", exact: true }).click();
  const dlg = app.screen("S9 Seal node");
  await expect(dlg).toBeVisible();
  await expect(dlg.getByRole("button", { name: "Seal node" })).toBeVisible();
  await expect(dlg).toContainText("ORPHANED");
  await expect(dlg).not.toContainText(/strict/i);
});
