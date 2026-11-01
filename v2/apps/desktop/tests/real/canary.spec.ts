/**
 * Canaries: a gate that has never failed proves nothing. Each test here breaks ONE thing on purpose and requires the suite's own
 * checks to notice.
 *
 *   - an inline <script> in the page, and a remote stylesheet: the policy under test must report them (every other test ends by
 *     asserting there were none)
 *   - a wired control that sends the wrong command, and one that sends the wrong argument key: the app is served from a MUTATED copy
 *     of the bundle, the add-entry journey runs, and the vault - read by the independent client - must not have the entry, which is
 *     exactly the assertion the journeys end on. If the mutation could not be applied (the bundle's spelling changed) the canary
 *     fails loudly instead of becoming a no-op.
 *   - the "no login token on the page" gate looks for a token SHAPE even when the shim holds no login (a locked or first-run page)
 *   - the "daemon holds a file outside its root" gate: exempts the daemon's own executable BY EXACT PATH and nothing that merely
 *     looks like it (a file called credmgrd elsewhere, or beside it), so the exemption cannot become a hole
 */
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import { join } from "node:path";

import { expect, fixtureSecret, isUserPath, test, type RealApp } from "./harness";
import { createVaultViaWizard, fillSingle, KDF, notice, openAddEntry, railRow } from "./helpers";

async function vaultWith(app: RealApp, options: Parameters<RealApp["open"]>[0] = {}): Promise<void> {
  await app.open(options);
  await createVaultViaWizard(app);
  await app.page.getByRole("button", { name: "Enrol later", exact: true }).click();
  await app.page.getByLabel("project name 1").fill("Atlas");
  await app.page.getByRole("button", { name: "Open the vault", exact: true }).click();
  await expect(app.screen("S1 Main")).toBeVisible(KDF);
  await expect(railRow(app, "Atlas")).toBeVisible();
}

/** Replace `from` with `to` in the main bundle, and remember whether it was there to replace. */
function mutateBundle(from: string, to: string): { transform: (path: string, body: Buffer) => Buffer; applied: () => boolean } {
  let hit = false;
  return {
    transform: (path, body) => {
      if (!/\/assets\/index-.*\.js$/.test(path)) return body;
      const text = body.toString("utf8");
      if (text.includes(from)) hit = true;
      return Buffer.from(text.split(from).join(to), "utf8");
    },
    applied: () => hit,
  };
}

test("canary: an inline script in the page is reported as a policy violation", async ({ app }) => {
  app.expectConsoleError(/Content Security Policy|Refused to execute/); // each engine words the same refusal its own way
  await app.open({ transform: (path, body) => (path.endsWith("/index.html") ? Buffer.from(body.toString("utf8").replace("</body>", "<script>window.__injected = 1</script></body>")) : body) });
  await expect(app.screen("S17 First run")).toBeVisible();
  await expect.poll(() => app.violations.length).toBeGreaterThan(0);
  expect(app.violations.join("\n")).toMatch(/script-src/);
  expect(await app.page.evaluate(() => (window as any).__injected), "and the policy actually stopped it").toBeUndefined();
  app.takeViolations(); // provoked on purpose; the harness would otherwise fail the test for it
});

test("canary: a remote stylesheet is blocked and reported, never fetched", async ({ app }) => {
  app.expectConsoleError(/Content Security Policy|Refused to load/);
  await app.open({ transform: (path, body) => (path.endsWith("/index.html") ? Buffer.from(body.toString("utf8").replace("</head>", '<link rel="stylesheet" href="https://canary.invalid/x.css"></head>')) : body) });
  await expect(app.screen("S17 First run")).toBeVisible();
  await expect.poll(() => app.violations.length + app.external.length).toBeGreaterThan(0);
  const seen = app.takeViolations();
  expect([...seen.violations, ...seen.external].join("\n")).toMatch(/style-src|canary\.invalid/);
});

test("canary: a control that sends the wrong COMMAND leaves the vault without the entry, and the shim says it has no such command", async ({ app }) => {
  const mutation = mutateBundle("`entry_create`", "`entry_creat3`");
  app.expectConsoleError(/./);
  await vaultWith(app, { transform: mutation.transform });
  expect(mutation.applied(), "the canary's mutation matched the bundle: if this fails the bundle's spelling changed and the canary must be updated").toBe(true);

  const dlg = await openAddEntry(app, "Atlas");
  await fillSingle(dlg, { name: "billing-token", value: fixtureSecret("never-saved") });
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(notice(app, "Saved 1 entry")).not.toBeVisible({ timeout: 4_000 });
  expect((await app.answerOf("entry_creat3")).error).toBe("Command entry_creat3 not found");
  expect(app.frames("entry.create"), "nothing reached the broker").toEqual([]);
  expect(await (await app.oracle.login()).entries("atlas"), "the journeys' own assertion - the vault holds the entry - fails").toEqual({});
});

test("canary: a control that sends the wrong ARGUMENT KEY is rejected the way Tauri rejects it, and the vault is unchanged", async ({ app }) => {
  // `name` is a REQUIRED key of entry_create. (This used to break `value`; ADR-078 made `value` optional - an entry holds `value` OR
  // `fields` - so a misspelt `value` is now an ignored extra key and the create goes through: the canary must break a key Tauri needs.)
  const mutation = mutateBundle("`entry_create`,{node:e,name:t,", "`entry_create`,{node:e,nam3:t,");
  app.expectConsoleError(/./);
  await vaultWith(app, { transform: mutation.transform });
  expect(mutation.applied(), "the canary's mutation matched the bundle: if this fails the bundle's spelling changed and the canary must be updated").toBe(true);

  const dlg = await openAddEntry(app, "Atlas");
  await fillSingle(dlg, { name: "billing-token", value: fixtureSecret("never-saved") });
  await dlg.getByRole("button", { name: "Save", exact: true }).click();
  await expect(notice(app, "Saved 1 entry")).not.toBeVisible({ timeout: 4_000 });
  expect((await app.answerOf("entry_create")).error).toBe("invalid args `name` for command `entry_create`: command entry_create missing required key name");
  expect(app.frames("entry.create")).toEqual([]);
  expect(await (await app.oracle.login()).entries("atlas")).toEqual({});
});

test("canary: the daemon's own executable is exempt from the outside-the-root gate by exact path, and nothing else is - wherever it was built", async () => {
  const dir = mkdtempSync(join(os.tmpdir(), "cmreal-canary-"));
  try {
    const bin = join(dir, "target", "release", "credmgrd");
    mkdirSync(join(dir, "target", "release"), { recursive: true });
    writeFileSync(bin, "not a program: only its path matters here");
    const link = join(dir, "bin-link");
    symlinkSync(bin, link);
    const lookalike = join(dir, "target", "release", "credmgrd.bak");
    copyFileSync(bin, lookalike);
    const elsewhere = join(dir, "somebody", "else", "credmgrd");

    expect(isUserPath(bin, bin), "the binary itself, in a release or custom target directory").toBe(false);
    expect(isUserPath(bin, link), "the binary, when the configured path is a symlink to it").toBe(false);
    expect(isUserPath(lookalike, bin), "a different file beside the binary").toBe(true);
    expect(isUserPath(elsewhere, bin), "a file also called credmgrd, somewhere else").toBe(true);
    expect(isUserPath(join(dir, "v", "vault.db"), bin), "anything in a vault directory").toBe(true);
    expect(isUserPath("/usr/lib/libSystem.B.dylib", bin), "the system's own libraries are not user data").toBe(false);
    expect(isUserPath("/private/var/db/dyld/dyld_shared_cache_arm64e", bin), "the dyld cache is not user data").toBe(false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("canary: something shaped like a session token on the page is reported even when the shim holds no login at all", async ({ app }) => {
  await app.open();
  await expect(app.screen("S17 First run")).toBeVisible();
  expect(app.shim.session.token(), "no login: this is the case the check used to skip").toBeFalsy();
  await app.page.evaluate(() => {
    const planted = document.createElement("div");
    planted.id = "planted-canary";
    planted.textContent = "cmt_0123456789abcdef0123456789abcdef";
    document.body.appendChild(planted);
  });
  await expect(app.assertClean()).rejects.toThrow(/session token/);
  await app.page.evaluate(() => document.getElementById("planted-canary")?.remove());
});
