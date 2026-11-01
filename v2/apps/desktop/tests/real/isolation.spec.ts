/**
 * What this suite is allowed to touch, proved from the outside (the kernel's and the OS's answers, not the harness's own claims):
 *
 *   - the daemon runs in a sealed environment: its vault, its state and its HOME are inside a fresh temp root, and nothing of the
 *     developer's environment (no real home, no token) reached it
 *   - every file and socket it holds open is inside that root; it holds no TCP or UDP socket at all
 *   - this test process (which runs the shim) listens on no port either
 *   - the root is deleted when the test is over
 *
 * The developer's real vault paths are never opened, listed or read by anything here. What guarantees it is the daemon's
 * environment, built from scratch with every location it reads pointed inside the root (the first step below, read back from the
 * kernel with `ps -E`); `lsof` is a point-in-time CHECK on top of that (what is open at the moment it runs), not the proof by itself.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import os from "node:os";
import { basename, join } from "node:path";

import { Daemon } from "./daemon.mjs";
import { expect, fixtureSecret, heldOutsideRoot, test } from "./harness";
import { addEntry, createVaultViaWizard, finishWizardBare } from "./helpers";

test("the daemon is sealed into its throwaway root: environment, open files, sockets - and no network socket anywhere", async ({ app }) => {
  await app.open();
  await createVaultViaWizard(app);
  await finishWizardBare(app);
  await addEntry(app, "Global", { name: "isolation-probe", value: fixtureSecret("isolation") });
  await app.restartDaemon(); // a restart must not change any of this
  const d = app.daemon;
  const pid = d.pid!;

  await test.step("its environment was built from scratch", async () => {
    const r = spawnSync("/bin/ps", ["-wwE", "-p", String(pid), "-o", "command="], { encoding: "utf8" });
    expect(r.status, `ps could not read the daemon's environment: ${r.stderr}`).toBe(0);
    // `command=` is the executable's path followed by the environment (`ps -E`): judge the environment, not where the binary lives
    const at = r.stdout.indexOf(" PATH=");
    expect(at, "ps printed an environment").toBeGreaterThan(0);
    const env = r.stdout.slice(at);
    expect(env).toContain(`CREDMGR_VAULT_DIR=${d.vaultDir}`);
    expect(env).toContain(`CREDMGR_STATE_DIR=${d.stateDir}`);
    expect(env).toContain(`HOME=${d.homeDir}`);
    expect(env, "no inherited token").not.toMatch(/CREDMGR_TOKEN=/);
    expect(env, "the developer's real home is nowhere in it").not.toContain(`HOME=${os.homedir()}`);
    expect(env).not.toContain(`${os.homedir()}/Library`);
    expect(env).not.toContain(`${os.homedir()}/Desktop`);
  });

  await test.step("every file, directory and socket the daemon holds is inside the root", async () => {
    const held = d.openPaths();
    const real = (p: string) => p.replace(/^\/private/, "");
    const mine = held.filter((h) => real(h.name).startsWith(real(d.root)));
    expect(mine.some((h) => real(h.name) === real(d.socketPath)), "it holds its Unix socket").toBe(true);
    // the same judgement the end of every test makes: nothing a user could own is held outside the root (the system's libraries and
    // the daemon's own executable, by exact path, are the only exemptions)
    expect(heldOutsideRoot(d), "something outside the throwaway root").toEqual([]);
  });

  await test.step("no network socket: not the daemon's, not this test process's", async () => {
    expect(d.networkSockets()).toEqual([]);
    const mine = spawnSync("/usr/sbin/lsof", ["-nP", "-a", "-p", String(process.pid), "-i"], { encoding: "utf8" });
    const listening = mine.stdout.split("\n").filter((l) => /LISTEN|UDP/.test(l));
    expect(listening, "this process listens on a port").toEqual([]);
    // the only transport the shim has is a Unix socket path
    expect(app.shim.socketPath).toBe(d.socketPath);
    expect(app.shim.socketPath.startsWith(d.root)).toBe(true);
  });

  await test.step("the root holds only what the harness and the broker put there", async () => {
    expect(readdirSync(d.root).sort()).toEqual(["credmgrd.log", "h", "s", "tmp", "v", "work"].sort());
    expect(readdirSync(d.homeDir), "the daemon wrote nothing into its throwaway HOME").toEqual([]);
  });
});

test("the throwaway root is deleted when its daemon is disposed, and refuses to delete anything that is not a root it made", async () => {
  const d = await Daemon.start();
  const root = d.root;
  expect(basename(root).startsWith("cmreal-")).toBe(true);
  expect(existsSync(d.socketPath)).toBe(true);
  await d.dispose();
  expect(existsSync(root)).toBe(false);

  const impostor = new Daemon(join(os.tmpdir(), "not-a-cmreal-root"));
  await expect(impostor.dispose()).rejects.toThrow(/refusing to delete/);
});
