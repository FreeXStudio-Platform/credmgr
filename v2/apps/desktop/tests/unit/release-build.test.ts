// A release build carries no demo vault and no fixture broker, and a page without the Tauri shell says so instead of inventing data.
//
// Three things are proven here, each so that it can go red:
//   1. every string the release gate bans really is in the code it names (so the ban list cannot rot into checking for nothing);
//   2. scripts/dc/verify-build.mjs fails a release bundle that contains one, and passes a clean one, and lets the TEST build keep them;
//   3. in a production-mode build `createModel()` has no demo source: with no shell the model is "broker-down", not a vault of examples.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

import { bannedModule, RELEASE_BANNED_MODULES, RELEASE_BANNED_TEXT, RELEASE_BANS, REQUIRED_WIRE } from "../../scripts/dc/release-bans.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const FONTS = [
  "inter-latin-400", "inter-latin-500", "inter-latin-600", "inter-latin-700", "inter-tight-latin-600", "inter-tight-latin-700",
  "jetbrains-mono-latin-400", "jetbrains-mono-latin-500", "jetbrains-mono-latin-600", "jetbrains-mono-latin-700",
];

/** A build directory that passes every check of verify-build.mjs, plus `extraJs`. */
function fakeBuild(extraJs = ""): string {
  const dir = mkdtempSync(join(tmpdir(), "credmgr-build-"));
  mkdirSync(join(dir, "assets"));
  writeFileSync(join(dir, "index.html"), '<!doctype html><html><head><script type="module" src="/assets/index-abc.js"></script></head><body><div id="dc-root"></div></body></html>');
  // the broker client's wire, as the typed client names it: a bundle without it would pass every ban (see REQUIRED_WIRE)
  writeFileSync(join(dir, "assets", "index-abc.js"), `console.log("app");\nvar wire = ${JSON.stringify(REQUIRED_WIRE)};\n${extraJs}`);
  for (const f of FONTS) writeFileSync(join(dir, "assets", `${f}-abc.woff2`), "x");
  return dir;
}

function verify(dir: string, ...flags: string[]) {
  const r = spawnSync(process.execPath, [join(ROOT, "scripts/dc/verify-build.mjs"), dir, ...flags], { encoding: "utf8" });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
}

const made: string[] = [];
const build = (js?: string) => {
  const d = fakeBuild(js);
  made.push(d);
  return d;
};
afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
  while (made.length) rmSync(made.pop() as string, { recursive: true, force: true });
});

describe("the release ban list", () => {
  it("names strings that are really in the code they stand for", () => {
    expect(RELEASE_BANS.length).toBeGreaterThanOrEqual(8);
    for (const { needle, where } of RELEASE_BANS) {
      for (const file of where) expect(readFileSync(join(ROOT, file), "utf8"), `${needle} in ${file}`).toContain(needle);
    }
  });
});

describe("scripts/dc/verify-build.mjs", () => {
  it("passes a clean release bundle", () => {
    const r = verify(build());
    expect(r.out).toContain("verify-build: ok");
    expect(r.code).toBe(0);
  });

  for (const { needle, what } of RELEASE_BANS) {
    it(`fails a release bundle that contains ${JSON.stringify(needle)} (${what})`, () => {
      const r = verify(build(`var leaked = ${JSON.stringify(needle)};`));
      expect(r.code).toBe(1);
      expect(r.out).toContain(`contains "${needle}"`);
    });
  }

  it("lets the TEST build keep them: the e2e specs and the design audit need the demo vault's strings in build-test/", () => {
    const r = verify(build(`var demo = ${JSON.stringify(RELEASE_BANS[0].needle)};`), "--test-build");
    expect(r.code).toBe(0);
  });
});

describe("the class of things a release must not contain (words, not just known strings)", () => {
  it("every banned word trips on its sample, so the list cannot rot into patterns that match nothing", () => {
    expect(RELEASE_BANNED_TEXT.length).toBeGreaterThanOrEqual(4);
    for (const { pattern, sample, what } of RELEASE_BANNED_TEXT) expect(sample, what).toMatch(pattern);
  });

  for (const { sample, what } of RELEASE_BANNED_TEXT) {
    it(`fails a release bundle that says ${what}`, () => {
      const r = verify(build(sample));
      expect(r.code).toBe(1);
      expect(r.out).toContain("must not be part of a release build");
    });
  }

  it("lets the TEST build say them (the e2e specs run on the example vault and the fixture broker)", () => {
    for (const { sample } of RELEASE_BANNED_TEXT) expect(verify(build(sample), "--test-build").code).toBe(0);
  });

  it("does not trip on ordinary words that merely resemble them", () => {
    expect(verify(build('var s = "demonstrate demolition fixtures-free";'.replace("fixtures-free", "settled"))).code).toBe(0);
  });
});

describe("the broker client is in every bundle", () => {
  for (const wire of REQUIRED_WIRE) {
    it(`fails a bundle that never names ${wire} (release and test alike)`, () => {
      const dir = build();
      const file = join(dir, "assets", "index-abc.js");
      writeFileSync(file, readFileSync(file, "utf8").replace(new RegExp(`"${wire}"`, "g"), '"renamed"'));
      for (const flags of [[], ["--test-build"]]) {
        const r = verify(dir, ...flags);
        expect(r.code, flags.join(" ")).toBe(1);
        expect(r.out).toContain(`never names the broker command ${wire}`);
      }
    });
  }
});

describe("bannedModule (what a release bundle may not import)", () => {
  it("names the demo vault, anything under tests/fixtures and the upstream snapshot, with either path separator", () => {
    for (const id of ["/w/apps/desktop/src/vault/demo-source.ts", "C:\\w\\apps\\desktop\\src\\vault\\demo-source.ts", "/w/apps/desktop/tests/fixtures/broker/core.js", "/w/apps/desktop/design-upstream/2026-10-02/extracted/app.logic.js"]) {
      expect(bannedModule(id), id).not.toBeNull();
    }
    expect(RELEASE_BANNED_MODULES.length).toBe(3);
  });

  it("lets the modules a release is made of through", () => {
    for (const id of ["/w/apps/desktop/src/vault/bridge-source.ts", "/w/apps/desktop/src/vault/no-shell-source.ts", "/w/apps/desktop/src/vault/model.ts", "/w/apps/desktop/src/lib/bridge.ts", "/w/node_modules/react/index.js", "\0dc:/w/apps/desktop/src/design/app.template.html.js"]) {
      expect(bannedModule(id), id).toBeNull();
    }
  });

  it("every banned path is one that really exists in this repository (the ban cannot rot into guarding a path nobody has)", () => {
    expect(existsSync(join(ROOT, "src/vault/demo-source.ts"))).toBe(true);
    expect(existsSync(join(ROOT, "tests/fixtures/broker/core.js"))).toBe(true);
    expect(existsSync(join(ROOT, "design-upstream/2026-10-02"))).toBe(true);
  });
});

// The artefact itself.  A green gate proves only what it checks, so these build the app for real, both ways, and look at what came out.
describe("a real build, both ways", () => {
  const viteBin = join(ROOT, "node_modules/vite/bin/vite.js");
  const buildTo = (out: string, mode: string, env: Record<string, string> = {}) =>
    spawnSync(process.execPath, [viteBin, "build", "--mode", mode, "--outDir", out, "--emptyOutDir"], { cwd: ROOT, env: { ...process.env, NODE_ENV: "production", ...env }, encoding: "utf8", timeout: 120_000 }); // vitest sets NODE_ENV=test, which would build React's development bundle
  const bundleText = (dir: string) => readFileSync(join(dir, "assets", readdirSync(join(dir, "assets")).find((f) => f.endsWith(".js")) as string), "utf8");

  it("a RELEASE build contains no mock, no fixture, no demo vault and no 'demo' model kind, imports neither module, and passes verify-build", () => {
    const out = mkdtempSync(join(tmpdir(), "credmgr-release-"));
    made.push(out);
    const r = buildTo(out, "production");
    expect(r.status, `${r.stdout}${r.stderr}`).toBe(0); // the plugin fails the build if a banned module is in any chunk
    const js = bundleText(out);
    // booleans, so a failure names the word and does not print the whole bundle
    for (const [re, name] of [[/mock/i, "mock"], [/fixture/i, "fixture"], [/browser preview/i, "browser preview"], [/[`"']demo[`"']/, "the 'demo' model kind"]] as const) expect(re.test(js), `the release bundle says ${name}`).toBe(false);
    for (const { needle } of RELEASE_BANS) expect(js.includes(needle), `the release bundle contains ${needle}`).toBe(false);
    for (const wire of REQUIRED_WIRE) expect(js.includes(wire), `the release bundle never names ${wire}`).toBe(true);
    const v = verify(out);
    expect(v.code, v.out).toBe(0);
    expect(v.out).toContain("no demo vault, no fixture broker, no mock of anything");
  }, 120_000);

  it("the TEST build does carry the demo vault (so the release's absence is a measurement, not a coincidence), and verify-build accepts it as one", () => {
    const out = mkdtempSync(join(tmpdir(), "credmgr-testbuild-"));
    made.push(out);
    const r = buildTo(out, "test");
    expect(r.status, `${r.stdout}${r.stderr}`).toBe(0);
    const js = bundleText(out);
    expect(js.includes("credmgr-demo-vault-marker"), "the test build carries the demo vault").toBe(true);
    expect(/[`"']demo[`"']/.test(js), "the test build carries the 'demo' model kind").toBe(true);
    const v = verify(out, "--test-build");
    expect(v.code, v.out).toBe(0);
    // and the same build REFUSED as a release, which is what the module check is for
    expect(verify(out).code).toBe(1);
  }, 120_000);

  it("the module check can fail: forced on for a build that carries the demo vault, the build stops and names the module", () => {
    const out = mkdtempSync(join(tmpdir(), "credmgr-forced-"));
    made.push(out);
    const r = buildTo(out, "test", { DC_ENFORCE_RELEASE_BANS: "1" });
    expect(r.status).not.toBe(0);
    expect(`${r.stdout}${r.stderr}`).toMatch(/release bundle must not contain: .*demo-source\.ts \(the in-memory demo vault\)/);
  }, 120_000);
});

describe("createModel() in a build that may not carry the demo vault", () => {
  it("has no demo source: with no Tauri shell the model is broker-down, never a vault of examples", async () => {
    vi.stubEnv("MODE", "production");
    vi.stubEnv("DEV", false);
    vi.resetModules();
    const { createModel } = await import("../../src/vault/index");
    const m = createModel();
    expect(m.kind).toBe("bridge");
    await m.boot();
    expect(m.status).toBe("broker-down");
    expect(m.view.nodes).toEqual([]);
    // and a lock attempt on it reports that the broker could not be told, rather than pretending
    expect(await m.lock()).toEqual({ confirmed: false, code: "broker_unreachable" });
  });

  it("in a test build (vitest, and build-test/) the demo vault is still there for the specs that want a page with no shell", async () => {
    const { createModel } = await import("../../src/vault/index");
    expect(createModel().kind).toBe("demo");
  });

  it("every model the shell talks through freezes its view, in every build", async () => {
    const { bridgeModelOptions } = await import("../../src/vault/index");
    expect(bridgeModelOptions().freezeView).toBe(true);
    vi.stubEnv("MODE", "production");
    expect(bridgeModelOptions().freezeView).toBe(true);
  });
});
