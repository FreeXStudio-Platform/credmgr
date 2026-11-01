// `npm run test:design` runs the design team's own audit probe.  It used to read the probe from an export outside the repository and
// to EXIT 0 when there was none, so on a fresh clone the gate never ran and "green" meant nothing.  Now the probe is a committed
// file, its digest is checked against design-upstream/PROVENANCE.md, and every missing input is an error.  Each refusal below is
// proven by running the real script (a child process) or its loader against a directory that lacks the thing.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { isPublicTree, loadCommittedProbe, recordedProbeSha, resolveProbe, snapshotDirs } from "../../scripts/verify-design-audit.mjs";

const ROOT = resolve(__dirname, "../..");
const SCRIPT = join(ROOT, "scripts/verify-design-audit.mjs");
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

const PROBE = "/* a probe */ window.__probe = function () {};\n";
const row = (disposition: string, raw = sha("raw bytes")) => `| 27 | \`audit-probe.js\` | 7434 | \`${raw}\` | ${disposition} |`;

let work: string;
beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), "credmgr-audit-"));
});
afterAll(() => rmSync(work, { recursive: true, force: true }));

/** A throwaway app root with a snapshot, a probe and a PROVENANCE record that agree - then a test breaks exactly one thing. */
function fixtureRoot(name: string, opts: { probe?: string | null; provenance?: string | null; snapshot?: boolean } = {}): string {
  const root = join(work, name);
  const probe = opts.probe === undefined ? PROBE : opts.probe;
  if (opts.snapshot !== false) {
    const dir = join(root, "design-upstream", "2026-10-02");
    mkdirSync(dir, { recursive: true });
    if (probe !== null) writeFileSync(join(dir, "audit-probe.js"), probe);
  }
  const provenance = opts.provenance === undefined ? `# p\n\n${row("**committed** (byte-identical to the raw download)", sha(PROBE))}\n` : opts.provenance;
  if (provenance !== null) {
    mkdirSync(join(root, "design-upstream"), { recursive: true });
    writeFileSync(join(root, "design-upstream", "PROVENANCE.md"), provenance);
  }
  return root;
}

describe("recordedProbeSha (what PROVENANCE.md says the committed probe is)", () => {
  it("is the raw digest for a byte-identical row, and the sanitized digest when the importer changed something", () => {
    const raw = sha("a");
    const clean = sha("b");
    expect(recordedProbeSha(row("**committed** (byte-identical to the raw download)", raw))).toBe(raw);
    expect(recordedProbeSha(row(`**committed**; sanitized -> \`${clean}\` (123 B)`, raw))).toBe(clean);
  });

  it("is null for a row that does not say committed, or has no digest, and for no row at all", () => {
    expect(recordedProbeSha(row("checksum only"))).toBeNull();
    expect(recordedProbeSha(row("**committed**"))).toBeNull(); // committed, but with no way to tell which bytes
    expect(recordedProbeSha("# nothing here")).toBeNull();
    expect(recordedProbeSha(`| 3 | \`audit-suite.js\` | 1 | \`${sha("x")}\` | **committed** (byte-identical to the raw download) |`)).toBeNull(); // another file's row
  });
});

describe("loadCommittedProbe", () => {
  it.skipIf(isPublicTree(ROOT))("accepts the probe this repository commits: it exists, and its digest is the one PROVENANCE.md records", () => {
    const r = loadCommittedProbe(ROOT);
    expect(r).toMatchObject({ ok: true });
    if (!r.ok) throw new Error(r.why);
    expect(r.source).toContain("window.__probe"); // the function the gate calls in every state
    expect(r.sha).toBe(sha(readFileSync(join(snapshotDirs(ROOT).at(-1)!, "audit-probe.js"))));
    expect(readFileSync(join(ROOT, "design-upstream", "PROVENANCE.md"), "utf8")).toContain(`\`${r.sha}\``);
    expect(snapshotDirs(ROOT).length).toBeGreaterThan(0);
  });

  it("accepts a consistent throwaway root (so the refusals below are each about one broken thing)", () => {
    expect(loadCommittedProbe(fixtureRoot("good"))).toMatchObject({ ok: true });
  });

  it("refuses a repository with no design snapshot at all", () => {
    const r = loadCommittedProbe(fixtureRoot("no-snapshot", { snapshot: false }));
    expect(r).toMatchObject({ ok: false });
    expect((r as { why: string }).why).toMatch(/no design snapshot/);
  });

  it("refuses a snapshot without the probe, and says the probe is a committed file and that the gate does not skip", () => {
    const r = loadCommittedProbe(fixtureRoot("no-probe", { probe: null }));
    expect(r).toMatchObject({ ok: false });
    expect((r as { why: string }).why).toMatch(/audit-probe\.js is missing/);
    expect((r as { why: string }).why).toMatch(/COMMITTED/);
    expect((r as { why: string }).why).toMatch(/does not skip/);
  });

  it("refuses a probe with no PROVENANCE record, and a record that does not mark it committed", () => {
    expect(loadCommittedProbe(fixtureRoot("no-prov", { provenance: null }))).toMatchObject({ ok: false });
    const r = loadCommittedProbe(fixtureRoot("prov-checksum-only", { provenance: row("checksum only") }));
    expect(r).toMatchObject({ ok: false });
    expect((r as { why: string }).why).toMatch(/no row marking audit-probe\.js as committed/);
  });

  it("refuses a probe that was changed after it was recorded (the digest is the guard)", () => {
    const r = loadCommittedProbe(fixtureRoot("tampered", { probe: PROBE + "window.__probe = function () { return { dead: [], nolab: [], ovf: [], squash: [], low: [] }; };\n" }));
    expect(r).toMatchObject({ ok: false });
    expect((r as { why: string }).why).toMatch(/changed or replaced/);
  });

  it("looks in the NEWEST snapshot, so a newer design drop without a probe is an error, not a fallback to the old one", () => {
    const root = fixtureRoot("newer");
    mkdirSync(join(root, "design-upstream", "2026-11-01"), { recursive: true }); // a newer drop, no probe in it
    const r = loadCommittedProbe(root);
    expect(r).toMatchObject({ ok: false });
    expect((r as { why: string }).why).toContain("2026-11-01");
  });
});

describe("the script itself never skips", () => {
  const run = (args: string[], env: Record<string, string> = {}) => {
    const r = spawnSync(process.execPath, [SCRIPT, ...args], { env: { ...process.env, ...env }, encoding: "utf8", timeout: 60_000 });
    return { code: r.status, out: `${r.stdout}${r.stderr}` };
  };

  it("exits non-zero, says FAILED, and does not say SKIPPED, when the probe is missing - whatever the environment holds", () => {
    const root = fixtureRoot("script-no-probe", { probe: null });
    const envs: Array<Record<string, string>> = [{}, { DESIGN_EXPORT_DIR: join(work, "somewhere-else") }, { DESIGN_EXPORT_DIR: "" }];
    for (const env of envs) {
      const r = run(["--root", root], env);
      expect(r.code, JSON.stringify(env)).toBe(2);
      expect(r.out).toContain("verify-design-audit: FAILED");
      expect(r.out).not.toMatch(/skipped/i);
    }
  });

  it("exits non-zero when the probe is fine but the build it audits is missing", () => {
    const r = run(["--root", fixtureRoot("script-no-build")]);
    expect(r.code).toBe(2);
    expect(r.out).toContain("build-test/ is missing");
    expect(r.out).not.toMatch(/skipped/i);
  });

  it("exits non-zero on an engine it does not know", () => {
    const root = fixtureRoot("script-bad-engine");
    mkdirSync(join(root, "build-test"), { recursive: true });
    writeFileSync(join(root, "build-test", "index.html"), "<!doctype html>");
    const r = run(["--root", root, "--engine", "netscape"]);
    expect(r.code).toBe(2);
    expect(r.out).toContain('unknown engine "netscape"');
  });

  it("has no skip path in the private repository: the only way past a missing probe is the public-tree marker", () => {
    const source = readFileSync(SCRIPT, "utf8");
    expect(source).not.toMatch(/console\.log\([^)]*SKIP/i);
    expect(source).not.toMatch(/return 0;\s*\n\s*}\s*\n\s*const probePath/); // the old early return
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as { scripts: Record<string, string> };
    expect(pkg.scripts["test:design"]).toContain("build:test"); // it builds what it audits, like test:e2e
    expect(pkg.scripts["test:design"]).not.toContain("DESIGN_EXPORT_DIR");
  });

  it.skipIf(isPublicTree(ROOT))("the private repository has no marker and commits the probe", () => {
    expect(isPublicTree(ROOT)).toBe(false); // so the strict rule applies to it
    expect(existsSync(join(ROOT, "design-upstream", "2026-10-18", "audit-probe.js"))).toBe(true);
  });
});

describe("resolveProbe: the public tree does not carry the probe (it is not licensed for redistribution)", () => {
  // The probe is absent from the exported tree (tools/public-export/manifest/denylist.txt).  In a public tree the gate is dev-only.
  it("a private repository (no marker) with no probe is still an error, even if DESIGN_EXPORT_DIR is set", () => {
    const root = fixtureRoot("res-private", { probe: null });
    const other = join(work, "res-private-export");
    mkdirSync(other, { recursive: true });
    writeFileSync(join(other, "audit-probe.js"), PROBE);
    const r = resolveProbe(root, { env: { DESIGN_EXPORT_DIR: other }, publicTree: false });
    expect(r).toMatchObject({ ok: false });
    expect((r as { devOnly?: boolean }).devOnly).toBeUndefined();
  });

  it("a public tree with no probe and no DESIGN_EXPORT_DIR says it is a development-only gate, and says what to set", () => {
    const r = resolveProbe(fixtureRoot("res-public-none", { probe: null }), { env: {}, publicTree: true });
    expect(r).toMatchObject({ ok: false, devOnly: true });
    expect((r as { why: string }).why).toMatch(/DESIGN_EXPORT_DIR/);
    expect((r as { why: string }).why).toMatch(/development-only/);
  });

  it("a public tree with DESIGN_EXPORT_DIR runs the probe from there, after the same digest check", () => {
    const root = fixtureRoot("res-public-dir", { probe: null });
    const dir = join(work, "res-public-dir-export");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "audit-probe.js"), PROBE);
    expect(resolveProbe(root, { env: { DESIGN_EXPORT_DIR: dir }, publicTree: true })).toMatchObject({ ok: true, sha: sha(PROBE) });
    writeFileSync(join(dir, "audit-probe.js"), PROBE + "// edited\n");
    const bad = resolveProbe(root, { env: { DESIGN_EXPORT_DIR: dir }, publicTree: true });
    expect(bad).toMatchObject({ ok: false });
    expect((bad as { why: string }).why).toMatch(/was changed or replaced/);
  });

  it("a public tree whose DESIGN_EXPORT_DIR is wrong is an error, not a quiet skip", () => {
    const r = resolveProbe(fixtureRoot("res-public-wrong", { probe: null }), { env: { DESIGN_EXPORT_DIR: join(work, "nowhere") }, publicTree: true });
    expect(r).toMatchObject({ ok: false });
    expect((r as { devOnly?: boolean }).devOnly).toBeUndefined();
  });

  it("the script itself exits 0 and says NOT RUN in a public tree without the probe", () => {
    // a public tree is <repo>/v2/apps/desktop with <repo>/.public-export beside v2
    const repo = join(work, "pub-repo");
    const app = join(repo, "v2", "apps", "desktop");
    mkdirSync(join(app, "design-upstream", "2026-10-02"), { recursive: true });
    writeFileSync(join(repo, ".public-export"), "marker\n");
    writeFileSync(join(app, "design-upstream", "PROVENANCE.md"), `# p\n\n${row("**committed** (byte-identical to the raw download)", sha(PROBE))}\n`);
    const r = spawnSync(process.execPath, [SCRIPT, "--root", app], { encoding: "utf8", env: { ...process.env, DESIGN_EXPORT_DIR: "" } });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("NOT RUN");
    expect(r.stdout).toContain("DESIGN_EXPORT_DIR");
  });
});
