// scripts/dc/import.mjs turns a design export into the committed, sanitized snapshot.  It is the ONLY place the maintainer's
// real project names can be stopped (the repository guards are structural and cannot see a name), so it must fail CLOSED:
// no name map, or a map that replaces nothing, means exit non-zero and nothing written.  A first version warned and exited 0.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { refusal, sanitize } from "../../scripts/dc/import.mjs";

const SCRIPT = resolve(__dirname, "../../scripts/dc/import.mjs");
const ALLOWLIST = [
  "CredMgr App.dc.html",
  "audit-probe.js",
  "assets/keep.css",
  "assets/keep-components.css",
  ...["inter-latin-400", "inter-latin-500", "inter-latin-600", "inter-latin-700", "inter-tight-latin-600", "inter-tight-latin-700", "jetbrains-mono-latin-400", "jetbrains-mono-latin-500", "jetbrains-mono-latin-600", "jetbrains-mono-latin-700"].map((n) => `assets/fonts/${n}.woff2`),
];
// Built from pieces so this test file never contains a contiguous private-key header (the secret gate would refuse it).
const PEM = "-----BEGIN " + "OPENSSH PRIVATE KEY-----";
// Likewise a real-looking mail domain is assembled at run time (the personal-data guard refuses one written out).
const REAL_DOMAIN = "brand" + ".org";

let work: string;
let exportDir: string;

beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), "credmgr-import-"));
  exportDir = join(work, "export");
  for (const rel of ALLOWLIST) {
    const p = join(exportDir, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, rel.endsWith(".dc.html") ? appFile() : rel === "audit-probe.js" ? probeFile() : "x");
  }
});
afterAll(() => rmSync(work, { recursive: true, force: true }));

function appFile(): string {
  return [
    "<x-dc>",
    "  <p>node zq-fixture-proj lives under ~/projects/zq-fixture-proj</p>",
    `  <textarea placeholder="${PEM}"></textarea>`,
    "  <p>Free for personal and individual use. Organisational or commercial use requires a paid licence, scoped to one major version. See LICENSE.</p>",
    `  <p>mail billing@${REAL_DOMAIN}</p>`,
    "</x-dc>",
    "<script>class Component { sealedPack(){return 1;} }</script>",
  ].join("\n");
}

/** The design's audit probe: a plain script. This one has a key header in a comment and a contactable address, to prove it goes through the sanitizer. */
function probeFile(): string {
  return ["/* dev tool */", `// ${PEM}`, `// mail billing@${REAL_DOMAIN}`, "window.__probe = function () {};"].join("\n");
}

function run(args: string[], env: Record<string, string> = {}) {
  const clean: NodeJS.ProcessEnv = { ...process.env };
  delete clean.DC_SANITIZE_MAP;
  delete clean.DC_SANITIZE_MAP_FILE;
  const r = spawnSync(process.execPath, [SCRIPT, ...args], { env: { ...clean, ...env }, encoding: "utf8" });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

describe("import.mjs fails closed", () => {
  it("refuses without a name map: exit non-zero, nothing written", () => {
    const root = join(work, "out-nomap");
    const r = run([exportDir, "--date", "2099-01-01", "--root", root]);
    expect(r.code).toBe(1);
    expect(r.err).toContain("REFUSED");
    expect(r.err).toContain("no project-name map");
    expect(existsSync(root)).toBe(false);
  });

  it("refuses a map that replaces nothing: exit non-zero, nothing written", () => {
    const root = join(work, "out-stale");
    const r = run([exportDir, "--date", "2099-01-01", "--root", root], { DC_SANITIZE_MAP: "name-not-in-the-export=neutral" });
    expect(r.code).toBe(1);
    expect(r.err).toContain("replaced nothing");
    expect(existsSync(root)).toBe(false);
  });

  it("refuses a DC_SANITIZE_MAP_FILE that does not exist", () => {
    const root = join(work, "out-nofile");
    const r = run([exportDir, "--date", "2099-01-01", "--root", root], { DC_SANITIZE_MAP_FILE: join(work, "no-such-map") });
    expect(r.code).not.toBe(0);
    expect(existsSync(root)).toBe(false);
  });

  it("refuses an export that lacks an allowlisted file", () => {
    const partial = join(work, "partial");
    mkdirSync(partial, { recursive: true });
    writeFileSync(join(partial, "CredMgr App.dc.html"), appFile());
    const root = join(work, "out-partial");
    const r = run([partial, "--date", "2099-01-01", "--root", root], { DC_SANITIZE_MAP: "zq-fixture-proj=neutral" });
    expect(r.code).toBe(1);
    expect(r.err).toContain("missing allowlisted files");
    expect(existsSync(root)).toBe(false);
  });

  it("runs with a map that replaces something, and the written file is sanitized", () => {
    const root = join(work, "out-ok");
    const r = run([exportDir, "--date", "2099-01-01", "--root", root], { DC_SANITIZE_MAP: "zq-fixture-proj=neutral" });
    expect(r.err).toBe("");
    expect(r.code).toBe(0);
    const text = readFileSync(join(root, "design-upstream", "2099-01-01", "CredMgr App.dc.html"), "utf8");
    expect(text).not.toContain("zq-fixture-proj");
    expect(text).toContain("neutral");
    expect(text).not.toContain(PEM);
    expect(text).toContain("-----BEGIN EXAMPLE KEY-----");
    expect(text).not.toContain("paid licence");
    expect(text).toContain("Source-available; see LICENSE for the terms.");
    expect(r.out).toContain("0 unlock-code value(s)");
    expect(text).not.toContain(REAL_DOMAIN);
  });

  it("brings the audit probe in through the sanitizer, and records its digests (the design gate reads it from the repository, never from an export)", () => {
    const root = join(work, "out-probe");
    const r = run([exportDir, "--date", "2099-01-01", "--root", root], { DC_SANITIZE_MAP: "zq-fixture-proj=neutral" });
    expect(r.code).toBe(0);
    const probe = readFileSync(join(root, "design-upstream", "2099-01-01", "audit-probe.js"), "utf8");
    expect(probe).toContain("window.__probe");
    expect(probe).not.toContain(PEM);
    expect(probe).toContain("-----BEGIN EXAMPLE KEY-----");
    expect(probe).not.toContain(REAL_DOMAIN);
    // the printed record says it was sanitized and gives the digest of what was committed
    const line = r.out.split("\n").find((l) => l.includes("`audit-probe.js`"));
    expect(line).toBeDefined();
    expect(line).toContain("**committed**");
    expect(line).toMatch(/sanitized -> `[0-9a-f]{64}`/);
  });

  it("an export without the audit probe is refused like one without the app file (the gate that needs it must never find it missing)", () => {
    const partial = join(work, "no-probe-export");
    mkdirSync(partial, { recursive: true });
    for (const rel of ALLOWLIST.filter((a) => a !== "audit-probe.js")) {
      const p = join(partial, rel);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, rel.endsWith(".dc.html") ? appFile() : "x");
    }
    const root = join(work, "out-no-probe");
    const r = run([partial, "--date", "2099-01-01", "--root", root], { DC_SANITIZE_MAP: "zq-fixture-proj=neutral" });
    expect(r.code).toBe(1);
    expect(r.err).toContain("audit-probe.js");
    expect(existsSync(root)).toBe(false);
  });

  it("refuses an export that reintroduces the old unlock-code function: exit non-zero, nothing written", () => {
    const bad = join(work, "export-bad");
    for (const rel of ALLOWLIST) {
      const p = join(bad, rel);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, rel.endsWith(".dc.html") ? appFile() + "\n<script>donateUnlockCodeVal(){return 'X';}</script>" : rel === "audit-probe.js" ? probeFile() : "x");
    }
    const root = join(work, "out-refused-code");
    const r = run([bad, "--date", "2099-01-01", "--root", root], { DC_SANITIZE_MAP: "zq-fixture-proj=neutral" });
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/unlock-code/);
    expect(existsSync(join(root, "design-upstream", "2099-01-01"))).toBe(false);
  });

  it("--no-name-map is the one explicit way past the gate, and says so", () => {
    const root = join(work, "out-explicit");
    const r = run([exportDir, "--date", "2099-01-01", "--root", root, "--no-name-map"]);
    expect(r.code).toBe(0);
    expect(r.err).toContain("NOT replaced");
    expect(r.out).toContain("NO name map was used");
  });
});

describe("refusal()", () => {
  it("is null only when the import may proceed", () => {
    expect(refusal({ pairs: [["a", "b"]], noNameMap: false, nameTokens: 3, missing: [] })).toBeNull();
    expect(refusal({ pairs: [], noNameMap: true, nameTokens: 0, missing: [] })).toBeNull();
    expect(refusal({ pairs: [], noNameMap: false, nameTokens: 0, missing: [] })).toMatch(/REFUSED/);
    expect(refusal({ pairs: [["a", "b"]], noNameMap: false, nameTokens: 0, missing: [] })).toMatch(/REFUSED/);
    expect(refusal({ pairs: [["a", "b"]], noNameMap: false, nameTokens: 2, missing: ["x"] })).toMatch(/missing/);
    expect(refusal({ pairs: [["a", "b"]], noNameMap: false, nameTokens: 3, missing: [], unlockCodes: 1 })).toMatch(/unlock-code/);
  });
});

describe("sanitize()", () => {
  it("replaces the licence sentence pair, whichever way the paragraph is split", () => {
    const a = sanitize("<p>Free for personal and individual use. Organisational or commercial use requires a paid licence, scoped to one major version. See LICENSE.</p>", []);
    expect(a.text).toBe("<p>Source-available; see LICENSE for the terms. See LICENSE.</p>");
    expect(a.counts.licence).toBe(1);
    const b = sanitize("<p>Commercial use requires a paid license.</p>", []);
    expect(b.text).toBe("<p>Source-available; see LICENSE for the terms.</p>");
  });

  it("moves an IPv4 address that is not a documentation, loopback or link-local constant into 203.0.113.0/24, keeping the last octet", () => {
    // Addresses are assembled at run time: the personal-data guard refuses a routable one written out in a tracked file.
    const ip = (...o: number[]) => o.join(".");
    const input = `a '${ip(10, 0, 0, 4)}' b ${ip(192, 168, 1, 20)} c ${ip(203, 0, 113, 9)} d ${ip(127, 0, 0, 1)} e ${ip(198, 51, 100, 7)} f ${ip(0, 0, 0, 0)} g ${ip(2, 0, 0, 1)}.5 h ${ip(300, 1, 1, 1)}`;
    const r = sanitize(input, []);
    expect(r.text).toBe(`a '${ip(203, 0, 113, 4)}' b ${ip(203, 0, 113, 20)} c ${ip(203, 0, 113, 9)} d ${ip(127, 0, 0, 1)} e ${ip(198, 51, 100, 7)} f ${ip(0, 0, 0, 0)} g ${ip(2, 0, 0, 1)}.5 h ${ip(300, 1, 1, 1)}`);
    expect(r.counts.ipv4).toBe(2);
  });

  it("counts, and never rewrites, a shared unlock code: zero for the sealed design, a hit for the old function or an all-caps constant", () => {
    expect(sanitize("class C { sealedPack(){return 1;} }", []).counts.unlockCode).toBe(0);
    expect(sanitize("donateUnlockCodeVal(){return 'ABC';}", []).counts.unlockCode).toBe(1);
    expect(sanitize("const supporterCode = 'ABCDEFGHIJKLMN';", []).counts.unlockCode).toBe(1);
    expect(sanitize("const label = 'ABCDEFGHIJKLMN';", []).counts.unlockCode).toBe(0);
    // nothing is rewritten: the refusal is the control
    expect(sanitize("donateUnlockCodeVal(){return 'ABC';}", []).text).toBe("donateUnlockCodeVal(){return 'ABC';}");
  });

  it("turns every private-key armour line (all key types) into a non-key", () => {
    for (const kind of ["", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED "]) {
      const r = sanitize(`-----BEGIN ${kind}PRIVATE KEY-----\n-----END ${kind}PRIVATE KEY-----`, []);
      expect(r.text).toBe("-----BEGIN EXAMPLE KEY-----\n-----END EXAMPLE KEY-----");
      expect(r.counts.keyHeaders).toBe(2);
    }
  });

  it("leaves reserved-domain e-mail addresses alone and moves the rest to example.com", () => {
    expect(sanitize(`a@example.com b@x.test c@${REAL_DOMAIN}`, []).text).toBe("a@example.com b@x.test c@example.com");
  });

  it("replaces project names whole-word, case-matched", () => {
    const r = sanitize("Foo and foo and FOO and food", [["foo", "bar"]]);
    expect(r.text).toBe("Bar and bar and BAR and food");
    expect(r.counts.names).toBe(3);
  });
});
