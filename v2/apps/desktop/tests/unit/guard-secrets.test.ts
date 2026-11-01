// The repository's secret guard (v2/scripts/guard-no-secrets.mjs) and the sealed extras pack (ADR-082).
//
// The pack is ~650 characters of base64 ciphertext inside the app, and a long unbroken base64 run is what a wrapped key looks like, so the
// guard has a rule for it.  The pack is allowed BY NAME (a function called extrasBlob that returns the pack's JSON, or a `credmgr-allow`
// comment above it), never by length: a canary of the same size anywhere else must still fail.  Each case below runs the real guard in a
// throwaway git repository with the file staged.
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

const GUARD = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../scripts/guard-no-secrets.mjs");
const work = mkdtempSync(join(tmpdir(), "guard-secrets-"));
afterAll(() => rmSync(work, { recursive: true, force: true }));

const b64 = (n: number) => randomBytes(n).toString("base64");
const blobJson = () => `{"v":1,"it":200000,"salt":"${b64(16)}","iv":"${b64(12)}","d":"${b64(480)}"}`;

/** Stage `files` in a fresh repository and run the guard on the staged set. */
function guard(name: string, files: Record<string, string>): { status: number | null; out: string } {
  const dir = join(work, name);
  const run = (cmd: string, args: string[]) => spawnSync(cmd, args, { cwd: dir, encoding: "utf8" });
  spawnSync("mkdir", ["-p", dir]);
  run("git", ["init", "-q"]);
  for (const [f, text] of Object.entries(files)) {
    writeFileSync(join(dir, f), text);
    run("git", ["add", f]);
  }
  const r = run(process.execPath, [GUARD]);
  return { status: r.status, out: r.stdout + r.stderr };
}

describe("the sealed extras pack and the base64-blob rule", () => {
  it("allows the pack where it is carried verbatim: a function named extrasBlob returning its JSON", () => {
    const r = guard("verbatim", { "app.logic.js": `  extrasBlob(){return '${blobJson()}';} // sealed\n` });
    expect(r.out).toContain("clean");
    expect(r.status).toBe(0);
  });

  it("allows it behind a credmgr-allow comment that says why (the app's own copy)", () => {
    const r = guard("allow-comment", { "extras.js": `// credmgr-allow: ciphertext only, no key material\nconst REAL_BLOB = '${blobJson()}';\n` });
    expect(r.status).toBe(0);
  });

  it("still fails the same bytes anywhere else: a canary with the pack's size and entropy is a finding", () => {
    for (const [name, line] of [
      ["canary-const", `const KEY_MATERIAL = '${blobJson()}';\n`],
      ["canary-other-function", `  otherBlob(){return '${blobJson()}';}\n`],
      ["canary-bare", `${b64(480)}\n`],
      ["canary-comment-too-far", `// credmgr-allow: nowhere near\n\n\n\n\n\n\nconst X = '${b64(480)}';\n`],
    ] as const) {
      const r = guard(name, { "leak.js": line });
      expect(r.status, name).toBe(1);
      expect(r.out, name).toContain("base64-blob");
      expect(r.out, name).not.toContain(b64(8)); // and the value is never printed
    }
  });

  it("does not fire on ordinary base64-looking text: a short token, a hash, a path", () => {
    const r = guard("ordinary", { "ok.js": `const h = '${b64(32)}';\nconst p = "/usr/local/share/${"abcdefghij".repeat(10)}";\n` });
    expect(r.status).toBe(0);
  });
});
