// The other write-then-re-read actions (the node lock, unlock and rename, the grants, the doctor): when the broker did the work and
// only the re-read failed, they resolve with the answer and `readbackError` - they do not throw, because a throw reads as "the write
// failed" and the screen would say "Nothing was changed".  (The entry, tray, node and seal actions: tests/unit/write-actions.test.ts.)
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/lib/bridge", () => ({
  vaultNodeLock: vi.fn(),
  vaultNodeUnlock: vi.fn(),
  nodeUpdate: vi.fn(),
  grantCreate: vi.fn(),
  grantRevoke: vi.fn(),
  maintenanceDoctor: vi.fn(),
  getVersion: vi.fn(),
  isBridgeError: (e: unknown) => typeof e === "object" && e !== null && "code" in e && "source" in e && "message" in e,
}));

import * as bridge from "../../src/lib/bridge";
import * as admin from "../../src/vault/actions/admin";
import * as read from "../../src/vault/actions/read";

const b = bridge as unknown as Record<string, ReturnType<typeof vi.fn>>;
const unreachable = { source: "transport", code: "broker_unreachable", message: "broker_unreachable" };

function fakeModel(readFails: boolean) {
  return {
    kind: "bridge" as const,
    refresh: vi.fn(async () => {
      if (readFails) throw unreachable;
    }),
    wipeSecrets: vi.fn(),
  };
}
const asModel = (m: ReturnType<typeof fakeModel>) => m as unknown as Parameters<typeof read.lockNode>[0];

beforeEach(() => {
  for (const fn of Object.values(b)) if (typeof fn?.mockReset === "function") fn.mockReset();
});

describe("node lock, unlock and rename", () => {
  it("lock drops the revealed values, then reports a failed re-read on the answer", async () => {
    b.vaultNodeLock.mockResolvedValue({ node: "n", locked: true });
    const m = fakeModel(true);
    const r = await read.lockNode(asModel(m), "n");
    expect(r).toMatchObject({ node: "n", readbackError: unreachable });
    expect(m.wipeSecrets).toHaveBeenCalledTimes(1);
    expect(b.vaultNodeLock).toHaveBeenCalledTimes(1);
  });

  it("unlock and rename the same way", async () => {
    b.vaultNodeUnlock.mockResolvedValue({ node: "n", locked: false });
    b.nodeUpdate.mockResolvedValue({ node: "n", label: "New" });
    expect((await read.unlockNode(asModel(fakeModel(true)), "n")).readbackError).toBe(unreachable);
    expect((await read.renameNode(asModel(fakeModel(true)), "n", " New ")).readbackError).toBe(unreachable);
    expect(b.nodeUpdate).toHaveBeenCalledWith("n", "New");
  });

  it("when the re-read works there is no readbackError key at all, and a refusal still throws and re-reads nothing", async () => {
    b.vaultNodeLock.mockResolvedValue({ node: "n", locked: true });
    expect("readbackError" in (await read.lockNode(asModel(fakeModel(false)), "n"))).toBe(false);
    b.nodeUpdate.mockRejectedValue({ source: "broker", code: "malformed_request", message: "x" });
    const m = fakeModel(true);
    await expect(read.renameNode(asModel(m), "global", "x")).rejects.toMatchObject({ code: "malformed_request" });
    expect(m.refresh).not.toHaveBeenCalled();
  });
});

describe("grants and the doctor", () => {
  it("createGrant and revokeGrant", async () => {
    b.grantCreate.mockResolvedValue({ id: "g1" });
    b.grantRevoke.mockResolvedValue({ id: "g1", revoked: true });
    expect((await admin.createGrant(asModel(fakeModel(true)), "a", { kind: "node", nodeId: "b" }, ["read"], "because")).readbackError).toBe(unreachable);
    expect((await admin.revokeGrant(asModel(fakeModel(true)), "g1")).readbackError).toBe(unreachable);
    expect("readbackError" in (await admin.revokeGrant(asModel(fakeModel(false)), "g1"))).toBe(false);
  });

  it("runDoctor re-reads only when it applied a fix, and reports a failed re-read on the result", async () => {
    b.maintenanceDoctor.mockResolvedValue({ applied: true, fixCount: 2, fixes: [{ node: "n", type: "manifest" }], unfixable: [] });
    const failing = fakeModel(true);
    const r = await admin.runDoctor(asModel(failing), { apply: true });
    expect(r).toMatchObject({ applied: true, fixCount: 2, readbackError: unreachable });
    // a dry run changes nothing, so there is nothing to re-read and nothing to fail
    b.maintenanceDoctor.mockResolvedValue({ applied: false, fixCount: 2, fixes: [], unfixable: [] });
    const dry = fakeModel(true);
    const d = await admin.runDoctor(asModel(dry), { apply: false });
    expect(dry.refresh).not.toHaveBeenCalled();
    expect("readbackError" in d).toBe(false);
  });
});
