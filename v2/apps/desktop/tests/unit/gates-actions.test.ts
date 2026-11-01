// The 2026-10-25 design drop's controls, at the vault layer: Undo (entry.undo), Generate (util.generate), the second-factor step-up
// (vault.gate_verify from a logged-in session), a decision while locked (vault.approval_decide), privateNames and the doctor's purge.
// Each is one bridge call; what the screens show after it is what the broker said, never a copy this layer kept.
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/lib/bridge", () => ({
  vaultStatus: vi.fn(),
  vaultApprovalGet: vi.fn(),
  auditTail: vi.fn(),
  entryUndo: vi.fn(),
  utilGenerate: vi.fn(),
  vaultGateVerify: vi.fn(),
  vaultApprovalDecide: vi.fn(),
  maintenanceDoctor: vi.fn(),
  nodeCreate: vi.fn(),
  nodePolicy: vi.fn(),
  homeDir: vi.fn(),
  isBridgeError: (e: unknown) => typeof e === "object" && e !== null && "code" in e && "source" in e && "message" in e,
}));

import * as bridge from "../../src/lib/bridge";
import * as admin from "../../src/vault/actions/admin";
import * as session from "../../src/vault/actions/session";
import * as write from "../../src/vault/actions/write";
import { classifyError, NotWiredError } from "../../src/vault/errors";
import { mapNode } from "../../src/vault/bridge-source";
import { isUnreadableCode } from "../../src/vault/types";

const b = bridge as unknown as Record<string, ReturnType<typeof vi.fn>>;

function fakeModel(over: { kind?: string; generation?: Record<string, number> } = {}) {
  return {
    kind: over.kind ?? "bridge",
    generation: over.generation ?? { atlas: 7 },
    refresh: vi.fn(async () => {}),
    detail: vi.fn(() => undefined),
    dropEntrySecrets: vi.fn(),
  };
}
const asModel = (m: ReturnType<typeof fakeModel>) => m as unknown as Parameters<typeof write.undoFieldChange>[0];
const brokerError = (code: string, detail?: Record<string, unknown>) => ({ source: "broker", code, message: code, ...(detail ? { detail } : {}) });

beforeEach(() => {
  for (const fn of Object.values(b)) if (typeof fn?.mockReset === "function") fn.mockReset();
});

describe("Undo (entry.undo, ADR-086)", () => {
  it("takes the audit id from the change's own answer (the shell passes the broker envelope's `audit` through), never from the trail", () => {
    expect(write.auditOf({ node: "atlas", entry: "e1", generation: 8, audit: "a_new" })).toBe("a_new");
    expect(write.auditOf({ node: "atlas", generation: 8 })).toBeNull(); // the record could not be written: no Undo, nothing guessed
    expect(write.auditOf({ audit: "" })).toBeNull();
    expect(write.auditOf({ audit: 7 })).toBeNull();
    expect(write.auditOf(null)).toBeNull();
    expect(b.auditTail).not.toHaveBeenCalled();
  });

  it("undoes with the audit id and the node's CURRENT generation, returns the broker's words, then re-reads node, graph and entry", async () => {
    const answer = { ok: true, restored: { action: "field.remove", entry: "e1", fieldCount: 3 }, generation: 8, undoneToGeneration: 6 };
    b.entryUndo.mockResolvedValue(answer);
    const m = fakeModel();
    const r = await write.undoFieldChange(asModel(m), { node: "atlas", entry: "e1", audit: "a_new", text: "remove field" });
    expect(b.entryUndo).toHaveBeenCalledExactlyOnceWith("atlas", "a_new", 7);
    expect(r).toEqual(answer);
    expect(m.dropEntrySecrets).toHaveBeenCalledExactlyOnceWith("atlas", "e1"); // a value held from before the undo is the old one
    expect(m.refresh).toHaveBeenCalledExactlyOnceWith({ graph: true, nodes: ["atlas"], details: [{ node: "atlas", entry: "e1" }] });
  });

  it("a refusal (not_undoable after seven days, conflict) is thrown untouched and refreshes nothing", async () => {
    for (const code of ["not_undoable", "conflict", "not_found"]) {
      b.entryUndo.mockRejectedValue(brokerError(code));
      const m = fakeModel();
      await expect(write.undoFieldChange(asModel(m), { node: "atlas", entry: "e1", audit: "a", text: "edit" })).rejects.toMatchObject({ code });
      expect(m.refresh).not.toHaveBeenCalled();
    }
  });

  it("a failed re-read after a successful undo is reported on the answer, not thrown", async () => {
    b.entryUndo.mockResolvedValue({ ok: true, restored: { action: "field.add", entry: "e1", fieldCount: 2 }, generation: 8, undoneToGeneration: 6 });
    const m = fakeModel();
    m.refresh.mockRejectedValue(brokerError("broker_unreachable"));
    const r = await write.undoFieldChange(asModel(m), { node: "atlas", entry: "e1", audit: "a", text: "add field" });
    expect(r.ok).toBe(true);
    expect(r.readbackError).toMatchObject({ code: "broker_unreachable" });
  });

  it("not_undoable is routed as 'can no longer be undone', not as a crash", () => {
    expect(classifyError(brokerError("not_undoable"), { op: "entry.undo", node: "atlas", entry: "e1" })).toMatchObject({ route: "refresh", nodes: ["atlas"], message: "That can no longer be undone. Reloaded." });
  });
});

describe("Generate (util.generate, ADR-087)", () => {
  it("asks the broker, with the length clamped to 8..128; the value is the caller's to show masked", async () => {
    b.utilGenerate.mockResolvedValue({ value: "fixture-generated-x", length: 24, symbols: true, pronounceable: false, entropyBits: 140 });
    const g = await write.generatePassword(asModel(fakeModel()), 24, true, false);
    expect(b.utilGenerate).toHaveBeenCalledExactlyOnceWith(24, true, false);
    expect(g).toMatchObject({ length: 24, entropyBits: 140 });
    await write.generatePassword(asModel(fakeModel()), 3, false, true);
    expect(b.utilGenerate).toHaveBeenLastCalledWith(8, false, true);
    await write.generatePassword(asModel(fakeModel()), 9999, true, false);
    expect(b.utilGenerate).toHaveBeenLastCalledWith(128, true, false);
    await write.generatePassword(asModel(fakeModel()), Number.NaN, true, false);
    expect(b.utilGenerate).toHaveBeenLastCalledWith(20, true, false); // the broker's own default
  });

  it("is never made in the page: without a broker it refuses", async () => {
    await expect(write.generatePassword(asModel(fakeModel({ kind: "demo" })), 24, true, false)).rejects.toBeInstanceOf(NotWiredError);
    expect(b.utilGenerate).not.toHaveBeenCalled();
  });

  it("a refusal (no create/update capability) is thrown for the router", async () => {
    b.utilGenerate.mockRejectedValue(brokerError("capability_not_held"));
    await expect(write.generatePassword(asModel(fakeModel()), 24, true, false)).rejects.toMatchObject({ code: "capability_not_held" });
  });
});

describe("the second-factor step-up (ADR-085)", () => {
  it("sends the trimmed code as vault.gate_verify and resolves with the five-minute window", async () => {
    b.vaultGateVerify.mockResolvedValue({ locked: false, authenticated: true, initialized: true });
    expect(await session.stepUp(asModel(fakeModel()), " 123456 ")).toEqual({ expiresIn: 300 });
    expect(b.vaultGateVerify).toHaveBeenCalledExactlyOnceWith("123456");
  });

  it("reads the window from the answer when the broker gives one, and bounds it", async () => {
    b.vaultGateVerify.mockResolvedValue({ locked: false, expiresIn: 120 });
    expect(await session.stepUp(asModel(fakeModel()), "123456")).toEqual({ expiresIn: 120 });
    b.vaultGateVerify.mockResolvedValue({ locked: false, expiresIn: 10 ** 9 });
    expect((await session.stepUp(asModel(fakeModel()), "123456")).expiresIn).toBe(3600);
  });

  it("a vault that answers 'locked' took the login with it: vault_locked, so the router ends at the Lock screen", async () => {
    b.vaultGateVerify.mockResolvedValue({ locked: true, authenticated: false, initialized: true });
    await expect(session.stepUp(asModel(fakeModel()), "123456")).rejects.toMatchObject({ code: "vault_locked" });
  });

  it("a wrong code and a wait are inline messages for the dialog", async () => {
    b.vaultGateVerify.mockRejectedValue(brokerError("gate_verification_failed"));
    await expect(session.stepUp(asModel(fakeModel()), "000000")).rejects.toMatchObject({ code: "gate_verification_failed" });
    expect(classifyError(brokerError("gate_verification_failed"), { op: "vault.gate_verify", field: "code" })).toMatchObject({ route: "inline", message: "That code was not accepted." });
    expect(classifyError(brokerError("rate_limited", { retryAfterSeconds: 30 }), { op: "vault.gate_verify", field: "code" })).toMatchObject({ route: "inline", message: "Too many attempts. Try again in 30 s." });
  });

  it("is not available without a broker", async () => {
    await expect(session.stepUp(asModel(fakeModel({ kind: "demo" })), "123456")).rejects.toBeInstanceOf(NotWiredError);
    expect(b.vaultGateVerify).not.toHaveBeenCalled();
  });
});

describe("a decision while locked (vault.approval_decide, ADR-088)", () => {
  it("sends the request id, the decision, the passphrase and the code; resolves with what was decided and nothing else", async () => {
    b.vaultApprovalDecide.mockResolvedValue({ request: "rq_1", node: "atlas", entry: "e1", approved: true, authorisedBy: "factors" });
    const r = await session.decideApproval(asModel(fakeModel()), " rq_1 ", true, "pass phrase", " 123456 ");
    expect(b.vaultApprovalDecide).toHaveBeenCalledExactlyOnceWith("rq_1", true, "pass phrase", "123456");
    expect(r).toEqual({ request: "rq_1", approved: true }); // the node and the entry the broker named are not carried on
  });

  it("sends no code when there is none (no second factor enrolled)", async () => {
    b.vaultApprovalDecide.mockResolvedValue({ request: "rq_1", node: "atlas", entry: "e1", approved: false, authorisedBy: "factors" });
    await session.decideApproval(asModel(fakeModel()), "rq_1", false, "p", "");
    expect(b.vaultApprovalDecide).toHaveBeenCalledWith("rq_1", false, "p", undefined);
  });

  it("rejections are the broker's: wrong passphrase, a code needed, a wrong code, a wait, no such request", async () => {
    for (const code of ["wrong_passphrase", "two_factor_required", "gate_verification_failed", "rate_limited", "not_found"]) {
      b.vaultApprovalDecide.mockRejectedValue(brokerError(code));
      await expect(session.decideApproval(asModel(fakeModel()), "rq_1", true, "p", "")).rejects.toMatchObject({ code });
    }
  });

  it("is not available without a broker", async () => {
    await expect(session.decideApproval(asModel(fakeModel({ kind: "demo" })), "rq_1", true, "p", "")).rejects.toBeInstanceOf(NotWiredError);
  });
});

describe("privateNames (ADR-083) and the node dialog", () => {
  const base = { siblingShare: true, twofaOnReveal: true, childRead: false, agentAccess: "read-write" as const };

  it("a node left at the defaults sends nothing; 'hide this node's name' is a narrowing choice sent in the narrowing call", () => {
    expect(write.policyPatches(base)).toEqual({ narrowing: {}, widening: {} });
    expect(write.policyPatches({ ...base, privateNames: false })).toEqual({ narrowing: {}, widening: {} });
    expect(write.policyPatches({ ...base, privateNames: true })).toEqual({ narrowing: { privateNames: true }, widening: {} });
  });

  it("travels with the node's other narrowing choices in ONE call, apart from a widening one", () => {
    expect(write.policyPatches({ siblingShare: false, twofaOnReveal: false, childRead: true, agentAccess: "none", privateNames: true })).toEqual({
      narrowing: { siblingVisibility: "isolated", requireTwoFactor: "never", agentAccess: "none", privateNames: true },
      widening: { descendantRead: true },
    });
  });

  it("creates the node, then applies the choice with node.policy; a refusal is reported with what the node is left as (visible name = WIDER than chosen)", async () => {
    b.homeDir.mockResolvedValue("/opt/unit-home/");
    b.nodeCreate.mockResolvedValue({ node: "n", created: true });
    b.nodePolicy.mockRejectedValue(brokerError("capability_not_held"));
    const m = fakeModel();
    const choices = { ...base, privateNames: true };
    const out = await write.createNodeWithPolicy(asModel(m), { id: "n", label: "N", parentId: "global" }, choices);
    expect(b.nodePolicy).toHaveBeenCalledExactlyOnceWith("n", write.POLICY_REASON_AT_CREATION, { privateNames: true });
    expect(out.refused).toHaveLength(1);
    const report = write.policyReport("N", "n", choices, out);
    expect(report?.kind).toBe("error");
    expect(report?.text).toContain("hiding this node's name from others (you chose on; it stays off)");
    expect(report?.text).toContain("WIDER than you chose");
  });

  it("the second-factor choice no longer says it is 'not enforced'", () => {
    const choices = { ...base, twofaOnReveal: false };
    const report = write.policyReport("N", "n", choices, { applied: [], refused: [{ fields: ["requireTwoFactor"], error: brokerError("capability_not_held") }] });
    expect(report?.text).toContain("second factor on reveal");
    expect(report?.text).not.toMatch(/not yet enforced|not enforced/i);
  });

  it("the owner's snapshot row carries nameHidden; every other row is unchanged", () => {
    const row = { id: "acme", label: "acme", kind: "project", depth: 1, parentId: "global", counts: { entries: 7, totp: 0 }, gate: { locked: false, twofa: "none" }, health: null } as const;
    expect(mapNode({ ...row, nameHidden: true } as never)).toMatchObject({ id: "acme", nameHidden: true });
    expect("nameHidden" in mapNode(row as never)).toBe(false);
    expect("nameHidden" in mapNode({ ...row, nameHidden: false } as never)).toBe(false);
  });
});

describe("a node that requires a second factor at level always (ADR-085)", () => {
  it("two_factor_required on a list is 'unreadable', not 'empty': the node says what it needs", () => {
    expect(isUnreadableCode("two_factor_required")).toBe(true);
    expect(isUnreadableCode("node_locked")).toBe(true);
    expect(isUnreadableCode("something_else")).toBe(false);
  });
});

describe("the doctor and expired seals (ADR-089)", () => {
  const drySeal = { applied: false, fixCount: 1, fixes: [{ node: "old", type: "would-purge-expired-seal", sealedAt: 1750000000, archiveRemoved: false }], unfixable: [] };

  it("asks for the purge when told to, and lists what it would remove with the node and when it was sealed", async () => {
    b.maintenanceDoctor.mockResolvedValue(drySeal);
    const m = fakeModel();
    const r = await admin.runDoctor(asModel(m), { apply: false, purgeExpiredSeals: true });
    expect(b.maintenanceDoctor).toHaveBeenCalledExactlyOnceWith(false, undefined, undefined, true);
    expect(r.fixes).toEqual([{ node: "old", type: "would-purge-expired-seal", sealedAt: 1750000000 }]);
    expect(m.refresh).not.toHaveBeenCalled(); // a dry run changes nothing
  });

  it("applying reads the graph again and reports purged-expired-seal", async () => {
    b.maintenanceDoctor.mockResolvedValue({ applied: true, fixCount: 1, fixes: [{ node: "old", type: "purged-expired-seal", sealedAt: 1750000000, archiveRemoved: true }], unfixable: [] });
    const m = fakeModel();
    const r = await admin.runDoctor(asModel(m), { apply: true, purgeExpiredSeals: true });
    expect(b.maintenanceDoctor).toHaveBeenCalledWith(true, undefined, undefined, true);
    expect(r.fixes[0]).toMatchObject({ type: "purged-expired-seal" });
    expect(m.refresh).toHaveBeenCalledExactlyOnceWith({ graph: true });
  });

  it("a registry rebuild does not ask for the purge", async () => {
    b.maintenanceDoctor.mockResolvedValue({ applied: true, fixCount: 0, fixes: [], unfixable: [] });
    await admin.runDoctor(asModel(fakeModel()), { apply: true, rebuildRegistry: true, passphrase: "p" });
    expect(b.maintenanceDoctor).toHaveBeenCalledWith(true, true, "p", undefined);
  });
});

describe("names the broker accepted with a warning (ADR-084)", () => {
  it("says the one sentence for mixed_script_name, and a batch's own sentence, and nothing for anything else", () => {
    expect(write.nameWarningText({ warnings: ["mixed_script_name"] })).toBe("This name mixes Latin with Greek or Cyrillic letters.");
    expect(write.nameWarningText({ warnings: ["mixed_script_name"] }, true)).toBe("A name in this batch mixes Latin with Greek or Cyrillic letters.");
    expect(write.nameWarningText({ warnings: ["something_new"] })).toBe(""); // an unknown code is never printed
    expect(write.nameWarningText({ warnings: [] })).toBe("");
    expect(write.nameWarningText({})).toBe("");
    expect(write.nameWarningText(null)).toBe("");
    expect(write.nameWarningText({ warnings: "mixed_script_name" })).toBe("");
  });

  it("node.create's warnings ride on createNodeWithPolicy's result", async () => {
    b.nodeCreate.mockResolvedValue({ node: "n_0123456789ab", created: true, warnings: ["mixed_script_name"] });
    const m = fakeModel();
    const out = await write.createNodeWithPolicy(asModel(m), { id: "n_0123456789ab", label: "x", parentId: "global" }, { siblingShare: true, twofaOnReveal: true, childRead: false, agentAccess: "read-write" });
    expect(write.nameWarningText(out)).toMatch(/mixes Latin/);
    b.nodeCreate.mockResolvedValue({ node: "plain", created: true });
    const plain = await write.createNodeWithPolicy(asModel(m), { id: "plain", label: "Plain", parentId: "global" }, { siblingShare: true, twofaOnReveal: true, childRead: false, agentAccess: "read-write" });
    expect(write.nameWarningText(plain)).toBe("");
  });
});

describe("a node whose name is private gets an id that says nothing (ADR-091)", () => {
  it("is n_ and twelve lower-case hex digits, different every time, and never one already taken", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const id = write.opaqueNodeId();
      expect(id).toMatch(/^n_[0-9a-f]{12}$/);
      seen.add(id);
    }
    expect(seen.size).toBe(50);
    const taken = new Set(["n_000000000000"]);
    expect(write.opaqueNodeId(taken)).not.toBe("n_000000000000");
  });
});

describe("the agent requests waiting while locked (ADR-090)", () => {
  const ask = (over: Record<string, unknown> = {}) => ({
    request: "rq_0001", node: "atlas", entry: "e_0123456789abcdef", nodeLabel: "Atlas", entryName: "API_KEY", command: "entry.reveal", state: "pending", expiresIn: 90, requestedAt: 1, ...over,
  });

  it("asks nothing more than the count while nothing waits, and nothing at all unless the vault is locked", async () => {
    b.vaultStatus.mockResolvedValue({ locked: true, authenticated: false, initialized: true });
    expect(await session.waitingApprovals(asModel(fakeModel()))).toEqual([]);
    expect(b.vaultApprovalGet).not.toHaveBeenCalled();
    b.vaultStatus.mockResolvedValue({ locked: false, authenticated: true, initialized: true, pendingApprovals: 2 });
    expect(await session.waitingApprovals(asModel(fakeModel()))).toEqual([]); // an unlocked vault is decided with the session, not listed here
    expect(b.vaultApprovalGet).not.toHaveBeenCalled();
    expect(await session.waitingApprovals(asModel(fakeModel({ kind: "demo" })))).toEqual([]);
  });

  it("with the count the boot's own status already gave, the first look makes no status call (none waiting: no call at all)", async () => {
    expect(await session.waitingApprovals(asModel(fakeModel()), 1_000, 0)).toEqual([]);
    expect(b.vaultStatus).not.toHaveBeenCalled();
    expect(b.vaultApprovalGet).not.toHaveBeenCalled();
    b.vaultApprovalGet.mockResolvedValue({ pending: [ask()] });
    const list = await session.waitingApprovals(asModel(fakeModel()), 1_000, 1);
    expect(list).toHaveLength(1);
    expect(b.vaultStatus).not.toHaveBeenCalled();
    expect(b.vaultApprovalGet).toHaveBeenCalledExactlyOnceWith();
  });

  it("lists them with the names the broker gave, when it gave them, and the ids when it did not", async () => {
    b.vaultStatus.mockResolvedValue({ locked: true, authenticated: false, initialized: true, pendingApprovals: 3 });
    b.vaultApprovalGet.mockResolvedValue({
      pending: [ask(), ask({ request: "rq_0002", node: "n_aabbccddeeff", nodeLabel: null, entryName: null, nameHidden: true }), ask({ request: "rq_0003", nodeLabel: null, entryName: null }), ask({ request: "rq_gone", state: "denied" })],
    });
    const list = await session.waitingApprovals(asModel(fakeModel()), 1_000_000);
    expect(b.vaultApprovalGet).toHaveBeenCalledExactlyOnceWith();
    expect(list.map((w) => w.request)).toEqual(["rq_0001", "rq_0002", "rq_0003"]);
    expect(list[0].title).toBe("“API_KEY” in Atlas");
    expect(list[1].title).toBe("an entry in a node whose name is private (n_aabbccddeeff)");
    expect(list[2].title).toBe("entry e_01234567 in atlas");
    expect(list[0].expiresAt).toBe(1_000_000 + 90_000);
    // a hidden name is never shown, never guessed at
    expect(JSON.stringify(list[1])).not.toMatch(/Atlas|API_KEY/);
  });

  it("a rejection is the caller's (a broker that is not running)", async () => {
    b.vaultStatus.mockRejectedValue(brokerError("broker_unreachable"));
    await expect(session.waitingApprovals(asModel(fakeModel()))).rejects.toMatchObject({ code: "broker_unreachable" });
  });
});
