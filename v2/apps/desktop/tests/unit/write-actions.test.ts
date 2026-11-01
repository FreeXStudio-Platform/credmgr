// Work package C: the write actions.  Each is one bridge call and then a refresh of exactly what that call touched; a
// rejected call refreshes nothing; policy goes in two kinds of call so a widening refusal cannot discard the rest.
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../src/lib/bridge", () => ({
  entryCreate: vi.fn(),
  entryCreateBatch: vi.fn(),
  fieldAdd: vi.fn(),
  fieldUpdate: vi.fn(),
  fieldRemove: vi.fn(),
  fieldReorder: vi.fn(),
  fieldsPreview: vi.fn(),
  previewFieldInputs: vi.fn(),
  vaultPendingAccept: vi.fn(),
  vaultPendingDiscard: vi.fn(),
  nodeCreate: vi.fn(),
  nodePolicy: vi.fn(),
  nodeSeal: vi.fn(),
  nodeRestore: vi.fn(),
  homeDir: vi.fn(),
  isBridgeError: (e: unknown) => typeof e === "object" && e !== null && "code" in e && "source" in e && "message" in e,
}));

import * as bridge from "../../src/lib/bridge";
import * as write from "../../src/vault/actions/write";

const b = bridge as unknown as Record<string, ReturnType<typeof vi.fn>>;

/** The part of the model the actions touch. */
function fakeModel(labels: Record<string, string> = {}, over: { kind?: string; generation?: Record<string, number>; detailGeneration?: number } = {}) {
  return {
    kind: over.kind ?? "bridge",
    generation: over.generation ?? { n: 5 },
    refresh: vi.fn(async () => {}),
    node: vi.fn((id: string) => (labels[id] ? { id, label: labels[id] } : undefined)),
    detail: vi.fn(() => (over.detailGeneration === undefined ? undefined : { generation: over.detailGeneration })),
    dropEntrySecrets: vi.fn(),
    rememberSealed: vi.fn(),
    forgetSealed: vi.fn(),
  };
}
const asModel = (m: ReturnType<typeof fakeModel>) => m as unknown as Parameters<typeof write.createEntry>[0];
const brokerError = (code: string) => ({ source: "broker", code, message: code });

beforeEach(() => {
  for (const fn of Object.values(b)) if (typeof fn?.mockReset === "function") fn.mockReset();
  b.homeDir.mockResolvedValue("/opt/unit-home/"); // the shell's home directory, through src/lib/bridge.ts like every other shell fact
});

describe("createEntry", () => {
  it("sends the name, value and trimmed label once, then re-reads the node and the graph", async () => {
    b.entryCreate.mockResolvedValue({ node: "n", entry: "e1", pending: false, generation: 4 });
    const m = fakeModel();
    const r = await write.createEntry(asModel(m), "n", { name: "x", value: "v", label: " api token " });
    expect(b.entryCreate).toHaveBeenCalledExactlyOnceWith("n", "x", "v", "api token", undefined, undefined, undefined);
    expect(m.refresh).toHaveBeenCalledExactlyOnceWith({ graph: true, nodes: ["n"] });
    expect(r.pending).toBe(false);
  });

  it("sends no label when there is none", async () => {
    b.entryCreate.mockResolvedValue({ node: "n", entry: "e1", pending: false, generation: 4 });
    await write.createEntry(asModel(fakeModel()), "n", { name: "x", value: "v", label: "   " });
    expect(b.entryCreate).toHaveBeenCalledWith("n", "x", "v", undefined, undefined, undefined, undefined);
  });

  it("sends `fields` INSTEAD of a value, and a pin only when the user chose one", async () => {
    b.entryCreate.mockResolvedValue({ node: "n", entry: "e1", pending: false, generation: 4, fieldCount: 2, fieldIds: ["f_1", "f_2"] });
    const fields = [{ label: "host", value: "h" }, { label: "note", value: "n", type: "text" as const, masked: false }];
    await write.createEntry(asModel(fakeModel()), "n", { name: "x", fields, entryType: "note" });
    expect(b.entryCreate).toHaveBeenCalledWith("n", "x", undefined, undefined, fields, "note", undefined);
    await write.createEntry(asModel(fakeModel()), "n", { name: "y", fields });
    expect(b.entryCreate).toHaveBeenLastCalledWith("n", "y", undefined, undefined, fields, undefined, undefined); // inferred: no pin goes out
  });

  it("a held entry (pending) changes only the tray", async () => {
    b.entryCreate.mockResolvedValue({ node: "n", entry: "e1", pending: true });
    const m = fakeModel();
    await write.createEntry(asModel(m), "n", { name: "x", value: "v" });
    expect(m.refresh).toHaveBeenCalledExactlyOnceWith({ pending: true });
  });

  it("a refusal propagates untouched and refreshes nothing", async () => {
    b.entryCreate.mockRejectedValue(brokerError("entry_exists"));
    const m = fakeModel();
    await expect(write.createEntry(asModel(m), "n", { name: "x", value: "v" })).rejects.toMatchObject({ code: "entry_exists" });
    expect(m.refresh).not.toHaveBeenCalled();
  });
});

describe("createEntries", () => {
  const made = (pending: boolean[]) => ({ node: "n", created: pending.map((p, i) => ({ name: `e${i}`, entry: `id${i}`, pending: p })), complete: true, failed: null, total: pending.length, generation: 9 });

  it("is ONE batch call with every entry in order, labels only where there are some", async () => {
    b.entryCreateBatch.mockResolvedValue(made([false, false]));
    const m = fakeModel();
    await write.createEntries(asModel(m), "n", [{ name: "a", value: "1", label: "host" }, { name: "b", value: "2" }]);
    expect(b.entryCreateBatch).toHaveBeenCalledExactlyOnceWith("n", [{ name: "a", value: "1", label: "host" }, { name: "b", value: "2" }]);
    expect(m.refresh).toHaveBeenCalledExactlyOnceWith({ graph: true, nodes: ["n"] });
    expect(b.entryCreate).not.toHaveBeenCalled();
  });

  it("refreshes the tray for held entries, and the node for the saved ones, in one refresh", async () => {
    b.entryCreateBatch.mockResolvedValue(made([true, false]));
    const m = fakeModel();
    await write.createEntries(asModel(m), "n", [{ name: "a", value: "1" }, { name: "b", value: "2" }]);
    expect(m.refresh).toHaveBeenCalledExactlyOnceWith({ graph: true, nodes: ["n"], pending: true });
  });

  it("a part-way stop still refreshes what was created, and reports the failure to the caller", async () => {
    b.entryCreateBatch.mockResolvedValue({ node: "n", created: [{ name: "a", entry: "i", pending: false }], complete: false, failed: { index: 1, name: "b", error: "x" }, total: 2, generation: 3 });
    const m = fakeModel();
    const r = await write.createEntries(asModel(m), "n", [{ name: "a", value: "1" }, { name: "b", value: "2" }]);
    expect(r.complete).toBe(false);
    expect(m.refresh).toHaveBeenCalledExactlyOnceWith({ graph: true, nodes: ["n"] });
  });

  it("a refused batch refreshes nothing", async () => {
    b.entryCreateBatch.mockRejectedValue(brokerError("entry_exists"));
    const m = fakeModel();
    await expect(write.createEntries(asModel(m), "n", [{ name: "a", value: "1" }])).rejects.toMatchObject({ code: "entry_exists" });
    expect(m.refresh).not.toHaveBeenCalled();
  });
});

describe("the tray", () => {
  it("accept re-reads graph, node and tray; discard only the tray; listing reads graph and tray", async () => {
    b.vaultPendingAccept.mockResolvedValue({ node: "n", entry: "e", accepted: true, generation: 2 });
    b.vaultPendingDiscard.mockResolvedValue({ node: "n", entry: "e", discarded: true });
    const m = fakeModel();
    await write.acceptPending(asModel(m), "n", "e");
    expect(b.vaultPendingAccept).toHaveBeenCalledExactlyOnceWith("n", "e");
    expect(m.refresh).toHaveBeenLastCalledWith({ graph: true, nodes: ["n"], pending: true });
    await write.discardPending(asModel(m), "n", "e");
    expect(b.vaultPendingDiscard).toHaveBeenCalledExactlyOnceWith("n", "e");
    expect(m.refresh).toHaveBeenLastCalledWith({ pending: true });
    await write.listPending(asModel(m));
    expect(m.refresh).toHaveBeenLastCalledWith({ graph: true, pending: true });
  });

  it("a refused accept refreshes nothing", async () => {
    b.vaultPendingAccept.mockRejectedValue(brokerError("node_locked"));
    const m = fakeModel();
    await expect(write.acceptPending(asModel(m), "n", "e")).rejects.toMatchObject({ code: "node_locked" });
    expect(m.refresh).not.toHaveBeenCalled();
  });
});

describe("policy", () => {
  const defaults = { siblingShare: true, twofaOnReveal: true, childRead: false, agentAccess: "read-write" as const };

  it("a node left at the defaults asks for no policy call at all", () => {
    expect(write.policyPatches(defaults)).toEqual({ narrowing: {}, widening: {} });
  });

  it("each choice that differs from what node.create gives lands in the right patch", () => {
    expect(write.policyPatches({ ...defaults, siblingShare: false })).toEqual({ narrowing: { siblingVisibility: "isolated" }, widening: {} });
    expect(write.policyPatches({ ...defaults, twofaOnReveal: false })).toEqual({ narrowing: { requireTwoFactor: "never" }, widening: {} });
    expect(write.policyPatches({ ...defaults, agentAccess: "none" })).toEqual({ narrowing: { agentAccess: "none" }, widening: {} });
    expect(write.policyPatches({ ...defaults, childRead: true })).toEqual({ narrowing: {}, widening: { descendantRead: true } });
    expect(write.policyPatches({ siblingShare: false, twofaOnReveal: false, childRead: true, agentAccess: "read-only" })).toEqual({
      narrowing: { siblingVisibility: "isolated", requireTwoFactor: "never", agentAccess: "read-only" },
      widening: { descendantRead: true },
    });
  });

  it("setNodePolicy sends the reason and re-reads the graph", async () => {
    b.nodePolicy.mockResolvedValue({ node: "n", policy: {}, changed: ["agentAccess"], reason: "why", notEnforced: [] });
    const m = fakeModel();
    await write.setNodePolicy(asModel(m), "n", "why", { agentAccess: "none" });
    expect(b.nodePolicy).toHaveBeenCalledExactlyOnceWith("n", "why", { agentAccess: "none" });
    expect(m.refresh).toHaveBeenCalledExactlyOnceWith({ graph: true });
  });
});

describe("createNode", () => {
  it("expands ~ with the home directory, drops blanks, and refreshes the graph and the new node", async () => {
    b.nodeCreate.mockResolvedValue({ node: "n", created: true });
    const m = fakeModel();
    await write.createNode(asModel(m), { id: "n", label: "N", parentId: "global", workdirs: ["~/projects/a", " /abs/b ", "", "~"] });
    expect(b.nodeCreate).toHaveBeenCalledExactlyOnceWith("n", "N", "global", ["/opt/unit-home/projects/a", "/abs/b", "/opt/unit-home"]);
    expect(m.refresh).toHaveBeenCalledExactlyOnceWith({ graph: true, nodes: ["n"] });
  });

  it("asks the shell for nothing, and sends no workdirs, when there are none", async () => {
    b.nodeCreate.mockResolvedValue({ node: "n", created: true });
    await write.createNode(asModel(fakeModel()), { id: "n", label: "N", parentId: "global", workdirs: ["/abs/only"] });
    expect(b.homeDir).not.toHaveBeenCalled();
    await write.createNode(asModel(fakeModel()), { id: "n", label: "N", parentId: "global" });
    expect(b.nodeCreate).toHaveBeenLastCalledWith("n", "N", "global", undefined);
  });

  it("expandHome leaves non-~ paths alone and does not double a trailing slash", () => {
    expect(write.expandHome(["~/x", "~", "~user/x", "/a/~b"], "/h/")).toEqual(["/h/x", "/h", "~user/x", "/a/~b"]);
  });
});

describe("createNodeWithPolicy", () => {
  const input = { id: "n", label: "N", parentId: "global" };

  it("creates, then applies narrowing together and widening alone, each with the reason", async () => {
    b.nodeCreate.mockResolvedValue({ node: "n", created: true });
    b.nodePolicy.mockImplementation(async (_n: string, _r: string, p: Record<string, unknown>) => ({ node: "n", policy: {}, changed: Object.keys(p), reason: "set at creation", notEnforced: [] }));
    const r = await write.createNodeWithPolicy(asModel(fakeModel()), input, { siblingShare: true, twofaOnReveal: false, childRead: true, agentAccess: "read-only" });
    expect(b.nodePolicy.mock.calls).toEqual([
      ["n", "set at creation", { requireTwoFactor: "never", agentAccess: "read-only" }],
      ["n", "set at creation", { descendantRead: true }],
    ]);
    expect(r).toEqual({ node: "n", applied: ["requireTwoFactor", "agentAccess", "descendantRead"], refused: [] });
  });

  it("a refused widening is reported, not thrown, and the narrowing before it stands", async () => {
    b.nodeCreate.mockResolvedValue({ node: "n", created: true });
    b.nodePolicy.mockResolvedValueOnce({ node: "n", policy: {}, changed: ["requireTwoFactor"], reason: "r", notEnforced: [] }).mockRejectedValueOnce(brokerError("presence_required"));
    const r = await write.createNodeWithPolicy(asModel(fakeModel()), input, { siblingShare: true, twofaOnReveal: false, childRead: true, agentAccess: "read-write" });
    expect(r.applied).toEqual(["requireTwoFactor"]);
    expect(r.refused).toHaveLength(1);
    expect(r.refused[0].fields).toEqual(["descendantRead"]);
    expect(r.refused[0].error).toMatchObject({ code: "presence_required" });
  });

  it("a refused narrowing does not stop the widening call from being tried", async () => {
    b.nodeCreate.mockResolvedValue({ node: "n", created: true });
    b.nodePolicy.mockRejectedValueOnce(brokerError("node_access_denied")).mockResolvedValueOnce({ node: "n", policy: {}, changed: ["descendantRead"], reason: "r", notEnforced: [] });
    const r = await write.createNodeWithPolicy(asModel(fakeModel()), input, { siblingShare: false, twofaOnReveal: true, childRead: true, agentAccess: "read-write" });
    expect(b.nodePolicy).toHaveBeenCalledTimes(2);
    expect(r.applied).toEqual(["descendantRead"]);
    expect(r.refused.map((x) => x.fields)).toEqual([["siblingVisibility"]]);
  });

  it("if the node cannot be created nothing else is attempted", async () => {
    b.nodeCreate.mockRejectedValue(brokerError("malformed_request"));
    const m = fakeModel();
    await expect(write.createNodeWithPolicy(asModel(m), input, { siblingShare: false, twofaOnReveal: false, childRead: true, agentAccess: "none" })).rejects.toMatchObject({ code: "malformed_request" });
    expect(b.nodePolicy).not.toHaveBeenCalled();
    expect(m.refresh).not.toHaveBeenCalled();
  });
});

describe("policyReport: what the user is told when a new node's settings were (partly) refused", () => {
  const input = { id: "ledger", label: "Ledger", parentId: "global" };
  const none = { siblingShare: true, twofaOnReveal: true, childRead: false, agentAccess: "read-write" as const };

  it("says nothing when nothing was refused", async () => {
    b.nodeCreate.mockResolvedValue({ node: "ledger", created: true });
    const out = await write.createNodeWithPolicy(asModel(fakeModel()), input, none);
    expect(write.policyReport("Ledger", "ledger", none, out)).toBeNull();
  });

  it("a refused widening (presence) leaves the node NARROWER than chosen, and says exactly that", async () => {
    b.nodeCreate.mockResolvedValue({ node: "ledger", created: true });
    b.nodePolicy.mockRejectedValue(brokerError("presence_required"));
    const choices = { ...none, childRead: true };
    const out = await write.createNodeWithPolicy(asModel(fakeModel()), input, choices);
    const r = write.policyReport("Ledger", "ledger", choices, out)!;
    expect(r.kind).toBe("warn");
    expect(r.sessionEnded).toBe(false);
    expect(r.text).toContain("this node reading its children (you chose on; it stays off)");
    expect(r.text).toContain("presence (Touch ID)");
    expect(r.text).toContain("The node is no wider than you chose.");
    expect(r.text).not.toContain("WIDER");
  });

  it("a refused NARROWING that is not presence is reported as what it is, and the node is said to be WIDER than chosen", async () => {
    b.nodeCreate.mockResolvedValue({ node: "ledger", created: true });
    b.nodePolicy.mockRejectedValue(brokerError("capability_not_held"));
    const choices = { siblingShare: false, twofaOnReveal: true, childRead: false, agentAccess: "none" as const };
    const out = await write.createNodeWithPolicy(asModel(fakeModel()), input, choices);
    const r = write.policyReport("Ledger", "ledger", choices, out)!;
    expect(r.kind).toBe("error");
    expect(r.text).toContain("agent access (you chose none; it stays read-write)");
    expect(r.text).toContain("sub-nodes seeing each other (you chose isolated; it stays shared)");
    expect(r.text).toContain("not allowed to change the node's settings");
    expect(r.text).not.toContain("presence"); // the old report said "Not permitted" or "Unexpected error (x)" with no account of the node
    expect(r.text).toContain("WIDER than you chose (sub-nodes seeing each other: shared; agent access: read-write)");
    expect(r.text).toContain('credmgr node policy ledger --reason');
  });

  it("two refusals make ONE report that names both, so the second cannot replace the first", async () => {
    b.nodeCreate.mockResolvedValue({ node: "ledger", created: true });
    b.nodePolicy.mockRejectedValueOnce(brokerError("internal")).mockRejectedValueOnce(brokerError("presence_required"));
    const choices = { siblingShare: true, twofaOnReveal: true, childRead: true, agentAccess: "read-only" as const };
    const out = await write.createNodeWithPolicy(asModel(fakeModel()), input, choices);
    expect(out.refused.map((x) => x.fields)).toEqual([["agentAccess"], ["descendantRead"]]);
    const r = write.policyReport("Ledger", "ledger", choices, out)!;
    expect(r.text).toContain("agent access (you chose read-only; it stays read-write)");
    expect(r.text).toContain("this node reading its children (you chose on; it stays off)");
    expect(r.text).toContain("The broker refused it (internal).");
    expect(r.text).toContain("presence (Touch ID)");
    expect(r.kind).toBe("error");
  });

  it("names what WAS applied, and flags a login that ended", async () => {
    b.nodeCreate.mockResolvedValue({ node: "ledger", created: true });
    b.nodePolicy.mockResolvedValueOnce({ node: "ledger", policy: {}, changed: ["agentAccess"], reason: "r", notEnforced: [] }).mockRejectedValueOnce(brokerError("session_expired"));
    const choices = { siblingShare: true, twofaOnReveal: true, childRead: true, agentAccess: "none" as const };
    const out = await write.createNodeWithPolicy(asModel(fakeModel()), input, choices);
    const r = write.policyReport("Ledger", "ledger", choices, out)!;
    expect(r.text).toContain("Applied: agent access.");
    expect(r.sessionEnded).toBe(true);
  });

  it("the report holds the codes, never an error's message or a value", async () => {
    b.nodeCreate.mockResolvedValue({ node: "ledger", created: true });
    b.nodePolicy.mockRejectedValue({ source: "broker", code: "internal", message: "SECRET-IN-MESSAGE" });
    const choices = { ...none, agentAccess: "none" as const };
    const out = await write.createNodeWithPolicy(asModel(fakeModel()), input, choices);
    expect(write.policyReport("Ledger", "ledger", choices, out)!.text).not.toContain("SECRET-IN-MESSAGE");
  });

  it("a re-read that fails AFTER the node was created is reported as that, not thrown (the node exists)", async () => {
    b.nodeCreate.mockResolvedValue({ node: "ledger", created: true });
    const m = fakeModel();
    m.refresh.mockRejectedValue(brokerError("broker_unreachable"));
    const out = await write.createNodeWithPolicy(asModel(m), input, none);
    expect(out.readbackError).toMatchObject({ code: "broker_unreachable" });
    expect(out.refused).toEqual([]);
  });
});

describe("sealExpiry (the end of the restore window, only if the broker says when)", () => {
  it("is the broker's time when its answer carries one, and nothing otherwise", () => {
    expect(write.sealExpiry({ node: "n", sealed: true })).toBeUndefined(); // the answer today
    expect(write.sealExpiry({ node: "n", sealed: true, expiresAt: 1760864000 })).toBe(1760864000);
    for (const bad of [{ expiresAt: "1760864000" }, { expiresAt: Number.NaN }, { expiresAt: Infinity }, { expiresAt: 0 }, { expiresAt: -5 }, { expiresAt: null }, { expiresAt: {} }, null, undefined, 7, "x"]) {
      expect(write.sealExpiry(bad), JSON.stringify(bad)).toBeUndefined();
    }
  });

  it("sealNode remembers it on the sealed node only when it was supplied", async () => {
    b.nodeSeal.mockResolvedValueOnce({ node: "beacon", sealed: true });
    const plain = fakeModel({ beacon: "Beacon" });
    await write.sealNode(asModel(plain), "beacon");
    expect(plain.rememberSealed.mock.calls[0][0]).not.toHaveProperty("expiresAt");
    b.nodeSeal.mockResolvedValueOnce({ node: "beacon", sealed: true, expiresAt: 1760864000 });
    const told = fakeModel({ beacon: "Beacon" });
    await write.sealNode(asModel(told), "beacon");
    expect(told.rememberSealed.mock.calls[0][0]).toMatchObject({ id: "beacon", expiresAt: 1760864000 });
  });
});

describe("seal and restore", () => {
  it("seal remembers the node (by the label it had), then re-reads graph, grants and the tray", async () => {
    b.nodeSeal.mockResolvedValue({ node: "beacon", sealed: true });
    const m = fakeModel({ beacon: "Beacon" });
    await write.sealNode(asModel(m), "beacon");
    expect(b.nodeSeal).toHaveBeenCalledExactlyOnceWith("beacon");
    expect(m.rememberSealed).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ id: "beacon", label: "Beacon", node: { id: "beacon", label: "Beacon" }, kids: [], date: expect.stringMatching(/^\d{4}-\d{2}-\d{2}$/) }));
    expect(m.refresh).toHaveBeenCalledExactlyOnceWith({ graph: true, grants: true, pending: true });
  });

  it("a refused seal remembers nothing and refreshes nothing", async () => {
    b.nodeSeal.mockRejectedValue(brokerError("node_locked"));
    const m = fakeModel({ beacon: "Beacon" });
    await expect(write.sealNode(asModel(m), "beacon")).rejects.toMatchObject({ code: "node_locked" });
    expect(m.rememberSealed).not.toHaveBeenCalled();
    expect(m.refresh).not.toHaveBeenCalled();
  });

  it("restore forgets the sealed node and re-reads graph, the node and the tray", async () => {
    b.nodeRestore.mockResolvedValue({ node: "beacon", restored: true });
    const m = fakeModel();
    await write.restoreNode(asModel(m), "beacon");
    expect(b.nodeRestore).toHaveBeenCalledExactlyOnceWith("beacon");
    expect(m.forgetSealed).toHaveBeenCalledExactlyOnceWith("beacon");
    expect(m.refresh).toHaveBeenCalledExactlyOnceWith({ graph: true, nodes: ["beacon"], pending: true });
  });

  it.each(["archive_expired", "not_found"])("a restore that answers %s forgets the node (it can never be restored) and still throws", async (code) => {
    b.nodeRestore.mockRejectedValue(brokerError(code));
    const m = fakeModel();
    await expect(write.restoreNode(asModel(m), "beacon")).rejects.toMatchObject({ code });
    expect(m.forgetSealed).toHaveBeenCalledExactlyOnceWith("beacon");
    expect(m.refresh).not.toHaveBeenCalled();
  });

  it("any other restore refusal keeps the node remembered", async () => {
    b.nodeRestore.mockRejectedValue(brokerError("vault_locked"));
    const m = fakeModel();
    await expect(write.restoreNode(asModel(m), "beacon")).rejects.toMatchObject({ code: "vault_locked" });
    expect(m.forgetSealed).not.toHaveBeenCalled();
  });
});

// The broker DID the work and only the re-read after it failed.  The action must not throw (a throw reads as "the write failed", and
// a retry meets entry_exists / not_found): it resolves with the broker's answer and says the re-read failed.
describe("a re-read that fails AFTER the broker wrote is reported on the answer, never thrown", () => {
  const unreachable = brokerError("broker_unreachable");
  const failing = () => {
    const m = fakeModel({ beacon: "Beacon" });
    m.refresh.mockRejectedValue(unreachable);
    return m;
  };

  it("createEntry", async () => {
    b.entryCreate.mockResolvedValue({ node: "n", entry: "e1", pending: false, generation: 4 });
    const r = await write.createEntry(asModel(failing()), "n", { name: "x", value: "v" });
    expect(r).toMatchObject({ entry: "e1", pending: false, readbackError: unreachable });
    expect(b.entryCreate).toHaveBeenCalledTimes(1);
  });

  it("createEntries, for saved and for held entries alike", async () => {
    b.entryCreateBatch.mockResolvedValue({ node: "n", created: [{ name: "a", entry: "i", pending: false }, { name: "b", entry: "j", pending: true }], complete: true, failed: null, total: 2, generation: 3 });
    const r = await write.createEntries(asModel(failing()), "n", [{ name: "a", value: "1" }, { name: "b", value: "2" }]);
    expect(r.created).toHaveLength(2);
    expect(r.readbackError).toBe(unreachable);
  });

  it("acceptPending and discardPending", async () => {
    b.vaultPendingAccept.mockResolvedValue({ node: "n", entry: "e", accepted: true, generation: 2 });
    b.vaultPendingDiscard.mockResolvedValue({ node: "n", entry: "e", discarded: true });
    expect((await write.acceptPending(asModel(failing()), "n", "e")).readbackError).toBe(unreachable);
    expect((await write.discardPending(asModel(failing()), "n", "e")).readbackError).toBe(unreachable);
  });

  it("sealNode (the sealed node is still remembered for Restore) and restoreNode (forgotten, it is back)", async () => {
    b.nodeSeal.mockResolvedValue({ node: "beacon", sealed: true });
    b.nodeRestore.mockResolvedValue({ node: "beacon", restored: true });
    const sealing = failing();
    expect((await write.sealNode(asModel(sealing), "beacon")).readbackError).toBe(unreachable);
    expect(sealing.rememberSealed).toHaveBeenCalledTimes(1);
    const restoring = failing();
    expect((await write.restoreNode(asModel(restoring), "beacon")).readbackError).toBe(unreachable);
    expect(restoring.forgetSealed).toHaveBeenCalledTimes(1);
  });

  it("createNode and setNodePolicy", async () => {
    b.nodeCreate.mockResolvedValue({ node: "n", created: true });
    b.nodePolicy.mockResolvedValue({ node: "n", policy: {}, changed: ["agentAccess"], reason: "r", notEnforced: [] });
    expect((await write.createNode(asModel(failing()), { id: "n", label: "N", parentId: "global" })).readbackError).toBe(unreachable);
    expect((await write.setNodePolicy(asModel(failing()), "n", "r", { agentAccess: "none" })).readbackError).toBe(unreachable);
  });

  it("when the re-read works, the answer carries no readbackError at all (the key is absent, not undefined)", async () => {
    b.entryCreate.mockResolvedValue({ node: "n", entry: "e1", pending: false, generation: 4 });
    const r = await write.createEntry(asModel(fakeModel()), "n", { name: "x", value: "v" });
    expect("readbackError" in r).toBe(false);
  });

  it("a refusal BEFORE the write still throws, and is not mistaken for a failed re-read", async () => {
    b.entryCreate.mockRejectedValue(brokerError("entry_exists"));
    const m = failing();
    await expect(write.createEntry(asModel(m), "n", { name: "x", value: "v" })).rejects.toMatchObject({ code: "entry_exists" });
    expect(m.refresh).not.toHaveBeenCalled();
  });
});

// ───────────────────────────── the fields of an entry (ADR-078) ─────────────────────────────

describe("field actions", () => {
  const changed = { node: "n", entry: "e1", generation: 6, fieldCount: 2, fieldIds: ["f_1", "f_2"] };
  const TOUCHED = { graph: true, nodes: ["n"], details: [{ node: "n", entry: "e1" }] };

  it("each echoes the NODE's generation the model last read, in the bridge's argument order, then re-reads the node, the graph and the entry's fields", async () => {
    b.fieldAdd.mockResolvedValue({ ...changed, added: ["f_2"] });
    b.fieldUpdate.mockResolvedValue(changed);
    b.fieldRemove.mockResolvedValue(changed);
    b.fieldReorder.mockResolvedValue(changed);
    const m = fakeModel();
    await write.addFields(asModel(m), "n", "e1", [{ label: "note", value: "v" }]);
    await write.updateField(asModel(m), "n", "e1", "f_1", { label: "renamed" });
    await write.removeField(asModel(m), "n", "e1", "f_1");
    await write.reorderFields(asModel(m), "n", "e1", ["f_2", "f_1"]);
    expect(b.fieldAdd).toHaveBeenCalledExactlyOnceWith("n", "e1", 5, [{ label: "note", value: "v" }], undefined);
    expect(b.fieldUpdate).toHaveBeenCalledExactlyOnceWith("n", "e1", 5, "f_1", { label: "renamed" });
    expect(b.fieldRemove).toHaveBeenCalledExactlyOnceWith("n", "e1", 5, "f_1");
    expect(b.fieldReorder).toHaveBeenCalledExactlyOnceWith("n", "e1", 5, ["f_2", "f_1"]);
    expect(m.refresh.mock.calls).toEqual([[TOUCHED], [TOUCHED], [TOUCHED], [TOUCHED]]);
  });

  it("the generation falls back to the entry's own detail when the list never gave one, and then to 0 (the broker answers conflict, the screen reloads)", async () => {
    b.fieldRemove.mockResolvedValue(changed);
    await write.removeField(asModel(fakeModel({}, { generation: {}, detailGeneration: 9 })), "n", "e1", "f_1");
    expect(b.fieldRemove).toHaveBeenLastCalledWith("n", "e1", 9, "f_1");
    await write.removeField(asModel(fakeModel({}, { generation: {} })), "n", "e1", "f_1");
    expect(b.fieldRemove).toHaveBeenLastCalledWith("n", "e1", 0, "f_1");
  });

  it("a value held from before a change is dropped when the field is updated or removed, and kept when fields are only added or reordered", async () => {
    b.fieldAdd.mockResolvedValue({ ...changed, added: ["f_3"] });
    b.fieldUpdate.mockResolvedValue(changed);
    b.fieldRemove.mockResolvedValue(changed);
    b.fieldReorder.mockResolvedValue(changed);
    const m = fakeModel();
    await write.addFields(asModel(m), "n", "e1", [{ label: "a", value: "b" }], 0);
    await write.reorderFields(asModel(m), "n", "e1", ["f_2", "f_1"]);
    expect(m.dropEntrySecrets).not.toHaveBeenCalled();
    expect(b.fieldAdd).toHaveBeenCalledWith("n", "e1", 5, [{ label: "a", value: "b" }], 0); // `position` travels when given
    await write.updateField(asModel(m), "n", "e1", "f_1", { value: "new" });
    await write.removeField(asModel(m), "n", "e1", "f_2");
    expect(m.dropEntrySecrets.mock.calls).toEqual([["n", "e1"], ["n", "e1"]]);
  });

  it("a refusal propagates untouched: nothing is refreshed and no held value is dropped (nothing changed)", async () => {
    for (const [fn, call] of [
      [b.fieldAdd, (m: ReturnType<typeof fakeModel>) => write.addFields(asModel(m), "n", "e1", [{ label: "a", value: "b" }])],
      [b.fieldUpdate, (m: ReturnType<typeof fakeModel>) => write.updateField(asModel(m), "n", "e1", "f_1", { label: "x" })],
      [b.fieldRemove, (m: ReturnType<typeof fakeModel>) => write.removeField(asModel(m), "n", "e1", "f_1")],
      [b.fieldReorder, (m: ReturnType<typeof fakeModel>) => write.reorderFields(asModel(m), "n", "e1", ["f_1"])],
    ] as const) {
      fn.mockRejectedValue(brokerError("conflict"));
      const m = fakeModel();
      await expect(call(m)).rejects.toMatchObject({ code: "conflict" });
      expect(m.refresh).not.toHaveBeenCalled();
      expect(m.dropEntrySecrets).not.toHaveBeenCalled();
    }
  });

  it("a failed re-read after a change that happened is reported on the answer, never thrown", async () => {
    b.fieldUpdate.mockResolvedValue(changed);
    const m = fakeModel();
    m.refresh.mockRejectedValue(brokerError("broker_unreachable"));
    const r = await write.updateField(asModel(m), "n", "e1", "f_1", { label: "x" });
    expect(r.generation).toBe(6);
    expect(r.readbackError).toMatchObject({ code: "broker_unreachable" });
    expect(m.dropEntrySecrets).toHaveBeenCalledOnce(); // the old value is gone whether or not the re-read worked
  });

  it("the preview runs locally, in the shell, only with a shell; the page never previews on its own", async () => {
    b.fieldsPreview.mockResolvedValue({ segments: [], singleBlobHint: false });
    await write.previewPaste(asModel(fakeModel()), "a: b", true);
    expect(b.fieldsPreview).toHaveBeenLastCalledWith("a: b", undefined, true);
    await write.previewRows(asModel(fakeModel()), [{ label: "a", value: "b", type: "text" }]);
    expect(b.fieldsPreview).toHaveBeenLastCalledWith(undefined, [{ label: "a", value: "b", type: "text" }]);
    await expect(write.previewPaste(asModel(fakeModel({}, { kind: "demo" })), "a: b", false)).rejects.toMatchObject({ code: "not_wired" });
    await expect(write.previewRows(asModel(fakeModel({}, { kind: "demo" })), [])).rejects.toMatchObject({ code: "not_wired" });
    expect(b.fieldsPreview).toHaveBeenCalledTimes(2);
  });

  it("previewFieldInputs is the bridge's: label and value verbatim, a pin only where the user made one", () => {
    b.previewFieldInputs.mockReturnValue([{ label: "a", value: "b" }]);
    const seg = { suggestedName: "a", fields: [], entryType: "other", sensitivity: "low", fieldCount: 0, hasTotp: false } as never;
    expect(write.previewFieldInputs(seg)).toEqual([{ label: "a", value: "b" }]);
    expect(b.previewFieldInputs).toHaveBeenCalledWith(seg);
  });
});

describe("itemOf", () => {
  it("is fields XOR value; a pin travels only when given", () => {
    expect(write.itemOf({ name: "x", value: "v", label: " l " })).toEqual({ name: "x", value: "v", label: "l" });
    expect(write.itemOf({ name: "x", value: "v" })).toEqual({ name: "x", value: "v" });
    expect(write.itemOf({ name: "x", fields: [{ label: "a", value: "b" }], entryType: "note", sensitivity: "high" })).toEqual({ name: "x", fields: [{ label: "a", value: "b" }], entryType: "note", sensitivity: "high" });
    expect("value" in write.itemOf({ name: "x", fields: [{ label: "a", value: "b" }] })).toBe(false);
  });
});
