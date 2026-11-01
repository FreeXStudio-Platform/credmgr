// Work package C: the pure parts of the write dialogs' logic (logic/write.js): what Save would send, what the node and seal
// dialogs allow, and the slug a node name becomes.  The demo vault supplies nodes ("linux" with sub-nodes dev, staging, prod)
// and an entry named "vps-root" to clash with; nothing here talks to a broker.
import { describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { slugify } from "../../src/design/logic/write.js";

async function logic(state: Record<string, unknown> = {}) {
  const l = new (Component as any)({ mode: "pro" });
  await l.model.boot();
  l.state = { ...l.state, ...state };
  return l;
}

describe("slugify (a node's id becomes a folder name: only letters, digits and single dashes survive)", () => {
  it.each([
    ["Payments API", "payments-api"],
    ["  spaced   out  ", "spaced-out"],
    ["../escape", "escape"],
    ["a/b\\c", "a-b-c"],
    ["Café Ünïcode", "cafe-unicode"],
    ["UPPER_snake-Case", "upper-snake-case"],
    ["--dash--", "dash"],
    ["!!!", ""],
    ["密钥", ""],
    ["x".repeat(80), "x".repeat(48)],
  ])("%j -> %j", (name, id) => expect(slugify(name)).toBe(id));
});

// A segment as the shell's `fields_preview` answers it (src/lib/bridge.ts PreviewSegment).  The page has no parser of its own, so the plan is
// built from what a preview said: these tests hand it previews, as the logic holds them in `state.preview`.
const seg = (name: string, fields: Array<[string, string]>, over: Record<string, unknown> = {}) => ({
  suggestedName: name,
  fields: fields.map(([label, value]) => ({ label, value, type: "text", masked: false, inferredType: "text", typeOverridden: false, maskedOverridden: false })),
  entryType: "other",
  sensitivity: "low",
  fieldCount: fields.length,
  hasTotp: false,
  ...over,
});
const preview = (...segs: unknown[]) => ({ segs, hint: false, failed: null });

describe("entryPlan (what Save would send)", () => {
  it("single: one entry named by the name field, holding the previewed fields verbatim; disabled until there is a name and a preview", async () => {
    const l = await logic({ addNode: "linux", addMode: "single", addName: "", singleFields: [{ label: "", value: "" }] });
    expect(l.entryPlan().disabled).toBe(true); // nothing previewed
    l.state = { ...l.state, preview: preview(seg("api token", [["api token", "v"], ["host", "h.example.test"]])) };
    expect(l.entryPlan().disabled).toBe(true); // no name yet
    l.state = { ...l.state, addName: "  new-one  " };
    const p = l.entryPlan();
    expect(p.disabled).toBe(false);
    expect(p.items).toHaveLength(1);
    expect(p.items[0]).toMatchObject({ name: "new-one", clash: false, fields: [{ label: "api token", value: "v" }, { label: "host", value: "h.example.test" }] });
  });

  it("what goes out is the preview, and a pin only where the user made one", async () => {
    const l = await logic({ addNode: "linux", addMode: "single", addName: "x" });
    const pinned = seg("x", [["a", "1"], ["b", "2"]]);
    (pinned.fields[1] as Record<string, unknown>).typeOverridden = true;
    (pinned.fields[1] as Record<string, unknown>).type = "password";
    l.state = { ...l.state, preview: preview(pinned) };
    expect(l.entryPlan().items[0].fields).toEqual([{ label: "a", value: "1" }, { label: "b", value: "2", type: "password" }]);
  });

  it("single: a name already in the node, or held in its tray, clashes (case-insensitive) and cannot be saved", async () => {
    const l = await logic({ addNode: "linux", addMode: "single", addName: "VPS-Root", preview: preview(seg("x", [["", "v"]])) });
    expect(l.entryPlan().items[0].clash).toBe(true);
    expect(l.entryPlan().disabled).toBe(true);
  });

  it("is disabled while the preview of the latest keystroke has not arrived, so a save can never send an earlier one", async () => {
    const l = await logic({ addNode: "linux", addMode: "single", addName: "ok", preview: preview(seg("x", [["", "v"]])), previewBusy: true });
    expect(l.entryPlan().disabled).toBe(true);
    l.state = { ...l.state, previewBusy: false };
    expect(l.entryPlan().disabled).toBe(false);
  });

  it("bulk, not split: the whole paste is ONE entry, named by the name field", async () => {
    const l = await logic({ addNode: "linux", addMode: "bulk", splitSegs: false, addName: "", preview: preview(seg("host", [["host", "a.example.test"], ["user", "root"], ["", "just text"]])) });
    expect(l.entryPlan().disabled).toBe(true); // a name is needed: nothing names it
    l.state = { ...l.state, addName: "box" };
    const p = l.entryPlan();
    expect(p.items.map((i: any) => [i.name, i.fields.length])).toEqual([["box", 3]]);
    expect(p.split).toBe(false);
    expect(p.disabled).toBe(false);
  });

  it("bulk, split: one entry per segment, named by its first label (else the shell's 'untitled n'), a repeat numbered; no name needed", async () => {
    const l = await logic({
      addNode: "linux", addMode: "bulk", splitSegs: true, addName: "",
      preview: preview(seg("token", [["token", "1"]]), seg("token", [["token", "2"]]), seg("Token", [["Token", "3"]]), seg("untitled 4", [["", "no label here"]])),
    });
    const p = l.entryPlan();
    expect(p.split).toBe(true);
    expect(p.items.map((i: any) => i.name)).toEqual(["token", "token 2", "Token 3", "untitled 4"]);
    expect(p.disabled).toBe(false);
  });

  it("bulk, split: a first label over the broker's 200-character name limit is cut to 190 so the numbered repeat still fits", async () => {
    const long = "x".repeat(250);
    const l = await logic({
      addNode: "linux", addMode: "bulk", splitSegs: true, addName: "",
      preview: preview(seg(long, [[long, "1"]]), seg(long, [[long, "2"]])),
    });
    const names = l.entryPlan().items.map((i: any) => i.name as string);
    expect(names[0]).toHaveLength(190);
    expect(names[1]).toBe("x".repeat(190) + " 2");
    expect(Math.max(...names.map((n: string) => Array.from(n).length))).toBeLessThanOrEqual(200);
  });

  it("bulk, split: one clashing name blocks the whole paste (the batch is all or nothing), and the clash is marked", async () => {
    const l = await logic({ addNode: "linux", addMode: "bulk", splitSegs: true, preview: preview(seg("vps-root", [["vps-root", "x"]]), seg("fresh", [["fresh", "y"]])) });
    const p = l.entryPlan();
    expect(p.items.map((i: any) => i.clash)).toEqual([true, false]);
    expect(p.disabled).toBe(true);
  });

  it("bulk, split: more than 500 entries cannot be saved", async () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => seg(`k${i}`, [[`k${i}`, "v"]]));
    const l = await logic({ addNode: "linux", addMode: "bulk", splitSegs: true, preview: preview(...many(501)) });
    const p = l.entryPlan();
    expect(p.tooMany).toBe(true);
    expect(p.disabled).toBe(true);
    l.state = { ...l.state, preview: preview(...many(500)) };
    expect(l.entryPlan().disabled).toBe(false);
  });

  it("is disabled while a save is in flight", async () => {
    const l = await logic({ addNode: "linux", addMode: "single", addName: "ok", preview: preview(seg("x", [["", "v"]])), addBusy: true });
    expect(l.entryPlan().disabled).toBe(true);
  });

  it("knows when the target node is locked", async () => {
    const l = await logic({ addNode: "linux" });
    expect(l.entryPlan().nodeLocked).toBe(false);
  });
});

describe("addNodeInfo", () => {
  it("derives the id and label, and keeps Create disabled for every name the broker would refuse", async () => {
    const l = await logic({ newNodeName: " My Project ", newNodeFolders: [""] });
    expect(l.addNodeInfo()).toMatchObject({ id: "my-project", label: "My Project", problem: "", disabled: false });
    for (const [name, problem] of [
      ["linux", 'a node called "linux" already exists'],
      ["Global", "“global” is reserved"],
      ["Orphan", "“orphan” is reserved"],
      ["???", "the name needs at least one letter or digit"],
      ["x".repeat(121), "the name must be 1 to 120 characters, with no control characters"],
    ] as const) {
      l.state = { ...l.state, newNodeName: name };
      expect(l.addNodeInfo().problem, name).toBe(problem);
      expect(l.addNodeInfo().disabled, name).toBe(true);
    }
  });

  it("requires absolute (or ~) work folders and ignores blank ones", async () => {
    const l = await logic({ newNodeName: "fine", newNodeFolders: ["", "  "] });
    expect(l.addNodeInfo().disabled).toBe(false);
    for (const ok of ["/abs/path", "~/x", "~"]) {
      l.state = { ...l.state, newNodeFolders: [ok] };
      expect(l.addNodeInfo().badFolder, ok).toBeUndefined();
    }
    for (const bad of ["rel/path", "./here", "~other/x"]) {
      l.state = { ...l.state, newNodeFolders: [bad] };
      expect(l.addNodeInfo().badFolder, bad).toBe(bad);
      expect(l.addNodeInfo().disabled, bad).toBe(true);
    }
  });
});

describe("sealInfo", () => {
  it("a node that still has sub-nodes is blocked and names them", async () => {
    const l = await logic({ sealTarget: "linux", sealTyped: "linux" });
    const i = l.sealInfo();
    expect(i.kids.map((k: any) => k.id).sort()).toEqual(["dev", "prod", "staging"]);
    expect(i.blocked).toMatch(/^Seal its sub-nodes first \(.*dev.*\)/);
    expect(i.disabled).toBe(true);
  });

  it("a leaf is sealable only once its name is typed exactly", async () => {
    const l = await logic({ sealTarget: "dev", sealTyped: "" });
    expect(l.sealInfo()).toMatchObject({ blocked: "", disabled: true });
    l.state = { ...l.state, sealTyped: "de" };
    expect(l.sealInfo().disabled).toBe(true);
    l.state = { ...l.state, sealTyped: "dev" };
    expect(l.sealInfo().disabled).toBe(false);
    l.state = { ...l.state, sealBusy: true };
    expect(l.sealInfo().disabled).toBe(true);
  });

  it("the global node is never sealable, and no target is not either", async () => {
    const l = await logic({ sealTarget: "global", sealTyped: "global" });
    expect(l.sealInfo().disabled).toBe(true);
    l.state = { ...l.state, sealTarget: null };
    expect(l.sealInfo().disabled).toBe(true);
  });
});

describe("writing without a broker", () => {
  it("every write says so and changes nothing (the demo data has no broker to write to)", async () => {
    const l = await logic({ addNode: "linux", addMode: "single", addName: "x", singleFields: [{ label: "", value: "v" }], sealTarget: "dev", sealTyped: "dev", newNodeName: "n" });
    const notices: string[] = [];
    l.notify = (_k: string, t: string) => notices.push(t);
    const before = JSON.stringify(l.vault);
    await l.saveNewEntry(false);
    await l.doSeal();
    await l.confirmAddNode();
    await l.restoreSealed("nothing-sealed");
    await l.acceptPending("linux", "e", "x");
    expect(notices).toHaveLength(4); // saveNewEntry, doSeal, confirmAddNode, acceptPending (restoreSealed("nothing-sealed") has nothing sealed to act on)
    expect(notices.every((t) => /needs the CredMgr app/i.test(t))).toBe(true);
    expect(JSON.stringify(l.vault)).toBe(before);
  });
});
