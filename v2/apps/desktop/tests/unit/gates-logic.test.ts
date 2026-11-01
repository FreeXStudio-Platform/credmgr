// What the 2026-10-25 controls bind to (logic/gates.js, and the parts of logic/fields.js, inspector.js and write.js that serve them): the second-factor
// dialog, the locked-approval panel, Undo, Generate and the node dialog's privateNames choice.  Pure parts only: the flows that call the broker are
// driven against the fixture broker by tests/e2e/gates.spec.ts and against a real daemon by tests/real/gates.spec.ts.
import { describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { LOCK_CODE, LOCK_PHRASE } from "../../src/design/logic/session.js";

async function logic(state: Record<string, unknown> = {}) {
  const l = new (Component as any)({ mode: "pro" });
  await l.model.boot();
  l.state = { ...l.state, ...state };
  l.__host = {
    setLogicState: (u: unknown, cb?: () => void) => {
      const next = typeof u === "function" ? (u as (s: unknown) => unknown)(l.state) : u;
      if (next) l.state = { ...l.state, ...(next as object) };
      cb?.();
    },
    forceUpdate: () => {},
  };
  return l;
}
const typing = (value: string) => ({ target: { value } });

describe("the locked-approval panel (S16a)", () => {
  it("is a link on the passphrase step of the Lock screen, and nowhere else", async () => {
    const l = await logic({ screen: "lock", lockStep: LOCK_PHRASE });
    expect(l.renderVals()).toMatchObject({ aprLinkShow: true, aprShow: false, aprResultShow: false });
    l.state = { ...l.state, lockStep: LOCK_CODE };
    expect(l.renderVals().aprLinkShow).toBe(false); // the second-factor step of a login has its own business
    l.state = { ...l.state, screen: "app", lockStep: LOCK_PHRASE };
    expect(l.renderVals()).toMatchObject({ aprLinkShow: false, aprShow: false });
    // a panel left open in state does not show on any other screen
    l.state = { ...l.state, aprOpen: true, aprResult: "approved" };
    expect(l.renderVals()).toMatchObject({ aprShow: false, aprResultShow: false });
  });

  it("opens, takes a request id, the passphrase and the code, and closes wiping all three", async () => {
    const l = await logic({ screen: "lock", lockStep: LOCK_PHRASE });
    l.renderVals().aprOpenPanel();
    expect(l.state.aprOpen).toBe(true);
    let v = l.renderVals();
    expect(v).toMatchObject({ aprShow: true, aprLinkShow: false, aprDisabled: true });
    v.onAprReq(typing("rq_abc123"));
    v = l.renderVals();
    expect(v.aprDisabled).toBe(true); // a request id alone decides nothing
    v.onAprPass(typing("a passphrase"));
    expect(l.renderVals().aprDisabled).toBe(false); // no second factor enrolled: no code needed (the broker asks for one if it is)
    l.renderVals().onAprCode(typing("12ab34"));
    expect(l.state.aprCode).toBe("1234"); // digits only
    expect(l.renderVals().aprDisabled).toBe(true); // a half code is not sent
    l.renderVals().onAprCode(typing("1234567"));
    expect(l.state.aprCode).toBe("123456"); // six digits at most
    expect(l.renderVals().aprDisabled).toBe(false);
    l.renderVals().aprClose();
    expect(l.state).toMatchObject({ aprOpen: false, aprReq: "", aprPass: "", aprCode: "" });
  });

  it("does nothing without a request id and a passphrase, and while busy", async () => {
    const l = await logic({ screen: "lock", lockStep: LOCK_PHRASE, aprOpen: true });
    await l.decideApproval(true);
    expect(l.state.aprBusy).toBe(false);
    l.state = { ...l.state, aprReq: "rq_1", aprPass: "p", aprBusy: true };
    const before = { ...l.state };
    await l.decideApproval(false);
    expect(l.state.aprReq).toBe(before.aprReq);
    expect(l.state.aprResult).toBe("");
  });

  it("without a broker the decision is refused in the panel, the passphrase and code are wiped, and the request id stays for another try", async () => {
    const l = await logic({ screen: "lock", lockStep: LOCK_PHRASE, aprOpen: true, aprReq: "rq_1", aprPass: "p", aprCode: "123456" });
    await l.decideApproval(true);
    expect(l.state).toMatchObject({ aprBusy: false, aprPass: "", aprCode: "", aprReq: "rq_1", aprOpen: true });
    expect(l.state.aprErr).toMatch(/not available in this build/);
    expect(l.state.aprResult).toBe("");
  });

  it("the decision line is gone as soon as an unlock attempt starts, so it does not follow the user to the code step", async () => {
    const l = await logic({ screen: "lock", lockStep: LOCK_PHRASE, passInput: "pw", aprResult: "approved with the passphrase · the vault is still locked" });
    expect(l.renderVals()).toMatchObject({ aprResultShow: true });
    await l.doUnlock();
    expect(l.state.aprResult).toBe("");
    expect(l.renderVals()).toMatchObject({ aprResultShow: false });
  });

  it("a lock wipes the panel", async () => {
    const l = await logic({ screen: "app", aprOpen: true, aprReq: "rq_1", aprPass: "p", aprCode: "123456", aprResult: "approved", aprErr: "x" });
    l.showLock("");
    expect(l.state).toMatchObject({ aprOpen: false, aprReq: "", aprPass: "", aprCode: "", aprResult: "", aprErr: "", screen: "lock" });
  });
});

describe("the second-factor dialog (S5c)", () => {
  it("opens for a node with the refused call remembered, takes six digits, and shows its refusal inside", async () => {
    const l = await logic();
    let ran = 0;
    l.askSecondFactor({ node: "atlas", retry: () => { ran++; } });
    expect(l.state).toMatchObject({ dialog: "tf", tf: { node: "atlas", code: "", err: "", busy: false } });
    let v = l.renderVals();
    expect(v).toMatchObject({ dlgTf: true, tfNode: "atlas", tfCode: "", tfDisabled: true, tfErrShow: false });
    v.onTfCode(typing("12 34x56789"));
    v = l.renderVals();
    expect(v).toMatchObject({ tfCode: "123456", tfDisabled: false });
    l.state = { ...l.state, tf: { ...l.state.tf, err: "That code was not accepted." } };
    expect(l.renderVals()).toMatchObject({ tfErrShow: true, tfErr: "That code was not accepted." });
    expect(ran).toBe(0); // nothing is repeated before the broker accepts a code
  });

  it("Cancel drops the refused call: it never runs", async () => {
    const l = await logic();
    let ran = 0;
    l.askSecondFactor({ node: "atlas", retry: () => { ran++; } });
    l.closeSecondFactor();
    expect(l.state).toMatchObject({ dialog: null, tf: null });
    expect(l._tfRetry).toBeNull();
    await l.verifySecondFactor();
    expect(ran).toBe(0);
  });

  it("Escape, the scrim or any other way of closing wipes the half-typed code and drops the refused call", async () => {
    const l = await logic();
    l._mounted = true;
    l.askSecondFactor({ node: "atlas", retry: () => {} });
    l.renderVals().onTfCode(typing("123"));
    expect(l.state.tf.code).toBe("123");
    l.setState({ dialog: null }); // what Escape and the scrim do
    l.renderVals();
    await Promise.resolve();
    expect(l.state.tf).toBeNull();
    expect(l._tfRetry).toBeNull();
  });

  it("is a dialog only when open, and a lock drops it together with the refused call", async () => {
    const l = await logic();
    expect(l.renderVals().dlgTf).toBe(false);
    l.askSecondFactor({ node: "atlas", retry: () => {} });
    l.showLock("");
    expect(l.state).toMatchObject({ dialog: null, tf: null });
    expect(l._tfRetry).toBeNull();
    expect(l.renderVals().dlgTf).toBe(false);
  });

  it("a lock ends the five-minute countdown: the chip and its timer are gone on the Lock screen", async () => {
    const l = await logic();
    l.state = { ...l.state, tfUntil: Date.now() + 200_000 };
    l.tfTick();
    expect(l._tfI).toBeDefined();
    l.showLock("");
    expect(l.state.tfUntil).toBe(0);
    expect(l.renderVals()).toMatchObject({ inspTf: false, inspTfLabel: "" });
    clearInterval(l._tfI);
  });

  it("without a broker the code is refused, the dialog closes and the call is not repeated", async () => {
    const l = await logic();
    let ran = 0;
    l.askSecondFactor({ node: "atlas", retry: () => { ran++; } });
    l.renderVals().onTfCode(typing("123456"));
    await l.verifySecondFactor();
    expect(ran).toBe(0);
    expect(l.state.dialog).toBeNull();
  });

  it("a read that is refused without anything to repeat keeps the older advice instead of opening a dialog that could not finish", async () => {
    const l = await logic();
    const e = { source: "broker", code: "two_factor_required", message: "x" };
    expect(l.routeReadError(e, { op: "entry.reveal", node: "atlas", entry: "e1" })).toMatchObject({ route: "two-factor" });
    expect(l.state.dialog).not.toBe("tf");
    expect(l.state.notice.text).toContain("This needs a fresh second factor.");
    expect(l.routeReadError(e, { op: "entry.reveal", node: "atlas", entry: "e1", retry: () => {} })).toEqual({ route: "two-factor" });
    expect(l.state.dialog).toBe("tf");
  });
});

describe("Undo and Generate in the field dialog", () => {
  const entryOpen = { openEntry: "e-a2", selected: "atlas" };

  it("Undo shows only for the entry it belongs to, in the node it belongs to, within the login it was made in", async () => {
    const l = await logic(entryOpen);
    expect(l.renderVals()).toMatchObject({ undoShow: false, undoMsgShow: false });
    const u = { node: "atlas", entry: "e-a2", audit: "a_1", text: "remove field", epoch: l.model.epoch };
    l.state = { ...l.state, undo: u };
    expect(l.renderVals()).toMatchObject({ undoShow: true, undoText: "remove field" });
    l.state = { ...l.state, openEntry: "e-a3" };
    expect(l.renderVals().undoShow).toBe(false);
    l.state = { ...l.state, openEntry: "e-a2", selected: "beacon" };
    expect(l.renderVals().undoShow).toBe(false);
    l.state = { ...l.state, selected: "atlas", undo: { ...u, epoch: l.model.epoch + 1 } };
    expect(l.renderVals().undoShow).toBe(false); // an audit id from an earlier login is not offered
  });

  it("the broker's words after an undo show for that entry only", async () => {
    const l = await logic(entryOpen);
    l.state = { ...l.state, undoDone: { entry: "e-a2", text: "Restored: 5 fields (undone remove field)" } };
    expect(l.renderVals()).toMatchObject({ undoMsgShow: true, undoMsg: "Restored: 5 fields (undone remove field)" });
    l.state = { ...l.state, openEntry: "e-a3" };
    expect(l.renderVals().undoMsgShow).toBe(false);
  });

  const addForm = (over: Record<string, unknown> = {}) => ({
    mode: "add", node: "atlas", entry: "e-a2", entryName: "pg-main", field: null, label: "", origLabel: "", value: "", type: "auto", origType: "auto",
    masked: "auto", origMasked: "auto", index: 5, busy: false, gl: "24", gs: true, gp: false, gen: false, genBits: 0, ...over,
  });

  it("the generator starts at 24 characters with symbols, and a generated value is shown masked with its entropy, never as text", async () => {
    const l = await logic({ dialog: "field", fieldForm: addForm() });
    expect(l.renderVals()).toMatchObject({ fdGl: "24", fdGs: true, fdGp: false, fdGenOn: false, fdGenNote: "" });
    const secret = "fixture-generated-SECRET-VALUE-0123456789";
    l.state = { ...l.state, fieldForm: addForm({ value: secret, gen: true, genBits: 142, gl: "41" }) };
    const v = l.renderVals();
    expect(v.fdGenOn).toBe(true);
    expect(v.fdValue).toBe("•".repeat(32)); // masked, and bounded
    expect(JSON.stringify(v)).not.toContain(secret); // the value is in no binding at all
    expect(v.fdGenNote).toBe("41 characters · about 142 bits of entropy · shown masked, never copied");
    expect(v.fdValueRows).toBe(2);
    // the write path still gets the real value
    expect(l.fieldPlan().disabled).toBe(false);
    expect(l.state.fieldForm.value).toBe(secret);
  });

  it("Clear returns to an empty, editable value; pronounceable has no symbols", async () => {
    const l = await logic({ dialog: "field", fieldForm: addForm({ value: "x".repeat(24), gen: true, genBits: 100 }) });
    l.renderVals().fdGenClear();
    expect(l.state.fieldForm).toMatchObject({ value: "", gen: false, genBits: 0 });
    expect(l.renderVals()).toMatchObject({ fdGenOn: false, fdGenNote: "" });
    expect(l.fieldPlan().disabled).toBe(true); // nothing to save
    l.renderVals().onFdGp();
    expect(l.renderVals()).toMatchObject({ fdGp: true, fdGs: false });
    l.renderVals().onFdGl(typing("40"));
    expect(l.renderVals().fdGl).toBe("40");
  });

  it("without a broker Generate says so and makes nothing: the page has no generator of its own", async () => {
    const l = await logic({ dialog: "field", fieldForm: addForm() });
    await l.generateField();
    expect(l.state.fieldForm.gen).toBe(false);
    expect(l.state.fieldForm.value).toBe("");
    expect(l.state.notice).toMatchObject({ kind: "info" });
  });

  it("Generate is the Add dialog's: an edit never generates", async () => {
    const l = await logic({ dialog: "field", fieldForm: addForm({ mode: "edit", field: "f_1" }) });
    await l.generateField();
    expect(l.state.notice ?? null).toBeNull();
  });
});

describe("the node dialog and the inspector chips", () => {
  it("'Hide this node's name' is off by default, toggles, and counts as a change to the form", async () => {
    const l = await logic({ dialog: "addNode" });
    expect(l.renderVals()).toMatchObject({ advPn: false, advTwofa: true });
    expect(l.nodeFormDirty()).toBe(false);
    l.renderVals().onAdvPn();
    expect(l.renderVals().advPn).toBe(true);
    expect(l.nodeFormDirty()).toBe(true);
    l.renderVals().onAdvPn();
    expect(l.nodeFormDirty()).toBe(false);
  });

  it("a choice left from one node never rides into the next", async () => {
    const l = await logic({ dialog: null, addNodeAdv: { subShare: true, twofa: true, childRead: false, agentAccess: "read-write", pn: true } });
    l._mounted = true;
    l.scheduleNodeFormReset();
    await Promise.resolve();
    expect(l.state.addNodeAdv.pn).toBe(false);
  });

  it("the second-factor chip is the broker's word: a static chip, the action while no window is open, and a countdown while one is", async () => {
    const l = await logic({ selected: "atlas" });
    let v = l.renderVals();
    expect(typeof v.insp2fa).toBe("boolean");
    expect(v.inspTf).toBe(false); // no window yet
    expect(v.inspTfLabel).toBe("");
    expect(v.inspTfBtn).toBe(v.insp2fa); // the action shows exactly where a node asks for a factor
    expect(v.inspNameHidden).toBe(false);
    l.state = { ...l.state, tfUntil: Date.now() + 125_000 };
    v = l.renderVals();
    expect(v.inspTf).toBe(true);
    expect(v.inspTfLabel).toMatch(/^second factor given · 2:0\d$/);
    expect(v.inspTfBtn).toBe(false); // the action gives way to the countdown
  });
});
