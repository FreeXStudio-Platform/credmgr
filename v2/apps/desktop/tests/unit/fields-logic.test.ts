// The field dialog's logic (logic/fields.js) and the inspector's guards (logic/inspector.js): what Save would send, from what the broker said about a
// field; the form that starts from it; and what is forgotten when a login ends.  Pure parts only: the controls themselves are driven by
// tests/e2e/field-ui-*.spec.ts against the fixture broker.
import { describe, expect, it } from "vitest";

import Component from "../../src/design/logic/core.js";
import { FIELD_TYPES } from "../../src/design/logic/fields.js";
import { fieldName } from "../../src/design/logic/inspector.js";

async function logic(state: Record<string, unknown> = {}) {
  const l = new (Component as any)({ mode: "pro" });
  await l.model.boot();
  l.state = { ...l.state, ...state };
  // a host that applies setState at once and renders nothing (the real one is DCHost, which also schedules a React render)
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

const form = (over: Record<string, unknown> = {}) => ({
  mode: "edit", node: "atlas", entry: "e-a2", entryName: "pg-main", field: "f_00a20005", index: 4,
  label: "note", origLabel: "note", value: "", type: "text", origType: "text", masked: "auto", origMasked: "auto", busy: false, ...over,
});

describe("fieldName", () => {
  it("is the label, or 'field N' (numbered from 1) when the label is empty or blank", () => {
    expect(fieldName({ label: "host" }, 0)).toBe("host");
    expect(fieldName({ label: "" }, 0)).toBe("field 1");
    expect(fieldName({ label: "   " }, 3)).toBe("field 4");
    expect(fieldName({ label: " padded " }, 0)).toBe(" padded "); // free text, shown as it is
  });
});

describe("fieldPlan (what Save would send)", () => {
  it("nothing without a form, and nothing while a save is in flight", async () => {
    const l = await logic({ fieldForm: null });
    expect(l.fieldPlan().disabled).toBe(true);
    l.state = { ...l.state, fieldForm: form({ label: "changed", busy: true }) };
    expect(l.fieldPlan().disabled).toBe(true);
  });

  it("add: needs a value; the label may be empty; a label over 200 characters is a problem named on the form", async () => {
    const l = await logic({ fieldForm: form({ mode: "add", label: "", origLabel: "", value: "" }) });
    expect(l.fieldPlan()).toMatchObject({ disabled: true, problem: "" });
    l.state = { ...l.state, fieldForm: form({ mode: "add", label: "", origLabel: "", value: "v" }) };
    expect(l.fieldPlan().disabled).toBe(false);
    l.state = { ...l.state, fieldForm: form({ mode: "add", label: "x".repeat(201), origLabel: "", value: "v" }) };
    expect(l.fieldPlan()).toMatchObject({ disabled: true, problem: "A label is at most 200 characters." });
    l.state = { ...l.state, fieldForm: form({ mode: "add", label: "x".repeat(200), origLabel: "", value: "v" }) };
    expect(l.fieldPlan().disabled).toBe(false);
    // 200 characters is a count of characters, not of UTF-16 units: an emoji is one
    l.state = { ...l.state, fieldForm: form({ mode: "add", label: "😀".repeat(200), origLabel: "", value: "v" }) };
    expect(l.fieldPlan().disabled).toBe(false);
  });

  it("edit: nothing changed is nothing to save; each changed thing is its own key and an unchanged one is not sent", async () => {
    const l = await logic({ fieldForm: form() });
    expect(l.fieldPlan()).toMatchObject({ disabled: true, patch: {} });
    const plan = (over: Record<string, unknown>) => {
      l.state = { ...l.state, fieldForm: form(over) };
      return l.fieldPlan();
    };
    expect(plan({ label: "remarks" })).toMatchObject({ disabled: false, patch: { label: "remarks" } });
    expect(plan({ value: "new" })).toMatchObject({ disabled: false, patch: { value: "new" } });
    expect(plan({ type: "password" })).toMatchObject({ disabled: false, patch: { type: "password" } });
    expect(plan({ type: "auto" })).toMatchObject({ disabled: false, patch: { type: "auto" } }); // "auto" clears the pin
    expect(plan({ masked: "hidden" })).toMatchObject({ patch: { masked: true } });
    expect(plan({ masked: "shown" })).toMatchObject({ patch: { masked: false } });
    expect(plan({ origMasked: "hidden", masked: "auto" })).toMatchObject({ patch: { masked: "auto" } });
    expect(plan({ label: "remarks", value: "new", type: "url", masked: "shown" }).patch).toEqual({ label: "remarks", value: "new", type: "url", masked: false });
    // an empty "new value" means keep the value; it is never sent as an empty value
    expect(plan({ label: "remarks", value: "" }).patch).toEqual({ label: "remarks" });
    // a label cleared to nothing is a change (an empty label is allowed)
    expect(plan({ label: "" }).patch).toEqual({ label: "" });
    // a label over the limit blocks the save
    expect(plan({ label: "x".repeat(201) })).toMatchObject({ disabled: true, problem: "A label is at most 200 characters." });
  });

  it("remove: always possible unless busy", async () => {
    const l = await logic({ fieldForm: form({ mode: "remove" }) });
    expect(l.fieldPlan().disabled).toBe(false);
    l.state = { ...l.state, fieldForm: form({ mode: "remove", busy: true }) };
    expect(l.fieldPlan().disabled).toBe(true);
  });
});

describe("the field dialog", () => {
  it("starts from what the broker said about the field: its label, its pin if it has one, its masking if pinned; never its value", async () => {
    const l = await logic();
    l.openFieldDlg("edit", "atlas", { id: "e-a2", name: "pg-main" }, { id: "f_1", label: "note", type: "text", masked: false, typeOverridden: true, maskedOverridden: false }, 4);
    expect(l.state.dialog).toBe("field");
    expect(l.state.fieldForm).toMatchObject({ mode: "edit", node: "atlas", entry: "e-a2", field: "f_1", label: "note", origLabel: "note", value: "", type: "text", origType: "text", masked: "auto", origMasked: "auto" });
    l.openFieldDlg("edit", "atlas", { id: "e-a2", name: "pg-main" }, { id: "f_2", label: "pw", type: "password", masked: true, typeOverridden: false, maskedOverridden: true }, 3);
    expect(l.state.fieldForm).toMatchObject({ type: "auto", origType: "auto", masked: "hidden", origMasked: "hidden" });
    l.openFieldDlg("edit", "atlas", { id: "e-a2", name: "pg-main" }, { id: "f_3", label: "host", type: "host", masked: false, typeOverridden: false, maskedOverridden: true }, 0);
    expect(l.state.fieldForm).toMatchObject({ masked: "shown" });
    l.openFieldDlg("add", "atlas", { id: "e-a2", name: "pg-main" }, null, 5);
    expect(l.state.fieldForm).toMatchObject({ mode: "add", field: null, label: "", value: "" });
  });

  it("offers every field type the broker has, and 'auto'", async () => {
    expect(FIELD_TYPES).toEqual(["password", "api-key", "private-key", "seed-phrase", "totp-seed", "username", "host", "port", "url", "certificate", "text"]);
    const l = await logic({ dialog: "field", fieldForm: form() });
    const v = l.renderVals();
    expect(v.fdTypeOpts.map((o: any) => o.id)).toEqual(["auto", ...FIELD_TYPES]);
    expect(v.fdMaskOpts.map((o: any) => o.id)).toEqual(["auto", "hidden", "shown"]);
    expect(v.fdIsEdit).toBe(true);
    expect(v.fdVariant).toBe("primary");
    l.state = { ...l.state, fieldForm: form({ mode: "remove", origLabel: "note" }) };
    expect(l.renderVals()).toMatchObject({ fdIsRemove: true, fdVariant: "danger", fdSaveLabel: "Remove field", fdRemoveText: "Remove the field “note” from “pg-main”? The entry keeps its other fields." });
  });

  it("a form that is not open reads as blank, so no value can show through a closed dialog", async () => {
    const l = await logic({ dialog: null, fieldForm: form({ value: "fixture-value-should-not-show" }) });
    const v = l.renderVals();
    expect(v.dlgField).toBe(false);
    expect(JSON.stringify({ ...v, onFdLabel: 0, onFdValue: 0, onFdType: 0, onFdMasked: 0, saveFieldForm: 0, cancelFieldDlg: 0 })).not.toContain("fixture-value-should-not-show");
  });

  it("typing clears the last attempt's error, and the busy flag does not", async () => {
    const l = await logic({ dialog: "field", fieldForm: form(), fieldErrors: { "field.save": "no", "entry.name": "keep" } });
    l.setFieldForm({ busy: true }, true);
    expect(l.state.fieldErrors["field.save"]).toBe("no");
    l.setFieldForm({ label: "x" });
    expect(l.state.fieldErrors).toEqual({ "entry.name": "keep" });
  });
});

describe("what a login's end makes the inspector forget", () => {
  it("the reads it remembered having asked for belong to one login: after the model clears they are asked again", async () => {
    const l = await logic();
    l.syncFieldGuards(); // (the first render of this login)
    l._detailAsked = new Set(["atlas\u0000e-a1"]);
    l._detailErr = { "atlas\u0000e-a1": "internal" };
    l._unmaskedAsked = { "atlas\u0000e-a1": "0|f_1" };
    l._unmaskedPending = { "atlas\u0000e-a1": true };
    l._unmaskedFor = "atlas\u0000e-a1";
    l.syncFieldGuards();
    expect(l._detailAsked).toBeInstanceOf(Set); // the same login: kept
    l.model.clear();
    l.syncFieldGuards();
    expect(l._detailAsked).toBeNull();
    expect(l._detailErr).toBeNull();
    expect(l._unmaskedAsked).toBeNull();
    expect(l._unmaskedPending).toBeNull();
    expect(l._unmaskedFor).toBeNull();
  });
});
