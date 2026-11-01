/**
 * The shim's `fields_preview` port (shim/preview.mjs) against the cases the Rust it ports already pins.
 *
 *   node --test tests/real/preview.test.mjs        (npm run test:real runs it with the drift guard, before the browser suite)
 *
 * Every expectation below is copied from a unit test in the Rust source (`crates/core/src/parser.rs`, `inference.rs`,
 * `apps/desktop/src-tauri/src/fields_preview.rs`), not derived from the port, so a port that drifts fails here before a journey
 * can pass on a preview the shipped shell would not have made. Pure Node: no browser, no daemon.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { inferFieldType, parseBulkSegments, preview } from "./shim/preview.mjs";

const flat = (input) => parseBulkSegments(input).flat();
const text = (input, split = false) => preview({ text: input, split });

// ── parser.rs ────────────────────────────────────────────────────────────────────────────────────────────────────────────────

test("parser: label: value, first colon-space wins, a bare url or host:port is unlabelled", () => {
  assert.deepEqual(flat("host: db.internal"), [{ label: "host", value: "db.internal" }]);
  assert.deepEqual(flat("db.internal:5432"), [{ label: "", value: "db.internal:5432" }]);
  assert.deepEqual(flat("https://api.example.com"), [{ label: "", value: "https://api.example.com" }]);
  assert.deepEqual(flat("url: https://api.example.com"), [{ label: "url", value: "https://api.example.com" }]);
  assert.deepEqual(flat("note: ratio is 3:1"), [{ label: "note", value: "ratio is 3:1" }]);
  assert.equal(flat("https: not actually a label")[0].label, "", "a reserved scheme is not a label");
});

test("parser: a label-only first line captures the lines that follow, verbatim", () => {
  assert.deepEqual(flat("private key:\nline one\nline two"), [{ label: "private key", value: "line one\nline two" }]);
  const input = "username: deploy\n///\nprivate key:\nBEGIN-x\nbody\nEND-x\n///\npassphrase: correct horse battery staple";
  const fields = flat(input);
  assert.equal(fields.length, 3);
  assert.deepEqual(fields[0], { label: "username", value: "deploy" });
  assert.equal(fields[1].label, "private key");
  assert.equal(fields[1].value, "BEGIN-x\nbody\nEND-x", "exactly one trailing terminator is trimmed");
  assert.deepEqual(fields[2], { label: "passphrase", value: "correct horse battery staple" });
});

test("parser: an unstructured blob is one unlabelled field; value whitespace and duplicate labels survive", () => {
  const blob = "prod db is at 203.0.113.4 port 5432 user svc_app pw Z9!kq2 rotate quarterly";
  assert.deepEqual(flat(blob), [{ label: "", value: blob }]);
  assert.equal(flat("password:  leading and trailing  ")[0].value, " leading and trailing  ");
  assert.deepEqual(flat("key: one\nkey: two"), [{ label: "key", value: "one" }, { label: "key", value: "two" }]);
});

test("parser: CRLF and a lone CR both split lines; empty input is no fields", () => {
  assert.equal(flat("host: a\r\nport: b").length, 2);
  assert.equal(flat("host: a\rport: b").length, 2);
  assert.deepEqual(flat(""), []);
});

test("parser: segments keep the /// boundaries, and an unlabelled blob keeps its own terminator", () => {
  const shape = parseBulkSegments("a: 1\nb: 2\n///\nloose blob\n///\nc: 3").map((s) => s.map((f) => [f.label, f.value]));
  assert.deepEqual(shape, [[["a", "1"], ["b", "2"]], [["", "loose blob\n"]], [["c", "3"]]]);
});

test("parser: empty segments produce no inner list, and no separator is one segment", () => {
  assert.deepEqual(parseBulkSegments(""), []);
  assert.deepEqual(parseBulkSegments("///"), []);
  assert.deepEqual(parseBulkSegments("///\n///\n///"), []);
  assert.equal(parseBulkSegments("///\na: 1\n///\n///\nb: 2\n///").length, 2);
  assert.equal(parseBulkSegments("a: 1\nb: 2").length, 1);
  for (const pathological of ["\0", "🎉".repeat(1000), "a".repeat(50), ":", ": ", "\r\r\r\n\n\r"]) parseBulkSegments(pathological);
});

// ── inference.rs ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

test("inference: a value is classified before its label", () => {
  assert.equal(inferFieldType("x", "https://a.example"), "url");
  assert.equal(inferFieldType("x", "5432"), "port");
  assert.equal(inferFieldType("x", "70000"), "text");
  assert.equal(inferFieldType("x", "203.0.113.4"), "host");
  assert.equal(inferFieldType("x", "db.internal.example"), "host");
  assert.equal(inferFieldType("x", "sk-abc"), "api-key");
  assert.equal(inferFieldType("x", "JBSWY3DPEHPK3PXP"), "totp-seed");
  assert.equal(inferFieldType("x", "a@b.example"), "username");
  assert.equal(inferFieldType("user", "deploy"), "username");
  assert.equal(inferFieldType("password", "pw-test"), "password");
  assert.equal(inferFieldType("api key", "not-a-prefix"), "api-key");
  assert.equal(inferFieldType("notes", "anything"), "text");
});

// ── fields_preview.rs ────────────────────────────────────────────────────────────────────────────────────────────────────────

test("preview: a paste is one entry with every field in order and verbatim", () => {
  const p = text("host: db.internal\nport: 5432\nusername: svc\npassword: pw-test-1  \n");
  assert.equal(p.segments.length, 1);
  const s = p.segments[0];
  assert.equal(s.suggestedName, "host");
  assert.equal(s.fieldCount, 4);
  assert.deepEqual(s.fields.map((f) => f.label), ["host", "port", "username", "password"]);
  assert.equal(s.fields[3].value, "pw-test-1  ", "a trailing space is part of the value");
  assert.equal(s.fields[3].masked, true);
  assert.equal(s.fields[3].type, "password");
  assert.equal(s.fields[3].inferredType, "password");
  assert.equal(s.fields[3].typeOverridden || s.fields[3].maskedOverridden, false);
  assert.equal(s.entryType, "server");
  assert.equal(p.singleBlobHint, false);
});

test("preview: the split toggle makes one entry per block and names the unlabelled", () => {
  const t = "host: a.example\npassword: p1\n///\nSOME UNLABELLED BLOCK\n///\nusername: u3";
  const merged = text(t, false);
  assert.equal(merged.segments.length, 1);
  assert.equal(merged.segments[0].fieldCount, 4);
  const split = text(t, true);
  assert.equal(split.segments.length, 3);
  assert.equal(split.segments[0].suggestedName, "host");
  assert.equal(split.segments[1].suggestedName, "untitled 2");
  assert.equal(split.segments[1].fields[0].label, "");
  assert.equal(split.segments[2].suggestedName, "username");
  assert.equal(split.segments.reduce((n, s) => n + s.fieldCount, 0), merged.segments[0].fieldCount);
});

test("preview: empty input previews nothing rather than failing", () => {
  assert.deepEqual(text("", false).segments, []);
  assert.deepEqual(text("", true).segments, []);
  assert.deepEqual(preview({ fields: [] }).segments, []);
});

test("preview: a single unlabelled blob of three lines earns the split-by-line hint", () => {
  assert.equal(text("one\ntwo\nthree\n", false).singleBlobHint, true);
  assert.equal(text("one\ntwo\n", false).singleBlobHint, false);
  assert.equal(text("a: 1\nb: 2\nc: 3\n", false).singleBlobHint, false);
  assert.equal(text("one\n\n\n", false).singleBlobHint, false);
  assert.equal(text("one\ntwo\nthree\n", true).singleBlobHint, true);
});

test("preview: a lone note is a note entry; a TOTP seed makes a totp entry", () => {
  assert.equal(text("note: remember to call\n").segments[0].entryType, "note");
  const t = text("totp seed: JBSWY3DPEHPK3PXP\n").segments[0];
  assert.equal(t.hasTotp, true);
  assert.equal(t.entryType, "totp");
  assert.equal(t.sensitivity, "high");
});

test("preview: structured fields keep their overrides and say so", () => {
  const s = preview({ fields: [{ label: "token", value: "abc", type: "text", masked: true }, { label: "password", value: "pw-test" }] }).segments[0];
  assert.equal(s.fieldCount, 2);
  const [a, b] = s.fields;
  assert.equal(a.type, "text");
  assert.equal(a.masked && a.maskedOverridden && a.typeOverridden, true);
  assert.equal(a.inferredType, inferFieldType("token", "abc"));
  assert.equal(b.typeOverridden || b.maskedOverridden, false);
  assert.equal(b.type, "password");
});

test("preview: bad input is refused as invalid_fields, by index, and never echoes what it was", () => {
  const refused = (args) => {
    try {
      preview(args);
    } catch (e) {
      return e;
    }
    assert.fail("expected a refusal");
  };
  const both = refused({ text: "a: b", fields: [] });
  assert.deepEqual([both.source, both.code], ["bridge", "invalid_fields"]);
  refused({});
  for (const [bad, needle] of [
    ["not an array", "array"],
    [[1], "fields[0] must be an object"],
    [[{ label: "a", value: "SECRET-A", extra: 1 }], "fields[0] has a key"],
    [[{ label: "a", value: 7 }], "wrong type"],
    [[{ label: "a", value: "x" }, { label: "bad\nlabel", value: "SECRET-B" }], "field"],
  ]) {
    const e = refused({ fields: bad });
    assert.equal(e.code, "invalid_fields");
    assert.ok(e.message.includes(needle), `${needle}: ${e.message}`);
    assert.ok(!e.message.includes("SECRET-A") && !e.message.includes("SECRET-B"), `an error echoed a value: ${e.message}`);
    assert.ok(!e.message.includes("bad\nlabel"), "an error echoed a label");
  }
});

test("preview: answers in the wire names the screen reads", () => {
  const v = text("password: pw-test\n");
  assert.equal(v.singleBlobHint, false);
  assert.deepEqual(Object.keys(v.segments[0]), ["suggestedName", "fields", "entryType", "sensitivity", "fieldCount", "hasTotp"]);
  assert.deepEqual(Object.keys(v.segments[0].fields[0]), ["label", "value", "type", "masked", "inferredType", "typeOverridden", "maskedOverridden"]);
});
