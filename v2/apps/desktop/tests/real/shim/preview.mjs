/**
 * `fields_preview`: the shell's LOCAL bulk-paste preview, rewritten in Node (ADR-078, `docs/08_FIELD_MODEL.md §5`).
 *
 * In the app this command is `src-tauri/src/fields_preview.rs`: no broker, no socket, no session, no audit record. It runs
 * `credmgr_core::parser`, `credmgr_core::fields` and `credmgr_core::inference` on the text the user is still typing, and answers
 * what the broker will store. This file is NOT that Rust. It is a line-for-line port of the same four sources, because the shim
 * is Node and credmgr-core is not callable from it (the shim speaks to `credmgrd` over its socket, and `credmgrd` never parses
 * this grammar: "the client previews, then sends the previewed `fields` to `entry_create` / `entry_create_batch` verbatim").
 *
 * What stays real regardless of this port: everything the page SENDS after a preview goes to the real broker, which validates it
 * with the real core code and stores it. A wrong port therefore shows up as a journey that stores something other than what it
 * previewed, not as a vault that holds something the broker never checked. The clipboard in `shim.mjs` is replaced the same way
 * and for the same reason, and the README says so.
 *
 * Ported, with the Rust source named for each piece:
 *   parser.rs      `split_lines`, `split_segments`, `parse_segment`, `parse_bulk_segments`, the label grammar
 *   inference.rs   `infer_field_type`, `default_masked`, `default_sensitivity`, `infer_entry_type_labelled`
 *   fields.rs      `check_label` (and the size cap), `effective`, `project`, `create`'s refusal order
 *   fields_preview.rs   `parse_field_inputs`, `segment`, `is_single_blob`, `preview`
 *
 * Not ported: minting field ids (a preview never shows one) and the exact encoded-size count of the 16 MiB cap (estimated).
 * Where this file and the Rust disagree, the Rust is right; `tests/real/preview.test.mjs` pins the cases that matter.
 */
import { bridgeError } from "./bridge-error.mjs";

// ───────────────────────────────────────────────── parser.rs ─────────────────────────────────────────────────

const RESERVED_SCHEMES = ["http", "https", "ftp", "ftps", "ssh", "sftp", "git", "file", "postgres", "postgresql", "mysql", "redis", "mongodb", "amqp", "otpauth", "data", "mailto", "s3", "gs"];

/** `LABEL ::= 1..40 chars matching [A-Za-z0-9 _.()#/-]+`, excluding the reserved URI schemes. */
function isValidLabel(s) {
  const len = [...s].length;
  if (len === 0 || len > 40) return false;
  if (!/^[A-Za-z0-9 _.()#/-]+$/.test(s)) return false;
  return !RESERVED_SCHEMES.includes(s.toLowerCase());
}

/** `LABELLED_LINE ::= LABEL ":" " " VALUE_TEXT`: exactly one literal space separates, everything after it is the value. */
function parseLabelledLine(line) {
  const sep = line.indexOf(": ");
  if (sep < 0) return null;
  const label = line.slice(0, sep);
  if (!isValidLabel(label)) return null;
  return { label, value: line.slice(sep + 2) };
}

/** `LABEL_ONLY ::= LABEL ":" WS* LINE_END`. */
function parseLabelOnly(line) {
  const trimmed = line.trimEnd();
  if (!trimmed.endsWith(":")) return null;
  const label = trimmed.slice(0, -1);
  return isValidLabel(label) ? label : null;
}

/** Split on `\n`, `\r\n` and a lone `\r`, keeping each line's offsets so a multi-line value is an exact substring of the input. */
function splitLines(input) {
  if (input === "") return [];
  const lines = [];
  let start = 0;
  let i = 0;
  while (i < input.length) {
    const c = input[i];
    if (c === "\n") {
      lines.push({ content: input.slice(start, i), start, next: i + 1 });
      i += 1;
      start = i;
    } else if (c === "\r") {
      const contentEnd = i;
      i += 1;
      if (i < input.length && input[i] === "\n") i += 1;
      lines.push({ content: input.slice(start, contentEnd), start, next: i });
      start = i;
    } else {
      i += 1;
    }
  }
  if (start < input.length) lines.push({ content: input.slice(start), start, next: input.length });
  return lines;
}

function splitSegments(lines) {
  const segments = [];
  let current = [];
  for (const line of lines) {
    if (line.content.trim() === "///") {
      segments.push(current);
      current = [];
    } else {
      current.push(line);
    }
  }
  segments.push(current);
  return segments;
}

/** Strip exactly one trailing terminator (`\r\n`, `\n` or `\r`). */
function trimOneTrailingTerminator(s) {
  if (s.endsWith("\r\n")) return s.slice(0, -2);
  if (s.endsWith("\n") || s.endsWith("\r")) return s.slice(0, -1);
  return s;
}

function parseSegment(input, lines) {
  const nonEmpty = lines.filter((l) => l.content.trim() !== "");
  if (nonEmpty.length > 0 && nonEmpty.every((l) => parseLabelledLine(l.content) !== null)) {
    return nonEmpty.map((l) => parseLabelledLine(l.content));
  }
  const first = lines[0];
  const last = lines[lines.length - 1];
  if (!first || !last) return [];
  const label = parseLabelOnly(first.content);
  if (label !== null) {
    return [{ label, value: trimOneTrailingTerminator(input.slice(first.next, last.next)) }];
  }
  return [{ label: "", value: input.slice(first.start, last.next) }];
}

/** One inner list per non-empty `///` segment, in input order; every inner list holds at least one field. */
export function parseBulkSegments(input) {
  return splitSegments(splitLines(input))
    .filter((seg) => seg.length > 0)
    .map((seg) => parseSegment(input, seg))
    .filter((fields) => fields.length > 0);
}

// ───────────────────────────────────────────────── inference.rs ──────────────────────────────────────────────

const FIELD_TYPES = ["password", "api-key", "private-key", "seed-phrase", "totp-seed", "username", "host", "port", "url", "certificate", "text"];
const SENSITIVITIES = ["low", "medium", "high", "critical"];

const looksLikePrivateKey = (v) => v.includes("-----BEGIN") && v.includes("PRIVATE KEY-----");
const looksLikeCertificate = (v) => v.includes("-----BEGIN CERTIFICATE-----");

function looksLikeTotpSeed(v) {
  if (v.startsWith("otpauth://")) return true;
  const stripped = v.trim();
  const len = Buffer.byteLength(stripped, "utf8");
  return (len === 16 || len === 26 || len === 32) && /^[A-Z2-7]+$/.test(stripped);
}

function looksLikeSeedPhrase(v) {
  const words = v.split(/\s+/).filter(Boolean);
  return [12, 15, 18, 21, 24].includes(words.length) && words.every((w) => /^[a-z]*$/.test(w));
}

function looksLikeApiKey(v) {
  return v.startsWith("sk-") || v.startsWith("ghp_") || v.startsWith("github_pat_") || v.startsWith("AKIA") || v.startsWith("AIza") || /^xox[abprs]-/.test(v);
}

const looksLikeUrl = (v) => v.startsWith("http://") || v.startsWith("https://");

/** Rust's `str::parse::<u32>()` accepts an optional leading `+` and digits only. */
function looksLikePort(v) {
  if (!/^\+?[0-9]+$/.test(v)) return false;
  const n = Number(v);
  return n <= 0xffffffff && n >= 1 && n <= 65535;
}

function looksLikeIpv4(v) {
  const parts = v.split(".");
  // `parse::<u8>()`: digits only (an optional `+`), 0..=255.
  return parts.length === 4 && parts.every((p) => /^\+?[0-9]+$/.test(p) && Number(p) <= 255);
}

function looksLikeHostname(v) {
  if (v === "" || v.includes(" ") || v.includes("://")) return false;
  if (looksLikeIpv4(v)) return true;
  return v.includes(".") && /^[A-Za-z0-9.-]+$/.test(v);
}

function looksLikeEmail(v) {
  const at = v.indexOf("@");
  if (at < 0) return false;
  const local = v.slice(0, at);
  const domain = v.slice(at + 1);
  return local !== "" && domain.includes(".") && !domain.includes(" ");
}

const labelMatches = (label, needles) => needles.some((n) => label.toLowerCase().includes(n));

export function inferFieldType(label, value) {
  if (looksLikePrivateKey(value)) return "private-key";
  if (looksLikeCertificate(value)) return "certificate";
  if (looksLikeTotpSeed(value)) return "totp-seed";
  if (looksLikeSeedPhrase(value)) return "seed-phrase";
  if (looksLikeApiKey(value)) return "api-key";
  if (looksLikeUrl(value)) return "url";
  if (looksLikePort(value)) return "port";
  if (looksLikeHostname(value)) return "host";
  if (looksLikeEmail(value) || labelMatches(label, ["user"])) return "username";
  if (labelMatches(label, ["pass", "pwd", "secret"])) return "password";
  if (labelMatches(label, ["key", "token", "api"])) return "api-key";
  return "text";
}

const MASKED_BY_DEFAULT = ["password", "api-key", "private-key", "seed-phrase", "totp-seed"];
const defaultMasked = (type) => MASKED_BY_DEFAULT.includes(type);

function defaultSensitivity(type) {
  switch (type) {
    case "seed-phrase":
    case "private-key":
      return "critical";
    case "password":
    case "api-key":
    case "totp-seed":
    case "certificate":
      return "high";
    case "username":
    case "host":
    case "port":
    case "url":
      return "medium";
    default:
      return "low";
  }
}

const labelNamesANote = (label) => ["note", "notes"].includes(label.trim().toLowerCase());

/** `fields`: `[label, effectiveType]`. First rule that matches wins (R0..R4 in inference.rs). */
function inferEntryTypeLabelled(fields) {
  if (fields.length === 1 && labelNamesANote(fields[0][0])) return "note";
  const has = (t) => fields.some(([, ft]) => ft === t);
  if (has("totp-seed") && fields.length <= 2) return "totp";
  if (has("seed-phrase") || has("private-key")) return "wallet";
  if (has("certificate")) return "certificate";
  if (has("host") && has("username") && (has("password") || has("api-key"))) return "server";
  return "other";
}

// ───────────────────────────────────────────────── fields.rs / fields_preview.rs ─────────────────────────────

const LABEL_MAX_CHARS = 200;
const ENTRY_DOC_MAX_BYTES = 16 * 1024 * 1024;
const FIELD_INPUT_KEYS = ["label", "value", "type", "masked"];

const invalid = (message) => bridgeError("invalid_fields", message);

/** `fields::validate` for a new document: at least one field, label rules, the size cap. The refusal names an index, never a label. */
function validateNewDocument(inputs) {
  if (inputs.length === 0) return invalid("an entry holds at least one field");
  for (let index = 0; index < inputs.length; index++) {
    const label = inputs[index].label;
    if ([...label].length > LABEL_MAX_CHARS) return invalid(`field ${index}: a label is at most ${LABEL_MAX_CHARS} characters`);
    if ([...label].some((c) => c < " " || c === "\u007f")) return invalid(`field ${index}: a label is one line, with no control characters`);
  }
  const estimate = Buffer.byteLength(JSON.stringify({ v: 1, fields: inputs.map((f) => ({ id: "f_00000000", ...f })) }), "utf8");
  if (estimate > ENTRY_DOC_MAX_BYTES) return invalid(`field document is ${estimate} bytes; the limit is ${ENTRY_DOC_MAX_BYTES}`);
  return null;
}

/** `parse_field_inputs`: the JSON the screen holds, read into field inputs, refusing what the broker would refuse. */
function parseFieldInputs(fields) {
  if (!Array.isArray(fields)) throw invalid("fields must be an array of {label, value} objects");
  return fields.map((item, i) => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) throw invalid(`fields[${i}] must be an object`);
    if (Object.keys(item).some((k) => !FIELD_INPUT_KEYS.includes(k))) {
      throw invalid(`fields[${i}] has a key that is not one of: ${FIELD_INPUT_KEYS.join(", ")}`);
    }
    // serde's own rule for FieldInput: label and value are strings, type is a field type or null, masked is a bool or null.
    const typeOk = item.type === undefined || item.type === null || FIELD_TYPES.includes(item.type);
    const maskedOk = item.masked === undefined || item.masked === null || typeof item.masked === "boolean";
    if (typeof item.label !== "string" || typeof item.value !== "string" || !typeOk || !maskedOk) throw invalid(`fields[${i}] has a value of the wrong type`);
    return { label: item.label, value: item.value, type: item.type ?? undefined, masked: item.masked ?? undefined };
  });
}

function segment(inputs, number) {
  const refusal = validateNewDocument(inputs);
  if (refusal) throw refusal;
  const fields = inputs.map((f) => {
    const type = f.type ?? inferFieldType(f.label, f.value);
    return {
      label: f.label,
      value: f.value,
      type,
      masked: f.masked ?? defaultMasked(type),
      inferredType: inferFieldType(f.label, f.value),
      typeOverridden: f.type !== undefined,
      maskedOverridden: f.masked !== undefined,
    };
  });
  const typed = fields.map((f) => [f.label, f.type]);
  const named = inputs.map((f) => f.label.trim()).find((l) => l !== "");
  return {
    suggestedName: named ?? `untitled ${number}`,
    fields,
    entryType: inferEntryTypeLabelled(typed),
    sensitivity: typed.map(([, t]) => defaultSensitivity(t)).reduce((best, s) => (SENSITIVITIES.indexOf(s) > SENSITIVITIES.indexOf(best) ? s : best), "low"),
    fieldCount: fields.length,
    hasTotp: typed.some(([, t]) => t === "totp-seed"),
  };
}

/** A single unlabelled value spread over three or more non-blank lines: almost certainly several values pasted without labels. */
function isSingleBlob(parsed) {
  if (parsed.length !== 1) return false;
  const [only] = parsed;
  return only.label === "" && only.value.split("\n").filter((l) => l.trim() !== "").length >= 3;
}

/**
 * Preview `text` (parsed with the bulk grammar) or `fields` (already structured) - exactly one of the two.
 * @param {{text?: string, fields?: unknown, split?: boolean}} args  the keys the page's `invoke("fields_preview", ...)` carried
 */
export function preview({ text, fields, split }) {
  const hasText = text !== undefined && text !== null;
  const hasFields = fields !== undefined && fields !== null;
  if (hasText && hasFields) throw invalid("give text or fields, not both");
  if (!hasText && !hasFields) throw invalid("give text or fields to preview");
  if (hasFields) {
    const inputs = parseFieldInputs(fields);
    if (inputs.length === 0) return { segments: [], singleBlobHint: false };
    return { segments: [segment(inputs, 1)], singleBlobHint: false };
  }
  const blocks = parseBulkSegments(text);
  const flat = blocks.flat();
  const singleBlobHint = isSingleBlob(flat);
  const groups = split ? blocks : blocks.length === 0 ? [] : [flat];
  return { segments: groups.map((group, i) => segment(group.map((p) => ({ label: p.label, value: p.value })), i + 1)), singleBlobHint };
}
