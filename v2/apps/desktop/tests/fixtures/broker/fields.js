/* FIXTURE BROKER - the field model (ADR-078).  See core.js.

   What an entry holds, as the real broker reports it:
     - an entry is a list of FIELDS (id, free-text label, value, type, masking); the type and the masking are inferred unless the user
       PINNED them (`typePin` / `maskedPin` here; `typeOverridden` / `maskedOverridden` on the wire);
     - the entry's own type and sensitivity are inferred from its fields unless pinned too;
     - a legacy (pre-ADR-078) entry has ONE field, id `f_00000000`, label "", read in place (`legacyFields`): a spec that seeds an
       entry with only a `value` gets exactly that, and nothing in the specs written before the field model had to change shape.

   Nothing here is the real inference or the real parser.  Those are Rust (`credmgr_core::inference`, `credmgr_core::parser`), exercised by
   their own suites, and the desktop shell runs them for `fields_preview`.  This is a small stand-in that gives the specs the same
   SHAPES and the same refusals, so that what a spec proves is what the UI does with the answer, never what this file infers.  The few
   rules it ports are the ones the specs lean on, and they are the real ones (core `inference.rs`, `parser.rs`) in miniature. */
(function (B) {
  "use strict";

  var FIELD_TYPES = ["password", "api-key", "private-key", "seed-phrase", "totp-seed", "username", "host", "port", "url", "certificate", "text"];
  var ENTRY_TYPES = ["server", "database", "api", "wallet", "login", "ssh", "certificate", "token", "totp", "env-bundle", "note", "other"];
  var SENSITIVITIES = ["low", "medium", "high", "critical"];
  var MASKED_BY_DEFAULT = ["password", "api-key", "private-key", "seed-phrase", "totp-seed"];
  var LEGACY_ID = "f_00000000";
  var FIELD_INPUT_KEYS = ["label", "value", "type", "masked"];
  var LABEL_MAX = 200;

  B.FIELD_TYPES = FIELD_TYPES;
  B.ENTRY_TYPES = ENTRY_TYPES;
  B.LEGACY_FIELD_ID = LEGACY_ID;

  // ───────────────────────────── inference (core inference.rs in miniature) ─────────────────────────────

  function looksLikeTotpSeed(v) {
    if (v.indexOf("otpauth://") === 0) return true;
    var s = v.trim();
    return (s.length === 16 || s.length === 26 || s.length === 32) && /^[A-Z2-7]+$/.test(s);
  }
  function looksLikeSeedPhrase(v) {
    var words = v.split(/\s+/).filter(Boolean);
    return [12, 15, 18, 21, 24].indexOf(words.length) >= 0 && words.every(function (w) { return /^[a-z]+$/.test(w); });
  }
  function looksLikeApiKey(v) {
    return /^(sk-|ghp_|github_pat_|AKIA|AIza)/.test(v) || /^xox[abprs]-/.test(v);
  }
  function looksLikeHostname(v) {
    if (!v || /\s/.test(v) || v.indexOf("://") >= 0) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return true;
    return v.indexOf(".") >= 0 && /^[A-Za-z0-9.-]+$/.test(v);
  }
  function labelHas(label, needles) {
    var l = String(label || "").toLowerCase();
    return needles.some(function (n) { return l.indexOf(n) >= 0; });
  }

  B.inferFieldType = function (label, value) {
    var v = String(value || "");
    if (v.indexOf("-----BEGIN") >= 0 && v.indexOf("PRIVATE KEY-----") >= 0) return "private-key";
    if (v.indexOf("-----BEGIN CERTIFICATE-----") >= 0) return "certificate";
    if (looksLikeTotpSeed(v)) return "totp-seed";
    if (looksLikeSeedPhrase(v)) return "seed-phrase";
    if (looksLikeApiKey(v)) return "api-key";
    if (/^https?:\/\//.test(v)) return "url";
    if (/^\d+$/.test(v) && +v >= 1 && +v <= 65535) return "port";
    if (looksLikeHostname(v)) return "host";
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v) || labelHas(label, ["user"])) return "username";
    if (labelHas(label, ["pass", "pwd", "secret"])) return "password";
    if (labelHas(label, ["key", "token", "api"])) return "api-key";
    return "text";
  };

  B.defaultSensitivity = function (type) {
    if (type === "seed-phrase" || type === "private-key") return "critical";
    if (type === "password" || type === "api-key" || type === "totp-seed" || type === "certificate") return "high";
    if (type === "username" || type === "host" || type === "port" || type === "url") return "medium";
    return "low";
  };

  /** `fields`: [{label, type}] with EFFECTIVE types. */
  B.inferEntryType = function (fields) {
    var has = function (t) { return fields.some(function (f) { return f.type === t; }); };
    if (fields.length === 1 && /^notes?$/i.test(String(fields[0].label || "").trim())) return "note";
    if (has("totp-seed") && fields.length <= 2) return "totp";
    if (has("seed-phrase") || has("private-key")) return "wallet";
    if (has("certificate")) return "certificate";
    if (has("host") && has("username") && (has("password") || has("api-key"))) return "server";
    return "other";
  };

  B.maxSensitivity = function (types) {
    var best = 0;
    types.forEach(function (t) { best = Math.max(best, SENSITIVITIES.indexOf(B.defaultSensitivity(t))); });
    return SENSITIVITIES[best];
  };

  // ───────────────────────────── fields ─────────────────────────────

  /** The effective type and masking of a stored field (the pin if there is one, else inferred / the type's default). */
  B.effective = function (f) {
    var type = f.typePin || B.inferFieldType(f.label, f.value);
    var masked = f.maskedPin !== undefined && f.maskedPin !== null ? !!f.maskedPin : MASKED_BY_DEFAULT.indexOf(type) >= 0;
    return { type: type, masked: masked };
  };

  /** A new field id: `f_` and eight hex digits, never the legacy one. */
  B.newFieldId = function () {
    B.S.fieldSeq = (B.S.fieldSeq || 0) + 1;
    return "f_" + (0xf1000000 + B.S.fieldSeq).toString(16);
  };

  function legacyType(e) {
    switch (e.type) {
      case "totp": return "totp-seed";
      case "wallet": return "seed-phrase";
      case "ssh": return "private-key";
      case "certificate": return "certificate";
      case "api": case "token": return "api-key";
      case "login": case "server": case "database": return "password";
      default: return "text";
    }
  }

  /** What an entry holds: its stored fields, or, for an entry written before the field model, its one value as one field. */
  B.fieldsOf = function (e) {
    if (e.fields) return e.fields;
    return [{ id: LEGACY_ID, label: "", value: e.value, typePin: legacyType(e), maskedPin: true }];
  };

  /** Make the entry hold its fields explicitly (the first write to a legacy entry), pinning what the manifest already said. */
  B.materialize = function (e) {
    if (!e.fields) {
      e.fields = B.fieldsOf(e);
      if (!e.typePin) e.typePin = e.type;
      if (!e.sensPin) e.sensPin = e.sensitivity;
    }
    return e;
  };

  B.hasTotp = function (e) {
    return B.fieldsOf(e).some(function (f) { return B.effective(f).type === "totp-seed"; });
  };

  /** Recompute the entry's type and sensitivity from its fields (a pin wins), and stamp the change. */
  B.project = function (e) {
    var fs = B.fieldsOf(e);
    var eff = fs.map(function (f) { return { label: f.label, type: B.effective(f).type }; });
    e.type = e.typePin || B.inferEntryType(eff);
    e.sensitivity = e.sensPin || B.maxSensitivity(eff.map(function (f) { return f.type; }));
    e.value = fs[0].value;
    e.modified = B.now();
    return e;
  };

  /** A field as `entry.get` states it: no value. */
  B.fieldMeta = function (f) {
    var eff = B.effective(f);
    return { id: f.id, label: f.label, type: eff.type, masked: eff.masked, typeOverridden: !!f.typePin, maskedOverridden: f.maskedPin !== undefined && f.maskedPin !== null };
  };

  /** A field as `entry.reveal` states it. */
  B.fieldWithValue = function (f) {
    var eff = B.effective(f);
    return { id: f.id, label: f.label, value: f.value, type: eff.type, masked: eff.masked };
  };

  function bad(message) {
    return B.error("malformed_request", message);
  }

  /** One element of a `fields` list, as the broker checks it: the message names the index, never a label or a value. */
  function checkOne(item, i, where) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw bad(where + "[" + i + "] must be an object");
    Object.keys(item).forEach(function (k) {
      if (FIELD_INPUT_KEYS.indexOf(k) < 0 && !(k === "id" && where === "fields-replace")) throw bad(where + "[" + i + "] has a key that is not one of: " + FIELD_INPUT_KEYS.join(", "));
    });
    if (typeof item.label !== "string") throw bad(where + "[" + i + "].label must be a string");
    if (typeof item.value !== "string") throw bad(where + "[" + i + "].value must be a string");
    if (item.label.length > LABEL_MAX) throw bad(where + "[" + i + "].label is longer than " + LABEL_MAX + " characters");
    if (/[\n\r\0]/.test(item.label)) throw bad(where + "[" + i + "].label must be one line");
    if (item.type !== undefined && FIELD_TYPES.indexOf(item.type) < 0) throw bad(where + "[" + i + "].type is not a field type");
    if (item.masked !== undefined && typeof item.masked !== "boolean") throw bad(where + "[" + i + "].masked must be true or false");
  }

  /** `FieldInput[]` → stored fields (ids minted).  1 or more. */
  B.makeFields = function (list, where) {
    if (!Array.isArray(list) || !list.length) throw bad(where + " must hold at least one field");
    return list.map(function (item, i) {
      checkOne(item, i, where);
      var f = { id: B.newFieldId(), label: item.label, value: item.value };
      if (item.type !== undefined) f.typePin = item.type;
      if (item.masked !== undefined) f.maskedPin = item.masked;
      return f;
    });
  };

  /** The `entryType` / `sensitivity` params: a value pins, `"auto"` clears, absent keeps.  `undefined` = keep. */
  B.pinParam = function (value, allowed, name, aliases) {
    if (value === undefined || value === null) return undefined;
    if (value === "auto") return null;
    if (aliases && aliases[value]) value = aliases[value];
    if (allowed.indexOf(value) < 0) throw bad("params." + name + " is not one of: " + allowed.join(", ") + ", auto");
    return value;
  };

  // ───────────────────────────── the parser, in miniature (core parser.rs) ─────────────────────────────

  var RESERVED_SCHEMES = ["http", "https", "ftp", "ftps", "ssh", "sftp", "git", "file", "postgres", "postgresql", "mysql", "redis", "mongodb", "amqp", "otpauth", "data", "mailto", "s3", "gs"];

  function isValidLabel(s) {
    return s.length >= 1 && s.length <= 40 && /^[A-Za-z0-9 _.()#\/-]+$/.test(s) && RESERVED_SCHEMES.indexOf(s.toLowerCase()) < 0;
  }
  function labelled(line) {
    var i = line.indexOf(": ");
    if (i < 0) return null;
    var label = line.slice(0, i);
    return isValidLabel(label) ? { label: label, value: line.slice(i + 2) } : null;
  }
  function labelOnly(line) {
    var t = line.replace(/\s+$/, "");
    if (t.charAt(t.length - 1) !== ":") return null;
    var label = t.slice(0, -1);
    return isValidLabel(label) ? label : null;
  }

  /** `[[{label, value}]]`: one inner list per non-empty `///` segment. */
  B.parseSegments = function (text) {
    var lines = text === "" ? [] : text.split(/\r\n|\r|\n/);
    if (lines.length && lines[lines.length - 1] === "" && /[\r\n]$/.test(text)) lines.pop();
    var segs = [];
    var cur = [];
    lines.forEach(function (ln) {
      if (ln.trim() === "///") { segs.push(cur); cur = []; } else cur.push(ln);
    });
    segs.push(cur);
    var out = [];
    segs.forEach(function (seg) {
      if (!seg.length) return;
      var nonEmpty = seg.filter(function (l) { return l.trim() !== ""; });
      var fields;
      if (nonEmpty.length && nonEmpty.every(function (l) { return labelled(l); })) {
        fields = nonEmpty.map(function (l) { return labelled(l); });
      } else {
        var lab = labelOnly(seg[0]);
        fields = lab !== null ? [{ label: lab, value: seg.slice(1).join("\n") }] : [{ label: "", value: seg.join("\n") }];
      }
      if (fields.length) out.push(fields);
    });
    return out;
  };

  // ───────────────────────────── fields_preview (the shell's local command) ─────────────────────────────

  function previewSegment(inputs, number) {
    var fields = inputs.map(function (f) {
      var inferred = B.inferFieldType(f.label, f.value);
      var typePin = f.type !== undefined ? f.type : undefined;
      var maskedPin = f.masked !== undefined ? f.masked : undefined;
      var type = typePin || inferred;
      return {
        label: f.label, value: f.value, type: type,
        masked: maskedPin !== undefined ? maskedPin : MASKED_BY_DEFAULT.indexOf(type) >= 0,
        inferredType: inferred, typeOverridden: typePin !== undefined, maskedOverridden: maskedPin !== undefined,
      };
    });
    var named = inputs.map(function (f) { return String(f.label).trim(); }).filter(Boolean)[0];
    var eff = fields.map(function (f) { return { label: f.label, type: f.type }; });
    return {
      suggestedName: named || "untitled " + number,
      fields: fields,
      entryType: B.inferEntryType(eff),
      sensitivity: B.maxSensitivity(eff.map(function (f) { return f.type; })),
      fieldCount: fields.length,
      hasTotp: fields.some(function (f) { return f.type === "totp-seed"; }),
    };
  }

  B.preview = function (a) {
    var hasText = a.text !== undefined && a.text !== null;
    var hasFields = a.fields !== undefined && a.fields !== null;
    if (hasText === hasFields) throw B.error("invalid_fields", "give the pasted text or the fields, not both and not neither", undefined, "bridge");
    if (hasFields) {
      if (!Array.isArray(a.fields)) throw B.error("invalid_fields", "fields must be an array of {label, value} objects", undefined, "bridge");
      try {
        a.fields.forEach(function (item, i) { checkOne(item, i, "fields"); });
      } catch (e) {
        throw B.error("invalid_fields", e.message, undefined, "bridge");
      }
      // Rows to preview are one entry; no rows is no entry (the real shell answers an empty list, not a refusal).
      return { segments: a.fields.length ? [previewSegment(a.fields, 1)] : [], singleBlobHint: false };
    }
    var parsed = B.parseSegments(String(a.text));
    var groups = a.split ? parsed : parsed.length ? [[].concat.apply([], parsed)] : [];
    var blob = parsed.length === 1 && parsed[0].length === 1 && parsed[0][0].label === "" && parsed[0][0].value.split("\n").filter(function (l) { return l.trim() !== ""; }).length >= 3;
    return { segments: groups.map(function (g, i) { return previewSegment(g, i + 1); }), singleBlobHint: blob };
  };
})((window.__brokerFixture = window.__brokerFixture || {}));
