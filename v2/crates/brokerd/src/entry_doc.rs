//! ADR-078 — the broker's side of the multi-field entry model.
//!
//! `credmgr_core::fields` owns the document, its validation and every pure
//! edit; this module is the glue between that and the broker: reading the
//! *params* of an op into those types without ever echoing a label or a value
//! back in an error, opening an entry's envelope into a document (a legacy
//! version-1 value is read in place — nothing is migrated), shaping the
//! `entry.reveal` / `entry.get` answers, and sealing a document back as an
//! envelope of version 2.
//!
//! **Where the params are read.** `ops.rs` reads each top-level param inside its
//! own dispatch arm, because the MCP schema guard
//! (`crates/mcp/tests/schemas_match_the_broker.rs`) and the desktop bridge's drift
//! guard (`apps/desktop/src-tauri/tests/drift_guards.rs`) pin every op's params
//! by scanning the arm's source text — a key read only in a helper is invisible
//! to both. The helpers here take the already-extracted `&Value` and do the
//! parsing, so the arm stays a list of reads.
//!
//! **No label or value in any error.** Every message below names an index, a key
//! of the *request* (`params.fields[2]`), or a field id — never serde's own text
//! (which quotes the offending value) and never a label.

use std::collections::HashSet;

use secrecy::ExposeSecret;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use credmgr_core::envelope::{self, PayloadKind};
use credmgr_core::fields::{
    self, EntryDoc, FieldDoc, FieldError, FieldInput, FieldReplace, Override,
};
use credmgr_core::inference::{
    default_sensitivity, infer_entry_type_labelled, infer_field_type, EntryType, Sensitivity,
};
use credmgr_store::manifest::ManifestEntry;

use crate::protocol::OpError;
use crate::state::BrokerState;

/// ADR-078: the most bytes one `entry.create_batch` call may seal in total —
/// the per-document 16 MiB limit holds for each item, and this bounds the call.
pub const BATCH_MAX_BYTES: usize = 64 * 1024 * 1024;

/// The label a single `value` gets when the caller sends none. It is the
/// documented default of the wire contract (`credmgr_create`'s `label`
/// parameter, `10_API_AND_MCP.md`), kept so that `{value}` still means exactly
/// what it always did; it is a stored label like any other, and the user can
/// rename it. A legacy (version-1) entry has no label at all and reads as `""`.
pub const DEFAULT_LABEL: &str = "value";

/// The keys a `fields` item of `entry.create` / `field.add` may carry.
pub const FIELD_INPUT_KEYS: &[&str] = &["label", "value", "type", "masked"];
/// The keys a `fields` item of `entry.update` / `entry.rotate` may carry.
pub const FIELD_REPLACE_KEYS: &[&str] = &["id", "label", "value", "type", "masked"];
/// The keys a `field.update` `patch` may carry.
pub const FIELD_PATCH_KEYS: &[&str] = &["label", "value", "type", "masked"];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A refused *edit* (a request's fault), as a wire error: an unknown field is
/// `not_found`, everything else `malformed_request`. `FieldError`'s text names
/// an index or an id and nothing the caller sent.
pub fn edit_error(e: FieldError) -> OpError {
    match e {
        FieldError::FieldNotFound { .. } => OpError::NotFound(e.to_string()),
        FieldError::AmbiguousField { field_count } => {
            OpError::Malformed(format!("entry has {field_count} fields; pass params.field"))
        }
        other => OpError::Malformed(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Reading params
// ---------------------------------------------------------------------------

/// An optional string param. Absent or `null` is `None`; any other non-string is
/// a refusal that names the key, never what was sent.
pub fn opt_str<'a>(v: &'a Value, name: &str) -> Result<Option<&'a str>, OpError> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.as_str())),
        _ => Err(OpError::Malformed(format!(
            "params.{name} must be a string"
        ))),
    }
}

/// One object of `what` (`"patch"`, `"fields[3]"`) read into `T`. A key outside
/// `allowed` or a value of the wrong type is a refusal naming `what`, not the
/// offending key or value (serde's own message would quote it).
pub fn parse_object<T: DeserializeOwned>(
    v: &Value,
    what: &str,
    allowed: &[&str],
) -> Result<T, OpError> {
    let object = v
        .as_object()
        .ok_or_else(|| OpError::Malformed(format!("params.{what} must be an object")))?;
    if object.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(OpError::Malformed(format!(
            "params.{what} has a key that is not one of: {}",
            allowed.join(", ")
        )));
    }
    T::deserialize(v)
        .map_err(|_| OpError::Malformed(format!("params.{what} has a value of the wrong type")))
}

/// An optional array of objects (`fields`). Absent or `null` is `None`.
pub fn opt_list<T: DeserializeOwned>(
    v: Option<&Value>,
    name: &str,
    allowed: &[&str],
) -> Result<Option<Vec<T>>, OpError> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let items = v
        .as_array()
        .ok_or_else(|| OpError::Malformed(format!("params.{name} must be an array")))?;
    items
        .iter()
        .enumerate()
        .map(|(i, item)| parse_object::<T>(item, &format!("{name}[{i}]"), allowed))
        .collect::<Result<Vec<T>, OpError>>()
        .map(Some)
}

/// An optional non-empty array of strings (`fieldIds`, `order`). The strings are
/// not checked for shape here — an id that names no field is `not_found`.
pub fn opt_string_list(v: Option<&Value>, name: &str) -> Result<Option<Vec<String>>, OpError> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let items = v
        .as_array()
        .ok_or_else(|| OpError::Malformed(format!("params.{name} must be an array of strings")))?;
    if items.is_empty() {
        return Err(OpError::Malformed(format!(
            "params.{name} must not be empty when it is present"
        )));
    }
    items
        .iter()
        .map(|item| {
            item.as_str().map(str::to_string).ok_or_else(|| {
                OpError::Malformed(format!("params.{name} must be an array of strings"))
            })
        })
        .collect::<Result<Vec<String>, OpError>>()
        .map(Some)
}

/// An optional non-negative integer param (`position`). Absent or `null` is
/// `None`; a negative, fractional or non-numeric value is a refusal.
pub fn opt_index(v: Option<&Value>, name: &str) -> Result<Option<usize>, OpError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| {
                OpError::Malformed(format!("params.{name} must be a non-negative integer"))
            }),
    }
}

/// A three-way override param (ADR-078, D6): absent keeps, `"auto"` clears, a
/// value sets. JSON `null` is **refused** — the desktop bridge drops nulls on the
/// way in, so `null` cannot mean "clear" end to end, and `"auto"` works the same
/// on the socket, the bridge, MCP and the CLI.
pub fn parse_override<T: DeserializeOwned>(
    v: Option<&Value>,
    name: &str,
) -> Result<Override<T>, OpError> {
    match v {
        None => Ok(Override::Keep),
        Some(Value::Null) => Err(OpError::Malformed(format!(
            "params.{name} must not be null: leave it out to keep it, or send \"auto\" to infer it again"
        ))),
        Some(v) => Override::<T>::deserialize(v).map_err(|_| {
            OpError::Malformed(format!(
                "params.{name} is not a recognised value (or \"auto\")"
            ))
        }),
    }
}

// ---------------------------------------------------------------------------
// Building a document from a create body
// ---------------------------------------------------------------------------

/// The body of `entry.create` and of one `entry.create_batch` item, already
/// pulled out of the request.
pub struct CreateBody<'a> {
    pub value: Option<&'a str>,
    pub label: Option<&'a str>,
    pub fields: Option<Vec<FieldInput>>,
    pub entry_type: Override<EntryType>,
    pub sensitivity: Override<Sensitivity>,
}

impl CreateBody<'_> {
    /// Exactly one of `value` / `fields`. `{value, label?}` is a one-field entry
    /// whose label is `label`, or [`DEFAULT_LABEL`] when none is sent; `label`
    /// belongs to `value` and is refused beside `fields`.
    pub fn into_doc(self) -> Result<EntryDoc, OpError> {
        let inputs = match (self.value, self.fields) {
            (Some(_), Some(_)) => {
                return Err(OpError::Malformed(
                    "give params.value or params.fields, not both".into(),
                ))
            }
            (None, None) => {
                return Err(OpError::Malformed(
                    "params.value or params.fields is required".into(),
                ))
            }
            (Some(value), None) => vec![FieldInput {
                label: self.label.unwrap_or(DEFAULT_LABEL).to_string(),
                value: value.to_string(),
                field_type: None,
                masked: None,
            }],
            (None, Some(fields)) => {
                if self.label.is_some() {
                    return Err(OpError::Malformed(
                        "params.label goes with params.value; with params.fields, label each field"
                            .into(),
                    ));
                }
                fields
            }
        };
        fields::create(inputs, self.entry_type, self.sensitivity).map_err(edit_error)
    }
}

// ---------------------------------------------------------------------------
// The body of entry.update / entry.rotate
// ---------------------------------------------------------------------------

/// What `entry.update` and `entry.rotate` were asked to do, validated for shape.
pub struct EntryEdit<'a> {
    value: Option<&'a str>,
    label: Option<&'a str>,
    field: Option<&'a str>,
    fields: Option<Vec<FieldReplace>>,
    entry_type: Override<EntryType>,
    sensitivity: Override<Sensitivity>,
}

impl<'a> EntryEdit<'a> {
    /// The shape rules (`4.3`): at least one of `value` / `fields` / `entryType`
    /// / `sensitivity`; `fields` replaces the whole list and so excludes the
    /// single-field `value` / `label` / `field`; `label` and `field` only mean
    /// something beside `value`.
    pub fn new(
        value: Option<&'a str>,
        label: Option<&'a str>,
        field: Option<&'a str>,
        fields: Option<Vec<FieldReplace>>,
        entry_type: Override<EntryType>,
        sensitivity: Override<Sensitivity>,
    ) -> Result<Self, OpError> {
        if value.is_none() && fields.is_none() && entry_type.is_keep() && sensitivity.is_keep() {
            return Err(OpError::Malformed(
                "give params.value, params.fields, params.entryType or params.sensitivity".into(),
            ));
        }
        if fields.is_some() && (value.is_some() || label.is_some() || field.is_some()) {
            return Err(OpError::Malformed(
                "params.fields replaces every field; it cannot be combined with params.value, \
                 params.label or params.field"
                    .into(),
            ));
        }
        if value.is_none() && fields.is_none() && (label.is_some() || field.is_some()) {
            return Err(OpError::Malformed(
                "params.label and params.field go with params.value".into(),
            ));
        }
        Ok(EntryEdit {
            value,
            label,
            field,
            fields,
            entry_type,
            sensitivity,
        })
    }

    /// The document after the edit. `value` replaces one field's value (the
    /// entry's only field, or the one `field` names — a multi-field entry with no
    /// `field` is refused); `fields` replaces the whole list; the entry-level
    /// overrides are set or cleared last.
    pub fn apply(self, doc: &EntryDoc) -> Result<EntryDoc, OpError> {
        let next = match (self.fields, self.value) {
            (Some(replacements), _) => {
                fields::replace_all(doc, replacements).map_err(edit_error)?
            }
            (None, Some(value)) => fields::replace_value(
                doc,
                self.field,
                value.to_string(),
                self.label.map(str::to_string),
            )
            .map_err(edit_error)?,
            (None, None) => doc.clone(),
        };
        Ok(fields::set_entry_overrides(
            &next,
            self.entry_type,
            self.sensitivity,
        ))
    }
}

// ---------------------------------------------------------------------------
// Opening an entry
// ---------------------------------------------------------------------------

/// An entry's envelope opened into its document.
pub struct Loaded {
    pub kind: PayloadKind,
    pub doc: EntryDoc,
}

/// Open `bytes` (an entry envelope found at `node`/`entry_id`) with `node_priv`.
///
/// A version-1 envelope is a legacy single value and is read in place as a
/// one-field document whose projection equals `stored` (the manifest entry it
/// belongs to); with no manifest entry the projection is simply what inference
/// says. A version-2 envelope is decoded strictly. An envelope that does not
/// open at all is `not_found` ("envelope failed to open", as it always was); a
/// stored document that opens but does not decode is `internal` — it is
/// tampering or a bug, never a partial answer.
pub fn open_bytes(
    bytes: &[u8],
    node: &str,
    entry_id: &str,
    node_priv: &StaticSecret,
    stored: Option<&ManifestEntry>,
) -> Result<Loaded, OpError> {
    let (kind, plaintext) = envelope::open_any(bytes, node_priv, node, entry_id)
        .map_err(|_| OpError::NotFound("envelope failed to open".into()))?;
    let (stored_type, stored_sens) = match (kind, stored) {
        (_, Some(e)) => (e.entry_type, e.sensitivity),
        (PayloadKind::RawValue, None) => {
            let raw = String::from_utf8_lossy(plaintext.expose_secret());
            let t = infer_field_type("", &raw);
            (
                infer_entry_type_labelled(&[("", t)]),
                default_sensitivity(t),
            )
        }
        // Not read for a field document; any pair will do.
        (PayloadKind::FieldDocument, None) => (EntryType::Other, Sensitivity::Low),
    };
    let doc = fields::read_payload(kind, plaintext.expose_secret(), stored_type, stored_sens)
        .map_err(|_| OpError::Internal("a stored entry document did not decode".into()))?;
    Ok(Loaded { kind, doc })
}

/// Read `entries/<entry_id>.env` and open it (see [`open_bytes`]).
pub fn load(
    state: &BrokerState,
    node: &str,
    entry_id: &str,
    node_priv: &StaticSecret,
    stored: Option<&ManifestEntry>,
) -> Result<Loaded, OpError> {
    let bytes = credmgr_store::atomic::read(&state.paths.entry_env(node, entry_id))
        .map_err(|_| OpError::NotFound(format!("no entry {entry_id} on node {node}")))?;
    open_bytes(&bytes, node, entry_id, node_priv, stored)
}

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

/// Encode `doc` and seal it to `node`'s public key as an envelope of version 2.
/// Returns the sealed bytes and their SHA-256 (ADR-067: the digest of the
/// envelope, never of the plaintext). The encoded plaintext is zeroised on drop.
pub fn seal_doc(
    state: &BrokerState,
    node: &str,
    entry_id: &str,
    doc: &EntryDoc,
) -> Result<(Vec<u8>, String), OpError> {
    let plaintext = Zeroizing::new(fields::encode(doc).map_err(edit_error)?);
    let node_pub = state
        .node_public_key(node)
        .ok_or_else(|| OpError::NotFound(format!("node {node} has no public key registered")))?;
    let sealed = envelope::seal_as(
        PayloadKind::FieldDocument,
        &plaintext,
        &node_pub,
        node,
        entry_id,
    )
    .map_err(|_| OpError::Internal("failed to seal the entry".into()))?;
    let sha256 = crate::ops::sha256_hex(&sealed);
    Ok((sealed, sha256))
}

/// The encoded size of `doc`, for the batch bound. Validates it on the way.
pub fn encoded_len(doc: &EntryDoc) -> Result<usize, OpError> {
    let bytes = Zeroizing::new(fields::encode(doc).map_err(edit_error)?);
    Ok(bytes.len())
}

/// ADR-048 / ADR-055: retain what is about to be superseded — the current
/// envelope bytes, and the pre-change manifest entry, signed — under
/// `generation` (the entry's generation *before* the change). `entry.undo` needs
/// both to put a rotation or a field edit back.
pub fn retain_history(
    state: &BrokerState,
    node: &str,
    entry_id: &str,
    prior: &ManifestEntry,
    generation: u64,
    now: i64,
) -> Result<(), OpError> {
    let current = credmgr_store::atomic::read(&state.paths.entry_env(node, entry_id))
        .map_err(|e| OpError::Internal(format!("reading entry to retain its history: {e}")))?;
    credmgr_store::atomic::write(
        &state.paths.entry_history_env(node, entry_id, generation),
        &current,
    )
    .map_err(|e| OpError::Internal(format!("retaining rotation history: {e}")))?;
    let root_key = state.reauth_root_key("entry history").map_err(|_| {
        OpError::Internal("could not re-derive the root key to retain history".into())
    })?;
    credmgr_store::rotation_history::save(
        &state.paths,
        root_key.expose_secret(),
        node,
        prior,
        generation,
        now,
    )
    .map_err(|e| OpError::Internal(format!("retaining rotation snapshot: {e}")))
}

// ---------------------------------------------------------------------------
// Answers
// ---------------------------------------------------------------------------

/// `{id, label, type, masked}` — a field without its value.
fn field_meta(f: &FieldDoc) -> Value {
    let (t, masked) = fields::effective(f);
    json!({ "id": f.id, "label": f.label, "type": t, "masked": masked })
}

/// The `entry.reveal` answer: the selected fields with their values, in stored
/// order, and `value` — the single-value shape every existing caller reads —
/// **iff exactly one field is returned**. `ids` narrows (each must exist, else
/// `not_found` and no partial answer; repeats are ignored).
pub fn reveal_json(
    node: &str,
    entry_id: &str,
    doc: &EntryDoc,
    ids: Option<&[String]>,
) -> Result<Value, OpError> {
    let selected: Vec<&FieldDoc> = match ids {
        None => doc.fields.iter().collect(),
        Some(ids) => {
            let wanted: HashSet<&str> = ids.iter().map(String::as_str).collect();
            for id in &wanted {
                if doc.field(id).is_none() {
                    return Err(OpError::NotFound(if fields::is_valid_field_id(id) {
                        format!("no field has the id {id}")
                    } else {
                        "no field has that id (it is not a well-formed field id)".to_string()
                    }));
                }
            }
            doc.fields
                .iter()
                .filter(|f| wanted.contains(f.id.as_str()))
                .collect()
        }
    };
    let rows: Vec<Value> = selected
        .iter()
        .map(|f| {
            let mut row = field_meta(f);
            if is_seed(f) {
                // The seed/code split: a stored 2FA seed is never returned by a reveal, to anyone.
                // The code comes from `totp.code`; the seed itself only from `totp.seed`, which needs presence.
                row["value"] = Value::Null;
                row["redacted"] = json!("totp_seed");
            } else {
                row["value"] = json!(f.value);
            }
            row
        })
        .collect();
    let mut body = json!({ "node": node, "entry": entry_id, "fields": rows });
    if let [only] = selected.as_slice() {
        body["value"] = if is_seed(only) {
            Value::Null
        } else {
            json!(only.value)
        };
    }
    Ok(body)
}

/// A field `totp.code` reads as a seed (an `otpauth://` URI or a bare base32 seed, by its effective type).
fn is_seed(f: &FieldDoc) -> bool {
    fields::effective_type(f) == credmgr_core::inference::FieldType::TotpSeed
}

/// The `entry.get` answer — metadata, labels, types and masking, **never a
/// value**. `type`/`sensitivity`/`fieldCount`/`hasTotp` are the document's own
/// projection (the decrypted truth); the rest is the manifest's.
pub fn get_json(node: &str, entry: &ManifestEntry, generation: u64, doc: &EntryDoc) -> Value {
    let p = fields::project(doc);
    let rows: Vec<Value> = doc
        .fields
        .iter()
        .map(|f| {
            let mut row = field_meta(f);
            row["typeOverridden"] = json!(f.field_type.is_some());
            row["maskedOverridden"] = json!(f.masked.is_some());
            row
        })
        .collect();
    json!({
        "node": node, "entry": entry.id, "name": entry.name, "ref": entry.r#ref,
        "type": p.entry_type, "sensitivity": p.sensitivity,
        "fieldCount": p.field_count, "hasTotp": p.has_totp,
        "modified": entry.modified, "rotatedAt": entry.rotated_at, "expiresAt": entry.expires_at,
        "generation": generation,
        "typeOverridden": doc.entry_type.is_some(),
        "sensitivityOverridden": doc.sensitivity.is_some(),
        "fields": rows,
    })
}

/// Which field `totp.code` / `totp.seed` means: the one `field` names; else the
/// only field; else the unique field whose effective type is a TOTP seed; else
/// the call is ambiguous and refused (the message counts, it does not quote).
pub fn select_totp_field<'d>(
    doc: &'d EntryDoc,
    field: Option<&str>,
) -> Result<&'d FieldDoc, OpError> {
    if let Some(id) = field {
        return doc.field(id).ok_or_else(|| {
            edit_error(FieldError::FieldNotFound {
                id: fields::is_valid_field_id(id).then(|| id.to_string()),
            })
        });
    }
    if let [only] = doc.fields.as_slice() {
        return Ok(only);
    }
    let seeds: Vec<&FieldDoc> = doc
        .fields
        .iter()
        .filter(|f| fields::effective_type(f) == credmgr_core::inference::FieldType::TotpSeed)
        .collect();
    match seeds.as_slice() {
        [one] => Ok(one),
        _ => Err(OpError::Malformed(format!(
            "entry has {} fields and {} TOTP seeds; pass params.field",
            doc.fields.len(),
            seeds.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use credmgr_core::inference::FieldType;

    fn doc() -> EntryDoc {
        fields::create(
            vec![
                FieldInput {
                    label: "host".into(),
                    value: "db.internal".into(),
                    field_type: None,
                    masked: None,
                },
                FieldInput {
                    label: "otp".into(),
                    value: "JBSWY3DPEHPK3PXP".into(),
                    field_type: None,
                    masked: None,
                },
            ],
            Override::Keep,
            Override::Keep,
        )
        .unwrap()
    }

    #[test]
    fn parse_errors_never_echo_what_was_sent() {
        let marker = "marker-secret-xyz";
        // A key that is not allowed, a value of the wrong type, a non-object.
        for (v, what) in [
            (json!({ marker: "x" }), "fields[0]"),
            (json!({ "label": 5, "value": marker }), "fields[0]"),
            (
                json!({ "label": "a", "value": "b", "masked": marker }),
                "fields[0]",
            ),
            (json!(marker), "fields[0]"),
        ] {
            let e = parse_object::<FieldInput>(&v, what, FIELD_INPUT_KEYS).unwrap_err();
            let OpError::Malformed(m) = e else {
                panic!("expected malformed")
            };
            assert!(!m.contains(marker), "{m}");
            assert!(m.contains(what), "{m}");
        }
        let e = parse_override::<EntryType>(Some(&json!(marker)), "entryType").unwrap_err();
        let OpError::Malformed(m) = e else {
            panic!("expected malformed")
        };
        assert!(!m.contains(marker), "{m}");
    }

    #[test]
    fn overrides_are_absent_auto_or_a_value_and_never_null() {
        assert!(matches!(
            parse_override::<Sensitivity>(None, "sensitivity"),
            Ok(Override::Keep)
        ));
        assert!(matches!(
            parse_override::<Sensitivity>(Some(&json!("auto")), "sensitivity"),
            Ok(Override::Auto)
        ));
        assert!(matches!(
            parse_override::<Sensitivity>(Some(&json!("high")), "sensitivity"),
            Ok(Override::Set(Sensitivity::High))
        ));
        assert!(matches!(
            parse_override::<EntryType>(Some(&json!("note-only")), "entryType"),
            Ok(Override::Set(EntryType::Note))
        ));
        assert!(parse_override::<Sensitivity>(Some(&Value::Null), "sensitivity").is_err());
        assert!(parse_override::<Sensitivity>(Some(&json!("severe")), "sensitivity").is_err());
    }

    #[test]
    fn create_takes_value_xor_fields_and_label_only_beside_value() {
        let body = |value, label, fields| CreateBody {
            value,
            label,
            fields,
            entry_type: Override::Keep,
            sensitivity: Override::Keep,
        };
        let one = body(Some("v"), None, None).into_doc().unwrap();
        assert_eq!(one.fields.len(), 1);
        assert_eq!(one.fields[0].label, DEFAULT_LABEL);
        let named = body(Some("v"), Some("password"), None).into_doc().unwrap();
        assert_eq!(named.fields[0].label, "password");
        assert!(body(None, None, None).into_doc().is_err());
        let input = || FieldInput {
            label: "a".into(),
            value: "b".into(),
            field_type: None,
            masked: None,
        };
        assert!(body(Some("v"), None, Some(vec![input()]))
            .into_doc()
            .is_err());
        assert!(body(None, Some("l"), Some(vec![input()]))
            .into_doc()
            .is_err());
        assert!(body(None, None, Some(vec![])).into_doc().is_err());
        assert_eq!(
            body(None, None, Some(vec![input(), input()]))
                .into_doc()
                .unwrap()
                .fields
                .len(),
            2
        );
    }

    #[test]
    fn an_edit_needs_something_to_do_and_fields_excludes_the_single_value_keys() {
        let keep = || (Override::<EntryType>::Keep, Override::<Sensitivity>::Keep);
        let (t, s) = keep();
        assert!(EntryEdit::new(None, None, None, None, t, s).is_err());
        let (t, s) = keep();
        assert!(EntryEdit::new(None, Some("l"), None, None, t, s).is_err());
        let (t, s) = keep();
        assert!(EntryEdit::new(None, None, Some("f_00000000"), None, t, s).is_err());
        let (t, s) = keep();
        assert!(EntryEdit::new(Some("v"), None, None, Some(vec![]), t, s).is_err());
        // metadata-only is an edit
        assert!(EntryEdit::new(
            None,
            None,
            None,
            None,
            Override::Set(EntryType::Note),
            Override::Keep
        )
        .is_ok());
    }

    #[test]
    fn a_value_edit_on_a_multi_field_entry_without_a_field_is_refused() {
        let d = doc();
        let edit =
            EntryEdit::new(Some("x"), None, None, None, Override::Keep, Override::Keep).unwrap();
        let OpError::Malformed(m) = edit.apply(&d).unwrap_err() else {
            panic!("expected malformed")
        };
        assert_eq!(m, "entry has 2 fields; pass params.field");
        let target = d.fields[1].id.clone();
        let edit = EntryEdit::new(
            Some("x"),
            None,
            Some(&target),
            None,
            Override::Keep,
            Override::Keep,
        )
        .unwrap();
        let next = edit.apply(&d).unwrap();
        assert_eq!(next.fields[1].value, "x");
        assert_eq!(next.fields[0].value, "db.internal");
    }

    #[test]
    fn reveal_carries_value_only_when_exactly_one_field_is_returned() {
        let d = doc();
        let all = reveal_json("n", "e", &d, None).unwrap();
        assert_eq!(all["fields"].as_array().unwrap().len(), 2);
        assert!(all.get("value").is_none());
        let ids = [d.fields[1].id.clone()];
        let one = reveal_json("n", "e", &d, Some(&ids)).unwrap();
        // a stored seed is never returned (audit P0-1): the single-value shape is null and the row says why
        assert_eq!(one["value"], Value::Null);
        assert_eq!(one["fields"][0]["redacted"], "totp_seed");
        assert!(!one.to_string().contains("JBSWY3DPEHPK3PXP"), "{one}");
        assert_eq!(one["fields"][0]["type"], "totp-seed");
        // a field that is not a seed still comes back with its value
        let plain = [d.fields[0].id.clone()];
        let host = reveal_json("n", "e", &d, Some(&plain)).unwrap();
        assert_eq!(host["value"], "db.internal");
        assert_eq!(one["fields"][0]["masked"], true);
        // an unknown id is not_found and there is no partial answer
        let bad = [d.fields[0].id.clone(), "f_deadbeef".to_string()];
        assert!(matches!(
            reveal_json("n", "e", &d, Some(&bad)),
            Err(OpError::NotFound(_))
        ));
        // a label sent as an id is not echoed
        let junk = ["marker-label-xyz".to_string()];
        let OpError::NotFound(m) = reveal_json("n", "e", &d, Some(&junk)).unwrap_err() else {
            panic!("expected not_found")
        };
        assert!(!m.contains("marker"), "{m}");
    }

    #[test]
    fn totp_field_selection_is_explicit_then_sole_then_unique_seed() {
        let d = doc();
        // two fields, exactly one seed: the seed
        assert_eq!(select_totp_field(&d, None).unwrap().label, "otp");
        // explicit wins
        assert_eq!(
            select_totp_field(&d, Some(&d.fields[0].id)).unwrap().label,
            "host"
        );
        assert!(matches!(
            select_totp_field(&d, Some("f_deadbeef")),
            Err(OpError::NotFound(_))
        ));
        // two seeds, ambiguous
        let mut two = d.clone();
        two.fields[0].field_type = Some(FieldType::TotpSeed);
        let OpError::Malformed(m) = select_totp_field(&two, None).unwrap_err() else {
            panic!("expected malformed")
        };
        assert_eq!(m, "entry has 2 fields and 2 TOTP seeds; pass params.field");
        // no seed at all among several fields, ambiguous
        let none = fields::create(
            vec![
                FieldInput {
                    label: "a".into(),
                    value: "b".into(),
                    field_type: None,
                    masked: None,
                },
                FieldInput {
                    label: "c".into(),
                    value: "d".into(),
                    field_type: None,
                    masked: None,
                },
            ],
            Override::Keep,
            Override::Keep,
        )
        .unwrap();
        assert!(select_totp_field(&none, None).is_err());
        // a sole field is the seed whatever its inferred type
        let sole = fields::create(
            vec![FieldInput {
                label: "x".into(),
                value: "short".into(),
                field_type: None,
                masked: None,
            }],
            Override::Keep,
            Override::Keep,
        )
        .unwrap();
        assert_eq!(select_totp_field(&sole, None).unwrap().value, "short");
    }
}
