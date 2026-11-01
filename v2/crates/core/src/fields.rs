//! The multi-field entry model (ADR-078, `docs/03_DATA_MODEL.md §3`).
//!
//! An entry's plaintext is a canonical-JSON **field document**: an ordered list
//! of `{id, label, value, type?, masked?}` plus two optional entry-level
//! overrides, sealed as one envelope of version 2 (`crate::envelope`). One
//! envelope per entry keeps one unit of rotation, AAD binding and undo — a
//! partial write can never half-rotate a credential.
//!
//! ```json
//! {"v":1,"entryType":"server","fields":[{"id":"f_1a2b3c4d","label":"host","value":"db.internal"}]}
//! ```
//!
//! **There is no field-name vocabulary here, or anywhere (ADR-011).** A label is
//! free text — empty is fine, any script is fine, no word is reserved. Nothing
//! looks a label up in a table; the one place a label is read at all is the
//! entry-type *suggestion* (`inference::infer_entry_type_labelled`, a single
//! `note`/`notes` rule) and the field-type *suggestion*
//! (`inference::infer_field_type`, a hint that never overrides the value).
//! `tests/no_field_schema.rs` is the gate.
//!
//! **Overrides, not cached answers.** `type`, `masked` and the entry-level
//! `entryType` / `sensitivity` are stored *only* when the user chose one
//! (ADR-012: inference is a suggestion, never a decision). Absent means
//! "infer it now", so a value or label edit re-infers everything the user did
//! not pin, and nothing stale lives in the ciphertext.
//!
//! **Legacy entries are read in place.** Every entry written up to
//! `2.0.0-alpha.6` is a version-1 envelope holding one raw value. [`from_legacy`]
//! presents it as a one-field document whose projection equals the manifest entry
//! the user already sees; nothing is rewritten by a read and nothing is migrated.
//!
//! This module is pure: bytes in, bytes out, no I/O, no clock. Randomness is the
//! OS generator through `OsRng`, as `envelope::seal` already uses.
//!
//! Errors name an **index or a field id, never a label or a value** — a message
//! that quoted either would carry a secret into a log.

use std::collections::{HashMap, HashSet};
use std::fmt;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize};

use crate::envelope::PayloadKind;
use crate::inference::{
    default_masked, default_sensitivity, infer_entry_type_labelled, infer_field_type, EntryType,
    FieldType, Sensitivity,
};
use crate::parser::ParsedField;

/// The document schema version, independent of the envelope version. A document
/// with any other `v` is refused rather than guessed at.
pub const DOC_VERSION: u32 = 1;

/// The id a legacy single-value entry's one field carries when read in place.
/// Reserved: [`new_field_id`] never mints it, so a field added later can never
/// collide with the upgraded legacy field.
pub const LEGACY_FIELD_ID: &str = "f_00000000";

/// The longest label, in characters.
pub const LABEL_MAX_CHARS: usize = 200;

/// The largest encoded document (`08 §3.5`'s "envelope limit", now enforced).
pub const ENTRY_DOC_MAX_BYTES: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a field document, or an edit to one, was refused. Never carries a label
/// or a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldError {
    /// The bytes are not a field document. Carries only the error's category
    /// and position — serde's own text can quote the offending value.
    Malformed {
        class: &'static str,
        line: usize,
        column: usize,
    },
    /// `v` is not [`DOC_VERSION`].
    UnsupportedDocVersion(u32),
    /// The encoded document exceeds [`ENTRY_DOC_MAX_BYTES`].
    TooLarge { bytes: usize },
    /// A document holds at least one field.
    NoFields,
    /// The field at this index has an id that is not `f_` + 8 lowercase hex.
    BadFieldId { index: usize },
    /// Two fields share this id.
    DuplicateFieldId { id: String },
    /// The field at this index has a label over [`LABEL_MAX_CHARS`] characters.
    LabelTooLong { index: usize },
    /// The field at this index has a label with a control character.
    LabelNotOneLine { index: usize },
    /// No field has this id (`None` when the id asked for is not even
    /// well-formed — it is not echoed).
    FieldNotFound { id: Option<String> },
    /// An entry keeps at least one field.
    LastField,
    /// A value edit without a target on an entry that has several fields.
    AmbiguousField { field_count: usize },
    /// A reorder that is not an exact permutation of the current ids.
    BadOrder,
    /// An insert position past the end.
    PositionOutOfRange { position: usize, len: usize },
    /// A patch that changes nothing.
    EmptyPatch,
    /// An add with no fields to add.
    NothingToAdd,
    /// A replacement list that names the same existing field twice.
    DuplicateReplace { id: String },
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldError::Malformed {
                class,
                line,
                column,
            } => write!(
                f,
                "field document is malformed ({class} error at line {line}, column {column})"
            ),
            FieldError::UnsupportedDocVersion(v) => {
                write!(
                    f,
                    "field document version {v} is not supported (expected {DOC_VERSION})"
                )
            }
            FieldError::TooLarge { bytes } => write!(
                f,
                "field document is {bytes} bytes; the limit is {ENTRY_DOC_MAX_BYTES}"
            ),
            FieldError::NoFields => write!(f, "an entry holds at least one field"),
            FieldError::BadFieldId { index } => {
                write!(
                    f,
                    "field {index} has a malformed id (expected f_ + 8 lowercase hex)"
                )
            }
            FieldError::DuplicateFieldId { id } => write!(f, "two fields share the id {id}"),
            FieldError::LabelTooLong { index } => write!(
                f,
                "field {index}: a label is at most {LABEL_MAX_CHARS} characters"
            ),
            FieldError::LabelNotOneLine { index } => {
                write!(
                    f,
                    "field {index}: a label is one line, with no control characters"
                )
            }
            FieldError::FieldNotFound { id: Some(id) } => write!(f, "no field has the id {id}"),
            FieldError::FieldNotFound { id: None } => {
                write!(f, "no field has that id (it is not a well-formed field id)")
            }
            FieldError::LastField => write!(
                f,
                "an entry keeps at least one field — remove the entry instead"
            ),
            FieldError::AmbiguousField { field_count } => {
                write!(
                    f,
                    "entry has {field_count} fields; say which one with a field id"
                )
            }
            FieldError::BadOrder => {
                write!(
                    f,
                    "a new order must list every current field id exactly once"
                )
            }
            FieldError::PositionOutOfRange { position, len } => {
                write!(f, "position {position} is past the end of {len} fields")
            }
            FieldError::EmptyPatch => write!(f, "a field patch must change something"),
            FieldError::NothingToAdd => write!(f, "there are no fields to add"),
            FieldError::DuplicateReplace { id } => {
                write!(
                    f,
                    "the replacement list names the field {id} more than once"
                )
            }
        }
    }
}

impl std::error::Error for FieldError {}

fn not_found(id: &str) -> FieldError {
    FieldError::FieldNotFound {
        id: is_valid_field_id(id).then(|| id.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Override<T> — the wire's three-way answer
// ---------------------------------------------------------------------------

/// What a request says about an override: nothing (`Keep`), "go back to
/// inferring" (`Auto`), or a chosen value (`Set`). On the wire: the key absent,
/// the string `"auto"`, or the value. JSON `null` is **refused**, not read as
/// either — the desktop bridge drops nulls on the way in, so `null` cannot mean
/// "clear" end to end, and `"auto"` works the same through the socket, the
/// bridge, MCP and the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Override<T> {
    Keep,
    Auto,
    Set(T),
}

// Not derived: `derive(Default)` would demand `T: Default`, and `FieldType` has
// no default — a patch that keeps everything is `Override::Keep` for any `T`.
#[allow(clippy::derivable_impls)]
impl<T> Default for Override<T> {
    fn default() -> Self {
        Override::Keep
    }
}

impl<T> Override<T> {
    /// Apply to the current stored override: `Keep` leaves it, `Auto` clears it,
    /// `Set` replaces it.
    pub fn apply(self, current: Option<T>) -> Option<T> {
        match self {
            Override::Keep => current,
            Override::Auto => None,
            Override::Set(v) => Some(v),
        }
    }

    /// For a *new* entry: there is nothing to keep, so `Keep` and `Auto` both
    /// mean "infer it".
    pub fn into_initial(self) -> Option<T> {
        self.apply(None)
    }

    pub fn is_keep(&self) -> bool {
        matches!(self, Override::Keep)
    }
}

/// Deserialises only from the string `"auto"`.
struct AutoMarker;

impl<'de> Deserialize<'de> for AutoMarker {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "auto" {
            Ok(AutoMarker)
        } else {
            Err(serde::de::Error::custom("not \"auto\""))
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Override<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire<T> {
            Auto(AutoMarker),
            Set(T),
        }
        Ok(match Wire::<T>::deserialize(deserializer)? {
            Wire::Auto(_) => Override::Auto,
            Wire::Set(v) => Override::Set(v),
        })
    }
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// One field. `field_type` and `masked` are the user's override only; absent
/// means inferred ([`effective`]).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldDoc {
    /// `f_` + 8 lowercase hex, unique within the entry, stable for the field's
    /// life: edits, reorders and rotations keep it.
    pub id: String,
    /// Free text. Empty allowed (renders as "field N"). No vocabulary.
    pub label: String,
    /// Verbatim — never trimmed, never normalised (ADR-038).
    pub value: String,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub field_type: Option<FieldType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
}

// The decoded value is a secret held in an ordinary `String`: wipe it (and the label, which is encrypted
// alongside it) when the field is dropped, so a decoded document does not leave plaintext in freed heap.
// A `Clone` is a second copy with the same duty, and runs the same `Drop`.
impl FieldDoc {
    /// Overwrite the value and label with zeros and empty them. `Drop` calls this.
    pub fn wipe(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.value);
        zeroize::Zeroize::zeroize(&mut self.label);
    }
}

impl Drop for FieldDoc {
    fn drop(&mut self) {
        self.wipe();
    }
}

// A derived `Debug` would print the secret into any log line or assertion that
// formats a document.
impl fmt::Debug for FieldDoc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldDoc")
            .field("id", &self.id)
            .field("label_chars", &self.label.chars().count())
            .field(
                "value",
                &format_args!("<redacted, {} bytes>", self.value.len()),
            )
            .field("field_type", &self.field_type)
            .field("masked", &self.masked)
            .finish()
    }
}

/// An entry's plaintext. Struct order is the canonical key order.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntryDoc {
    /// Must equal [`DOC_VERSION`].
    pub v: u32,
    /// The user's chosen entry type, if any. Absent: inferred from the fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_type: Option<EntryType>,
    /// The user's chosen sensitivity, if any. Absent: the strongest field's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<Sensitivity>,
    /// Ordered — the user's order verbatim. At least one.
    pub fields: Vec<FieldDoc>,
}

impl fmt::Debug for EntryDoc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryDoc")
            .field("v", &self.v)
            .field("entry_type", &self.entry_type)
            .field("sensitivity", &self.sensitivity)
            .field("fields", &self.fields)
            .finish()
    }
}

impl EntryDoc {
    /// The field with this id.
    pub fn field(&self, id: &str) -> Option<&FieldDoc> {
        self.fields.iter().find(|f| f.id == id)
    }

    /// Every field id, in order.
    pub fn field_ids(&self) -> Vec<String> {
        self.fields.iter().map(|f| f.id.clone()).collect()
    }

    fn position_of(&self, id: &str) -> Result<usize, FieldError> {
        self.fields
            .iter()
            .position(|f| f.id == id)
            .ok_or_else(|| not_found(id))
    }
}

// ---------------------------------------------------------------------------
// Ids
// ---------------------------------------------------------------------------

/// Whether `id` is `f_` followed by exactly eight lowercase hex digits.
pub fn is_valid_field_id(id: &str) -> bool {
    id.len() == 10
        && id.starts_with("f_")
        && id.as_bytes()[2..]
            .iter()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A fresh random field id. Never [`LEGACY_FIELD_ID`]. Uniqueness within one
/// entry is the caller's to ensure — the edit helpers below use
/// [`mint_field_id`], which does.
pub fn new_field_id() -> String {
    loop {
        let mut b = [0u8; 4];
        OsRng.fill_bytes(&mut b);
        let id = format!("f_{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3]);
        if id != LEGACY_FIELD_ID {
            return id;
        }
    }
}

/// A fresh id not in `taken`, recorded into it.
fn mint_field_id(taken: &mut HashSet<String>) -> String {
    loop {
        let id = new_field_id();
        if taken.insert(id.clone()) {
            return id;
        }
    }
}

// ---------------------------------------------------------------------------
// Validation, encode, decode
// ---------------------------------------------------------------------------

fn check_label(index: usize, label: &str) -> Result<(), FieldError> {
    if label.chars().take(LABEL_MAX_CHARS + 1).count() > LABEL_MAX_CHARS {
        return Err(FieldError::LabelTooLong { index });
    }
    // C0 controls and DEL: a label is one line.
    if label.chars().any(|c| c < '\u{20}' || c == '\u{7f}') {
        return Err(FieldError::LabelNotOneLine { index });
    }
    Ok(())
}

/// Everything but the size: version, at least one field, well-formed unique ids,
/// label rules.
fn validate_shape(doc: &EntryDoc) -> Result<(), FieldError> {
    if doc.v != DOC_VERSION {
        return Err(FieldError::UnsupportedDocVersion(doc.v));
    }
    if doc.fields.is_empty() {
        return Err(FieldError::NoFields);
    }
    let mut seen: HashSet<&str> = HashSet::with_capacity(doc.fields.len());
    for (index, field) in doc.fields.iter().enumerate() {
        if !is_valid_field_id(&field.id) {
            return Err(FieldError::BadFieldId { index });
        }
        if !seen.insert(field.id.as_str()) {
            return Err(FieldError::DuplicateFieldId {
                id: field.id.clone(),
            });
        }
        check_label(index, &field.label)?;
    }
    Ok(())
}

/// Counts bytes without keeping them.
struct CountingSink(usize);

impl std::io::Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Check a document: at least one field, well-formed and unique ids, label
/// rules, and an encoded size within [`ENTRY_DOC_MAX_BYTES`]. **No cap on the
/// number of fields** (`08 §3.5`), **no label vocabulary**, no reserved labels.
pub fn validate(doc: &EntryDoc) -> Result<(), FieldError> {
    validate_shape(doc)?;
    let mut sink = CountingSink(0);
    serde_json::to_writer(&mut sink, doc).expect("EntryDoc always serialises");
    if sink.0 > ENTRY_DOC_MAX_BYTES {
        return Err(FieldError::TooLarge { bytes: sink.0 });
    }
    Ok(())
}

/// Validate, then serialise to the canonical bytes (compact JSON, struct key
/// order). These bytes are the plaintext of a version-2 envelope.
pub fn encode(doc: &EntryDoc) -> Result<Vec<u8>, FieldError> {
    validate(doc)?;
    Ok(serde_json::to_vec(doc).expect("EntryDoc always serialises"))
}

/// Parse and check a field document. **Total**: arbitrary bytes give `Ok` or
/// `Err`, never a panic. Strict: an unknown key, a duplicate key, a `v` other
/// than [`DOC_VERSION`], no fields, a malformed or duplicated id, or a label
/// that breaks the rules is an `Err`.
pub fn decode(bytes: &[u8]) -> Result<EntryDoc, FieldError> {
    if bytes.len() > ENTRY_DOC_MAX_BYTES {
        return Err(FieldError::TooLarge { bytes: bytes.len() });
    }
    let doc: EntryDoc = serde_json::from_slice(bytes).map_err(|e| {
        use serde_json::error::Category;
        FieldError::Malformed {
            class: match e.classify() {
                Category::Io => "io",
                Category::Syntax => "syntax",
                Category::Data => "data",
                Category::Eof => "eof",
            },
            line: e.line(),
            column: e.column(),
        }
    })?;
    validate_shape(&doc)?;
    Ok(doc)
}

// ---------------------------------------------------------------------------
// Effective type, masking and the manifest projection
// ---------------------------------------------------------------------------

/// The type a field has: the user's override, else inferred from label and
/// value now.
pub fn effective_type(field: &FieldDoc) -> FieldType {
    field
        .field_type
        .unwrap_or_else(|| infer_field_type(&field.label, &field.value))
}

/// `(type, masked)`: the override, else the inference — and masking follows the
/// *effective* type when it is not itself overridden.
pub fn effective(field: &FieldDoc) -> (FieldType, bool) {
    let t = effective_type(field);
    (t, field.masked.unwrap_or_else(|| default_masked(t)))
}

/// The plaintext metadata an entry's document projects into the manifest. Pure
/// function of the document, so the manifest can never claim more than the
/// ciphertext holds, and never carries a label, a field type or a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Projection {
    pub entry_type: EntryType,
    pub sensitivity: Sensitivity,
    pub field_count: u32,
    /// Some field's effective type is a TOTP seed.
    pub has_totp: bool,
}

/// Project a document into its manifest metadata:
///
/// - `entry_type` — the override, else `infer_entry_type_labelled` over the
///   fields' labels and effective types;
/// - `sensitivity` — the override, else the strongest of the fields' default
///   sensitivities;
/// - `field_count`, and `has_totp` (any effective type is a TOTP seed).
pub fn project(doc: &EntryDoc) -> Projection {
    let typed: Vec<(&str, FieldType)> = doc
        .fields
        .iter()
        .map(|f| (f.label.as_str(), effective_type(f)))
        .collect();
    let entry_type = doc
        .entry_type
        .unwrap_or_else(|| infer_entry_type_labelled(&typed));
    let sensitivity = doc.sensitivity.unwrap_or_else(|| {
        typed
            .iter()
            .map(|(_, t)| default_sensitivity(*t))
            .max()
            .unwrap_or(Sensitivity::Low)
    });
    Projection {
        entry_type,
        sensitivity,
        field_count: u32::try_from(doc.fields.len()).unwrap_or(u32::MAX),
        has_totp: typed.iter().any(|(_, t)| *t == FieldType::TotpSeed),
    }
}

// ---------------------------------------------------------------------------
// Reading a payload — raw (legacy) or document
// ---------------------------------------------------------------------------

/// A version-1 raw value read as a one-field document, **preserving what the
/// manifest already shows**: its projection equals `(stored_type,
/// stored_sens, 1, has_totp)` and the field is masked whenever `stored_sens` is
/// `high` or above.
///
/// The one field is `{id: f_00000000, label: "", value: raw}`. The label was
/// never stored (it biased inference once and was thrown away), so `""` is the
/// honest answer; it renders as "field 1". Inference without the lost label may
/// disagree with what was stored, so an override is pinned **only where it
/// would**: masking (when the stored sensitivity is high or above and the
/// inferred type would not mask), the entry's sensitivity, and the entry's type.
/// An old password whose label was lost therefore stays masked and `high`.
pub fn from_legacy(raw: &str, stored_type: EntryType, stored_sens: Sensitivity) -> EntryDoc {
    let t = infer_field_type("", raw);
    let masked = (stored_sens >= Sensitivity::High && !default_masked(t)).then_some(true);
    let sensitivity = (stored_sens != default_sensitivity(t)).then_some(stored_sens);
    let entry_type = (stored_type != infer_entry_type_labelled(&[("", t)])).then_some(stored_type);
    EntryDoc {
        v: DOC_VERSION,
        entry_type,
        sensitivity,
        fields: vec![FieldDoc {
            id: LEGACY_FIELD_ID.to_string(),
            label: String::new(),
            value: raw.to_string(),
            field_type: None,
            masked,
        }],
    }
}

/// Interpret an opened envelope's plaintext by the payload kind its
/// (authenticated) version byte declared. **The kind decides; the bytes are
/// never sniffed.** A raw value that happens to look like a field document is
/// one raw field holding that text.
///
/// A raw value is decoded with `String::from_utf8_lossy` — the same lossy decode
/// the broker's single-value reveal has always used — and `stored_type` /
/// `stored_sens` are the manifest's, used only to pin the legacy projection.
pub fn read_payload(
    kind: PayloadKind,
    plaintext: &[u8],
    stored_type: EntryType,
    stored_sens: Sensitivity,
) -> Result<EntryDoc, FieldError> {
    match kind {
        PayloadKind::RawValue => Ok(from_legacy(
            &String::from_utf8_lossy(plaintext),
            stored_type,
            stored_sens,
        )),
        PayloadKind::FieldDocument => decode(plaintext),
    }
}

// ---------------------------------------------------------------------------
// Edit inputs
// ---------------------------------------------------------------------------

/// A field as a client supplies it (create, add). No id: the broker mints one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldInput {
    pub label: String,
    pub value: String,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub field_type: Option<FieldType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
}

impl fmt::Debug for FieldInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldInput")
            .field("label_chars", &self.label.chars().count())
            .field(
                "value",
                &format_args!("<redacted, {} bytes>", self.value.len()),
            )
            .field("field_type", &self.field_type)
            .field("masked", &self.masked)
            .finish()
    }
}

impl From<ParsedField> for FieldInput {
    /// A parsed bulk-paste field, verbatim: the parser's label and value are the
    /// stored label and value, byte for byte.
    fn from(p: ParsedField) -> Self {
        FieldInput {
            label: p.label,
            value: p.value,
            field_type: None,
            masked: None,
        }
    }
}

/// An element of an update/rotate `fields` list: a [`FieldInput`] that may name
/// an existing field by `id` to keep its identity. No `id` mints a new field.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldReplace {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub label: String,
    pub value: String,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub field_type: Option<FieldType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked: Option<bool>,
}

impl fmt::Debug for FieldReplace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldReplace")
            .field("id", &self.id)
            .field("label_chars", &self.label.chars().count())
            .field(
                "value",
                &format_args!("<redacted, {} bytes>", self.value.len()),
            )
            .field("field_type", &self.field_type)
            .field("masked", &self.masked)
            .finish()
    }
}

/// A change to one field (`field.update`). Every key is optional but at least
/// one must be present. `type` / `masked` take `"auto"` to go back to inferring.
#[derive(Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldPatch {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(rename = "type", default)]
    pub field_type: Override<FieldType>,
    #[serde(default)]
    pub masked: Override<bool>,
}

impl fmt::Debug for FieldPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldPatch")
            .field("label", &self.label.as_ref().map(|l| l.chars().count()))
            .field(
                "value",
                &self
                    .value
                    .as_ref()
                    .map(|v| format!("<redacted, {} bytes>", v.len())),
            )
            .field("field_type", &self.field_type)
            .field("masked", &self.masked)
            .finish()
    }
}

impl FieldPatch {
    /// A patch that changes nothing.
    pub fn is_empty(&self) -> bool {
        self.label.is_none()
            && self.value.is_none()
            && self.field_type.is_keep()
            && self.masked.is_keep()
    }
}

// ---------------------------------------------------------------------------
// Pure edit helpers — each returns a new, validated document and leaves the
// input untouched, so a failed edit can never leave a half-applied one.
// ---------------------------------------------------------------------------

fn field_from_input(id: String, input: FieldInput) -> FieldDoc {
    FieldDoc {
        id,
        label: input.label,
        value: input.value,
        field_type: input.field_type,
        masked: input.masked,
    }
}

fn checked(doc: EntryDoc) -> Result<EntryDoc, FieldError> {
    validate(&doc)?;
    Ok(doc)
}

/// A new document from client-supplied fields, minting an id for each. The
/// entry-level overrides are the user's choices; `Keep` and `Auto` both mean
/// "infer it" for a new entry.
pub fn create(
    inputs: Vec<FieldInput>,
    entry_type: Override<EntryType>,
    sensitivity: Override<Sensitivity>,
) -> Result<EntryDoc, FieldError> {
    if inputs.is_empty() {
        return Err(FieldError::NoFields);
    }
    let mut taken = HashSet::new();
    let fields = inputs
        .into_iter()
        .map(|input| field_from_input(mint_field_id(&mut taken), input))
        .collect();
    checked(EntryDoc {
        v: DOC_VERSION,
        entry_type: entry_type.into_initial(),
        sensitivity: sensitivity.into_initial(),
        fields,
    })
}

/// `field.add`: insert `inputs` at `position` (`None` = append; "paste more"
/// appends, it never replaces — `08 §7`). Returns the new document and the
/// minted ids, in the order given.
pub fn add(
    doc: &EntryDoc,
    inputs: Vec<FieldInput>,
    position: Option<usize>,
) -> Result<(EntryDoc, Vec<String>), FieldError> {
    if inputs.is_empty() {
        return Err(FieldError::NothingToAdd);
    }
    let len = doc.fields.len();
    let position = position.unwrap_or(len);
    if position > len {
        return Err(FieldError::PositionOutOfRange { position, len });
    }
    let mut taken: HashSet<String> = doc.fields.iter().map(|f| f.id.clone()).collect();
    let mut added = Vec::with_capacity(inputs.len());
    let mut new_fields = Vec::with_capacity(inputs.len());
    for input in inputs {
        let id = mint_field_id(&mut taken);
        added.push(id.clone());
        new_fields.push(field_from_input(id, input));
    }
    let mut next = doc.clone();
    next.fields.splice(position..position, new_fields);
    Ok((checked(next)?, added))
}

/// `field.update`: change one field. A changed `value`/`label` re-infers an
/// un-overridden type; an overridden type sticks. `type` / `masked` `"auto"`
/// clears the override.
pub fn patch(doc: &EntryDoc, id: &str, change: FieldPatch) -> Result<EntryDoc, FieldError> {
    if change.is_empty() {
        return Err(FieldError::EmptyPatch);
    }
    let index = doc.position_of(id)?;
    let mut next = doc.clone();
    let field = &mut next.fields[index];
    if let Some(label) = change.label {
        field.label = label;
    }
    if let Some(value) = change.value {
        field.value = value;
    }
    field.field_type = change.field_type.apply(field.field_type);
    field.masked = change.masked.apply(field.masked);
    checked(next)
}

/// `field.remove`: drop one field. The last field cannot be removed — remove the
/// entry instead.
pub fn remove(doc: &EntryDoc, id: &str) -> Result<EntryDoc, FieldError> {
    let index = doc.position_of(id)?;
    if doc.fields.len() == 1 {
        return Err(FieldError::LastField);
    }
    let mut next = doc.clone();
    next.fields.remove(index);
    checked(next)
}

/// `field.reorder`: `order` must be an exact permutation of the current ids.
pub fn reorder(doc: &EntryDoc, order: &[String]) -> Result<EntryDoc, FieldError> {
    if order.len() != doc.fields.len() {
        return Err(FieldError::BadOrder);
    }
    let mut by_id: HashMap<&str, &FieldDoc> =
        doc.fields.iter().map(|f| (f.id.as_str(), f)).collect();
    let mut fields = Vec::with_capacity(order.len());
    for id in order {
        // `remove` makes a repeated id fail on its second appearance.
        match by_id.remove(id.as_str()) {
            Some(field) => fields.push(field.clone()),
            None => return Err(FieldError::BadOrder),
        }
    }
    let mut next = doc.clone();
    next.fields = fields;
    checked(next)
}

/// `entry.update` / `entry.rotate` with a single `value`: replace one field's
/// value. `target` names the field; with `None` the entry must have exactly one
/// field, otherwise the call is ambiguous and refused. `label`, when given,
/// renames that same field. Type and mask overrides are left alone — a changed
/// value re-infers whatever the user did not pin.
pub fn replace_value(
    doc: &EntryDoc,
    target: Option<&str>,
    value: String,
    label: Option<String>,
) -> Result<EntryDoc, FieldError> {
    let index = match target {
        Some(id) => doc.position_of(id)?,
        None if doc.fields.len() == 1 => 0,
        None => {
            return Err(FieldError::AmbiguousField {
                field_count: doc.fields.len(),
            })
        }
    };
    let mut next = doc.clone();
    next.fields[index].value = value;
    if let Some(label) = label {
        next.fields[index].label = label;
    }
    checked(next)
}

/// `entry.update` / `entry.rotate` with a `fields` list: replace the whole field
/// list. An `id` that names an existing field keeps that field's identity (ids
/// given must exist, each at most once); no `id` mints a new field; an existing
/// field not mentioned is dropped. Each replacement is taken whole — its
/// `type`/`masked` are the input's (absent = inferred), not merged with what the
/// old field carried. The entry-level overrides are kept.
pub fn replace_all(
    doc: &EntryDoc,
    replacements: Vec<FieldReplace>,
) -> Result<EntryDoc, FieldError> {
    if replacements.is_empty() {
        return Err(FieldError::NoFields);
    }
    let existing: HashSet<&str> = doc.fields.iter().map(|f| f.id.as_str()).collect();
    let mut used: HashSet<String> = HashSet::new();
    for r in &replacements {
        if let Some(id) = &r.id {
            if !existing.contains(id.as_str()) {
                return Err(not_found(id));
            }
            if !used.insert(id.clone()) {
                return Err(FieldError::DuplicateReplace { id: id.clone() });
            }
        }
    }
    // New ids avoid every id the entry has ever shown — including the ones this
    // call drops, so a dropped field's identity is never recycled.
    let mut taken: HashSet<String> = doc.fields.iter().map(|f| f.id.clone()).collect();
    let fields = replacements
        .into_iter()
        .map(|r| FieldDoc {
            id: r.id.unwrap_or_else(|| mint_field_id(&mut taken)),
            label: r.label,
            value: r.value,
            field_type: r.field_type,
            masked: r.masked,
        })
        .collect();
    let mut next = doc.clone();
    next.fields = fields;
    checked(next)
}

/// Set or clear the entry-level overrides (`entryType`, `sensitivity`). `Keep`
/// leaves one alone, `Auto` clears it, `Set` pins it.
pub fn set_entry_overrides(
    doc: &EntryDoc,
    entry_type: Override<EntryType>,
    sensitivity: Override<Sensitivity>,
) -> EntryDoc {
    let mut next = doc.clone();
    next.entry_type = entry_type.apply(next.entry_type);
    next.sensitivity = sensitivity.apply(next.sensitivity);
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(label: &str, value: &str) -> FieldInput {
        FieldInput {
            label: label.to_string(),
            value: value.to_string(),
            field_type: None,
            masked: None,
        }
    }

    fn doc3() -> EntryDoc {
        create(
            vec![
                input("host", "db.internal"),
                input("username", "root"),
                input("password", "hunter2"),
            ],
            Override::Keep,
            Override::Keep,
        )
        .unwrap()
    }

    #[test]
    fn a_created_document_encodes_to_canonical_compact_json_and_round_trips() {
        let doc = doc3();
        let bytes = encode(&doc).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with(r#"{"v":1,"fields":[{"id":"f_"#), "{text}");
        assert!(
            !text.contains(' ') || text.contains("db.internal"),
            "compact"
        );
        assert!(!text.contains("entryType"), "absent overrides are omitted");
        assert!(!text.contains("\"type\""), "absent overrides are omitted");
        assert_eq!(decode(&bytes).unwrap(), doc);
    }

    #[test]
    fn the_exact_canonical_bytes_are_pinned() {
        let doc = EntryDoc {
            v: 1,
            entry_type: Some(EntryType::Server),
            sensitivity: Some(Sensitivity::High),
            fields: vec![
                FieldDoc {
                    id: "f_0a1b2c3d".into(),
                    label: "host".into(),
                    value: "db.internal".into(),
                    field_type: Some(FieldType::Host),
                    masked: Some(false),
                },
                FieldDoc {
                    id: "f_00000000".into(),
                    label: String::new(),
                    value: "a\"b\\c\nd".into(),
                    field_type: None,
                    masked: None,
                },
            ],
        };
        assert_eq!(
            std::str::from_utf8(&encode(&doc).unwrap()).unwrap(),
            r#"{"v":1,"entryType":"server","sensitivity":"high","fields":[{"id":"f_0a1b2c3d","label":"host","value":"db.internal","type":"host","masked":false},{"id":"f_00000000","label":"","value":"a\"b\\c\nd"}]}"#
        );
    }

    #[test]
    fn debug_output_never_contains_a_value() {
        let doc = create(
            vec![input("password", "marker-secret-value-xyz")],
            Override::Keep,
            Override::Keep,
        )
        .unwrap();
        let shown = format!("{doc:?} {:?}", input("p", "marker-secret-value-xyz"));
        assert!(!shown.contains("marker-secret-value-xyz"), "{shown}");
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn decode_refuses_what_validate_refuses_and_what_serde_does() {
        let good = encode(&doc3()).unwrap();
        let text = String::from_utf8(good).unwrap();

        // Unknown key at the top and inside a field.
        let with_extra = text.replacen("{\"v\":1", "{\"v\":1,\"surprise\":true", 1);
        assert!(matches!(
            decode(with_extra.as_bytes()),
            Err(FieldError::Malformed { class: "data", .. })
        ));
        let with_field_extra = text.replacen("\"label\"", "\"extra\":1,\"label\"", 1);
        assert!(decode(with_field_extra.as_bytes()).is_err());

        // Wrong document version.
        let v2 = text.replacen("\"v\":1", "\"v\":2", 1);
        assert_eq!(
            decode(v2.as_bytes()),
            Err(FieldError::UnsupportedDocVersion(2))
        );

        // No fields.
        assert_eq!(decode(br#"{"v":1,"fields":[]}"#), Err(FieldError::NoFields));

        // Bad id, duplicate id.
        assert_eq!(
            decode(br#"{"v":1,"fields":[{"id":"F_0A1B2C3D","label":"","value":""}]}"#),
            Err(FieldError::BadFieldId { index: 0 })
        );
        assert_eq!(
            decode(br#"{"v":1,"fields":[{"id":"f_0a1b2c3d","label":"","value":""},{"id":"f_0a1b2c3d","label":"","value":""}]}"#),
            Err(FieldError::DuplicateFieldId { id: "f_0a1b2c3d".into() })
        );

        // A duplicate JSON key.
        assert!(
            decode(br#"{"v":1,"v":1,"fields":[{"id":"f_0a1b2c3d","label":"","value":""}]}"#)
                .is_err()
        );

        // Not JSON at all, and trailing garbage.
        assert!(decode(b"not json").is_err());
        assert!(decode(b"").is_err());
        let trailing = format!("{text} x");
        assert!(decode(trailing.as_bytes()).is_err());
    }

    #[test]
    fn labels_follow_the_rules_and_nothing_else() {
        let f = |label: &str| {
            create(vec![input(label, "v")], Override::Keep, Override::Keep).map(|_| ())
        };
        // Free text, any script, empty, with spaces and punctuation, and the
        // words that look like keys of this very format.
        for ok in [
            "",
            "host",
            "ssh key (prod)",
            "密码",
            "пароль",
            "🔑 key",
            "id",
            "value",
            "type",
            "label",
            "v",
            "fields",
            "x".repeat(200).as_str(),
        ] {
            assert_eq!(f(ok), Ok(()), "{ok:?}");
        }
        assert!(matches!(
            f(&"x".repeat(201)),
            Err(FieldError::LabelTooLong { index: 0 })
        ));
        for bad in ["a\nb", "a\rb", "a\0b", "tab\there", "\u{7f}", "bell\u{7}"] {
            assert!(
                matches!(f(bad), Err(FieldError::LabelNotOneLine { index: 0 })),
                "{bad:?}"
            );
        }
        // 200 four-byte characters is 200 characters.
        assert_eq!(f(&"🔑".repeat(200)), Ok(()));
        assert!(f(&"🔑".repeat(201)).is_err());
    }

    #[test]
    fn values_are_verbatim_including_nul_crlf_and_surrounding_space() {
        let value = "  lead\0nul\r\nend\rlone-cr 🔑  ";
        let doc = create(vec![input("x", value)], Override::Keep, Override::Keep).unwrap();
        let back = decode(&encode(&doc).unwrap()).unwrap();
        assert_eq!(back.fields[0].value, value);
    }

    #[test]
    fn an_oversize_document_is_refused_and_a_big_one_is_not() {
        let big = "x".repeat(ENTRY_DOC_MAX_BYTES / 2);
        assert!(create(vec![input("a", &big)], Override::Keep, Override::Keep).is_ok());
        let too_big = "x".repeat(ENTRY_DOC_MAX_BYTES);
        assert!(matches!(
            create(vec![input("a", &too_big)], Override::Keep, Override::Keep),
            Err(FieldError::TooLarge { .. })
        ));
        assert!(matches!(
            decode(&vec![b' '; ENTRY_DOC_MAX_BYTES + 1]),
            Err(FieldError::TooLarge { .. })
        ));
    }

    #[test]
    fn there_is_no_cap_on_the_number_of_fields() {
        let many: Vec<FieldInput> = (0..2000).map(|i| input("k", &i.to_string())).collect();
        let doc = create(many, Override::Keep, Override::Keep).unwrap();
        assert_eq!(doc.fields.len(), 2000);
        assert_eq!(decode(&encode(&doc).unwrap()).unwrap(), doc);
    }

    #[test]
    fn new_field_ids_have_the_shape_and_are_never_the_legacy_id() {
        for _ in 0..2000 {
            let id = new_field_id();
            assert!(is_valid_field_id(&id), "{id}");
            assert_ne!(id, LEGACY_FIELD_ID);
        }
        assert!(
            is_valid_field_id(LEGACY_FIELD_ID),
            "stored docs may carry it"
        );
        for bad in [
            "",
            "f_",
            "f_0a1b2c3",
            "f_0a1b2c3de",
            "f_0A1B2C3D",
            "g_0a1b2c3d",
            "f_0a1b2c3g",
        ] {
            assert!(!is_valid_field_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn created_ids_are_unique_within_the_entry() {
        let many: Vec<FieldInput> = (0..500).map(|_| input("k", "v")).collect();
        let doc = create(many, Override::Keep, Override::Keep).unwrap();
        let ids: HashSet<&str> = doc.fields.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids.len(), 500);
    }

    #[test]
    fn override_parses_absent_auto_and_a_value_and_refuses_null() {
        #[derive(Deserialize)]
        struct W {
            #[serde(default)]
            t: Override<FieldType>,
            #[serde(default)]
            m: Override<bool>,
        }
        let w: W = serde_json::from_str("{}").unwrap();
        assert!(w.t.is_keep() && w.m.is_keep());
        let w: W = serde_json::from_str(r#"{"t":"auto","m":"auto"}"#).unwrap();
        assert_eq!((w.t, w.m), (Override::Auto, Override::Auto));
        let w: W = serde_json::from_str(r#"{"t":"api-key","m":true}"#).unwrap();
        assert_eq!(
            (w.t, w.m),
            (Override::Set(FieldType::ApiKey), Override::Set(true))
        );
        assert!(serde_json::from_str::<W>(r#"{"t":null}"#).is_err());
        assert!(serde_json::from_str::<W>(r#"{"m":null}"#).is_err());
        assert!(serde_json::from_str::<W>(r#"{"t":"nonsense"}"#).is_err());
        assert!(serde_json::from_str::<W>(r#"{"m":"yes"}"#).is_err());
    }

    #[test]
    fn the_wire_shapes_deserialize_strictly() {
        // FieldPatch: every key optional, "auto" clears, null and strangers refused.
        let p: FieldPatch =
            serde_json::from_str(r#"{"label":"x","type":"auto","masked":false}"#).unwrap();
        assert_eq!(p.label.as_deref(), Some("x"));
        assert_eq!(p.value, None);
        assert_eq!(p.field_type, Override::Auto);
        assert_eq!(p.masked, Override::Set(false));
        assert!(!p.is_empty());
        assert!(serde_json::from_str::<FieldPatch>("{}").unwrap().is_empty());
        assert!(serde_json::from_str::<FieldPatch>(r#"{"surprise":1}"#).is_err());
        assert!(serde_json::from_str::<FieldPatch>(r#"{"type":null}"#).is_err());
        assert!(serde_json::from_str::<FieldPatch>(r#"{"type":"bogus"}"#).is_err());

        // FieldInput: label and value are required; `id` belongs to FieldReplace.
        let i: FieldInput =
            serde_json::from_str(r#"{"label":"a","value":"b","type":"password","masked":true}"#)
                .unwrap();
        assert_eq!(i.field_type, Some(FieldType::Password));
        assert_eq!(i.masked, Some(true));
        assert!(serde_json::from_str::<FieldInput>(r#"{"value":"b"}"#).is_err());
        assert!(serde_json::from_str::<FieldInput>(r#"{"label":"a"}"#).is_err());
        assert!(serde_json::from_str::<FieldInput>(
            r#"{"label":"a","value":"b","id":"f_0a1b2c3d"}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<FieldInput>(r#"{"label":"a","value":"b","type":"bogus"}"#)
                .is_err()
        );

        // FieldReplace: the same plus an optional id.
        let r: FieldReplace =
            serde_json::from_str(r#"{"id":"f_0a1b2c3d","label":"a","value":"b"}"#).unwrap();
        assert_eq!(r.id.as_deref(), Some("f_0a1b2c3d"));
        let r: FieldReplace = serde_json::from_str(r#"{"label":"a","value":"b"}"#).unwrap();
        assert_eq!(r.id, None);

        // Serialising an input omits what was not set.
        let out = serde_json::to_string(&input("a", "b")).unwrap();
        assert_eq!(out, r#"{"label":"a","value":"b"}"#);
    }

    #[test]
    fn auto_clears_an_override_and_keep_leaves_it() {
        let doc = create(
            vec![FieldInput {
                label: "x".into(),
                value: "plain".into(),
                field_type: Some(FieldType::Password),
                masked: Some(false),
            }],
            Override::Set(EntryType::Login),
            Override::Set(Sensitivity::Critical),
        )
        .unwrap();
        let id = doc.fields[0].id.clone();

        let kept = patch(
            &doc,
            &id,
            FieldPatch {
                label: Some("renamed".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(kept.fields[0].field_type, Some(FieldType::Password));
        assert_eq!(kept.fields[0].masked, Some(false));

        let cleared = patch(
            &doc,
            &id,
            FieldPatch {
                field_type: Override::Auto,
                masked: Override::Auto,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(cleared.fields[0].field_type, None);
        assert_eq!(cleared.fields[0].masked, None);
        assert_eq!(effective(&cleared.fields[0]), (FieldType::Text, false));

        let entry_cleared = set_entry_overrides(&doc, Override::Auto, Override::Keep);
        assert_eq!(entry_cleared.entry_type, None);
        assert_eq!(entry_cleared.sensitivity, Some(Sensitivity::Critical));
        let entry_kept = set_entry_overrides(&doc, Override::Keep, Override::Keep);
        assert_eq!(entry_kept, doc);
    }

    #[test]
    fn effective_type_reinfers_unless_overridden() {
        let doc = create(
            vec![input("password", "hunter2")],
            Override::Keep,
            Override::Keep,
        )
        .unwrap();
        let id = doc.fields[0].id.clone();
        assert_eq!(effective(&doc.fields[0]), (FieldType::Password, true));

        // A changed value re-infers the un-overridden type.
        let url = patch(
            &doc,
            &id,
            FieldPatch {
                value: Some("https://example.com".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(effective(&url.fields[0]), (FieldType::Url, false));

        // An overridden type sticks, and masking follows it.
        let pinned = patch(
            &url,
            &id,
            FieldPatch {
                field_type: Override::Set(FieldType::Password),
                ..Default::default()
            },
        )
        .unwrap();
        let moved = patch(
            &pinned,
            &id,
            FieldPatch {
                value: Some("203.0.113.9".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(effective(&moved.fields[0]), (FieldType::Password, true));
    }

    #[test]
    fn projection_takes_the_strongest_sensitivity_and_flags_totp() {
        let doc = create(
            vec![
                input("host", "db.internal"),
                input("username", "root"),
                input("password", "hunter2"),
                input("2fa", "JBSWY3DPEHPK3PXP"),
            ],
            Override::Keep,
            Override::Keep,
        )
        .unwrap();
        let p = project(&doc);
        assert_eq!(p.entry_type, EntryType::Server);
        assert_eq!(p.sensitivity, Sensitivity::High);
        assert_eq!(p.field_count, 4);
        assert!(p.has_totp);

        let wallet = create(
            vec![input("seed", "abandon ability able about above absent absorb abstract absurd abuse access accident")],
            Override::Keep,
            Override::Keep,
        )
        .unwrap();
        let p = project(&wallet);
        assert_eq!(
            (p.entry_type, p.sensitivity, p.has_totp),
            (EntryType::Wallet, Sensitivity::Critical, false)
        );

        // Overrides win.
        let pinned = set_entry_overrides(
            &wallet,
            Override::Set(EntryType::Note),
            Override::Set(Sensitivity::Low),
        );
        let p = project(&pinned);
        assert_eq!(
            (p.entry_type, p.sensitivity),
            (EntryType::Note, Sensitivity::Low)
        );
    }

    #[test]
    fn a_note_entry_is_one_field_labelled_note() {
        let doc = create(
            vec![input("note", "remember to rotate the keys quarterly")],
            Override::Keep,
            Override::Keep,
        )
        .unwrap();
        let p = project(&doc);
        assert_eq!(p.entry_type, EntryType::Note);
        assert_eq!(p.sensitivity, Sensitivity::Low);
        assert!(!effective(&doc.fields[0]).1, "free text is not masked");
        assert!(!p.has_totp);
    }

    // ---- legacy ----

    #[test]
    fn legacy_values_read_as_one_unlabelled_field_with_the_reserved_id() {
        let doc = from_legacy("hunter2", EntryType::Other, Sensitivity::High);
        assert_eq!(doc.fields.len(), 1);
        assert_eq!(doc.fields[0].id, LEGACY_FIELD_ID);
        assert_eq!(doc.fields[0].label, "");
        assert_eq!(doc.fields[0].value, "hunter2");
        // Re-inference without the lost label says text/low, so the stored
        // `high` is pinned and the field stays masked.
        let p = project(&doc);
        assert_eq!(p.sensitivity, Sensitivity::High);
        assert!(effective(&doc.fields[0]).1);
        // And the document is valid and encodable (the first write re-seals it).
        validate(&doc).unwrap();
    }

    #[test]
    fn legacy_pins_nothing_when_inference_already_agrees() {
        let doc = from_legacy("sk-abcdefghijklmnop", EntryType::Other, Sensitivity::High);
        assert_eq!(doc.entry_type, None);
        assert_eq!(doc.sensitivity, None);
        assert_eq!(doc.fields[0].masked, None);
    }

    #[test]
    fn a_legacy_raw_value_that_looks_like_a_document_is_never_parsed() {
        let lookalike = r#"{"v":1,"fields":[{"id":"f_0a1b2c3d","label":"x","value":"y"}]}"#;
        let doc = read_payload(
            PayloadKind::RawValue,
            lookalike.as_bytes(),
            EntryType::Other,
            Sensitivity::Low,
        )
        .unwrap();
        assert_eq!(doc.fields.len(), 1);
        assert_eq!(doc.fields[0].id, LEGACY_FIELD_ID);
        assert_eq!(doc.fields[0].label, "");
        assert_eq!(doc.fields[0].value, lookalike);
    }

    #[test]
    fn a_field_document_payload_is_decoded_and_a_raw_one_is_not() {
        let doc = doc3();
        let bytes = encode(&doc).unwrap();
        let read = read_payload(
            PayloadKind::FieldDocument,
            &bytes,
            EntryType::Other,
            Sensitivity::Low,
        )
        .unwrap();
        assert_eq!(read, doc);
        // The same bytes read as a raw value are just a value.
        let raw = read_payload(
            PayloadKind::RawValue,
            &bytes,
            EntryType::Other,
            Sensitivity::Low,
        )
        .unwrap();
        assert_eq!(raw.fields[0].value.as_bytes(), bytes.as_slice());
        // And a document payload that is not a document is an error, not a value.
        assert!(read_payload(
            PayloadKind::FieldDocument,
            b"just a password",
            EntryType::Other,
            Sensitivity::Low
        )
        .is_err());
    }

    #[test]
    fn legacy_non_utf8_plaintext_reads_lossily_like_the_single_value_reveal_always_did() {
        let doc = read_payload(
            PayloadKind::RawValue,
            &[0x68, 0x69, 0xff],
            EntryType::Other,
            Sensitivity::Low,
        )
        .unwrap();
        assert_eq!(doc.fields[0].value, "hi\u{fffd}");
    }

    // ---- edit helpers ----

    #[test]
    fn add_appends_by_default_inserts_at_a_position_and_returns_the_minted_ids() {
        let doc = doc3();
        let (appended, ids) = add(&doc, vec![input("a", "1"), input("b", "2")], None).unwrap();
        assert_eq!(appended.fields.len(), 5);
        assert_eq!(&appended.fields[3].id, &ids[0]);
        assert_eq!(&appended.fields[4].id, &ids[1]);
        assert_eq!(appended.fields[3].label, "a");

        let (front, ids) = add(&doc, vec![input("first", "0")], Some(0)).unwrap();
        assert_eq!(front.fields[0].id, ids[0]);
        assert_eq!(front.fields[1].label, "host");

        let (middle, _) = add(&doc, vec![input("mid", "m")], Some(1)).unwrap();
        assert_eq!(middle.fields[1].label, "mid");
        assert_eq!(middle.fields[2].label, "username");

        // The original is untouched.
        assert_eq!(doc.fields.len(), 3);
    }

    #[test]
    fn add_refuses_nothing_to_add_and_a_position_past_the_end() {
        let doc = doc3();
        assert_eq!(
            add(&doc, vec![], None).unwrap_err(),
            FieldError::NothingToAdd
        );
        assert_eq!(
            add(&doc, vec![input("a", "1")], Some(4)).unwrap_err(),
            FieldError::PositionOutOfRange {
                position: 4,
                len: 3
            }
        );
        assert!(add(&doc, vec![input("a", "1")], Some(3)).is_ok());
    }

    #[test]
    fn add_never_reuses_an_existing_id() {
        let mut doc = doc3();
        for _ in 0..200 {
            let (next, _) = add(&doc, vec![input("k", "v")], None).unwrap();
            doc = next;
        }
        let ids: HashSet<&str> = doc.fields.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids.len(), doc.fields.len());
    }

    #[test]
    fn patch_refuses_an_empty_patch_and_an_unknown_id() {
        let doc = doc3();
        let id = doc.fields[0].id.clone();
        assert_eq!(
            patch(&doc, &id, FieldPatch::default()).unwrap_err(),
            FieldError::EmptyPatch
        );
        assert_eq!(
            patch(
                &doc,
                "f_ffffffff",
                FieldPatch {
                    label: Some("x".into()),
                    ..Default::default()
                }
            )
            .unwrap_err(),
            FieldError::FieldNotFound {
                id: Some("f_ffffffff".into())
            }
        );
        // A malformed id is not echoed.
        let err = patch(
            &doc,
            "attacker-or-secret-text",
            FieldPatch {
                label: Some("x".into()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err, FieldError::FieldNotFound { id: None });
        assert!(!err.to_string().contains("attacker-or-secret-text"));
    }

    #[test]
    fn patch_validates_the_result() {
        let doc = doc3();
        let id = doc.fields[0].id.clone();
        let err = patch(
            &doc,
            &id,
            FieldPatch {
                label: Some("two\nlines".into()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err, FieldError::LabelNotOneLine { index: 0 });
    }

    #[test]
    fn remove_drops_one_field_and_refuses_the_last() {
        let doc = doc3();
        let id = doc.fields[1].id.clone();
        let fewer = remove(&doc, &id).unwrap();
        assert_eq!(fewer.fields.len(), 2);
        assert!(fewer.field(&id).is_none());

        let one = create(vec![input("only", "v")], Override::Keep, Override::Keep).unwrap();
        assert_eq!(
            remove(&one, &one.fields[0].id).unwrap_err(),
            FieldError::LastField
        );
        assert!(matches!(
            remove(&doc, "f_ffffffff").unwrap_err(),
            FieldError::FieldNotFound { .. }
        ));
    }

    #[test]
    fn reorder_takes_an_exact_permutation_and_nothing_else() {
        let doc = doc3();
        let ids = doc.field_ids();
        let reversed: Vec<String> = ids.iter().rev().cloned().collect();
        let out = reorder(&doc, &reversed).unwrap();
        assert_eq!(out.field_ids(), reversed);
        // Labels and values travel with their ids.
        assert_eq!(out.fields[0].label, "password");

        let mut dup = ids.clone();
        let first = dup[0].clone();
        dup[1] = first;
        assert_eq!(reorder(&doc, &dup).unwrap_err(), FieldError::BadOrder);
        assert_eq!(reorder(&doc, &ids[..2]).unwrap_err(), FieldError::BadOrder);
        let mut foreign = ids.clone();
        foreign[2] = "f_ffffffff".into();
        assert_eq!(reorder(&doc, &foreign).unwrap_err(), FieldError::BadOrder);
        let mut longer = ids.clone();
        longer.push("f_ffffffff".into());
        assert_eq!(reorder(&doc, &longer).unwrap_err(), FieldError::BadOrder);
    }

    #[test]
    fn replace_value_needs_a_target_on_a_multi_field_entry() {
        let multi = doc3();
        assert_eq!(
            replace_value(&multi, None, "x".into(), None).unwrap_err(),
            FieldError::AmbiguousField { field_count: 3 }
        );
        let id = multi.fields[2].id.clone();
        let out = replace_value(&multi, Some(&id), "new".into(), Some("pw".into())).unwrap();
        assert_eq!(out.fields[2].value, "new");
        assert_eq!(out.fields[2].label, "pw");
        assert_eq!(out.fields[2].id, id);
        assert_eq!(out.fields[0].value, "db.internal");

        let single = create(vec![input("a", "1")], Override::Keep, Override::Keep).unwrap();
        let out = replace_value(&single, None, "2".into(), None).unwrap();
        assert_eq!(out.fields[0].value, "2");
        assert_eq!(out.fields[0].label, "a", "no label given: not renamed");
        assert!(matches!(
            replace_value(&single, Some("f_ffffffff"), "2".into(), None).unwrap_err(),
            FieldError::FieldNotFound { .. }
        ));
    }

    #[test]
    fn replace_all_keeps_given_ids_drops_the_rest_and_mints_for_new() {
        let doc = doc3();
        let keep = doc.fields[1].id.clone();
        let dropped = [doc.fields[0].id.clone(), doc.fields[2].id.clone()];
        let out = replace_all(
            &doc,
            vec![
                FieldReplace {
                    id: Some(keep.clone()),
                    label: "user".into(),
                    value: "admin".into(),
                    field_type: None,
                    masked: None,
                },
                FieldReplace {
                    id: None,
                    label: "token".into(),
                    value: "t".into(),
                    field_type: Some(FieldType::ApiKey),
                    masked: None,
                },
            ],
        )
        .unwrap();
        assert_eq!(out.fields.len(), 2);
        assert_eq!(out.fields[0].id, keep);
        assert_eq!(out.fields[0].value, "admin");
        assert!(
            !dropped.contains(&out.fields[1].id),
            "a dropped id is not recycled"
        );
        assert!(is_valid_field_id(&out.fields[1].id));
        assert_eq!(out.fields[1].field_type, Some(FieldType::ApiKey));
    }

    #[test]
    fn replace_all_refuses_an_unknown_id_a_repeated_id_and_an_empty_list() {
        let doc = doc3();
        let id = doc.fields[0].id.clone();
        let r = |id: Option<String>| FieldReplace {
            id,
            label: "l".into(),
            value: "v".into(),
            field_type: None,
            masked: None,
        };
        assert!(matches!(
            replace_all(&doc, vec![r(Some("f_ffffffff".into()))]).unwrap_err(),
            FieldError::FieldNotFound { .. }
        ));
        assert_eq!(
            replace_all(&doc, vec![r(Some(id.clone())), r(Some(id.clone()))]).unwrap_err(),
            FieldError::DuplicateReplace { id }
        );
        assert_eq!(replace_all(&doc, vec![]).unwrap_err(), FieldError::NoFields);
    }

    #[test]
    fn replace_all_keeps_the_entry_level_overrides() {
        let doc = create(
            vec![input("a", "1")],
            Override::Set(EntryType::Login),
            Override::Set(Sensitivity::Critical),
        )
        .unwrap();
        let out = replace_all(
            &doc,
            vec![FieldReplace {
                id: Some(doc.fields[0].id.clone()),
                label: "b".into(),
                value: "2".into(),
                field_type: None,
                masked: None,
            }],
        )
        .unwrap();
        assert_eq!(out.entry_type, Some(EntryType::Login));
        assert_eq!(out.sensitivity, Some(Sensitivity::Critical));
    }

    #[test]
    fn a_parsed_bulk_paste_becomes_fields_verbatim() {
        let parsed = crate::parser::parse_bulk("host: db.internal\n///\nblob line one\nline two");
        let inputs: Vec<FieldInput> = parsed.iter().cloned().map(FieldInput::from).collect();
        let doc = create(inputs, Override::Keep, Override::Keep).unwrap();
        assert_eq!(doc.fields.len(), 2);
        for (field, p) in doc.fields.iter().zip(&parsed) {
            assert_eq!((&field.label, &field.value), (&p.label, &p.value));
        }
    }

    #[test]
    fn errors_never_quote_a_label_or_a_value() {
        let secret_label = "label-marker-qqq";
        let secret_value = "value-marker-qqq";
        let doc = create(
            vec![input(secret_label, secret_value)],
            Override::Keep,
            Override::Keep,
        )
        .unwrap();
        let id = doc.fields[0].id.clone();
        let errors: Vec<FieldError> = vec![
            remove(&doc, &id).unwrap_err(),
            add(&doc, vec![], None).unwrap_err(),
            patch(&doc, &id, FieldPatch::default()).unwrap_err(),
            reorder(&doc, &[]).unwrap_err(),
            replace_value(&doc, Some("f_ffffffff"), secret_value.into(), None).unwrap_err(),
            decode(format!(r#"{{"v":"{secret_value}","fields":[]}}"#).as_bytes()).unwrap_err(),
            decode(format!(r#"{{"v":1,"fields":[{{"id":"f_0a1b2c3d","label":"{secret_label}","value":{{"x":"{secret_value}"}}}}]}}"#).as_bytes()).unwrap_err(),
            decode(format!(r#"{{"v":1,"{secret_label}":1}}"#).as_bytes()).unwrap_err(),
            create(vec![input(&format!("{secret_label}\n"), secret_value)], Override::Keep, Override::Keep).unwrap_err(),
        ];
        for e in errors {
            let shown = format!("{e} / {e:?}");
            assert!(!shown.contains("marker-qqq"), "{shown}");
        }
    }
}
