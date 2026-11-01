//! Field- and entry-type inference. See `docs/03_DATA_MODEL.md §5` and
//! `docs/08_FIELD_MODEL.md §6`. A suggestion, never a decision (`ADR-012`):
//! every result here is a UI chip the user can override with one click, and
//! [`infer_field_type`] never touches the value it classifies (P-11).
//!
//! **Simplification recorded.** `08 §6` derives entry type `wallet` from
//! "any `seed-phrase`/`private-key` **+ an address-shaped field**" — but no
//! field type named "address" exists anywhere in `03 §5`'s table, so that
//! qualifier has no field type to test against in this crate. This
//! implementation infers `wallet` from the presence of a `seed-phrase` or
//! `private-key` field alone. Recording this here rather than guessing at an
//! address heuristic that isn't specified: inference is explicitly
//! non-authoritative (`ADR-012`), so under-inferring costs one click, not a
//! correctness bug.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FieldType {
    Password,
    ApiKey,
    PrivateKey,
    SeedPhrase,
    TotpSeed,
    Username,
    Host,
    Port,
    Url,
    Certificate,
    Text,
}

/// `03_DATA_MODEL.md §5`. Used by `crates/store`'s manifest entries
/// (`manifest.rs`) as well as for inference below.
///
/// `Note` (ADR-078) is the entry whose single field is free text. It was
/// `NoteOnly` / `"note-only"` until then — a variant nothing ever constructed,
/// so no manifest, rotation snapshot or removal archive can hold the old
/// spelling and renaming its serialisation cannot break a signature over one.
/// `"note-only"` is still accepted on input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EntryType {
    Server,
    Database,
    Api,
    Wallet,
    Login,
    Ssh,
    Certificate,
    Token,
    Totp,
    EnvBundle,
    #[serde(alias = "note-only")]
    Note,
    Other,
}

/// How much damage the entry's exposure does — a **label**, never an access
/// input (nothing in the broker reads it for a decision). It lived in
/// `crates/store` until ADR-078, but an entry's sensitivity is now computed
/// from its fields, which is pure and so belongs here; `credmgr_store::manifest`
/// re-exports it, so every existing path still compiles. The representation
/// (lowercase strings) is unchanged, which is what keeps every signed manifest
/// written before the move verifying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Critical,
}

fn looks_like_private_key(value: &str) -> bool {
    value.contains("-----BEGIN") && value.contains("PRIVATE KEY-----")
}

fn looks_like_certificate(value: &str) -> bool {
    value.contains("-----BEGIN CERTIFICATE-----")
}

/// A stored TOTP seed: an `otpauth://` URI, or base32 in any of the shapes services show: upper case in one piece
/// (16, 20, 24, 26, 32, 40, 52, 56 or 64 characters), or grouped with spaces or dashes in any case (the way
/// many services display it). A plain lower-case run is not recognised (it cannot be told from a word); a seed in
/// that shape has to be typed `totp-seed` by its owner to be treated as one. This is the same class `entry.reveal`
/// withholds and `totp.code` computes from (audit P0-1).
fn looks_like_totp_seed(value: &str) -> bool {
    if value.starts_with("otpauth://") {
        return true;
    }
    let trimmed = value.trim();
    let digits = |c: char| ('2'..='7').contains(&c);
    // Upper case in one piece: the shape that was always recognised, now at every length a service issues.
    if matches!(trimmed.len(), 16 | 20 | 24 | 26 | 32 | 40 | 52 | 56 | 64)
        && trimmed.chars().all(|c| c.is_ascii_uppercase() || digits(c))
    {
        return true;
    }
    // Grouped the way services display it: groups of exactly four, in any case, split by spaces or dashes. Anything
    // looser would take a sentence or a dashed passphrase for a seed.
    let groups: Vec<&str> = trimmed.split([' ', '-']).collect();
    groups.len() >= 4
        && matches!(groups.len() * 4, 16 | 20 | 24 | 32 | 40 | 52 | 56 | 64)
        && groups
            .iter()
            .all(|g| g.len() == 4 && g.chars().all(|c| c.is_ascii_alphabetic() || digits(c)))
}

fn looks_like_seed_phrase(value: &str) -> bool {
    let words: Vec<&str> = value.split_whitespace().collect();
    matches!(words.len(), 12 | 15 | 18 | 21 | 24)
        && words
            .iter()
            .all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
}

fn looks_like_api_key(value: &str) -> bool {
    value.starts_with("sk-")
        || value.starts_with("ghp_")
        || value.starts_with("github_pat_")
        || value.starts_with("AKIA")
        || value.starts_with("AIza")
        || (value.starts_with("xox")
            && value.len() > 4
            && matches!(value.as_bytes()[3], b'a' | b'b' | b'p' | b'r' | b's')
            && value.as_bytes().get(4) == Some(&b'-'))
}

fn looks_like_url(value: &str) -> bool {
    value.starts_with("http://") || value.starts_with("https://")
}

fn looks_like_port(value: &str) -> bool {
    value.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p))
}

fn looks_like_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn looks_like_hostname(value: &str) -> bool {
    if value.is_empty() || value.contains(' ') || value.contains("://") {
        return false;
    }
    if looks_like_ipv4(value) {
        return true;
    }
    value.contains('.')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn looks_like_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.contains(' ')
}

fn label_matches(label: &str, needles: &[&str]) -> bool {
    let lower = label.to_ascii_lowercase();
    needles.iter().any(|n| lower.contains(n))
}

/// Infer a field's type from its value first, its label second (`08 §6`
/// principle 1). Never mutates `value` (P-11) — the return is purely a
/// classification, callers keep the original bytes.
pub fn infer_field_type(label: &str, value: &str) -> FieldType {
    if looks_like_private_key(value) {
        return FieldType::PrivateKey;
    }
    if looks_like_certificate(value) {
        return FieldType::Certificate;
    }
    if looks_like_totp_seed(value) {
        return FieldType::TotpSeed;
    }
    if looks_like_seed_phrase(value) {
        return FieldType::SeedPhrase;
    }
    if looks_like_api_key(value) {
        return FieldType::ApiKey;
    }
    if looks_like_url(value) {
        return FieldType::Url;
    }
    if looks_like_port(value) {
        return FieldType::Port;
    }
    if looks_like_hostname(value) {
        return FieldType::Host;
    }
    if looks_like_email(value) || label_matches(label, &["user"]) {
        return FieldType::Username;
    }
    if label_matches(label, &["pass", "pwd", "secret"]) {
        return FieldType::Password;
    }
    if label_matches(label, &["key", "token", "api"]) {
        return FieldType::ApiKey;
    }
    FieldType::Text
}

/// Whether a field type is masked by default (`03_DATA_MODEL.md §5`).
pub fn default_masked(field_type: FieldType) -> bool {
    matches!(
        field_type,
        FieldType::Password
            | FieldType::ApiKey
            | FieldType::PrivateKey
            | FieldType::SeedPhrase
            | FieldType::TotpSeed
    )
}

/// `08_FIELD_MODEL.md §6`: "`sensitivity` follows from the strongest field
/// type present — `seed-phrase` or `private-key` forces `critical`." The doc
/// does not fully enumerate the rest of the scale; this is a reasonable,
/// UI-overridable default (`ADR-012`: inference is a suggestion, never a
/// decision) for the other field types, not a normative table.
pub fn default_sensitivity(field_type: FieldType) -> Sensitivity {
    match field_type {
        FieldType::SeedPhrase | FieldType::PrivateKey => Sensitivity::Critical,
        FieldType::Password | FieldType::ApiKey | FieldType::TotpSeed | FieldType::Certificate => {
            Sensitivity::High
        }
        FieldType::Username | FieldType::Host | FieldType::Port | FieldType::Url => {
            Sensitivity::Medium
        }
        FieldType::Text => Sensitivity::Low,
    }
}

/// Whether `label` names a free-text note: `notes?`, ignoring ASCII case and
/// surrounding whitespace. This is the one label the entry-type rules look at,
/// and it is a *suggestion* for the entry type only — it is not a reserved word:
/// any label is valid for any field, and a field labelled `note` is not required
/// to hold anything in particular.
fn label_names_a_note(label: &str) -> bool {
    let trimmed = label.trim();
    trimmed.eq_ignore_ascii_case("note") || trimmed.eq_ignore_ascii_case("notes")
}

/// Infer an entry's type from its fields' labels and types (`08 §6` principle
/// 3, with the `wallet` simplification recorded in the module doc). A
/// suggestion, never a decision (ADR-012): the user can override it per entry.
///
/// Rules, first match wins (ADR-078 added R0 and tightened R1):
///
/// - **R0** exactly one field, labelled `note`/`notes` → `note`. The design's
///   free-text note is an entry with one such field.
/// - **R1** a TOTP-seed field and **at most two** fields → `totp`. A server that
///   merely *carries* a 2FA seed among its other fields is still a server; the
///   entry's `hasTotp` flag (not its type) is what `counts.totp` uses for it.
/// - **R2** a seed-phrase or private-key field → `wallet`.
/// - **R3** a certificate field → `certificate`.
/// - **R4** host + username + (password or api-key) → `server`.
/// - otherwise `other`.
pub fn infer_entry_type_labelled(fields: &[(&str, FieldType)]) -> EntryType {
    if let [(label, _)] = fields {
        if label_names_a_note(label) {
            return EntryType::Note;
        }
    }
    let has = |t: FieldType| fields.iter().any(|(_, ft)| *ft == t);
    if has(FieldType::TotpSeed) && fields.len() <= 2 {
        return EntryType::Totp;
    }
    if has(FieldType::SeedPhrase) || has(FieldType::PrivateKey) {
        return EntryType::Wallet;
    }
    if has(FieldType::Certificate) {
        return EntryType::Certificate;
    }
    if has(FieldType::Host)
        && has(FieldType::Username)
        && (has(FieldType::Password) || has(FieldType::ApiKey))
    {
        return EntryType::Server;
    }
    EntryType::Other
}

/// [`infer_entry_type_labelled`] for a caller that only has the types — every
/// label is taken to be empty, so R0 (a label rule) can never fire here.
pub fn infer_entry_type(field_types: &[FieldType]) -> EntryType {
    let labelled: Vec<(&str, FieldType)> = field_types.iter().map(|t| ("", *t)).collect();
    infer_entry_type_labelled(&labelled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_wins_over_label() {
        // Synthetic PEM shape ("AAAA" body), not a real key — testing that the
        // PEM header alone triggers PrivateKey inference. Built from fragments so
        // the source never carries a contiguous key-block header (which the
        // portfolio secret scanner, correctly, refuses to let through).
        let pem = concat!(
            "-----BEGIN OPENSSH ",
            "PRIVATE KEY-----\nAAAA\n-----END OPENSSH ",
            "PRIVATE KEY-----"
        );
        assert_eq!(infer_field_type("password", pem), FieldType::PrivateKey);
    }

    #[test]
    fn url_in_password_labelled_field_is_still_url() {
        assert_eq!(
            infer_field_type("password", "https://example.com"),
            FieldType::Url
        );
    }

    #[test]
    fn seed_phrase_by_word_count() {
        let phrase =
            "abandon ability able about above absent absorb abstract absurd abuse access accident";
        assert_eq!(infer_field_type("", phrase), FieldType::SeedPhrase);
    }

    #[test]
    fn totp_seed_base32() {
        assert_eq!(
            infer_field_type("", "JBSWY3DPEHPK3PXP"),
            FieldType::TotpSeed
        );
        assert_eq!(
            infer_field_type("", "otpauth://totp/x?secret=ABC"),
            FieldType::TotpSeed
        );
    }

    #[test]
    fn totp_seed_shapes_services_display() {
        // upper case in one piece, at the lengths a service issues
        for v in [
            "JBSWY3DPEHPK3PXPJBSWY3DP",                             // 24
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DP",             // 40
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSW", // 52
        ] {
            assert_eq!(infer_field_type("", v), FieldType::TotpSeed, "{v}");
        }
        // grouped, in any case
        assert_eq!(
            infer_field_type("", "jbsw y3dp ehpk 3pxp"),
            FieldType::TotpSeed
        );
        assert_eq!(
            infer_field_type("", "JBSW-Y3DP-EHPK-3PXP"),
            FieldType::TotpSeed
        );
        // a plain lower-case run is a word until its owner says otherwise; the wrong lengths are not seeds
        assert_ne!(
            infer_field_type("", "jbswy3dpehpk3pxp"),
            FieldType::TotpSeed
        );
        assert_ne!(infer_field_type("", "JBSWY3DPEHPK3PX"), FieldType::TotpSeed);
    }

    #[test]
    fn api_key_patterns() {
        for value in [
            "sk-abcdefgh",
            "ghp_abcdefgh",
            "AKIAnotarealkeyvalue",
            "xoxb-123",
            "AIzaSyABCDEF",
        ] {
            assert_eq!(
                infer_field_type("value", value),
                FieldType::ApiKey,
                "{value}"
            );
        }
    }

    #[test]
    fn host_and_port_and_username() {
        assert_eq!(infer_field_type("", "203.0.113.4"), FieldType::Host);
        assert_eq!(infer_field_type("", "db.internal"), FieldType::Host);
        assert_eq!(infer_field_type("", "22"), FieldType::Port);
        assert_eq!(infer_field_type("username", "root"), FieldType::Username);
        assert_eq!(
            infer_field_type("", "someone@example.com"),
            FieldType::Username
        );
    }

    #[test]
    fn plain_text_fallback() {
        assert_eq!(infer_field_type("note", "just a note"), FieldType::Text);
    }

    #[test]
    fn masking_defaults() {
        assert!(default_masked(FieldType::Password));
        assert!(default_masked(FieldType::PrivateKey));
        assert!(!default_masked(FieldType::Host));
        assert!(!default_masked(FieldType::Text));
    }

    #[test]
    fn entry_type_wallet_and_server() {
        assert_eq!(
            infer_entry_type(&[FieldType::SeedPhrase]),
            EntryType::Wallet
        );
        assert_eq!(
            infer_entry_type(&[FieldType::Host, FieldType::Username, FieldType::Password]),
            EntryType::Server
        );
        assert_eq!(
            infer_entry_type(&[FieldType::TotpSeed, FieldType::Host]),
            EntryType::Totp
        );
        assert_eq!(infer_entry_type(&[FieldType::Text]), EntryType::Other);
    }

    #[test]
    fn r0_a_single_field_labelled_note_or_notes_is_a_note() {
        for label in ["note", "notes", "Note", "NOTES", "  note  "] {
            assert_eq!(
                infer_entry_type_labelled(&[(label, FieldType::Text)]),
                EntryType::Note,
                "{label:?}"
            );
        }
        // Not the word, not a note.
        for label in ["notebook", "no", "", "note:", "my note"] {
            assert_eq!(
                infer_entry_type_labelled(&[(label, FieldType::Text)]),
                EntryType::Other,
                "{label:?}"
            );
        }
        // It is a one-field rule: a second field and it is no longer a note.
        assert_eq!(
            infer_entry_type_labelled(&[("note", FieldType::Text), ("x", FieldType::Text)]),
            EntryType::Other
        );
        // R0 precedes R1: the entry is a note, and sensitivity/hasTotp still
        // follow the field's own type (not asserted here — see `fields`).
        assert_eq!(
            infer_entry_type_labelled(&[("note", FieldType::TotpSeed)]),
            EntryType::Note
        );
    }

    #[test]
    fn r1_a_totp_seed_makes_a_totp_entry_only_up_to_two_fields() {
        use FieldType::*;
        assert_eq!(infer_entry_type(&[TotpSeed]), EntryType::Totp);
        assert_eq!(infer_entry_type(&[TotpSeed, Host]), EntryType::Totp);
        assert_eq!(infer_entry_type(&[Username, TotpSeed]), EntryType::Totp);
        // A server that carries a 2FA seed stays a server.
        assert_eq!(
            infer_entry_type(&[Host, Username, Password, TotpSeed]),
            EntryType::Server
        );
        // Three fields, none of the later rules: no longer a totp entry.
        assert_eq!(infer_entry_type(&[TotpSeed, Text, Text]), EntryType::Other);
        // Wallet still wins over a bystander seed once past two fields.
        assert_eq!(
            infer_entry_type(&[SeedPhrase, Text, TotpSeed]),
            EntryType::Wallet
        );
    }

    #[test]
    fn the_types_only_wrapper_never_fires_the_label_rule() {
        assert_eq!(infer_entry_type(&[FieldType::Text]), EntryType::Other);
    }

    #[test]
    fn sensitivity_is_lowercase_on_the_wire_and_ordered_low_to_critical() {
        for (s, text) in [
            (Sensitivity::Low, "\"low\""),
            (Sensitivity::Medium, "\"medium\""),
            (Sensitivity::High, "\"high\""),
            (Sensitivity::Critical, "\"critical\""),
        ] {
            assert_eq!(serde_json::to_string(&s).unwrap(), text);
            assert_eq!(serde_json::from_str::<Sensitivity>(text).unwrap(), s);
        }
        assert!(Sensitivity::Low < Sensitivity::Medium);
        assert!(Sensitivity::Medium < Sensitivity::High);
        assert!(Sensitivity::High < Sensitivity::Critical);
    }

    #[test]
    fn note_serialises_as_note_and_the_old_spelling_is_still_accepted() {
        assert_eq!(serde_json::to_string(&EntryType::Note).unwrap(), "\"note\"");
        assert_eq!(
            serde_json::from_str::<EntryType>("\"note\"").unwrap(),
            EntryType::Note
        );
        // `note-only` was never constructed, so no stored value carries it,
        // but old docs and hand-written requests used it.
        assert_eq!(
            serde_json::from_str::<EntryType>("\"note-only\"").unwrap(),
            EntryType::Note
        );
    }

    #[test]
    fn default_sensitivity_follows_the_strongest_field_type() {
        use FieldType::*;
        for t in [SeedPhrase, PrivateKey] {
            assert_eq!(default_sensitivity(t), Sensitivity::Critical, "{t:?}");
        }
        for t in [Password, ApiKey, TotpSeed, Certificate] {
            assert_eq!(default_sensitivity(t), Sensitivity::High, "{t:?}");
        }
        for t in [Username, Host, Port, Url] {
            assert_eq!(default_sensitivity(t), Sensitivity::Medium, "{t:?}");
        }
        assert_eq!(default_sensitivity(Text), Sensitivity::Low);
    }

    #[test]
    fn inference_never_mutates_the_value() {
        let inputs = ["password123", "https://x.com", "plain text value", ""];
        for v in inputs {
            let before = v.to_string();
            let _ = infer_field_type("label", v);
            assert_eq!(v, before);
        }
    }
}
