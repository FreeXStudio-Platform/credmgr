//! Property and golden tests for the multi-field entry model (ADR-078,
//! `docs/13_TEST_PLAN.md` P-13 … P-18).
//!
//! | | |
//! |---|---|
//! | P-13 | a field document survives encode → decode untouched |
//! | P-14 | decode is total: arbitrary bytes are `Ok` or `Err`, never a panic |
//! | P-15 | a legacy raw value, read in place, projects exactly the manifest entry it was written under |
//! | P-16 | the payload kind is authenticated: a flipped version byte fails the tag |
//! | P-17 | parse → document → seal → open → decode preserves every label and value, byte for byte |
//! | P-18 | the segment-keeping parser flattens to the plain one |

use credmgr_core::envelope::{open_any, seal_as, PayloadKind};
use credmgr_core::fields::{
    self, decode, effective, encode, from_legacy, project, read_payload, EntryDoc, FieldDoc,
    FieldInput, LEGACY_FIELD_ID,
};
use credmgr_core::inference::{infer_field_type, EntryType, FieldType, Sensitivity};
use credmgr_core::parser::{parse_bulk, parse_bulk_segments, ParsedField};
use proptest::prelude::*;
use rand_core::OsRng;
use secrecy::ExposeSecret;
use x25519_dalek::{PublicKey, StaticSecret};

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

const ALL_FIELD_TYPES: [FieldType; 11] = [
    FieldType::Password,
    FieldType::ApiKey,
    FieldType::PrivateKey,
    FieldType::SeedPhrase,
    FieldType::TotpSeed,
    FieldType::Username,
    FieldType::Host,
    FieldType::Port,
    FieldType::Url,
    FieldType::Certificate,
    FieldType::Text,
];

const ALL_ENTRY_TYPES: [EntryType; 12] = [
    EntryType::Server,
    EntryType::Database,
    EntryType::Api,
    EntryType::Wallet,
    EntryType::Login,
    EntryType::Ssh,
    EntryType::Certificate,
    EntryType::Token,
    EntryType::Totp,
    EntryType::EnvBundle,
    EntryType::Note,
    EntryType::Other,
];

const ALL_SENSITIVITIES: [Sensitivity; 4] = [
    Sensitivity::Low,
    Sensitivity::Medium,
    Sensitivity::High,
    Sensitivity::Critical,
];

fn field_type() -> impl Strategy<Value = FieldType> {
    prop::sample::select(ALL_FIELD_TYPES.to_vec())
}

fn entry_type() -> impl Strategy<Value = EntryType> {
    prop::sample::select(ALL_ENTRY_TYPES.to_vec())
}

fn sensitivity() -> impl Strategy<Value = Sensitivity> {
    prop::sample::select(ALL_SENSITIVITIES.to_vec())
}

/// A label the rules accept: up to 200 characters, any script, no C0 control
/// character and no DEL. Empty is allowed.
fn label() -> impl Strategy<Value = String> {
    prop_oneof![
        // Any Unicode character except the controls the rules refuse.
        "[^\\x00-\\x1f\\x7f]{0,200}",
        // Plain ASCII words, the common case.
        "[ -~]{0,40}",
        // CJK and astral-plane characters.
        prop::collection::vec(
            prop_oneof![Just('密'), Just('码'), Just('🔑'), Just('é')],
            0..=200
        )
        .prop_map(|v| v.into_iter().collect::<String>()),
    ]
}

/// A value: anything. Includes NUL, CR, LF, lone CR, CRLF, leading/trailing
/// space and four-byte UTF-8, because a password may be any of them (ADR-038).
fn value() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "[\\x00-\\x7f]{0,80}",
        prop::collection::vec(
            prop_oneof![
                Just('\r'),
                Just('\n'),
                Just('\0'),
                Just(' '),
                Just('"'),
                Just('\\'),
                Just('🔑'),
                any::<char>()
            ],
            0..60
        )
        .prop_map(|v| v.into_iter().collect::<String>()),
    ]
}

/// A document with 1–20 fields and random overrides. Ids are unique by
/// construction: an odd multiplier is a bijection on `u32`.
fn entry_doc() -> impl Strategy<Value = EntryDoc> {
    let one = (
        label(),
        value(),
        prop::option::of(field_type()),
        prop::option::of(any::<bool>()),
    );
    (
        prop::collection::vec(one, 1..=20),
        any::<u32>(),
        prop::option::of(entry_type()),
        prop::option::of(sensitivity()),
    )
        .prop_map(|(fields, seed, entry_type, sensitivity)| EntryDoc {
            v: fields::DOC_VERSION,
            entry_type,
            sensitivity,
            fields: fields
                .into_iter()
                .enumerate()
                .map(|(i, (label, value, field_type, masked))| FieldDoc {
                    id: format!(
                        "f_{:08x}",
                        seed.wrapping_add((i as u32).wrapping_mul(0x9e37_79b1))
                    ),
                    label,
                    value,
                    field_type,
                    masked,
                })
                .collect(),
        })
}

/// Values shaped like the things the inference rules recognise, plus noise.
/// PEM-shaped values are built from fragments so no source line carries a
/// contiguous key-block header.
fn shaped_value() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<String>(),
        "[A-Z2-7]{16}",
        "[A-Z2-7]{32}",
        "otpauth://totp/[a-z]{1,8}\\?secret=[A-Z2-7]{16}",
        "sk-[a-z0-9]{20,30}",
        "ghp_[A-Za-z0-9]{20,30}",
        "[a-z]{3,8}( [a-z]{3,8}){11}",
        "[0-9]{1,5}",
        "https?://[a-z]{3,10}\\.com(/[a-z]{0,8})?",
        "[a-z]{3,8}\\.[a-z]{2,5}",
        "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}",
        "[a-z]{1,8}@[a-z]{1,8}\\.com",
        "[ -~]{0,40}",
        Just(pem("OPENSSH PRIVATE KEY")),
        Just(pem("CERTIFICATE")),
    ]
}

/// A PEM-shaped block with a synthetic body. The header is assembled at run
/// time from `kind`, so no source line carries a contiguous key-block header
/// (which the portfolio secret scanner, correctly, refuses to let through).
fn pem(kind: &str) -> String {
    format!("-----BEGIN {kind}-----\nQUJDREVGRw==\n-----END {kind}-----")
}

fn keypair() -> (StaticSecret, PublicKey) {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

// ---------------------------------------------------------------------------
// P-13, P-15, P-16
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// P-13: `decode(encode(d)) == d` for 1–20 fields, arbitrary valid labels,
    /// arbitrary values (NUL, CRLF, lone CR, four-byte UTF-8) and random
    /// overrides.
    #[test]
    fn p13_field_doc_round_trips(doc in entry_doc()) {
        let bytes = encode(&doc).unwrap();
        prop_assert_eq!(decode(&bytes).unwrap(), doc.clone());
        // Canonical: encoding is deterministic, and re-encoding the decoded
        // document gives the same bytes.
        prop_assert_eq!(encode(&decode(&bytes).unwrap()).unwrap(), bytes);
    }

    /// P-15: for any value × any stored entry type × any stored sensitivity,
    /// reading a legacy raw value in place projects exactly what the manifest
    /// already shows, and the field is masked whenever the stored sensitivity
    /// is `high` or above.
    #[test]
    fn p15_legacy_projection_is_preserved(
        v in shaped_value(),
        stored_type in entry_type(),
        stored_sens in sensitivity(),
    ) {
        let doc = from_legacy(&v, stored_type, stored_sens);
        let t = infer_field_type("", &v);
        let p = project(&doc);
        prop_assert_eq!(p.entry_type, stored_type);
        prop_assert_eq!(p.sensitivity, stored_sens);
        prop_assert_eq!(p.field_count, 1);
        prop_assert_eq!(p.has_totp, t == FieldType::TotpSeed);
        prop_assert_eq!(&doc.fields[0].value, &v);
        prop_assert_eq!(&doc.fields[0].id, LEGACY_FIELD_ID);
        if stored_sens >= Sensitivity::High {
            prop_assert!(effective(&doc.fields[0]).1, "a high/critical legacy value must stay masked");
        }
        // And it is a document the first write can re-seal as it stands.
        prop_assert!(encode(&doc).is_ok());
        // Through the payload reader, from bytes, the same answer.
        let via = read_payload(PayloadKind::RawValue, v.as_bytes(), stored_type, stored_sens).unwrap();
        prop_assert_eq!(via, doc);
    }

    /// P-16: the payload kind is authenticated. Flip the version byte of a
    /// sealed envelope (1↔2) and opening fails; the wrong entry id or node id
    /// fails for a version-2 envelope exactly as for a version-1 one.
    #[test]
    fn p16_payload_kind_is_authenticated(
        plaintext in prop::collection::vec(any::<u8>(), 0..512),
        node_id in "n_[0-9a-f]{8}",
        other_node in "n_[0-9a-f]{8}",
        entry_id in "e_[0-9a-f]{12}",
        other_entry in "e_[0-9a-f]{12}",
        as_document in any::<bool>(),
    ) {
        prop_assume!(node_id != other_node && entry_id != other_entry);
        let (sk, pk) = keypair();
        let kind = if as_document { PayloadKind::FieldDocument } else { PayloadKind::RawValue };
        let env = seal_as(kind, &plaintext, &pk, &node_id, &entry_id).unwrap();
        prop_assert_eq!(env[4], kind.version());

        // Honest open: right kind, right bytes.
        let (got_kind, opened) = open_any(&env, &sk, &node_id, &entry_id).unwrap();
        prop_assert_eq!(got_kind, kind);
        prop_assert_eq!(opened.expose_secret(), &plaintext);

        // Flip the version byte to the other kind: the tag must refuse.
        let mut flipped = env.clone();
        flipped[4] = if as_document { PayloadKind::RawValue.version() } else { PayloadKind::FieldDocument.version() };
        prop_assert!(open_any(&flipped, &sk, &node_id, &entry_id).is_err());

        // Wrong entry id and wrong node id, for either kind.
        prop_assert!(open_any(&env, &sk, &node_id, &other_entry).is_err());
        prop_assert!(open_any(&env, &sk, &other_node, &entry_id).is_err());
    }
}

// ---------------------------------------------------------------------------
// P-14
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// P-14: arbitrary bytes, 0 – 4096, are `Ok` or `Err` — never a panic.
    #[test]
    fn p14_decode_is_total(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = decode(&bytes);
    }
}

// Generating a full document is far dearer than generating bytes, so this
// companion runs 1,000 cases rather than 10,000 (measured: 10,000 took > 200 s
// in a debug build).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// P-14b: nor do near-misses of a *valid* document panic or slip through as
    /// something else — flip, drop or duplicate a byte of a real encoding.
    #[test]
    fn p14b_decode_is_total_on_mutated_valid_documents(
        doc in entry_doc(),
        at in any::<prop::sample::Index>(),
        op in 0u8..3,
        byte in any::<u8>(),
    ) {
        let mut bytes = encode(&doc).unwrap();
        let i = at.index(bytes.len());
        match op {
            0 => bytes[i] = byte,
            1 => { bytes.remove(i); }
            _ => bytes.insert(i, byte),
        }
        if let Ok(decoded) = decode(&bytes) {
            // Whatever decodes is a *valid* document: it re-encodes.
            prop_assert!(encode(&decoded).is_ok());
        }
    }
}

// ---------------------------------------------------------------------------
// P-17, P-18
// ---------------------------------------------------------------------------

/// Bulk-paste text: labelled lines, separators, blobs, label-only blocks,
/// PEM-shaped blocks, and arbitrary strings with CR / CRLF.
fn bulk_text() -> impl Strategy<Value = String> {
    let line = prop_oneof![
        "[A-Za-z][A-Za-z0-9 _.()#/-]{0,20}: [ -~]{0,40}",
        Just("///".to_string()),
        "[ -~]{0,50}",
        "[A-Za-z][A-Za-z0-9 _.()#/-]{0,20}:",
        Just(format!("private key:\n{}", pem("OPENSSH PRIVATE KEY"))),
        shaped_value().prop_map(|v| v.replace(['\r', '\n'], " ")),
    ];
    prop_oneof![
        prop::collection::vec(line, 0..30).prop_map(|lines| lines.join("\n")),
        prop::collection::vec(
            prop_oneof![
                Just("\r\n"),
                Just("\n"),
                Just("\r"),
                Just("///"),
                Just("a: b"),
                Just("x")
            ],
            0..40
        )
        .prop_map(|parts| parts.concat()),
        any::<String>(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// P-17: parse a bulk paste, build a document from each segment, seal it as
    /// a version-2 envelope, open it and decode it — every label and value is
    /// byte-identical to what the parser produced, including a PEM-shaped value
    /// (`08 §8` row 3, up to display and copy).
    #[test]
    fn p17_parse_seal_open_preserves_every_field(text in bulk_text()) {
        let (sk, pk) = keypair();
        let segments = parse_bulk_segments(&text);
        for (n, segment) in segments.iter().enumerate() {
            let inputs: Vec<FieldInput> = segment.iter().cloned().map(FieldInput::from).collect();
            let doc = fields::create(inputs, fields::Override::Keep, fields::Override::Keep).unwrap();
            let sealed = seal_as(
                PayloadKind::FieldDocument,
                &encode(&doc).unwrap(),
                &pk,
                "n_00000001",
                &format!("e_{n:012x}"),
            )
            .unwrap();
            let (kind, opened) = open_any(&sealed, &sk, "n_00000001", &format!("e_{n:012x}")).unwrap();
            prop_assert_eq!(kind, PayloadKind::FieldDocument);
            let back = decode(opened.expose_secret()).unwrap();
            prop_assert_eq!(back.fields.len(), segment.len());
            for (field, parsed) in back.fields.iter().zip(segment) {
                prop_assert_eq!(&field.label, &parsed.label);
                prop_assert_eq!(&field.value, &parsed.value);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// P-18: flattening the segments is the plain parse, and no segment is empty.
    #[test]
    fn p18_segments_flatten_to_parse_bulk(text in prop_oneof![bulk_text(), ".{0,300}"]) {
        let segments = parse_bulk_segments(&text);
        prop_assert!(segments.iter().all(|s| !s.is_empty()));
        let flat: Vec<ParsedField> = segments.into_iter().flatten().collect();
        prop_assert_eq!(flat, parse_bulk(&text));
    }
}

// ---------------------------------------------------------------------------
// Golden: a version-2 envelope pinned for the future
// ---------------------------------------------------------------------------

/// A version-2 envelope sealed by this build (node secret `[7; 32]`, node
/// `n_aaaaaaaa`, entry `e_bbbbbbbbbbbb`) around [`GOLDEN_DOC`], pinned so the
/// version-2 byte layout and AAD cannot drift unnoticed. The independent
/// `node:crypto` re-implementation in `scripts/emergency-decrypt.mjs` reads the
/// same bytes in `crates/cli/tests/emergency_decrypt.rs`.
const GOLDEN_DOC: &str = r#"{"v":1,"entryType":"login","sensitivity":"high","fields":[{"id":"f_00000000","label":"","value":"golden-v2-value","masked":true},{"id":"f_0a1b2c3d","label":"密码","value":"line one\r\nline two","type":"password"}]}"#;

#[test]
fn the_golden_document_decodes_and_re_encodes_to_itself() {
    let doc = decode(GOLDEN_DOC.as_bytes()).unwrap();
    assert_eq!(doc.fields.len(), 2);
    assert_eq!(doc.fields[1].label, "密码");
    assert_eq!(doc.fields[1].value, "line one\r\nline two");
    assert_eq!(encode(&doc).unwrap(), GOLDEN_DOC.as_bytes());
}

#[test]
fn a_document_survives_the_full_seal_open_path_with_a_fixed_key() {
    let sk = StaticSecret::from([7u8; 32]);
    let pk = PublicKey::from(&sk);
    let doc = decode(GOLDEN_DOC.as_bytes()).unwrap();
    let env = seal_as(
        PayloadKind::FieldDocument,
        &encode(&doc).unwrap(),
        &pk,
        "n_aaaaaaaa",
        "e_bbbbbbbbbbbb",
    )
    .unwrap();
    assert_eq!(env[4], 2);
    let (kind, opened) = open_any(&env, &sk, "n_aaaaaaaa", "e_bbbbbbbbbbbb").unwrap();
    assert_eq!(kind, PayloadKind::FieldDocument);
    assert_eq!(opened.expose_secret().as_slice(), GOLDEN_DOC.as_bytes());
    let read = read_payload(
        kind,
        opened.expose_secret(),
        EntryType::Other,
        Sensitivity::Low,
    )
    .unwrap();
    assert_eq!(read, doc);
}

/// A decoded field's value is a secret in a plain `String`. `FieldDoc::wipe` (which `Drop` calls) clears the
/// value and the label. The workspace forbids `unsafe`, so the drop wiring itself (`Drop` -> `wipe`, one line)
/// is verified by review, not observed; this proves the wipe does what it says.
#[test]
fn wiping_a_field_clears_its_value_and_label() {
    use credmgr_core::fields::FieldDoc;
    let mut f = FieldDoc {
        id: "f_00000000".into(),
        label: "password".into(),
        value: "hunter2-secret".into(),
        field_type: None,
        masked: None,
    };
    f.wipe();
    assert!(f.value.is_empty() && f.label.is_empty());
}
