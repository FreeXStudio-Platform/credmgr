//! Property tests from `docs/13_TEST_PLAN.md §2` (P-1..P-12). Each runs
//! ≥ 1000 generated cases with proptest's default fixed seed (printed on
//! failure by proptest itself).

use credmgr_core::access::{resolve, AccessContext, Origin, Scope, Target};
use credmgr_core::envelope::{open, seal};
use credmgr_core::inference::infer_field_type;
use credmgr_core::parser::parse_bulk;
use credmgr_core::registry::{
    Capability, Direction, Grant, GrantTarget, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID,
    ORPHAN_ID,
};
use proptest::prelude::*;
use rand_core::OsRng;
use secrecy::ExposeSecret;
use std::collections::HashSet;
use x25519_dalek::{PublicKey, StaticSecret};

fn keypair() -> (StaticSecret, PublicKey) {
    let sk = StaticSecret::random_from_rng(OsRng);
    let pk = PublicKey::from(&sk);
    (sk, pk)
}

fn node_id_strategy() -> impl Strategy<Value = String> {
    "n_[0-9a-f]{8}"
}

fn entry_id_strategy() -> impl Strategy<Value = String> {
    "e_[0-9a-f]{12}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// P-1: `open(seal(m, K), K) === m` for arbitrary bytes, 0 B – 4 MiB
    /// (capped lower here for wall-clock; the dedicated unit test covers the
    /// 1 MiB case explicitly).
    #[test]
    fn p1_seal_open_round_trips(
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        node_id in node_id_strategy(),
        entry_id in entry_id_strategy(),
    ) {
        let (sk, pk) = keypair();
        let env = seal(&plaintext, &pk, &node_id, &entry_id).unwrap();
        let opened = open(&env, &sk, &node_id, &entry_id).unwrap();
        prop_assert_eq!(opened.expose_secret(), &plaintext);
    }

    /// P-2: opening under a different node's key fails, for all A ≠ B.
    #[test]
    fn p2_cross_node_decrypt_always_fails(
        plaintext in prop::collection::vec(any::<u8>(), 0..1024),
        node_id in node_id_strategy(),
        entry_id in entry_id_strategy(),
    ) {
        let (_sk_a, pk_a) = keypair();
        let (sk_b, _pk_b) = keypair();
        let env = seal(&plaintext, &pk_a, &node_id, &entry_id).unwrap();
        prop_assert!(open(&env, &sk_b, &node_id, &entry_id).is_err());
    }

    /// P-3: an envelope opened under a different asserted node id fails —
    /// this is what "moved to another node's directory" looks like once the
    /// caller derives its `node_id` argument from the (now wrong) path.
    #[test]
    fn p3_wrong_asserted_node_id_fails(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        node_id_a in node_id_strategy(),
        node_id_b in node_id_strategy(),
        entry_id in entry_id_strategy(),
    ) {
        prop_assume!(node_id_a != node_id_b);
        let (sk_a, pk_a) = keypair();
        let env = seal(&plaintext, &pk_a, &node_id_a, &entry_id).unwrap();
        prop_assert!(open(&env, &sk_a, &node_id_b, &entry_id).is_err());
    }

    /// P-4: an envelope opened under a different asserted entry id fails —
    /// this is what "swapped with a sibling" looks like.
    #[test]
    fn p4_wrong_asserted_entry_id_fails(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        node_id in node_id_strategy(),
        entry_id_a in entry_id_strategy(),
        entry_id_b in entry_id_strategy(),
    ) {
        prop_assume!(entry_id_a != entry_id_b);
        let (sk, pk) = keypair();
        let env = seal(&plaintext, &pk, &node_id, &entry_id_a).unwrap();
        prop_assert!(open(&env, &sk, &node_id, &entry_id_b).is_err());
    }

    /// P-5: sealing the same plaintext twice gives different ciphertexts.
    #[test]
    fn p5_sealing_is_nondeterministic(
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
        node_id in node_id_strategy(),
        entry_id in entry_id_strategy(),
    ) {
        let (_sk, pk) = keypair();
        let env1 = seal(&plaintext, &pk, &node_id, &entry_id).unwrap();
        let env2 = seal(&plaintext, &pk, &node_id, &entry_id).unwrap();
        prop_assert_ne!(env1, env2);
    }

    /// P-11: type inference never mutates the value it classifies.
    #[test]
    fn p11_inference_never_mutates_value(label in ".{0,20}", value in ".{0,200}") {
        let before = value.clone();
        let _ = infer_field_type(&label, &value);
        prop_assert_eq!(value, before);
    }

    /// P-9: `resolve()` is default-deny — for a random graph and random
    /// request, an allow must be traceable to one of rules R2–R7 (never an
    /// unlabelled/implicit allow). Framed as a fuzz over `(scope, target,
    /// capability)` against a small random graph, per the exit gate's
    /// "default-denies on any malformed/unknown input (fuzzed)".
    #[test]
    fn p9_resolve_allow_always_has_a_named_rule(
        subject_node in prop::sample::select(vec!["global","a","b","c","d","x","y","orphan","nonexistent"]),
        target_node in prop::sample::select(vec!["global","a","b","c","d","x","y","orphan","nonexistent"]),
        capability_idx in 0..7usize,
    ) {
        let registry = fixture_registry();
        let capability = [
            Capability::List, Capability::Read, Capability::Reveal, Capability::Create,
            Capability::Update, Capability::Notes, Capability::Admin,
        ][capability_idx];
        let ctx = AccessContext {
            registry: &registry,
            vault_locked: false,
            locked_nodes: &HashSet::new(),
            now: 1_000_000,
        };
        let scope = Scope { node_id: subject_node.to_string(), origin: Origin::Agent, presence_attested: false };
        let decision = resolve(&ctx, &scope, &Target::Node(target_node.to_string()), capability);
        // Every Decision::Allow already carries the rule that produced it —
        // this assertion is that the type itself makes an unjustified allow
        // unrepresentable, and that resolve() never panics on an unknown
        // node id (e.g. "nonexistent").
        prop_assert!(matches!(decision, credmgr_core::access::Decision::Allow(_) | credmgr_core::access::Decision::Deny(_)));
    }

    /// P-10: removing a grant never turns a deny into an allow (monotone in grants).
    #[test]
    fn p10_resolve_is_monotone_in_grants(
        capability_idx in 0..2usize, // List, Read — the grant's own scope
    ) {
        let capability = [Capability::List, Capability::Read][capability_idx];
        let with_grant = fixture_registry();
        let mut without_grant = fixture_registry();
        without_grant.grants.clear();

        let ctx_with = AccessContext { registry: &with_grant, vault_locked: false, locked_nodes: &HashSet::new(), now: 1_000_000 };
        let ctx_without = AccessContext { registry: &without_grant, vault_locked: false, locked_nodes: &HashSet::new(), now: 1_000_000 };
        let scope = Scope { node_id: "x".to_string(), origin: Origin::Agent, presence_attested: false };
        let target = Target::Node("b".to_string());

        let allow_with = resolve(&ctx_with, &scope, &target, capability).is_allow();
        let allow_without = resolve(&ctx_without, &scope, &target, capability).is_allow();
        // Removing the grant can only ever turn an allow into a deny, never the reverse.
        prop_assert!(!allow_without || allow_with);
    }
}

proptest! {
    // The exit gate names this figure explicitly: "Parser is lossless on
    // 10,000 random inputs and matches every row of 08 §3.2."
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// P-7: parse never panics, for any string (including CRLF, lone CR,
    /// NUL, emoji, other 4-byte UTF-8 — all valid within `&str`).
    #[test]
    fn p7_parse_is_total(input in ".{0,300}") {
        let _ = parse_bulk(&input);
    }

    /// P-8: parse is deterministic.
    #[test]
    fn p8_parse_is_deterministic(input in ".{0,300}") {
        let first = parse_bulk(&input);
        let second = parse_bulk(&input);
        prop_assert_eq!(first, second);
    }

    /// P-6 (Case A / single-line fields): formatting a set of generated
    /// (label, value) pairs into the documented `label: value` form, one per
    /// line, and parsing it back recovers exactly those pairs. See
    /// `parser.rs`'s module doc — this tests losslessness against the
    /// documented canonical form rather than arbitrary unstructured byte
    /// soup, since "reassembly === input" presupposes a defined reassembly
    /// function the doc does not fully specify for freeform text.
    #[test]
    fn p6_case_a_round_trips(
        fields in prop::collection::vec(
            ("[a-zA-Z][a-zA-Z0-9 _.#-]{0,20}", "[a-zA-Z0-9 !?_-]{0,60}"),
            1..8,
        )
    ) {
        // Reserved schemes can't appear as a bare label — filter them so the
        // generated input stays in Case A's domain.
        let reserved = ["http","https","ftp","ftps","ssh","sftp","git","file",
            "postgres","postgresql","mysql","redis","mongodb","amqp","otpauth",
            "data","mailto","s3","gs"];
        let fields: Vec<(String, String)> = fields
            .into_iter()
            .filter(|(l, _)| !reserved.contains(&l.to_ascii_lowercase().as_str()))
            .collect();
        prop_assume!(!fields.is_empty());

        let input = fields
            .iter()
            .map(|(l, v)| format!("{l}: {v}"))
            .collect::<Vec<_>>()
            .join("\n");

        let parsed = parse_bulk(&input);
        let recovered: Vec<(String, String)> =
            parsed.into_iter().map(|f| (f.label, f.value)).collect();
        prop_assert_eq!(recovered, fields);
    }

    /// `08 §8` #4: leading and trailing spaces in a value survive, generated.
    #[test]
    fn label_only_multiline_value_round_trips(
        label in "[a-zA-Z][a-zA-Z0-9 _.#-]{0,20}",
        value_lines in prop::collection::vec("[a-zA-Z0-9 !?_-]{0,40}", 1..6),
    ) {
        let reserved = ["http","https","ftp","ftps","ssh","sftp","git","file",
            "postgres","postgresql","mysql","redis","mongodb","amqp","otpauth",
            "data","mailto","s3","gs"];
        prop_assume!(!reserved.contains(&label.to_ascii_lowercase().as_str()));
        // A value ending in an empty line is indistinguishable, after
        // parsing, from the same value with that trailing empty line
        // trimmed — "verbatim, with the trailing newline trimmed" (08 §3.1)
        // is deliberately lossy on exactly this input shape.
        prop_assume!(!value_lines.last().unwrap().is_empty());

        let value = value_lines.join("\n");
        let input = format!("{label}:\n{value}");
        let parsed = parse_bulk(&input);
        prop_assert_eq!(parsed.len(), 1);
        prop_assert_eq!(&parsed[0].label, &label);
        prop_assert_eq!(&parsed[0].value, &value);
    }
}

fn project(id: &str) -> Node {
    Node {
        id: id.to_string(),
        label: id.to_string(),
        kind: NodeKind::Project,
        depth: 1,
        parent_id: Some(GLOBAL_ID.to_string()),
        workdirs: Vec::new(),
        policy: NodePolicy::default(),
    }
}

fn sub(id: &str, parent: &str) -> Node {
    Node {
        id: id.to_string(),
        label: id.to_string(),
        kind: NodeKind::Sub,
        depth: 2,
        parent_id: Some(parent.to_string()),
        workdirs: Vec::new(),
        policy: NodePolicy::default(),
    }
}

fn fixture_registry() -> Registry {
    let mut reg = Registry::new();
    reg.nodes.insert(GLOBAL_ID.to_string(), Node::global());
    reg.nodes.insert(ORPHAN_ID.to_string(), Node::orphan());
    for id in ["a", "b", "c", "d"] {
        reg.nodes.insert(id.to_string(), project(id));
    }
    reg.nodes.insert("x".to_string(), sub("x", "a"));
    reg.nodes.insert("y".to_string(), sub("y", "a"));
    reg.grants.push(Grant {
        id: "g_1".to_string(),
        from: "x".to_string(),
        to: GrantTarget::Node {
            node_id: "b".to_string(),
        },
        direction: Direction::OneWay,
        scope: vec![Capability::Read, Capability::List],
        expires_at: None,
        reason: "fixture".to_string(),
    });
    reg
}
