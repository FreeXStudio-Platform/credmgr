//! The exact worked example from `docs/06_ACCESS_GRAPH.md §2`, table-driven,
//! all 8×8 cells. Phase 1 exit gate item: "`resolve()` matches every cell of
//! the matrix in `06 §2`".
//!
//! Graph: Global; projects A, B, C, D (depth 1); sub-nodes X, Y under A
//! (depth 2); one human grant `X → B (read)`. All other policy at default.

use credmgr_core::access::{resolve, AccessContext, Origin, Rule, Scope, Target};
use credmgr_core::registry::{
    Capability, Direction, Grant, GrantTarget, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID,
    ORPHAN_ID,
};
use std::collections::HashSet;

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

fn build_registry() -> Registry {
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
        scope: vec![Capability::Read],
        expires_at: None,
        reason: "worked example from 06 §2".to_string(),
    });
    reg
}

fn scope(node_id: &str) -> Scope {
    Scope {
        node_id: node_id.to_string(),
        origin: Origin::Agent,
        presence_attested: false,
    }
}

const NODES: [&str; 8] = [GLOBAL_ID, "a", "b", "c", "d", "x", "y", ORPHAN_ID];

/// `true` at `[reader][target]` iff the doc's matrix marks that cell ✅.
/// Row/column order matches `NODES` above.
const EXPECTED_READ: [[bool; 8]; 8] = [
    // reads →     global a      b      c      d      x      y      orphan
    /* global */
    [true, false, false, false, false, false, false, false],
    /* a      */ [true, true, false, false, false, false, false, false],
    /* b      */ [true, false, true, false, false, false, false, false],
    /* c      */ [true, false, false, true, false, false, false, false],
    /* d      */ [true, false, false, false, true, false, false, false],
    /* x      */ [true, true, true, false, false, true, true, false],
    /* y      */ [true, true, false, false, false, true, true, false],
    /* orphan */ [false, false, false, false, false, false, false, false],
];

#[test]
fn worked_example_matrix_matches_every_cell() {
    let registry = build_registry();
    let ctx = AccessContext {
        registry: &registry,
        vault_locked: false,
        locked_nodes: &HashSet::new(),
        now: 1_000_000,
    };

    let mut failures = Vec::new();
    for (i, reader) in NODES.iter().enumerate() {
        for (j, target) in NODES.iter().enumerate() {
            let decision = resolve(
                &ctx,
                &scope(reader),
                &Target::Node(target.to_string()),
                Capability::Read,
            );
            let expected = EXPECTED_READ[i][j];
            if decision.is_allow() != expected {
                failures.push(format!(
                    "{reader} -> {target}: expected {}, got {:?}",
                    if expected { "ALLOW" } else { "DENY" },
                    decision
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "matrix mismatches:\n{}",
        failures.join("\n")
    );
}

#[test]
fn x_reads_b_at_read_not_reveal_the_grant_is_narrow() {
    let registry = build_registry();
    let ctx = AccessContext {
        registry: &registry,
        vault_locked: false,
        locked_nodes: &HashSet::new(),
        now: 1_000_000,
    };
    let decision = resolve(
        &ctx,
        &scope("x"),
        &Target::Node("b".to_string()),
        Capability::Reveal,
    );
    assert!(
        !decision.is_allow(),
        "grant only covers `read`, not `reveal`"
    );
}

#[test]
fn y_cannot_use_its_sibling_xs_grant() {
    let registry = build_registry();
    let ctx = AccessContext {
        registry: &registry,
        vault_locked: false,
        locked_nodes: &HashSet::new(),
        now: 1_000_000,
    };
    let decision = resolve(
        &ctx,
        &scope("y"),
        &Target::Node("b".to_string()),
        Capability::Read,
    );
    assert!(!decision.is_allow(), "the grant is X's, not Y's — 06 §2");
}

#[test]
fn a_cannot_read_its_own_children_by_default() {
    let registry = build_registry();
    let ctx = AccessContext {
        registry: &registry,
        vault_locked: false,
        locked_nodes: &HashSet::new(),
        now: 1_000_000,
    };
    for child in ["x", "y"] {
        let decision = resolve(
            &ctx,
            &scope("a"),
            &Target::Node(child.to_string()),
            Capability::Read,
        );
        assert!(
            !decision.is_allow(),
            "descendantRead defaults to false — D-01"
        );
    }
}

#[test]
fn x_reads_b_specifically_via_r7() {
    let registry = build_registry();
    let ctx = AccessContext {
        registry: &registry,
        vault_locked: false,
        locked_nodes: &HashSet::new(),
        now: 1_000_000,
    };
    let decision = resolve(
        &ctx,
        &scope("x"),
        &Target::Node("b".to_string()),
        Capability::Read,
    );
    assert_eq!(decision, credmgr_core::access::Decision::Allow(Rule::R7));
}
