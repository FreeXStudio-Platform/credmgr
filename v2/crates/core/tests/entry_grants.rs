//! ADR-172 — an entry-level grant in `resolve()`: it lists, reads or reveals exactly the one entry it names and
//! nothing else. Graph: Global; projects A and B; one entry-level grant `B → A/e_1` and nothing else, so every
//! allow below can only come from that grant (R7).

use credmgr_core::access::{resolve, AccessContext, Decision, Origin, Rule, Scope, Target};
use credmgr_core::registry::{
    Capability, Direction, Grant, GrantTarget, Node, NodeKind, NodePolicy, Registry, GLOBAL_ID,
};
use std::collections::HashSet;

const NOW: i64 = 1_000_000;

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

fn registry(scope: Vec<Capability>, direction: Direction) -> Registry {
    let mut reg = Registry::new();
    reg.nodes.insert(GLOBAL_ID.to_string(), Node::global());
    reg.nodes.insert("a".to_string(), project("a"));
    reg.nodes.insert("b".to_string(), project("b"));
    reg.grants.push(Grant {
        id: "g_entry".to_string(),
        from: "b".to_string(),
        to: GrantTarget::Entry {
            node_id: "a".to_string(),
            entry_id: "e_1".to_string(),
        },
        direction,
        scope,
        expires_at: Some(NOW + 60),
        reason: "ADR-172 fixture".to_string(),
    });
    reg
}

fn decide(reg: &Registry, subject: &str, target: Target, cap: Capability, now: i64) -> Decision {
    let ctx = AccessContext {
        registry: reg,
        vault_locked: false,
        locked_nodes: &HashSet::new(),
        now,
    };
    let scope = Scope {
        node_id: subject.to_string(),
        origin: Origin::Agent,
        presence_attested: false,
    };
    resolve(&ctx, &scope, &target, cap)
}

fn entry(id: &str) -> Target {
    Target::Entry {
        node_id: "a".to_string(),
        entry_id: id.to_string(),
    }
}

#[test]
fn a_reveal_grant_lists_and_reveals_its_entry_and_nothing_else() {
    let reg = registry(vec![Capability::Reveal], Direction::OneWay);
    assert_eq!(
        decide(&reg, "b", entry("e_1"), Capability::Reveal, NOW),
        Decision::Allow(Rule::R7)
    );
    assert_eq!(
        decide(&reg, "b", entry("e_1"), Capability::List, NOW),
        Decision::Allow(Rule::R7),
        "the implied list of the one entry"
    );
    // Not read: reveal does not imply the metadata read.
    assert!(!decide(&reg, "b", entry("e_1"), Capability::Read, NOW).is_allow());
    // Never a sibling entry, at any capability.
    for cap in [Capability::List, Capability::Read, Capability::Reveal] {
        assert!(
            !decide(&reg, "b", entry("e_2"), cap, NOW).is_allow(),
            "{cap:?} on a sibling"
        );
    }
    // Never the node: not its listing, not its notes, not a reveal through it.
    for cap in [
        Capability::List,
        Capability::Read,
        Capability::Reveal,
        Capability::Notes,
    ] {
        assert!(
            !decide(&reg, "b", Target::Node("a".to_string()), cap, NOW).is_allow(),
            "{cap:?} on the node"
        );
    }
    // Expired: nothing, not even the implied list.
    assert!(!decide(&reg, "b", entry("e_1"), Capability::List, NOW + 61).is_allow());
    assert!(!decide(&reg, "b", entry("e_1"), Capability::Reveal, NOW + 61).is_allow());
}

#[test]
fn a_read_grant_lists_and_reads_its_entry_but_does_not_reveal_it() {
    let reg = registry(vec![Capability::Read], Direction::OneWay);
    assert!(decide(&reg, "b", entry("e_1"), Capability::List, NOW).is_allow());
    assert!(decide(&reg, "b", entry("e_1"), Capability::Read, NOW).is_allow());
    assert!(!decide(&reg, "b", entry("e_1"), Capability::Reveal, NOW).is_allow());
}

#[test]
fn a_notes_only_entry_grant_implies_no_list() {
    let reg = registry(vec![Capability::Notes], Direction::OneWay);
    assert!(!decide(&reg, "b", entry("e_1"), Capability::List, NOW).is_allow());
}

#[test]
fn a_mutual_entry_grant_mirrors_nothing() {
    let reg = registry(
        vec![Capability::Read, Capability::Reveal],
        Direction::Mutual,
    );
    // The forward direction still works for its one entry...
    assert!(decide(&reg, "b", entry("e_1"), Capability::Reveal, NOW).is_allow());
    // ...but the entry's node gets nothing of the grant's `from` node.
    for cap in [Capability::List, Capability::Read, Capability::Reveal] {
        assert!(
            !decide(&reg, "a", Target::Node("b".to_string()), cap, NOW).is_allow(),
            "{cap:?}: a mutual entry grant must not open b to a"
        );
        assert!(!decide(
            &reg,
            "a",
            Target::Entry {
                node_id: "b".to_string(),
                entry_id: "e_9".to_string()
            },
            cap,
            NOW
        )
        .is_allow());
    }
}

#[test]
fn a_node_grant_is_unchanged_and_implies_no_list() {
    let mut reg = registry(vec![Capability::Read], Direction::OneWay);
    reg.grants[0].to = GrantTarget::Node {
        node_id: "a".to_string(),
    };
    assert!(decide(
        &reg,
        "b",
        Target::Node("a".to_string()),
        Capability::Read,
        NOW
    )
    .is_allow());
    assert!(
        !decide(
            &reg,
            "b",
            Target::Node("a".to_string()),
            Capability::List,
            NOW
        )
        .is_allow(),
        "a node grant still lists only when its scope says so"
    );
}
