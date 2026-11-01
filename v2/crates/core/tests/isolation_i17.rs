//! I-17 (`docs/13_TEST_PLAN.md §3`): "Fuzz: 10,000 random `(scope, target,
//! capability)` triples against a random 30-node graph. Assert: never an
//! allow that `resolve()`'s rule trace cannot justify."
//!
//! `properties.rs`'s P-9 already fuzzes `resolve()` against a small *fixed*
//! 8-node graph and checks only that the returned `Decision` is a real
//! variant (catches panics, not wrong allows). I-17 is a materially
//! different, stronger check: a fresh **random** 30-node graph per case
//! (random per-project `descendantRead`/`siblingVisibility`, random grants
//! with random scope/expiry/direction), and — for every `Allow(rule)` —
//! an **independent re-derivation** of whether `rule`'s condition actually
//! holds against that same graph, written fresh from `06_ACCESS_GRAPH.md`'s
//! rule descriptions rather than by calling back into `access.rs`. A bug
//! that made `resolve()` allow via the wrong rule, or via a rule whose
//! condition doesn't actually hold (a non-ancestor let through by R4, an
//! expired grant honoured by R7, non-siblings let through by R6, ...) is
//! exactly what this catches and P-9 structurally cannot.
//!
//! No external RNG crate: `crates/core`'s dependency set is pinned deliberately
//! narrow (`Cargo.toml`'s own comments on the edition2024/MSRV wall), and a
//! `proptest`-generated `u64` seed driving a tiny in-file xorshift is enough
//! determinism for reproducible, shrinkable fuzz cases without adding one.

use std::collections::HashSet;

use credmgr_core::access::{resolve, AccessContext, Decision, Origin, Rule, Scope, Target};
use credmgr_core::registry::{
    Capability, Direction, Grant, GrantTarget, Node, NodeKind, NodePolicy, Registry,
    SiblingVisibility, GLOBAL_ID, ORPHAN_ID,
};
use proptest::prelude::*;

const NOW: i64 = 1_800_000_000;
const NUM_PROJECTS: usize = 14; // + global + orphan + 14 sub-nodes = 30

/// xorshift64* — small, deterministic, no dependency. Seeded non-zero
/// (xorshift is fixed at an all-zero state) so every proptest-generated
/// `u64` seed produces a real stream.
struct Xorshift64(u64);

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Xorshift64(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn range(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }
}

const CAPS: [Capability; 7] = [
    Capability::List,
    Capability::Read,
    Capability::Reveal,
    Capability::Create,
    Capability::Update,
    Capability::Notes,
    Capability::Admin,
];

/// Builds a random 30-node graph: `global`, `orphan`, 14 depth-1 projects
/// (`p0`..`p13`, random `descendantRead`/`siblingVisibility`) each with one
/// depth-2 sub-node (`s0`..`s13`), plus 0-5 random grants.
fn random_graph(rng: &mut Xorshift64) -> Registry {
    let mut registry = Registry::new();
    registry.nodes.insert(GLOBAL_ID.to_string(), Node::global());
    registry.nodes.insert(ORPHAN_ID.to_string(), Node::orphan());

    for i in 0..NUM_PROJECTS {
        let pid = format!("p{i}");
        let sibling_visibility = if rng.bool() {
            SiblingVisibility::Shared
        } else {
            SiblingVisibility::Isolated
        };
        registry.nodes.insert(
            pid.clone(),
            Node {
                id: pid.clone(),
                label: pid.clone(),
                kind: NodeKind::Project,
                depth: 1,
                parent_id: Some(GLOBAL_ID.to_string()),
                workdirs: Vec::new(),
                policy: NodePolicy {
                    descendant_read: rng.bool(),
                    sibling_visibility,
                    ..NodePolicy::default()
                },
            },
        );
        let sid = format!("s{i}");
        registry.nodes.insert(
            sid.clone(),
            Node {
                id: sid.clone(),
                label: sid.clone(),
                kind: NodeKind::Sub,
                depth: 2,
                parent_id: Some(pid.clone()),
                workdirs: Vec::new(),
                policy: NodePolicy::default(),
            },
        );
    }

    let all_ids: Vec<String> = registry.nodes.keys().cloned().collect();
    let n_grants = rng.range(6); // 0..=5
    for i in 0..n_grants {
        let from = all_ids[rng.range(all_ids.len())].clone();
        let to_id = all_ids[rng.range(all_ids.len())].clone();
        let direction = if rng.bool() {
            Direction::OneWay
        } else {
            Direction::Mutual
        };
        let mut scope = Vec::new();
        while scope.is_empty() {
            for cap in CAPS {
                if rng.bool() {
                    scope.push(cap);
                }
            }
        }
        let expires_at = match rng.range(3) {
            0 => None,
            1 => Some(NOW - 1_000), // already expired
            _ => Some(NOW + 1_000), // future
        };
        registry.grants.push(Grant {
            id: format!("g{i}"),
            from,
            to: GrantTarget::Node { node_id: to_id },
            direction,
            scope,
            expires_at,
            reason: "I-17 fuzz fixture".to_string(),
        });
    }

    registry
}

/// `Target::node_id` is a private helper on `access.rs`'s own type — this is
/// the same one-line match, written locally, since a test crate can't reach
/// a private inherent method.
fn target_node_id(target: &Target) -> &str {
    match target {
        Target::Node(n) => n,
        Target::Entry { node_id, .. } => node_id,
    }
}

fn parent_of<'a>(registry: &'a Registry, id: &str) -> Option<&'a str> {
    registry.nodes.get(id).and_then(|n| n.parent_id.as_deref())
}

/// Independent of `Registry::is_strict_ancestor` — walks the same
/// `parent_id` chain, written fresh, bounded to a few hops (the graph's own
/// invariant caps depth at 2, so 4 hops is generous headroom, not a magic
/// number tied to the real implementation).
fn is_ancestor_independent(registry: &Registry, candidate: &str, of: &str) -> bool {
    let mut current = of.to_string();
    for _ in 0..4 {
        match parent_of(registry, &current) {
            Some(p) if p == candidate => return true,
            Some(p) => current = p.to_string(),
            None => return false,
        }
    }
    false
}

/// Independent of `access::has_matching_grant` — re-derives grant coverage
/// from `06_ACCESS_GRAPH.md §1`'s R7 description: an unexpired grant, whose
/// scope contains the capability, held by the subject or one of its
/// ancestors (or, for a mutual grant, usable from the other side).
fn independent_matching_grant(
    registry: &Registry,
    subject: &str,
    target: &Target,
    capability: Capability,
    now: i64,
) -> bool {
    registry.grants.iter().any(|grant| {
        if let Some(exp) = grant.expires_at {
            if exp <= now {
                return false;
            }
        }
        if !grant.scope.contains(&capability) {
            return false;
        }
        let target_matches = match &grant.to {
            GrantTarget::Node { node_id } => target_node_id(target) == node_id,
            GrantTarget::Entry { node_id, entry_id } => matches!(
                target,
                Target::Entry { node_id: tn, entry_id: te } if tn == node_id && te == entry_id
            ),
        };
        let subject_on_from_side =
            grant.from == subject || is_ancestor_independent(registry, &grant.from, subject);
        if subject_on_from_side && target_matches {
            return true;
        }
        if grant.direction == Direction::Mutual {
            let to_id = grant.to.node_id();
            let subject_on_to_side =
                to_id == subject || is_ancestor_independent(registry, to_id, subject);
            let target_is_from_side = target_node_id(target) == grant.from;
            if subject_on_to_side && target_is_from_side {
                return true;
            }
        }
        false
    })
}

/// For a claimed `Decision::Allow(rule)`, independently re-checks whether
/// `rule`'s own condition (`06_ACCESS_GRAPH.md §1`) actually holds against
/// this graph. `R1`/`R8` are structurally deny-only in `access.rs` (grep
/// confirms `resolve()` never constructs `Decision::Allow(Rule::R1)` or
/// `Decision::Allow(Rule::R8)`) — always `false` here so a future edit that
/// broke that invariant would fail loudly instead of this function quietly
/// agreeing with it.
fn independently_justified(
    registry: &Registry,
    subject: &Scope,
    target: &Target,
    capability: Capability,
    rule: Rule,
    now: i64,
) -> bool {
    let target_id = target_node_id(target);
    match rule {
        Rule::R0 => {
            target_id == ORPHAN_ID && subject.origin == Origin::Native && subject.presence_attested
        }
        Rule::R2 => subject.node_id == target_id,
        Rule::R3 => target_id == GLOBAL_ID,
        Rule::R4 => is_ancestor_independent(registry, target_id, &subject.node_id),
        Rule::R5 => {
            is_ancestor_independent(registry, &subject.node_id, target_id)
                && registry
                    .nodes
                    .get(&subject.node_id)
                    .is_some_and(|n| n.policy.descendant_read)
        }
        Rule::R6 => {
            let (Some(a), Some(b)) = (
                registry.nodes.get(&subject.node_id),
                registry.nodes.get(target_id),
            ) else {
                return false;
            };
            a.depth == 2
                && b.depth == 2
                && a.parent_id.is_some()
                && a.parent_id == b.parent_id
                && a.parent_id
                    .as_deref()
                    .and_then(|p| registry.nodes.get(p))
                    .is_some_and(|p| p.policy.sibling_visibility == SiblingVisibility::Shared)
        }
        Rule::R7 => independent_matching_grant(registry, &subject.node_id, target, capability, now),
        Rule::R1 | Rule::R8 => false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// I-17. A single `u64` seed drives graph generation, the query, and the
    /// grant set — one proptest input, fully deterministic and shrinkable,
    /// rather than several independent strategies that would shrink out of
    /// sync with each other.
    #[test]
    fn i17_every_allow_is_independently_justified(seed in any::<u64>()) {
        let mut rng = Xorshift64::new(seed);
        let registry = random_graph(&mut rng);
        let all_ids: Vec<String> = registry.nodes.keys().cloned().collect();

        // One case in 20 fuzzes a node id that doesn't exist at all — R2/R3
        // are pure string comparisons in `resolve()` and must stay total
        // over unknown ids, never panic, never allow-by-accident.
        let pick_id = |rng: &mut Xorshift64| -> String {
            if rng.range(20) == 0 {
                "zzz-does-not-exist".to_string()
            } else {
                all_ids[rng.range(all_ids.len())].clone()
            }
        };

        let subject_id = pick_id(&mut rng);
        let target_id = pick_id(&mut rng);
        let target = if rng.bool() {
            Target::Node(target_id.clone())
        } else {
            Target::Entry { node_id: target_id.clone(), entry_id: "e_fuzz".to_string() }
        };
        let capability = CAPS[rng.range(CAPS.len())];
        let origin = [Origin::HumanUi, Origin::Cli, Origin::Agent, Origin::Native][rng.range(4)];
        let presence_attested = rng.bool();
        let vault_locked = rng.bool();
        let mut locked_nodes = HashSet::new();
        if rng.bool() {
            locked_nodes.insert(target_id.clone());
        }

        let scope = Scope { node_id: subject_id, origin, presence_attested };
        let ctx = AccessContext { registry: &registry, vault_locked, locked_nodes: &locked_nodes, now: NOW };
        let decision = resolve(&ctx, &scope, &target, capability);

        if let Decision::Allow(rule) = decision {
            prop_assert!(
                independently_justified(&registry, &scope, &target, capability, rule, NOW),
                "resolve() returned Allow({rule:?}) for subject={:?} target={target:?} cap={capability:?} \
                 origin={origin:?} presence={presence_attested} vault_locked={vault_locked}, but an \
                 independent re-derivation of {rule:?}'s own condition against the same graph does not hold",
                scope.node_id,
            );
        }
    }
}
