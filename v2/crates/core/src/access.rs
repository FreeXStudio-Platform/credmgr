//! `resolve()` — the one function that decides every read in the system.
//! See `docs/06_ACCESS_GRAPH.md §1`. Pure: every input the rules need (the
//! graph, lock state, "now") is a parameter; nothing is read from the clock,
//! a file, or the environment.

use crate::registry::{Capability, Direction, GrantTarget, Registry, GLOBAL_ID, ORPHAN_ID};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    HumanUi,
    Cli,
    Agent,
    Native,
}

/// The caller. The full `Scope` in `06_ACCESS_GRAPH.md §4` also carries a
/// capability ceiling, token id and bound workdir — those govern how a
/// caller's scope is *established* (broker concern, Phase 3) and are not
/// inputs to the graph rules themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub node_id: String,
    pub origin: Origin,
    /// A live biometric + fresh-TOTP presence check, obtained immediately
    /// before this request. Only ever `true` for `Origin::Native` in
    /// practice — `resolve` does not itself enforce that pairing; the broker
    /// is the only thing that can produce a `Scope` claiming presence.
    pub presence_attested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Node(String),
    Entry { node_id: String, entry_id: String },
}

impl Target {
    fn node_id(&self) -> &str {
        match self {
            Target::Node(n) => n,
            Target::Entry { node_id, .. } => node_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow(Rule),
    Deny(Rule),
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow(_))
    }

    pub fn rule(&self) -> Rule {
        match self {
            Decision::Allow(r) | Decision::Deny(r) => *r,
        }
    }
}

/// Runtime state `resolve` needs beyond the static graph: what's locked, and
/// what time it is (for grant expiry). All caller-supplied — see the module
/// doc.
pub struct AccessContext<'a> {
    pub registry: &'a Registry,
    pub vault_locked: bool,
    /// Nodes individually locked while the vault stays open (`06 §1a`).
    pub locked_nodes: &'a HashSet<String>,
    /// Unix epoch seconds.
    pub now: i64,
}

fn grant_covers(to: &GrantTarget, target: &Target) -> bool {
    match to {
        GrantTarget::Node { node_id: n } => target.node_id() == n,
        GrantTarget::Entry { node_id, entry_id } => matches!(
            target,
            Target::Entry { node_id: tn, entry_id: te } if tn == node_id && te == entry_id
        ),
    }
}

/// Does an unexpired grant, held by `subject_node` (or usable via a mutual
/// mirror — see `registry::Direction`), cover `target` at `capability`?
fn has_matching_grant(
    registry: &Registry,
    subject_node: &str,
    target: &Target,
    capability: Capability,
    now: i64,
) -> bool {
    registry.grants.iter().any(|grant| {
        if let Some(expires_at) = grant.expires_at {
            if expires_at <= now {
                return false;
            }
        }
        if !grant.scope.contains(&capability) {
            return false;
        }

        let forward = (grant.from == subject_node
            || registry.is_strict_ancestor(&grant.from, subject_node))
            && grant_covers(&grant.to, target);
        if forward {
            return true;
        }

        if grant.direction == Direction::Mutual {
            let to_node = grant.to.node_id();
            let subject_is_to_side =
                to_node == subject_node || registry.is_strict_ancestor(to_node, subject_node);
            let target_is_from_side = target.node_id() == grant.from;
            if subject_is_to_side && target_is_from_side {
                return true;
            }
        }

        false
    })
}

/// `06_ACCESS_GRAPH.md §1`, rules R0–R8, evaluated in precedence order.
/// Default is deny (R8).
pub fn resolve(
    ctx: &AccessContext,
    subject: &Scope,
    target: &Target,
    capability: Capability,
) -> Decision {
    let target_node = target.node_id();

    // Orphan can never legitimately BE a subject — `06_ACCESS_GRAPH.md §2`'s
    // worked matrix marks its entire row denied, including Global, which R3
    // would otherwise allow. The broker is expected to never issue a scope
    // for it (only the native-app-with-presence orphan-reveal path touches
    // orphan data at all, and that path is never a *subject*); this is the
    // pure-function backstop for that expectation.
    if subject.node_id == ORPHAN_ID {
        return Decision::Deny(Rule::R8);
    }

    // R0 — orphan is denied to everyone except native + live presence, full stop.
    if target_node == ORPHAN_ID {
        return if subject.origin == Origin::Native && subject.presence_attested {
            Decision::Allow(Rule::R0)
        } else {
            Decision::Deny(Rule::R0)
        };
    }

    // R1 — locked (vault-wide or this node individually) blocks reveal/update only.
    let target_locked = ctx.vault_locked || ctx.locked_nodes.contains(target_node);
    if target_locked && matches!(capability, Capability::Reveal | Capability::Update) {
        return Decision::Deny(Rule::R1);
    }

    // R2 — subject reading itself.
    if subject.node_id == target_node {
        return Decision::Allow(Rule::R2);
    }

    // R3 — global is readable by every node.
    if target_node == GLOBAL_ID {
        return Decision::Allow(Rule::R3);
    }

    // R4 — strict upward inheritance: target is an ancestor of subject.
    if ctx
        .registry
        .is_strict_ancestor(target_node, &subject.node_id)
    {
        return Decision::Allow(Rule::R4);
    }

    // R5 — descendant read, opt-in per node.
    if ctx
        .registry
        .is_strict_ancestor(&subject.node_id, target_node)
    {
        if let Some(subject_node_data) = ctx.registry.nodes.get(&subject.node_id) {
            if subject_node_data.policy.descendant_read {
                return Decision::Allow(Rule::R5);
            }
        }
    }

    // R6 — depth-2 siblings under a shared-visibility parent.
    if ctx
        .registry
        .are_shared_depth2_siblings(&subject.node_id, target_node)
    {
        return Decision::Allow(Rule::R6);
    }

    // R7 — an explicit, unexpired, human-created grant.
    if has_matching_grant(ctx.registry, &subject.node_id, target, capability, ctx.now) {
        return Decision::Allow(Rule::R7);
    }

    // R8 — default deny.
    Decision::Deny(Rule::R8)
}
