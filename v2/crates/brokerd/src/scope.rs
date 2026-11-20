//! Scope resolution — `06_ACCESS_GRAPH.md §4`. Turns "who just connected,
//! and what token (if any) did they present" into the [`BrokerScope`] every
//! operation checks a requested capability against before `resolve()` ever
//! runs.

use credmgr_core::access::Origin;
use credmgr_core::registry::{AgentAccess, Capability, Registry, GLOBAL_ID};

use crate::peer::PeerInfo;
use crate::token::{AgentLookup, Token, TokenStore};

#[derive(Clone, PartialEq)]
pub struct BrokerScope {
    pub node_id: String,
    /// The ceiling — `resolve()` is checked in addition to this, never
    /// instead of it (`06 §4`: "cannot be raised at runtime").
    pub capabilities: Vec<Capability>,
    pub origin: Origin,
    /// The presented token's id — **the bearer secret** (ADR-077). Used to look
    /// the session up and for nothing else: it is never recorded, returned or
    /// printed. A session is named in the audit log by its
    /// [`crate::token::Token::public_id`] instead.
    pub token_id: Option<String>,
    pub bound_workdir: Option<String>,
}

/// ADR-164 review P2-5: the scope carries a copy of the presented bearer for the length of one request; it is wiped
/// when the scope goes, whichever kind of bearer it is.
impl Drop for BrokerScope {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(t) = self.token_id.as_mut() {
            t.zeroize();
        }
    }
}

/// `Debug` shows that a token is present, never what it is (ADR-077).
impl std::fmt::Debug for BrokerScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerScope")
            .field("node_id", &self.node_id)
            .field("capabilities", &self.capabilities)
            .field("origin", &self.origin)
            .field(
                "token_id",
                &self.token_id.as_ref().map(|_| "<bearer, redacted>"),
            )
            .field("bound_workdir", &self.bound_workdir)
            .finish()
    }
}

impl BrokerScope {
    pub fn holds(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// `06_ACCESS_GRAPH.md §3`'s capability table, applied to a node's
/// `agentAccess` policy — the read/write split a cwd-scoped caller (no
/// token) gets. Not itself spelled out as a table in the docs; this is the
/// reading consistent with `08 §3`'s capability semantics: read-write agents
/// get everything short of `admin`/`notes` (both require an explicit grant
/// regardless of `agentAccess` — `06 §3`: "`notes` ... must be granted
/// explicitly, never inherited by default"); read-only agents can see and
/// reveal but not write; `none` gets nothing, full stop.
pub fn capabilities_for_agent_access(access: AgentAccess) -> Vec<Capability> {
    match access {
        AgentAccess::ReadWrite => vec![
            Capability::List,
            Capability::Read,
            Capability::Reveal,
            Capability::Create,
            Capability::Update,
        ],
        AgentAccess::ReadOnly => vec![Capability::List, Capability::Read, Capability::Reveal],
        AgentAccess::None => vec![],
    }
}

/// A registered `workdirs[]` entry matches `cwd` if `cwd` equals it or is a
/// subdirectory of it ("launched inside", `02 §3`). Longest match wins so a
/// sub-node's own `workdirs` entry beats an ancestor's.
pub(crate) fn match_workdir<'a>(registry: &'a Registry, cwd: &str) -> Option<&'a str> {
    let mut best: Option<(&str, &str)> = None;
    for (node_id, node) in &registry.nodes {
        for wd in &node.workdirs {
            let matches = cwd == wd || cwd.starts_with(&format!("{wd}/"));
            if matches && best.map_or(true, |(b, _)| wd.len() > b.len()) {
                best = Some((wd.as_str(), node_id.as_str()));
            }
        }
    }
    best.map(|(_, id)| id)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Anomaly {
    pub kind: AnomalyKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyKind {
    /// A token's `boundWorkdir` disagrees with the presenting process's
    /// live cwd (`06 §4`, `05 §7`).
    TokenWorkdirMismatch,
    /// ADR-164 review P2-10: an agent token presented from a folder registered to another node — a sign it was
    /// copied to where it does not belong. Logged only; the request proceeds under the token's own node.
    AgentTokenWorkdirMismatch,
}

/// `06_ACCESS_GRAPH.md §4`'s resolution order. Returns the scope plus any
/// anomaly the resolution itself surfaced (a mismatch never blocks the
/// request — "the request still proceeds under the token" — it only gets
/// logged).
pub fn resolve_scope(
    registry: &Registry,
    tokens: &TokenStore,
    peer: &PeerInfo,
    presented_token: Option<&str>,
) -> (BrokerScope, Option<Anomaly>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    resolve_scope_at(registry, tokens, peer, presented_token, now)
}

/// ADR-164: what an agent token may hold on `node_id` right now — the token's
/// own capabilities, cut down to what the node's `agentAccess` gives an agent
/// today. The owner narrowing a node's agent access narrows every token on it
/// at the next request; a node that is gone gives nothing.
pub fn agent_token_ceiling(
    registry: &Registry,
    node_id: &str,
    capabilities: &[Capability],
) -> Vec<Capability> {
    let ceiling = registry.nodes.get(node_id).map_or_else(Vec::new, |n| {
        capabilities_for_agent_access(n.policy.agent_access)
    });
    capabilities
        .iter()
        .copied()
        .filter(|c| ceiling.contains(c))
        .collect()
}

/// [`resolve_scope`] at a given time — the clock an agent token's expiry is
/// read against (the server passes the request's own `now`).
pub fn resolve_scope_at(
    registry: &Registry,
    tokens: &TokenStore,
    peer: &PeerInfo,
    presented_token: Option<&str>,
    now: i64,
) -> (BrokerScope, Option<Anomaly>) {
    // 1a. ADR-164: an agent token — exactly one node, its own capability subset
    // under the node's agent ceiling, `origin: agent`. A dead or unknown one
    // falls through like a dead login does, and the server refuses it
    // (`session_expired`, ADR-068).
    if let Some(bearer) = presented_token.filter(|b| crate::token::is_agent_bearer(b)) {
        if let AgentLookup::Live(t) = tokens.lookup_agent(bearer, now) {
            // Review P1-1: a token whose node is not in the registry (sealed, or gone some other way) is dead, not
            // dormant: it is revoked here, so a restore or a new node under the same id never revives it.
            if !registry.nodes.contains_key(&t.node_id) {
                tokens.kill_agent(&t.public_id, crate::token::AgentTokenDeath::NodeGone, now);
            } else {
                let capabilities = agent_token_ceiling(registry, &t.node_id, &t.capabilities);
                // Re-review N-4: the record is filed under the token's own node, whose readers may not see the other
                // project, so it names neither that node nor the folder: only that it was another project's.
                let anomaly = peer.cwd.as_deref().and_then(|cwd| {
                    let other = match_workdir(registry, cwd)?;
                    (other != t.node_id).then(|| Anomaly {
                        kind: AnomalyKind::AgentTokenWorkdirMismatch,
                        detail: format!(
                            "agent token {} for node {} presented from a folder registered to another project",
                            t.public_id, t.node_id
                        ),
                    })
                });
                return (
                    BrokerScope {
                        node_id: t.node_id,
                        capabilities,
                        origin: Origin::Agent,
                        token_id: Some(bearer.to_string()),
                        bound_workdir: None,
                    },
                    anomaly,
                );
            }
        }
    }
    // 1. Explicit token — its nodeId wins, always.
    if let Some(token_id) = presented_token.filter(|b| !crate::token::is_agent_bearer(b)) {
        if let Some(Token {
            id,
            public_id,
            node_id,
            capabilities,
            origin,
            bound_workdir,
        }) = tokens.get(token_id)
        {
            // ADR-077: this detail is written to the plaintext audit log and
            // returned by `audit.tail`, so it names the session by its public
            // id. It used to interpolate `id` — the bearer — which handed any
            // process that could read the feed a login to replay.
            let anomaly = match (&bound_workdir, &peer.cwd) {
                (Some(bound), Some(live)) if bound != live => Some(Anomaly {
                    kind: AnomalyKind::TokenWorkdirMismatch,
                    detail: format!(
                        "session {public_id} bound to {bound:?}, presenting process cwd is {live:?}"
                    ),
                }),
                _ => None,
            };
            return (
                BrokerScope {
                    node_id,
                    capabilities,
                    origin,
                    token_id: Some(id),
                    bound_workdir,
                },
                anomaly,
            );
        }
    }

    // 2. No token, cwd matches a registered workdirs[] entry.
    if let Some(cwd) = &peer.cwd {
        if let Some(node_id) = match_workdir(registry, cwd) {
            let access = registry
                .nodes
                .get(node_id)
                .map(|n| n.policy.agent_access)
                .unwrap_or(AgentAccess::None);
            return (
                BrokerScope {
                    node_id: node_id.to_string(),
                    capabilities: capabilities_for_agent_access(access),
                    origin: Origin::Agent,
                    token_id: None,
                    bound_workdir: Some(cwd.clone()),
                },
                None,
            );
        }
    }

    // 3. No token, cwd unknown (or no cwd at all) — global, list only.
    (
        BrokerScope {
            node_id: GLOBAL_ID.to_string(),
            capabilities: vec![Capability::List],
            origin: Origin::Agent,
            token_id: None,
            bound_workdir: peer.cwd.clone(),
        },
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use credmgr_core::registry::{Node, NodePolicy};

    fn peer(cwd: Option<&str>) -> PeerInfo {
        PeerInfo {
            uid: 501,
            pid: 1234,
            cwd: cwd.map(str::to_string),
        }
    }

    fn registry_with_northwind() -> Registry {
        let mut reg = Registry::new();
        reg.nodes.insert(GLOBAL_ID.to_string(), Node::global());
        reg.nodes.insert(
            "northwind".to_string(),
            Node {
                id: "northwind".to_string(),
                label: "Northwind".to_string(),
                kind: credmgr_core::registry::NodeKind::Project,
                depth: 1,
                parent_id: Some(GLOBAL_ID.to_string()),
                workdirs: vec!["/Users/x/projects/Northwind".to_string()],
                policy: NodePolicy::default(),
            },
        );
        reg
    }

    #[test]
    fn explicit_token_always_wins() {
        let reg = registry_with_northwind();
        let tokens = TokenStore::new();
        let t = tokens.issue("northwind", vec![Capability::List], Origin::Agent, None);
        let (scope, anomaly) =
            resolve_scope(&reg, &tokens, &peer(Some("/somewhere/else")), Some(&t.id));
        assert_eq!(scope.node_id, "northwind");
        assert!(anomaly.is_none(), "no bound_workdir means no mismatch");
    }

    #[test]
    fn cwd_under_a_registered_workdir_resolves_with_no_token() {
        let reg = registry_with_northwind();
        let tokens = TokenStore::new();
        let (scope, _) = resolve_scope(
            &reg,
            &tokens,
            &peer(Some("/Users/x/projects/Northwind/sub/dir")),
            None,
        );
        assert_eq!(scope.node_id, "northwind");
        assert!(scope.holds(Capability::Reveal));
    }

    #[test]
    fn unknown_cwd_resolves_to_global_list_only() {
        let reg = registry_with_northwind();
        let tokens = TokenStore::new();
        let (scope, _) = resolve_scope(&reg, &tokens, &peer(Some("/tmp/whatever")), None);
        assert_eq!(scope.node_id, GLOBAL_ID);
        assert_eq!(scope.capabilities, vec![Capability::List]);
    }

    #[test]
    fn token_cwd_mismatch_is_an_anomaly_but_the_request_still_proceeds() {
        let reg = registry_with_northwind();
        let tokens = TokenStore::new();
        let t = tokens.issue(
            "northwind",
            vec![Capability::List],
            Origin::Agent,
            Some("/Users/x/projects/Northwind".to_string()),
        );
        let (scope, anomaly) =
            resolve_scope(&reg, &tokens, &peer(Some("/somewhere/else")), Some(&t.id));
        assert_eq!(scope.node_id, "northwind", "token is still the authority");
        assert_eq!(anomaly.unwrap().kind, AnomalyKind::TokenWorkdirMismatch);
    }

    /// ADR-077: the anomaly detail is persisted and returned by `audit.tail`, so
    /// it must name the session, never carry the bearer.
    #[test]
    fn an_anomaly_names_the_session_not_the_bearer_and_debug_hides_it() {
        let reg = registry_with_northwind();
        let tokens = TokenStore::new();
        let t = tokens.issue(
            "northwind",
            vec![Capability::List],
            Origin::Agent,
            Some("/Users/x/projects/Northwind".to_string()),
        );
        let (scope, anomaly) =
            resolve_scope(&reg, &tokens, &peer(Some("/somewhere/else")), Some(&t.id));
        let detail = anomaly.expect("a mismatch").detail;
        assert!(!detail.contains(&t.id), "bearer leaked into: {detail}");
        assert!(detail.contains(&t.public_id), "{detail}");
        let shown = format!("{scope:?}");
        assert!(!shown.contains(&t.id), "bearer leaked into: {shown}");
    }
}
