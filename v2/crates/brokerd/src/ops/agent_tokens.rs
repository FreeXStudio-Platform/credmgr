//! ADR-164 — the bodies of the four `agent.token_*` ops: node-scoped agent tokens. The dispatch arms in
//! `ops.rs` read the request's parameters (with literal keys, so the desktop bridge's drift guard can see
//! them) and call in here; this is a child module of `ops`, so it shares the authorisation helpers.
//!
//! The rules, in one place:
//! - **Only the owner's login** reaches any of the four. An agent — a token-less caller inside a project
//!   folder, an agent token, a fixture token — is refused before anything is read (`capability_not_held`).
//!   An agent can therefore neither mint, widen, narrow, rotate, list nor revoke a token, its own included.
//! - **Issuing and rotating create a bearer secret**, so each needs a fresh second factor where one is
//!   enrolled and a Touch ID proof for exactly that request, the gate `grant.create` has (ADR-098). Every
//!   check that needs no finger runs first, so a request that will be refused never costs a prompt.
//! - **A token is one node, a subset of what the node gives agents, and a short life.** Capabilities are
//!   at most `list, read, reveal, create, update`, and at most what the node's `agentAccess` gives an agent
//!   now (re-applied at every request, `scope::agent_token_ceiling`). The expiry is mandatory: one day by
//!   default, seven at most.
//! - **The bearer is in the issue or rotate answer and nowhere else.** The store keeps its hash; the status
//!   answer is metadata; the audit record of the issue holds the node and the op, never the answer.

use serde_json::{json, Value};

use credmgr_core::registry::{Capability, GLOBAL_ID, ORPHAN_ID};
use zeroize::Zeroizing;

use super::{
    access_denied_error, owner_session, refuse_agent, require_fresh_second_factor,
    require_presence, resolve_capability, rule_name,
};
use crate::protocol::OpError;
use crate::scope::{agent_token_ceiling, capabilities_for_agent_access, BrokerScope};
use crate::state::BrokerState;
use crate::token::{
    AgentIssueError, AgentToken, AGENT_TOKENS_MAX, AGENT_TOKEN_TTL_DEFAULT, AGENT_TOKEN_TTL_MAX,
    AGENT_TOKEN_TTL_MIN,
};

/// The longest label accepted.
const LABEL_MAX: usize = 64;

/// The capabilities an agent token may ever carry. `notes` and `admin` are never an agent's (`06 §3`).
const TOKEN_CAPABILITIES: [Capability; 5] = [
    Capability::List,
    Capability::Read,
    Capability::Reveal,
    Capability::Create,
    Capability::Update,
];

/// The gate all four share: never an agent, and the caller is a live login.
fn owner_only(state: &BrokerState, scope: &BrokerScope) -> Result<(), OpError> {
    refuse_agent(scope)?;
    owner_session(state, scope)
}

/// ADR-164 re-review N-3: a character a label must not hold because it changes how the text around it reads or is
/// invisible: control characters (Cc), Unicode format characters (Cf: the bidi embeddings, overrides and isolates,
/// zero-width spaces and joiners, the word joiner and invisible operators, the BOM, interlinear annotation, tags…),
/// line and paragraph separators, and the invisible fillers. A label is shown in the Touch ID sentence and beside
/// every request a token makes, so it must read as what it is.
pub(crate) fn is_hidden_or_format_char(c: char) -> bool {
    c.is_control()
        || matches!(
            u32::from(c),
            0x00AD
                | 0x034F
                | 0x0600..=0x0605
                | 0x061C
                | 0x06DD
                | 0x070F
                | 0x0890..=0x0891
                | 0x08E2
                | 0x115F..=0x1160
                | 0x17B4..=0x17B5
                | 0x180B..=0x180F
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x206F
                | 0x3164
                | 0xFE00..=0xFE0F
                | 0xFEFF
                | 0xFFA0
                | 0xFFF9..=0xFFFB
                | 0x110BD
                | 0x110CD
                | 0x13430..=0x1343F
                | 0x1BCA0..=0x1BCA3
                | 0x1D173..=0x1D17A
                | 0xE0000..=0xE0FFF
        )
}

fn valid_label(raw: &str) -> Result<String, OpError> {
    let label = raw.trim();
    if label.is_empty()
        || label.chars().count() > LABEL_MAX
        || label.chars().any(is_hidden_or_format_char)
    {
        return Err(OpError::Malformed(format!(
            "label must be 1–{LABEL_MAX} characters with no control, direction-changing or invisible characters"
        )));
    }
    Ok(label.to_string())
}

/// `expiresIn` in seconds: absent or null is the default; anything else must be a whole number of seconds
/// between the minimum and the maximum. There is no "never".
fn valid_ttl(raw: Option<&Value>) -> Result<i64, OpError> {
    match raw {
        None | Some(Value::Null) => Ok(AGENT_TOKEN_TTL_DEFAULT),
        Some(v) => match v.as_i64() {
            Some(t) if (AGENT_TOKEN_TTL_MIN..=AGENT_TOKEN_TTL_MAX).contains(&t) => Ok(t),
            _ => Err(OpError::Malformed(format!(
                "params.expiresIn must be whole seconds from {AGENT_TOKEN_TTL_MIN} to {AGENT_TOKEN_TTL_MAX} \
                 (seven days); an agent token always expires"
            ))),
        },
    }
}

/// The node a token is for: it exists, it is neither Orphaned nor Global, and the owner's login holds `admin` on it.
/// Global is refused (review P2-7): it holds the vault-wide shared secrets, and the owner's own actions are filed under
/// it, so a Global token would be the broadest token possible. Taken as the most restrictive reading; the owner may
/// decide to allow it behind an explicit choice.
fn token_node(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    now: i64,
) -> Result<Vec<Capability>, OpError> {
    if node == ORPHAN_ID {
        return Err(OpError::Malformed(
            "an agent token cannot be issued for the Orphaned node".into(),
        ));
    }
    if node == GLOBAL_ID {
        return Err(OpError::Malformed(
            "an agent token cannot be issued for Global: issue it for the project the agent works on".into(),
        ));
    }
    let ceiling = {
        let registry = state.registry.read().expect("registry poisoned");
        let n = registry
            .nodes
            .get(node)
            .ok_or_else(|| OpError::NotFound(format!("no node {node}")))?;
        capabilities_for_agent_access(n.policy.agent_access)
    };
    let decision = resolve_capability(state, scope, node, Capability::Admin, now);
    if !decision.is_allow() {
        return Err(access_denied_error(
            state,
            scope,
            node,
            Capability::Admin,
            rule_name(decision),
            now,
        ));
    }
    Ok(ceiling)
}

/// The requested capabilities: a non-empty array, each one an agent capability the node allows agents.
fn valid_capabilities(
    raw: &Value,
    node: &str,
    ceiling: &[Capability],
) -> Result<Vec<Capability>, OpError> {
    let requested: Vec<Capability> = serde_json::from_value(raw.clone()).map_err(|_| {
        OpError::Malformed(
            "params.capabilities must be an array of list, read, reveal, create, update".into(),
        )
    })?;
    if requested.is_empty() {
        return Err(OpError::Malformed(
            "params.capabilities must name at least one capability".into(),
        ));
    }
    let mut out: Vec<Capability> = Vec::new();
    for c in requested {
        if !TOKEN_CAPABILITIES.contains(&c) {
            return Err(OpError::Malformed(
                "an agent token may carry only list, read, reveal, create and update; notes and admin \
                 are never an agent's"
                    .into(),
            ));
        }
        if !ceiling.contains(&c) {
            return Err(OpError::Malformed(format!(
                "node {node} does not give agents {}: change its agent access first, or ask for less",
                capability_name(c)
            )));
        }
        if !out.contains(&c) {
            out.push(c);
        }
    }
    // A stable order, whatever order they were asked in.
    out.sort_by_key(|c| TOKEN_CAPABILITIES.iter().position(|t| t == c));
    Ok(out)
}

fn capability_name(c: Capability) -> String {
    serde_json::to_value(c)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The metadata view of a token. There is no bearer to put in it.
fn view(state: &BrokerState, t: &AgentToken) -> Value {
    let effective = {
        let registry = state.registry.read().expect("registry poisoned");
        agent_token_ceiling(&registry, &t.node_id, &t.capabilities)
    };
    json!({
        "id": t.public_id,
        "label": t.label,
        "node": t.node_id,
        "capabilities": t.capabilities,
        "effectiveCapabilities": effective,
        "createdAt": t.created_at,
        "expiresAt": t.expires_at,
        "lastUsedAt": t.last_used_at,
        "rotatedAt": t.rotated_at,
    })
}

/// The answer that carries a bearer: the issue's and the rotation's. Shown once.
/// The one copy made here goes into the answer, which the server wipes after writing it; `bearer` is wiped on drop.
fn with_secret(state: &BrokerState, bearer: Zeroizing<String>, t: &AgentToken) -> Value {
    let mut v = view(state, t);
    v["token"] = Value::String(bearer.as_str().to_owned());
    v["shownOnce"] = json!(true);
    v
}

/// `agent.token_issue`.
#[allow(clippy::too_many_arguments)]
pub(super) fn issue(
    state: &BrokerState,
    scope: &BrokerScope,
    node: &str,
    label: &str,
    capabilities: &Value,
    expires_in: Option<&Value>,
    params: &Value,
    now: i64,
) -> Result<Value, OpError> {
    owner_only(state, scope)?;
    let label = valid_label(label)?;
    let ceiling = token_node(state, scope, node, now)?;
    let capabilities = valid_capabilities(capabilities, node, &ceiling)?;
    let ttl = valid_ttl(expires_in)?;
    if state.tokens.agent_tokens(now).len() >= AGENT_TOKENS_MAX {
        return Err(too_many());
    }
    // Everything above needed no finger. A new bearer secret needs both.
    require_fresh_second_factor(state, now)?;
    require_presence(state, scope, "agent.token_issue", params, now)?;
    let (bearer, token) = state
        .tokens
        .issue_agent(node, capabilities, &label, now, ttl)
        .map_err(|AgentIssueError::TooMany| too_many())?;
    Ok(with_secret(state, bearer, &token))
}

fn too_many() -> OpError {
    OpError::Malformed(format!(
        "at most {AGENT_TOKENS_MAX} agent tokens can be live at once; revoke one first"
    ))
}

/// `agent.token_status`: every live token, metadata only, optionally for one node.
pub(super) fn status(
    state: &BrokerState,
    scope: &BrokerScope,
    only_node: Option<&str>,
    now: i64,
) -> Result<Value, OpError> {
    owner_only(state, scope)?;
    let tokens: Vec<Value> = state
        .tokens
        .agent_tokens(now)
        .iter()
        .filter(|t| only_node.map_or(true, |n| t.node_id == n))
        .map(|t| view(state, t))
        .collect();
    Ok(json!({
        "tokens": tokens,
        "max": AGENT_TOKENS_MAX,
        "defaultExpiresIn": AGENT_TOKEN_TTL_DEFAULT,
        "maxExpiresIn": AGENT_TOKEN_TTL_MAX,
    }))
}

/// `agent.token_rotate`: a new bearer for an existing token, with a new expiry. The old bearer stops working
/// at once. The node and capabilities do not change (a different scope is a different token).
pub(super) fn rotate(
    state: &BrokerState,
    scope: &BrokerScope,
    id: &str,
    expires_in: Option<&Value>,
    params: &Value,
    now: i64,
) -> Result<Value, OpError> {
    owner_only(state, scope)?;
    let ttl = valid_ttl(expires_in)?;
    let existing = state
        .tokens
        .agent_tokens(now)
        .into_iter()
        .find(|t| t.public_id == id)
        .ok_or_else(|| OpError::NotFound(format!("no live agent token {id}")))?;
    token_node(state, scope, &existing.node_id, now)?;
    require_fresh_second_factor(state, now)?;
    require_presence(state, scope, "agent.token_rotate", params, now)?;
    let (bearer, token) = state
        .tokens
        .rotate_agent(id, now, ttl)
        .ok_or_else(|| OpError::NotFound(format!("no live agent token {id}")))?;
    Ok(with_secret(state, bearer, &token))
}

/// `agent.token_revoke`: the next request that presents the token is refused. Revoking only takes access
/// away, so like `grant.revoke` it waits on no second factor or proof.
pub(super) fn revoke(
    state: &BrokerState,
    scope: &BrokerScope,
    id: &str,
    now: i64,
) -> Result<Value, OpError> {
    owner_only(state, scope)?;
    let token = state
        .tokens
        .revoke_agent(id, now)
        .ok_or_else(|| OpError::NotFound(format!("no live agent token {id}")))?;
    Ok(json!({
        "revoked": true,
        "id": token.public_id,
        "label": token.label,
        "node": token.node_id,
    }))
}

/// "7-day", "8-hour", "90-minute", "75-second": how long a token lasts, for the Touch ID sentence.
fn lifetime_words(ttl: i64) -> String {
    if ttl % 86_400 == 0 {
        format!("{}-day", ttl / 86_400)
    } else if ttl % 3_600 == 0 {
        format!("{}-hour", ttl / 3_600)
    } else if ttl % 60 == 0 {
        format!("{}-minute", ttl / 60)
    } else {
        format!("{ttl}-second")
    }
}

/// Review P2-1: the Touch ID sentence for issuing or rotating, built from the exact params the proof is bound to, so
/// the person sees what they are signing: the node, the capabilities and the lifetime. The label (typed by whoever
/// asked) comes last and is quoted and cut short. `None` when the params do not describe a token that could be
/// issued, so the fixed sentence is used instead (the op itself will refuse those params).
pub(super) fn presence_reason(
    state: &BrokerState,
    op: &str,
    inner: &Value,
    now: i64,
) -> Option<String> {
    let ttl = valid_ttl(inner.get("expiresIn")).ok()?;
    let (verb, node, caps, label) = match op {
        "agent.token_issue" => {
            let node = inner.get("node")?.as_str()?.to_string();
            let requested: Vec<Capability> =
                serde_json::from_value(inner.get("capabilities")?.clone()).ok()?;
            let mut caps: Vec<Capability> = Vec::new();
            for c in requested {
                if !caps.contains(&c) {
                    caps.push(c);
                }
            }
            caps.sort_by_key(|c| TOKEN_CAPABILITIES.iter().position(|t| t == c));
            let label = inner.get("label")?.as_str()?.trim().to_string();
            ("Issue", node, caps, label)
        }
        "agent.token_rotate" => {
            let id = inner.get("id")?.as_str()?;
            let t = state
                .tokens
                .agent_tokens(now)
                .into_iter()
                .find(|t| t.public_id == id)?;
            ("Renew for", t.node_id, t.capabilities, t.label)
        }
        _ => return None,
    };
    let caps: Vec<String> = caps.into_iter().map(capability_name).collect();
    let mut label: String = label
        .chars()
        .filter(|c| !is_hidden_or_format_char(*c))
        .take(40)
        .collect();
    if label.is_empty() {
        label = "unnamed".into();
    }
    let reason = if verb == "Issue" {
        format!(
            "Issue a {} agent token for project {node} that may {}: \u{201c}{label}\u{201d}",
            lifetime_words(ttl),
            caps.join(", ")
        )
    } else {
        format!(
            "Give agent token \u{201c}{label}\u{201d} (project {node}, may {}) a new secret for {}",
            caps.join(", "),
            lifetime_words(ttl).replace('-', " ")
        )
    };
    Some(reason.chars().take(240).collect())
}

/// Review P2-2: what the audit record of an allowed issue, rotate or revoke says about the token it acted on — its
/// public id (not secret), node, capabilities and expiry. Never the bearer (the answer's `token` is not read).
pub(crate) fn audit_detail(op: &str, answer: &Value) -> Option<String> {
    if !matches!(
        op,
        "agent.token_issue" | "agent.token_rotate" | "agent.token_revoke"
    ) {
        return None;
    }
    let id = answer.get("id")?.as_str()?;
    let mut parts = vec![format!("token {id}")];
    if let Some(node) = answer.get("node").and_then(Value::as_str) {
        parts.push(format!("node {node}"));
    }
    if let Some(caps) = answer.get("capabilities").and_then(Value::as_array) {
        let caps: Vec<&str> = caps.iter().filter_map(Value::as_str).collect();
        parts.push(format!("caps {}", caps.join(",")));
    }
    if let Some(exp) = answer.get("expiresAt").and_then(Value::as_i64) {
        parts.push(format!("expires {exp}"));
    }
    Some(parts.join("; "))
}
