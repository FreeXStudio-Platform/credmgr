//! Capability tokens — `06_ACCESS_GRAPH.md §4`. A token's `node_id` and
//! `capabilities` are fixed at issue time ("cannot be raised at runtime");
//! this store is the broker's only source of truth for what a presented
//! token id actually authorises.
//!
//! **The token id IS the bearer secret** (ADR-077): whoever presents it is that
//! session. It therefore never appears anywhere a second party can read — not
//! in the audit log, not in an op response other than the one that mints it, not
//! in a log line, not in a `Debug` print. What the rest of the system may name a
//! session by is [`Token::public_id`], a second random value drawn independently
//! of the token id: knowing it authenticates nothing, and it cannot be turned
//! back into the token. [`redact_bearer_tokens`] is the last line of defence for
//! any string that is about to be persisted or returned.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use rand_core::{OsRng, RngCore};

use credmgr_core::access::Origin;
use credmgr_core::registry::Capability;

#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    /// The bearer secret. Never log it, never record it, never return it except
    /// from the op that mints it (`vault.unlock` / `vault.gate_verify`).
    pub id: String,
    /// ADR-077: the name this session goes by in the audit log. Random, drawn
    /// separately from `id`, so it is not derived from the secret and cannot
    /// authenticate anything. `s_` plus 16 hex digits (a bearer is `cmt_` plus
    /// 32), so the two can never be mistaken for one another.
    pub public_id: String,
    pub node_id: String,
    pub capabilities: Vec<Capability>,
    pub origin: Origin,
    /// Recorded at issue; compared at use (`06 §4`) — a mismatch does not
    /// invalidate the token (the token is the authority) but is an anomaly
    /// signal (`05_THREAT_MODEL.md §7`).
    pub bound_workdir: Option<String>,
}

/// `Debug` must never print the bearer: a `{token:?}` in a test failure, a panic
/// message or a future log line would otherwise write the secret to a place the
/// whole machine can read.
impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("id", &"<bearer, redacted>")
            .field("public_id", &self.public_id)
            .field("node_id", &self.node_id)
            .field("capabilities", &self.capabilities)
            .field("origin", &self.origin)
            .field("bound_workdir", &self.bound_workdir)
            .finish()
    }
}

/// The prefix of every bearer token this broker mints.
const BEARER_PREFIX: &str = "cmt_";

fn new_token_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::from(BEARER_PREFIX);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// ADR-077: a fresh session name for the audit log, from its own draw of the
/// CSPRNG — deliberately not a hash of the bearer, so nothing about the bearer
/// can be recovered from it even in principle.
fn new_public_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::from("s_");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Replaces anything shaped like a bearer token (`cmt_` — a login — or `cma_` —
/// an agent token, ADR-164 — followed by at least eight hex digits) with
/// `[redacted-token]`. Applied to every string the
/// broker writes to the audit log and to every audit string it returns, so a
/// bearer that reached a record by any route — a future call site, a `reason`
/// someone pasted, a record written by a build that had the leak (ADR-077) —
/// still never leaves the process. Returns the input unchanged (no allocation
/// in the common case) when there is nothing to redact.
pub fn redact_bearer_tokens(text: &str) -> std::borrow::Cow<'_, str> {
    const MIN_HEX: usize = 8;
    const PREFIXES: [&str; 2] = [BEARER_PREFIX, AGENT_BEARER_PREFIX];
    if !PREFIXES.iter().any(|p| text.contains(p)) {
        return std::borrow::Cow::Borrowed(text);
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut changed = false;
    while i < bytes.len() {
        if let Some(prefix) = PREFIXES.iter().find(|p| text[i..].starts_with(**p)) {
            let hex_start = i + prefix.len();
            let mut end = hex_start;
            while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end - hex_start >= MIN_HEX {
                out.push_str("[redacted-token]");
                i = end;
                changed = true;
                continue;
            }
        }
        // Copy one whole character (the input is UTF-8 and `i` is always on a
        // character boundary).
        let ch_len = text[i..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&text[i..i + ch_len]);
        i += ch_len;
    }
    if changed {
        std::borrow::Cow::Owned(out)
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

// ---------------------------------------------------------------------------
// ADR-164: node-scoped agent tokens.
//
// An agent token is a bearer secret the owner issues for one node, with an
// explicit capability subset, a label and a mandatory short expiry. Unlike a
// login the **store** never keeps it in the clear: it keeps the SHA-256 of the
// bearer (domain-separated) and compares every live record in constant time,
// with no early exit, so neither the lookup's timing nor a dump of this store
// gives the bearer back. The bearer does pass through memory in the clear twice:
// once in the issue or rotation answer, and on every request that presents it.
// Those copies are wiped when they are done with (the new bearer is held in
// `Zeroizing`; the server wipes the answer after writing it and the request
// after handling it; `BrokerScope` wipes its copy on drop), but buffers the
// standard library or the kernel made on the way out are not (K-10). Records
// are memory-only: no hash, label or id is ever written to disk, and a broker
// restart revokes every agent token.

/// The prefix of every agent bearer token (`cma_` plus 64 hex digits, 256 bits).
/// Distinct from a login's `cmt_`, so a client can refuse to present a login
/// where only an agent token belongs (the MCP server does, ADR-164).
pub const AGENT_BEARER_PREFIX: &str = "cma_";
/// The expiry an issue or rotation gets when none is asked for: one day.
pub const AGENT_TOKEN_TTL_DEFAULT: i64 = 24 * 3600;
/// The longest expiry accepted: seven days. There is no "never".
pub const AGENT_TOKEN_TTL_MAX: i64 = 7 * 24 * 3600;
/// The shortest expiry accepted: one minute.
pub const AGENT_TOKEN_TTL_MIN: i64 = 60;
/// At most this many live agent tokens at once.
pub const AGENT_TOKENS_MAX: usize = 32;
/// How many dead (revoked, rotated-out, expired) bearers are remembered, so a
/// replay is still audited under the token's public id.
const AGENT_TOMBSTONES_MAX: usize = 256;

/// Whether `bearer` is shaped like an agent token (prefix only — it says
/// nothing about whether the broker holds it).
pub fn is_agent_bearer(bearer: &str) -> bool {
    bearer.starts_with(AGENT_BEARER_PREFIX)
}

fn agent_hash(bearer: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"credmgr-agent-token-v1\0");
    h.update(bearer.as_bytes());
    h.finalize().into()
}

/// Constant time for equal lengths (both are always 32 bytes here).
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn new_agent_bearer() -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(bytes.as_mut());
    // Sized once and written in place, so no partial copy is left behind by a reallocation or a temporary.
    let mut s = Zeroizing::new(String::with_capacity(AGENT_BEARER_PREFIX.len() + 64));
    s.push_str(AGENT_BEARER_PREFIX);
    for b in bytes.iter() {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// ADR-164 review P2-8: the monotonic deadline that goes with a wall-clock expiry. A token is dead when either has
/// passed, so setting the clock back never lengthens a token's life.
fn monotonic_deadline(ttl: i64) -> Instant {
    let secs = u64::try_from(ttl.max(0)).unwrap_or(0);
    Instant::now()
        .checked_add(Duration::from_secs(secs))
        .unwrap_or_else(Instant::now)
}

fn new_agent_public_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::from("a_");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// One live agent token. Holds no bearer: only its hash, which `Debug` and the
/// metadata view leave out.
#[derive(Clone)]
pub struct AgentToken {
    /// `a_` plus 16 hex digits: the name the audit log, the list and a revoke
    /// use. Its own random draw, so it says nothing about the bearer.
    pub public_id: String,
    hash: [u8; 32],
    pub node_id: String,
    pub capabilities: Vec<Capability>,
    pub label: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
    /// When the bearer was last replaced (`agent.token_rotate`), if ever.
    pub rotated_at: Option<i64>,
    /// The same expiry on the monotonic clock ([`monotonic_deadline`]).
    deadline: Instant,
}

impl std::fmt::Debug for AgentToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentToken")
            .field("public_id", &self.public_id)
            .field("node_id", &self.node_id)
            .field("capabilities", &self.capabilities)
            .field("label", &self.label)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Why a presented agent bearer no longer works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentTokenDeath {
    Revoked,
    Rotated,
    Expired,
    /// Its node was sealed, or is no longer in the registry (review P1-1): a restore, or a new node under the same
    /// id, never brings it back.
    NodeGone,
}

impl AgentTokenDeath {
    pub fn as_str(self) -> &'static str {
        match self {
            AgentTokenDeath::Revoked => "revoked",
            AgentTokenDeath::Rotated => "rotated",
            AgentTokenDeath::Expired => "expired",
            AgentTokenDeath::NodeGone => "node_gone",
        }
    }
}

/// What a presented agent bearer resolves to.
#[derive(Debug, Clone)]
pub enum AgentLookup {
    Live(AgentToken),
    /// The broker once held it; it is dead now. The public id is kept only so the
    /// refusal is audited under the token's own name.
    Dead {
        public_id: String,
        why: AgentTokenDeath,
    },
    Unknown,
}

/// `agent.token_issue` refused for a reason the store decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentIssueError {
    TooMany,
}

#[derive(Default)]
struct AgentTokens {
    live: Vec<AgentToken>,
    dead: Vec<([u8; 32], String, AgentTokenDeath)>,
}

impl AgentTokens {
    fn bury(&mut self, hash: [u8; 32], public_id: String, why: AgentTokenDeath) {
        if self.dead.len() >= AGENT_TOMBSTONES_MAX {
            self.dead.remove(0);
        }
        self.dead.push((hash, public_id, why));
    }

    /// Moves every token whose expiry has passed, on the wall clock or the monotonic one, to the dead list.
    fn prune(&mut self, now: i64) {
        let mono = Instant::now();
        let (keep, gone): (Vec<_>, Vec<_>) = std::mem::take(&mut self.live)
            .into_iter()
            .partition(|t| t.expires_at > now && t.deadline > mono);
        self.live = keep;
        for t in gone {
            self.bury(t.hash, t.public_id, AgentTokenDeath::Expired);
        }
    }

    /// Index of the live record whose hash is `hash`. Every record is compared,
    /// whether or not one matched earlier.
    fn find_live(&self, hash: &[u8; 32]) -> Option<usize> {
        let mut found = None;
        for (i, t) in self.live.iter().enumerate() {
            if ct_eq(&t.hash, hash) && found.is_none() {
                found = Some(i);
            }
        }
        found
    }

    fn find_dead(&self, hash: &[u8; 32]) -> Option<(String, AgentTokenDeath)> {
        let mut found = None;
        for (h, id, why) in &self.dead {
            if ct_eq(h, hash) && found.is_none() {
                found = Some((id.clone(), *why));
            }
        }
        found
    }
}

#[derive(Default)]
pub struct TokenStore {
    tokens: Mutex<HashMap<String, Token>>,
    /// ADR-164: agent tokens, by hash only.
    agents: Mutex<AgentTokens>,
}

/// Never prints a bearer or a hash: only how many of each kind are held.
impl std::fmt::Debug for TokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sessions = self.tokens.lock().map(|t| t.len()).unwrap_or(0);
        let agents = self.agents.lock().map(|a| a.live.len()).unwrap_or(0);
        f.debug_struct("TokenStore")
            .field("sessions", &sessions)
            .field("agent_tokens", &agents)
            .finish()
    }
}

impl TokenStore {
    pub fn new() -> Self {
        TokenStore::default()
    }

    /// Scope-immutable by construction: nothing in this crate exposes a way
    /// to mutate `capabilities`/`node_id` on an already-issued token.
    pub fn issue(
        &self,
        node_id: impl Into<String>,
        capabilities: Vec<Capability>,
        origin: Origin,
        bound_workdir: Option<String>,
    ) -> Token {
        let token = Token {
            id: new_token_id(),
            public_id: new_public_id(),
            node_id: node_id.into(),
            capabilities,
            origin,
            bound_workdir,
        };
        self.tokens
            .lock()
            .expect("token store mutex poisoned")
            .insert(token.id.clone(), token.clone());
        token
    }

    /// The audit-log name of the session behind bearer `id` (ADR-077), or `None`
    /// if the broker does not hold that token. The only thing about a token the
    /// rest of the broker is allowed to record.
    pub fn public_id(&self, id: &str) -> Option<String> {
        if is_agent_bearer(id) {
            let agents = self.agents.lock().expect("token store mutex poisoned");
            return agents
                .find_live(&agent_hash(id))
                .map(|i| agents.live[i].public_id.clone());
        }
        self.tokens
            .lock()
            .expect("token store mutex poisoned")
            .get(id)
            .map(|t| t.public_id.clone())
    }

    pub fn get(&self, id: &str) -> Option<Token> {
        self.tokens
            .lock()
            .expect("token store mutex poisoned")
            .get(id)
            .cloned()
    }

    pub fn revoke(&self, id: &str) {
        self.tokens
            .lock()
            .expect("token store mutex poisoned")
            .remove(id);
    }

    // ---- ADR-164: agent tokens ------------------------------------------------

    /// Mints an agent token. The bearer is returned here and nowhere else; the
    /// store keeps its hash. `ttl` is already validated by the caller.
    pub fn issue_agent(
        &self,
        node_id: &str,
        capabilities: Vec<Capability>,
        label: &str,
        now: i64,
        ttl: i64,
    ) -> Result<(Zeroizing<String>, AgentToken), AgentIssueError> {
        let mut agents = self.agents.lock().expect("token store mutex poisoned");
        agents.prune(now);
        if agents.live.len() >= AGENT_TOKENS_MAX {
            return Err(AgentIssueError::TooMany);
        }
        let bearer = new_agent_bearer();
        let token = AgentToken {
            public_id: new_agent_public_id(),
            hash: agent_hash(&bearer),
            node_id: node_id.to_string(),
            capabilities,
            label: label.to_string(),
            created_at: now,
            expires_at: now + ttl,
            last_used_at: None,
            rotated_at: None,
            deadline: monotonic_deadline(ttl),
        };
        agents.live.push(token.clone());
        Ok((bearer, token))
    }

    /// Replaces the bearer of live token `public_id` and gives it a new expiry.
    /// The old bearer stops working at once. `None` when no such live token.
    pub fn rotate_agent(
        &self,
        public_id: &str,
        now: i64,
        ttl: i64,
    ) -> Option<(Zeroizing<String>, AgentToken)> {
        let mut agents = self.agents.lock().expect("token store mutex poisoned");
        agents.prune(now);
        let i = agents.live.iter().position(|t| t.public_id == public_id)?;
        let bearer = new_agent_bearer();
        let old_hash = std::mem::replace(&mut agents.live[i].hash, agent_hash(&bearer));
        agents.live[i].expires_at = now + ttl;
        agents.live[i].deadline = monotonic_deadline(ttl);
        agents.live[i].rotated_at = Some(now);
        let token = agents.live[i].clone();
        agents.bury(old_hash, token.public_id.clone(), AgentTokenDeath::Rotated);
        Some((bearer, token))
    }

    /// Revokes live token `public_id`; the next request that presents it is
    /// refused. `None` when no such live token.
    pub fn revoke_agent(&self, public_id: &str, now: i64) -> Option<AgentToken> {
        let mut agents = self.agents.lock().expect("token store mutex poisoned");
        agents.prune(now);
        let i = agents.live.iter().position(|t| t.public_id == public_id)?;
        let token = agents.live.remove(i);
        agents.bury(
            token.hash,
            token.public_id.clone(),
            AgentTokenDeath::Revoked,
        );
        Some(token)
    }

    /// Ends live token `public_id` for `why` (review P1-1: its node is gone). No-op when it is not live.
    pub fn kill_agent(&self, public_id: &str, why: AgentTokenDeath, now: i64) {
        let mut agents = self.agents.lock().expect("token store mutex poisoned");
        agents.prune(now);
        if let Some(i) = agents.live.iter().position(|t| t.public_id == public_id) {
            let t = agents.live.remove(i);
            agents.bury(t.hash, t.public_id, why);
        }
    }

    /// Review P1-1: revokes every live token bound to `node_id` (a sealed node), burying each as
    /// [`AgentTokenDeath::NodeGone`] so a replay is still audited by name. Returns what was revoked.
    pub fn revoke_agents_for_node(&self, node_id: &str, now: i64) -> Vec<AgentToken> {
        let mut agents = self.agents.lock().expect("token store mutex poisoned");
        agents.prune(now);
        let (gone, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut agents.live)
            .into_iter()
            .partition(|t| t.node_id == node_id);
        agents.live = keep;
        for t in &gone {
            agents.bury(t.hash, t.public_id.clone(), AgentTokenDeath::NodeGone);
        }
        gone
    }

    /// The live token a presented bearer names, without recording a use: for naming the requester on an approval or
    /// a setting request (review P1-2). Never authenticates anything.
    pub fn peek_agent(&self, bearer: &str, now: i64) -> Option<AgentToken> {
        if !is_agent_bearer(bearer) {
            return None;
        }
        let hash = agent_hash(bearer);
        let mut agents = self.agents.lock().expect("token store mutex poisoned");
        agents.prune(now);
        agents.find_live(&hash).map(|i| agents.live[i].clone())
    }

    /// Every live agent token, oldest first. Metadata only: no bearer exists here
    /// to return.
    pub fn agent_tokens(&self, now: i64) -> Vec<AgentToken> {
        let mut agents = self.agents.lock().expect("token store mutex poisoned");
        agents.prune(now);
        agents.live.clone()
    }

    /// Resolves a presented agent bearer at `now`. A live hit records its use; a
    /// token whose expiry has passed is moved to the dead list here, so an
    /// expired token stops working on its very next request.
    pub fn lookup_agent(&self, bearer: &str, now: i64) -> AgentLookup {
        if !is_agent_bearer(bearer) {
            return AgentLookup::Unknown;
        }
        let hash = agent_hash(bearer);
        let mut agents = self.agents.lock().expect("token store mutex poisoned");
        agents.prune(now);
        if let Some(i) = agents.find_live(&hash) {
            agents.live[i].last_used_at = Some(now);
            return AgentLookup::Live(agents.live[i].clone());
        }
        match agents.find_dead(&hash) {
            Some((public_id, why)) => AgentLookup::Dead { public_id, why },
            None => AgentLookup::Unknown,
        }
    }

    /// The public id of a dead agent bearer, for the audit record of a refused
    /// replay. Never authenticates anything.
    pub fn dead_agent_public_id(&self, bearer: &str) -> Option<(String, AgentTokenDeath)> {
        if !is_agent_bearer(bearer) {
            return None;
        }
        self.agents
            .lock()
            .expect("token store mutex poisoned")
            .find_dead(&agent_hash(bearer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_token_is_retrievable_and_ids_are_unique() {
        let store = TokenStore::new();
        let a = store.issue("acme", vec![Capability::List], Origin::Cli, None);
        let b = store.issue("acme", vec![Capability::List], Origin::Cli, None);
        assert_ne!(a.id, b.id);
        assert_eq!(store.get(&a.id).unwrap().node_id, "acme");
    }

    #[test]
    fn the_public_id_is_independent_of_the_bearer_and_authenticates_nothing() {
        let store = TokenStore::new();
        let t = store.issue("acme", vec![Capability::List], Origin::Cli, None);
        assert!(
            t.id.starts_with("cmt_") && t.id.len() == 4 + 32,
            "{}",
            t.id.len()
        );
        assert!(
            t.public_id.starts_with("s_") && t.public_id.len() == 2 + 16,
            "{}",
            t.public_id.len()
        );
        // The public id shares no 8-digit run with the bearer (it is its own
        // random draw, not a truncation or a hash of it).
        let secret_hex = &t.id[4..];
        for window in secret_hex.as_bytes().windows(8) {
            let w = std::str::from_utf8(window).unwrap();
            assert!(
                !t.public_id.contains(w),
                "public id shares {w} with the bearer"
            );
        }
        // And it is not a key: presenting it resolves to no token.
        assert!(store.get(&t.public_id).is_none());
        assert_eq!(
            store.public_id(&t.id).as_deref(),
            Some(t.public_id.as_str())
        );
        assert!(store.public_id(&t.public_id).is_none());
        // Two sessions never share a name.
        let u = store.issue("acme", vec![Capability::List], Origin::Cli, None);
        assert_ne!(t.public_id, u.public_id);
    }

    #[test]
    fn debug_never_prints_the_bearer() {
        let store = TokenStore::new();
        let t = store.issue("acme", vec![Capability::List], Origin::Cli, None);
        let shown = format!("{t:?}");
        assert!(!shown.contains(&t.id), "{shown}");
        assert!(shown.contains(&t.public_id), "{shown}");
    }

    #[test]
    fn redact_replaces_every_bearer_shaped_string_and_nothing_else() {
        let bearer = "cmt_0123456789abcdef0123456789abcdef";
        assert_eq!(redact_bearer_tokens(bearer), "[redacted-token]");
        assert_eq!(
            redact_bearer_tokens(&format!("token {bearer} bound to {bearer}!")),
            "token [redacted-token] bound to [redacted-token]!"
        );
        // A bearer inside a longer word, and upper-case hex.
        assert_eq!(
            redact_bearer_tokens("x-cmt_DEADBEEF12-y"),
            "x-[redacted-token]-y"
        );
        for untouched in [
            "",
            "Agent",
            "HumanUi:s_0123456789abcdef",
            "cmt_",
            "cmt_abc",
            "cmt_zzzzzzzzzzzz",
            "no token here — ünïcödé ✓",
        ] {
            assert_eq!(redact_bearer_tokens(untouched), untouched);
        }
        // Non-ASCII text around a bearer survives intact.
        assert_eq!(
            redact_bearer_tokens(&format!("é{bearer}ü")),
            "é[redacted-token]ü"
        );
    }

    #[test]
    fn an_agent_token_is_kept_as_a_hash_and_looked_up_until_it_expires() {
        let store = TokenStore::new();
        let (bearer, t) = store
            .issue_agent("acme", vec![Capability::List], "ci", 1_000, 3_600)
            .unwrap();
        assert!(
            bearer.starts_with("cma_") && bearer.len() == 4 + 64,
            "{}",
            bearer.len()
        );
        assert!(t.public_id.starts_with("a_") && t.public_id.len() == 2 + 16);
        assert!(!bearer.contains(&t.public_id[2..]));
        // Nothing the store can print holds the bearer or its hash.
        let shown = format!("{t:?} {store:?}");
        assert!(!shown.contains(bearer.as_str()), "{shown}");
        assert!(!shown.contains(&hex(&agent_hash(&bearer))), "{shown}");
        // The session map never sees it.
        assert!(store.get(&bearer).is_none());
        match store.lookup_agent(&bearer, 1_500) {
            AgentLookup::Live(live) => {
                assert_eq!(live.node_id, "acme");
                assert_eq!(live.last_used_at, Some(1_500));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            store.public_id(&bearer).as_deref(),
            Some(t.public_id.as_str())
        );
        // One character off is a different token.
        let mut wrong = bearer.clone();
        wrong.pop();
        wrong.push(if bearer.ends_with('0') { '1' } else { '0' });
        assert!(matches!(
            store.lookup_agent(&wrong, 1_500),
            AgentLookup::Unknown
        ));
        // At its expiry it is dead, and says so under its own name.
        match store.lookup_agent(&bearer, 4_600) {
            AgentLookup::Dead { public_id, why } => {
                assert_eq!(public_id, t.public_id);
                assert_eq!(why, AgentTokenDeath::Expired);
            }
            other => panic!("{other:?}"),
        }
        assert!(store.agent_tokens(4_600).is_empty());
        assert!(store.public_id(&bearer).is_none());
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[test]
    fn rotating_kills_the_old_bearer_and_revoking_kills_the_token() {
        let store = TokenStore::new();
        let (old, t) = store
            .issue_agent("acme", vec![Capability::List], "ci", 0, 600)
            .unwrap();
        let (new, rotated) = store.rotate_agent(&t.public_id, 100, 600).unwrap();
        assert_ne!(old, new);
        assert_eq!(rotated.public_id, t.public_id);
        assert_eq!(rotated.expires_at, 700);
        assert_eq!(rotated.rotated_at, Some(100));
        assert!(matches!(
            store.lookup_agent(&old, 101),
            AgentLookup::Dead {
                why: AgentTokenDeath::Rotated,
                ..
            }
        ));
        assert!(matches!(
            store.lookup_agent(&new, 101),
            AgentLookup::Live(_)
        ));
        assert!(store.revoke_agent(&t.public_id, 102).is_some());
        assert!(matches!(
            store.lookup_agent(&new, 103),
            AgentLookup::Dead {
                why: AgentTokenDeath::Revoked,
                ..
            }
        ));
        assert!(store.revoke_agent(&t.public_id, 104).is_none());
        assert!(store.rotate_agent(&t.public_id, 104, 600).is_none());
        assert_eq!(
            store.dead_agent_public_id(&new),
            Some((t.public_id.clone(), AgentTokenDeath::Revoked))
        );
        // A login bearer is never looked up as an agent token.
        let login = store.issue("acme", vec![Capability::List], Origin::HumanUi, None);
        assert!(matches!(
            store.lookup_agent(&login.id, 0),
            AgentLookup::Unknown
        ));
    }

    #[test]
    fn at_most_the_cap_of_live_agent_tokens_and_an_expired_one_frees_a_place() {
        let store = TokenStore::new();
        for _ in 0..AGENT_TOKENS_MAX {
            store
                .issue_agent("acme", vec![Capability::List], "x", 0, 60)
                .unwrap();
        }
        assert_eq!(
            store
                .issue_agent("acme", vec![Capability::List], "x", 0, 60)
                .unwrap_err(),
            AgentIssueError::TooMany
        );
        assert!(store
            .issue_agent("acme", vec![Capability::List], "x", 61, 60)
            .is_ok());
    }

    #[test]
    fn an_agent_bearer_is_redacted_like_a_login() {
        let bearer = format!("cma_{}", "ab".repeat(32));
        assert_eq!(
            redact_bearer_tokens(&format!("x {bearer} y")),
            "x [redacted-token] y"
        );
        assert_eq!(
            redact_bearer_tokens("a_0123456789abcdef"),
            "a_0123456789abcdef"
        );
        assert_eq!(redact_bearer_tokens("cma_"), "cma_");
    }

    #[test]
    fn revoked_token_is_gone_immediately() {
        let store = TokenStore::new();
        let t = store.issue("acme", vec![Capability::List], Origin::Cli, None);
        store.revoke(&t.id);
        assert!(store.get(&t.id).is_none());
    }
}
