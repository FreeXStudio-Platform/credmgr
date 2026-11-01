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

/// Replaces anything shaped like a bearer token (`cmt_` followed by at least
/// eight hex digits) with `[redacted-token]`. Applied to every string the
/// broker writes to the audit log and to every audit string it returns, so a
/// bearer that reached a record by any route — a future call site, a `reason`
/// someone pasted, a record written by a build that had the leak (ADR-077) —
/// still never leaves the process. Returns the input unchanged (no allocation
/// in the common case) when there is nothing to redact.
pub fn redact_bearer_tokens(text: &str) -> std::borrow::Cow<'_, str> {
    const MIN_HEX: usize = 8;
    if !text.contains(BEARER_PREFIX) {
        return std::borrow::Cow::Borrowed(text);
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut changed = false;
    while i < bytes.len() {
        if text[i..].starts_with(BEARER_PREFIX) {
            let hex_start = i + BEARER_PREFIX.len();
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

#[derive(Debug, Default)]
pub struct TokenStore {
    tokens: Mutex<HashMap<String, Token>>,
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
    fn revoked_token_is_gone_immediately() {
        let store = TokenStore::new();
        let t = store.issue("acme", vec![Capability::List], Origin::Cli, None);
        store.revoke(&t.id);
        assert!(store.get(&t.id).is_none());
    }
}
