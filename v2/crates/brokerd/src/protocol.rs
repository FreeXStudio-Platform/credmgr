//! The wire protocol — `docs/10_API_AND_MCP.md §1`. Newline-delimited JSON,
//! request/response with an `id`.
//!
//! [`OpError`] is the strongly-typed shape every denial takes internally —
//! `ops::dispatch` and the isolation suite work with it directly, so a test
//! can assert `matches!(err, OpError::NodeAccessDenied { rule: "R8", .. })`
//! without round-tripping through JSON. [`to_wire`] is the one place that
//! shape becomes the JSON envelopes `10 §1` documents; only `server.rs`
//! calls it.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use credmgr_core::registry::Capability;

#[derive(Clone, Deserialize)]
pub struct Request {
    pub id: String,
    pub op: String,
    /// The caller's bearer token (ADR-077: a secret — see `Debug` below).
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub params: Value,
}

/// `Debug` shows that a token was presented, never what it was (ADR-077).
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("id", &self.id)
            .field("op", &self.op)
            .field("token", &self.token.as_ref().map(|_| "<bearer, redacted>"))
            .field("params", &self.params)
            .finish()
    }
}

/// Every way a request can fail to produce a value, typed so callers (tests
/// included) can match on *why* rather than parse a message string.
#[derive(Debug, Clone, PartialEq)]
pub enum OpError {
    /// `06_ACCESS_GRAPH.md §5` — carries the full structured shape
    /// including `remedy`, per Phase 3's exit gate.
    NodeAccessDenied {
        subject: String,
        target: String,
        capability: Capability,
        rule: &'static str,
        message: String,
        remedy: String,
    },
    TwoFactorRequired {
        challenge: String,
        scope: String,
        expires_in: u32,
    },
    /// Vault locked; a human can approve this one request (ADR-026).
    ApprovalPending {
        request: String,
        expires_in: u32,
        message: String,
    },
    /// A concurrent writer moved the node on (F-9).
    Conflict {
        node_id: String,
        expected_generation: u64,
        current_generation: u64,
    },
    /// `entry.update` (or any write) attempted while the **whole vault** is
    /// locked — only `entry.create` is permitted (ADR-023). A single locked
    /// node on an unlocked vault is [`OpError::NodeLocked`], never this: the
    /// desktop bridge ends the session on `vault_locked`.
    VaultLocked,
    /// ADR-077 (G3): the vault is unlocked but `node` is locked individually
    /// (`vault.node_lock`, `06 §1a`). A distinct code so a client can tell
    /// "this node is locked" from "your login is over" — the first is fixed by
    /// unlocking the node, the second by logging in again.
    NodeLocked {
        node: String,
    },
    /// The token/passphrase presented at `vault.unlock` did not authenticate.
    WrongPassphrase,
    /// Unknown `op`, or `params` did not match what the op expects.
    Malformed(String),
    /// A capability the caller's token doesn't carry at all — checked before
    /// `resolve()` even runs, so it never claims a rule number.
    CapabilityNotHeld {
        capability: Capability,
    },
    NotFound(String),
    /// `entry.create` named an entry that already exists on the node
    /// (`06_ACCESS_GRAPH.md §3`: "a name not already in the node").
    EntryExists {
        node: String,
        name: String,
    },
    /// An unexpected local failure (e.g. a filesystem error) outside the
    /// documented `10_API_AND_MCP.md §1` error taxonomy.
    Internal(String),
    /// The op's full grant gate includes native presence attestation
    /// (`04_CRYPTO_AND_KEYS.md §6`: seal/reparent), which no Phase 3
    /// transport can ever supply (`ops.rs`'s dispatcher hardcodes
    /// `presence_attested: false` — Phase 5 builds the native shell that
    /// makes it real). Distinct from `TwoFactorRequired`, which names a
    /// challenge a caller can go complete; there is nothing to complete here
    /// yet on this build.
    PresenceRequired {
        operation: String,
    },
    /// A `node.restore` attempt after the 7-day recovery window
    /// (`04_CRYPTO_AND_KEYS.md §6`, F-4) — the archive and the node key are
    /// already destroyed; the only remaining path is presence + a fresh
    /// code, one item at a time, native app only.
    ArchiveExpired {
        node: String,
    },
    /// A retried `entry.reveal` against an approval-on-demand request
    /// (ADR-042) that was explicitly denied, or that timed out without a
    /// decision — `07_TWO_FACTOR.md §5a`: "defaults to deny". Also returned
    /// by `vault.approval_decide` against a request id that no longer names
    /// a live, undecided request. `reason` is `"denied"`, `"expired"`, or —
    /// ADR-079 (4a) — `"locked"`: the request was approved, then the vault
    /// locked before the requester came back, which dropped the value staged
    /// for it.
    ApprovalDenied {
        request: String,
        reason: &'static str,
    },
    /// `vault.unlock` refused before even attempting the passphrase, because
    /// this uid's consecutive-failure backoff (`07 §5`) has not yet elapsed.
    RateLimited {
        retry_after_seconds: u64,
    },
    /// `vault.gate_verify`/`vault.gate_enroll_confirm` failed: wrong code, a
    /// replayed TOTP step, an expired or missing pending challenge, or an
    /// already-consumed recovery code. Deliberately undifferentiated —
    /// `07 §5`'s replay rule exists specifically so a caller cannot learn
    /// *which* check failed, the same "telling an attacker which check
    /// failed is a side channel" convention `crypto_core::CryptoError`
    /// already applies to AEAD failures.
    GateVerificationFailed,
    /// `vault.gate_enroll_begin` was never called for this scope (or its
    /// enrolment is already confirmed and no new one is in flight) —
    /// `vault.gate_enroll_confirm` has nothing to check the code against.
    GateNotEnrolling,
    /// `entry.restore` against a removal past its 7-day recovery window
    /// (ADR-048) — unlike a sealed node, a removed entry has no cold orphan
    /// copy behind it; this is the terminal state, not a remedy path.
    EntryRemovalExpired {
        node: String,
        entry: String,
    },
    /// `entry.undo` (ADR-055) against an audit record whose `action` has no
    /// undo mechanism (anything but `entry.rotate`/`entry.remove`), or
    /// whose `decision` was `"deny"` — the action never happened, so there
    /// is nothing to undo.
    NotUndoable {
        id: String,
        reason: &'static str,
    },
    /// `vault.init_begin`/`vault.init_confirm` (ADR-061) against a vault
    /// that already has a `registry.json` on disk.
    VaultAlreadyInitialized,
    /// `vault.init_begin` (ADR-061): the resolved vault root sits inside a
    /// `.git` working tree — V1 parity, `v1/CHANGELOG.md` 1.9.0.
    VaultInsideGitWorkingTree,
    /// `vault.init_confirm` (ADR-061) with no `vault.init_begin` in flight,
    /// or one whose TTL already elapsed.
    VaultInitNotPending,
    /// `vault.init_confirm` (ADR-061): the retyped recovery code did not
    /// match. The pending init is left in place — retry `init_confirm`.
    RecoveryCodeMismatch,
    /// ADR-068: the request presented a token the broker does not hold — a
    /// login that idled out (ADR-065), was dropped when the vault locked, or
    /// never existed. Refused rather than resolved from the caller's cwd, so
    /// a dead login is an error its holder can see, never a silent demotion.
    SessionExpired,
}

pub type OpResult = Result<Value, OpError>;

/// `10_API_AND_MCP.md §1`'s JSON envelopes, built from a typed [`OpResult`].
pub fn to_wire(id: &str, result: &OpResult) -> Value {
    match result {
        Ok(value) => json!({ "id": id, "ok": true, "value": value }),
        Err(OpError::NodeAccessDenied {
            subject,
            target,
            capability,
            rule,
            message,
            remedy,
        }) => json!({
            "id": id, "ok": false, "error": "node_access_denied",
            "subject": subject, "target": target, "capability": capability,
            "rule": rule, "message": message, "remedy": remedy,
        }),
        Err(OpError::TwoFactorRequired {
            challenge,
            scope,
            expires_in,
        }) => json!({
            "id": id, "ok": false, "error": "two_factor_required",
            "challenge": challenge, "scope": scope, "expiresIn": expires_in,
        }),
        Err(OpError::ApprovalPending {
            request,
            expires_in,
            message,
        }) => json!({
            "id": id, "ok": false, "error": "approval_pending",
            "request": request, "expiresIn": expires_in, "message": message,
        }),
        Err(OpError::Conflict {
            node_id,
            expected_generation,
            current_generation,
        }) => json!({
            "id": id, "ok": false, "error": "conflict", "node": node_id,
            "expectedGeneration": expected_generation, "currentGeneration": current_generation,
        }),
        Err(OpError::VaultLocked) => json!({
            "id": id, "ok": false, "error": "vault_locked",
            "message": "the vault is locked; only entry.create and entry.create_batch are permitted",
            "remedy": "unlock the vault, then retry",
        }),
        Err(OpError::NodeLocked { node }) => json!({
            "id": id, "ok": false, "error": "node_locked", "node": node,
            "message": format!("node {node} is locked; the vault itself is unlocked"),
            "remedy": "unlock this node (vault.node_unlock) and retry — the login is still valid",
        }),
        Err(OpError::WrongPassphrase) => json!({
            "id": id, "ok": false, "error": "wrong_passphrase",
        }),
        Err(OpError::Malformed(detail)) => json!({
            "id": id, "ok": false, "error": "malformed_request", "message": detail,
        }),
        Err(OpError::CapabilityNotHeld { capability }) => json!({
            "id": id, "ok": false, "error": "capability_not_held", "capability": capability,
        }),
        Err(OpError::NotFound(detail)) => json!({
            "id": id, "ok": false, "error": "not_found", "message": detail,
        }),
        Err(OpError::EntryExists { node, name }) => json!({
            "id": id, "ok": false, "error": "entry_exists", "node": node, "name": name,
        }),
        Err(OpError::Internal(detail)) => json!({
            "id": id, "ok": false, "error": "internal", "message": detail,
        }),
        Err(OpError::PresenceRequired { operation }) => json!({
            "id": id, "ok": false, "error": "presence_required", "operation": operation,
            "message": "this operation requires native presence attestation, not available on this transport",
        }),
        Err(OpError::ArchiveExpired { node }) => json!({
            "id": id, "ok": false, "error": "archive_expired", "node": node,
            "message": "the 7-day recovery window has passed; this node's archive and key are gone",
        }),
        Err(OpError::ApprovalDenied { request, reason }) => json!({
            "id": id, "ok": false, "error": "approval_denied",
            "request": request, "reason": reason,
        }),
        Err(OpError::RateLimited {
            retry_after_seconds,
        }) => json!({
            "id": id, "ok": false, "error": "rate_limited",
            "retryAfterSeconds": retry_after_seconds,
        }),
        Err(OpError::GateVerificationFailed) => json!({
            "id": id, "ok": false, "error": "gate_verification_failed",
            "message": "the code did not verify — wrong, already used, or expired",
        }),
        Err(OpError::GateNotEnrolling) => json!({
            "id": id, "ok": false, "error": "gate_not_enrolling",
            "message": "no gate enrolment is in flight for this scope",
        }),
        Err(OpError::EntryRemovalExpired { node, entry }) => json!({
            "id": id, "ok": false, "error": "entry_removal_expired", "node": node, "entry": entry,
            "message": "the 7-day recovery window has passed; this removal is final",
        }),
        Err(OpError::NotUndoable {
            id: record_id,
            reason,
        }) => json!({
            "id": id, "ok": false, "error": "not_undoable", "recordId": record_id,
            "message": reason,
        }),
        Err(OpError::VaultAlreadyInitialized) => json!({
            "id": id, "ok": false, "error": "vault_already_initialized",
            "message": "a vault already exists at this path",
        }),
        Err(OpError::VaultInsideGitWorkingTree) => json!({
            "id": id, "ok": false, "error": "vault_inside_git_working_tree",
            "message": "refusing to create a vault inside a git working tree",
        }),
        Err(OpError::VaultInitNotPending) => json!({
            "id": id, "ok": false, "error": "vault_init_not_pending",
            "message": "no vault.init_begin is in flight, or it expired — start over",
        }),
        Err(OpError::RecoveryCodeMismatch) => json!({
            "id": id, "ok": false, "error": "recovery_code_mismatch",
            "message": "the retyped recovery code did not match",
        }),
        Err(OpError::SessionExpired) => json!({
            "id": id, "ok": false, "error": "session_expired",
            "message": "this login is no longer valid (it idled out, the vault locked, or it never existed) — unlock again",
        }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireOrigin {
    HumanUi,
    Cli,
    Agent,
    Native,
}
