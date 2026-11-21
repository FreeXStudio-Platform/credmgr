//! The UDS server. Newline-delimited JSON (`10_API_AND_MCP.md §1`), one
//! thread per connection. `02_ARCHITECTURE.md §3`: **every connection is
//! identified before the token is even read** — `LOCAL_PEERCRED` first,
//! hard gate, then the request frame.

use std::io::{self, BufRead, BufReader, Read, Write};

use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use secrecy::ExposeSecret;

use crate::ops;
use crate::peer::{self, PeerInfo};
use crate::protocol::{self, OpError, Request};
use crate::scope::{self, Anomaly, AnomalyKind};
use crate::state::BrokerState;

/// I-12's own name for the action, exhaustively matched so a future
/// `AnomalyKind` variant is a compile error here, not a silently generic
/// audit line.
fn audit_action_for(kind: AnomalyKind) -> &'static str {
    match kind {
        AnomalyKind::TokenWorkdirMismatch => "anomaly.token_workdir_mismatch",
        AnomalyKind::AgentTokenWorkdirMismatch => "anomaly.agent_token_workdir_mismatch",
        AnomalyKind::ProjectLoginWrongFolder => "anomaly.project_login_wrong_folder",
    }
}

/// ADR-077: who an audit record says did something. **Never the bearer token**
/// — the audit log is plaintext on disk and `audit.tail` serves it to anyone who
/// holds `list`, so a token recorded here is a login handed to every process
/// that can read either. A caller with a live session is
/// `<Origin>:<session public id>` (for example `HumanUi:s_9f3a…`), which names
/// the session without being able to authenticate as it; a caller with none is
/// just its `<Origin>`.
///
/// Computed once per request, before dispatch: `vault.lock` revokes every token
/// during the request that locks, and the record about that request must still
/// say who asked.
fn audit_actor(state: &BrokerState, scope: &crate::scope::BrokerScope) -> String {
    match scope
        .token_id
        .as_deref()
        .and_then(|bearer| state.tokens.public_id(bearer))
    {
        Some(public_id) => format!("{:?}:{public_id}", scope.origin),
        None => format!("{:?}", scope.origin),
    }
}

/// ADR-164: a revoked, rotated-out or expired agent token that is presented again
/// is refused (`session_expired`), and the record of that refusal names the token
/// by its public id and why it is dead (`Agent:a_…(revoked)`), so a replay is
/// visible on the trail. Never the bearer.
fn dead_agent_actor(
    state: &BrokerState,
    scope: &crate::scope::BrokerScope,
    presented: Option<&str>,
) -> Option<String> {
    if scope.token_id.is_some() {
        return None;
    }
    let (public_id, why) = state.tokens.dead_agent_public_id(presented?)?;
    Some(format!("Agent:{public_id}({})", why.as_str()))
}

/// ADR-077: the last line of defence on the way into the audit log. Whatever a
/// caller passes — an actor, a `reason` somebody pasted a token into, a detail
/// built by a future call site — a bearer-shaped string is replaced before it is
/// written, so it cannot reach the plaintext file whatever route it took.
fn scrubbed(mut event: credmgr_store::audit::NewEvent) -> credmgr_store::audit::NewEvent {
    event.actor = crate::token::redact_bearer_tokens(&event.actor).into_owned();
    event.detail = event
        .detail
        .map(|d| crate::token::redact_bearer_tokens(&d).into_owned());
    event
}

/// ADR-156: `05 §7`'s "five cross-node denials in ten minutes", on the audit trail. Best-effort like
/// [`record_anomaly`]; the detail is a fixed sentence, never anything a caller sent.
fn record_cross_node_alarm(
    state: &BrokerState,
    scope: &crate::scope::BrokerScope,
    actor: &str,
    target: &str,
    now: i64,
) {
    let Ok(root_key) = state.reauth_root_key("audit: anomaly") else {
        return;
    };
    let event = scrubbed(credmgr_store::audit::NewEvent {
        actor: actor.to_string(),
        action: "anomaly.cross_node_denials".to_string(),
        node_id: Some(scope.node_id.clone()),
        entry_id: None,
        decision: None,
        detail: Some(format!(
            "five cross-node denials in ten minutes; the last asked for node {target}"
        )),
        generation: None,
    });
    let year_month = credmgr_store::audit::year_month_for(now);
    let _ = credmgr_store::audit::append(
        &state.paths,
        root_key.expose_secret(),
        &year_month,
        event,
        now,
    );
}

/// `10_API_AND_MCP.md §1`: an anomaly "only gets logged" — it never blocks
/// the request that raised it, and by the same logic a failure to persist
/// it (a full disk, a keystore hiccup on `reauth_root_key`) must not turn
/// into a second, audit-layer denial of a request the access graph already
/// allowed. Best-effort, deliberately swallowing the error.
fn record_anomaly(
    state: &BrokerState,
    scope: &crate::scope::BrokerScope,
    actor: &str,
    anomaly: &Anomaly,
    now: i64,
) {
    let Ok(root_key) = state.reauth_root_key("audit: anomaly") else {
        return;
    };
    let event = scrubbed(credmgr_store::audit::NewEvent {
        actor: actor.to_string(),
        action: audit_action_for(anomaly.kind).to_string(),
        node_id: Some(scope.node_id.clone()),
        entry_id: None,
        decision: None,
        detail: Some(anomaly.detail.clone()),
        generation: None,
    });
    let year_month = credmgr_store::audit::year_month_for(now);
    let _ = credmgr_store::audit::append(
        &state.paths,
        root_key.expose_secret(),
        &year_month,
        event,
        now,
    );
}

/// The same short, static discriminant `to_wire`'s `"error"` field uses —
/// reusing that vocabulary rather than a fresh one keeps a caller's audit
/// trail and its own error responses telling the same story. Exhaustively
/// matched so a new `OpError` variant is a compile error here, not a
/// silently-generic audit line — the same guarantee `audit_action_for` gives
/// `AnomalyKind` above.
pub(crate) fn error_tag(err: &OpError) -> &'static str {
    match err {
        OpError::NodeAccessDenied { .. } => "node_access_denied",
        OpError::TwoFactorRequired { .. } => "two_factor_required",
        OpError::ApprovalPending { .. } => "approval_pending",
        OpError::Conflict { .. } => "conflict",
        OpError::VaultLocked => "vault_locked",
        OpError::NodeLocked { .. } => "node_locked",
        OpError::WrongPassphrase => "wrong_passphrase",
        OpError::Malformed(_) => "malformed_request",
        OpError::CapabilityNotHeld { .. } => "capability_not_held",
        OpError::NotFound(_) => "not_found",
        OpError::EntryExists { .. } => "entry_exists",
        OpError::Internal(_) => "internal",
        OpError::PresenceRequired { .. } => "presence_required",
        OpError::PresenceFailed { .. } => "presence_failed",
        OpError::ArchiveExpired { .. } => "archive_expired",
        OpError::ApprovalDenied { .. } => "approval_denied",
        OpError::RateLimited { .. } => "rate_limited",
        OpError::GateVerificationFailed => "gate_verification_failed",
        OpError::GateNotEnrolling => "gate_not_enrolling",
        OpError::EntryRemovalExpired { .. } => "entry_removal_expired",
        OpError::NotUndoable { .. } => "not_undoable",
        OpError::VaultAlreadyInitialized => "vault_already_initialized",
        OpError::VaultInsideGitWorkingTree => "vault_inside_git_working_tree",
        OpError::VaultInitNotPending => "vault_init_not_pending",
        OpError::RecoveryCodeMismatch => "recovery_code_mismatch",
        OpError::SessionExpired => "session_expired",
        OpError::ConfirmationRequired { .. } => "confirmation_required",
        OpError::MachineLockRefused { .. } => "machine_lock_refused",
    }
}

/// The most field ids one audit line lists before it says `+N more`.
const AUDIT_FIELD_IDS_MAX: usize = 32;

/// Whether `s` is shaped like a field id the broker mints: `f_` + 8 lowercase
/// hex digits. Only a string of exactly this shape is ever copied into an audit
/// line, so whatever else a caller put in a `field` / `fieldIds` param — a
/// label, a value, anything — can never be written to the log (ADR-078).
fn is_field_id_shaped(s: &str) -> bool {
    credmgr_core::fields::is_valid_field_id(s)
}

/// ADR-078: the audit detail of an **allowed** call that addresses fields — the
/// ids it named and nothing else. `params.field` (one id: `entry.update`,
/// `entry.rotate`, `field.update`, `field.remove`, `totp.code`, `totp.seed`)
/// gives `field: f_…`; `params.fieldIds` (`entry.reveal`) gives
/// `fields: f_…,f_…`, at most [`AUDIT_FIELD_IDS_MAX`] of them and then
/// `+N more`.
///
/// **A label or a value never reaches this function's output**: `params.fields`
/// (the objects that carry them), `params.patch` and `params.value` are not
/// read at all, and an id-shaped test gates the two keys that are. A
/// `fieldIds` array with any element that is not id-shaped contributes
/// nothing — a request that sends a label there is malformed and refused, and
/// the log does not preserve what it sent.
fn field_audit_detail(params: &serde_json::Value) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(id) = params
        .get("field")
        .and_then(|v| v.as_str())
        .filter(|s| is_field_id_shaped(s))
    {
        parts.push(format!("field: {id}"));
    }
    if let Some(ids) = params.get("fieldIds").and_then(|v| v.as_array()) {
        let shaped: Option<Vec<&str>> = ids
            .iter()
            .map(|v| v.as_str().filter(|s| is_field_id_shaped(s)))
            .collect();
        if let Some(shaped) = shaped.filter(|s| !s.is_empty()) {
            let shown: Vec<&str> = shaped.iter().take(AUDIT_FIELD_IDS_MAX).copied().collect();
            let mut line = format!("fields: {}", shown.join(","));
            if shaped.len() > AUDIT_FIELD_IDS_MAX {
                line.push_str(&format!(" +{} more", shaped.len() - AUDIT_FIELD_IDS_MAX));
            }
            parts.push(line);
        }
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// `a_` and 16 lower-case hex digits: an agent token's public id. Anything else a caller sent as `params.id` stays out
/// of the log.
fn is_agent_public_id_shaped(s: &str) -> bool {
    s.len() == 18
        && s.starts_with("a_")
        && s[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `10_API_AND_MCP.md §1`: "every decision, allow or deny, appends one audit
/// record and returns its id, so a caller can cite exactly what it did."
/// Generic and op-agnostic by design — one call site here covers every
/// dispatched op, rather than every match arm in `ops::dispatch` remembering
/// to log itself. `node_id` prefers the request's own `params.node` (the
/// entry/target this call actually concerns) and falls back to the caller's
/// own scope for ops with no node param at all (`whoami`, `vault.unlock`) —
/// either way it names a node the record's own actor can already resolve
/// back to itself, so no record is orphaned outside every reader's own
/// reachable set (`node.list`/`graph.snapshot`'s own visibility filter,
/// reused by `audit.tail`). Best-effort for the same reason `record_anomaly`
/// is: a locked vault (no root key) must not turn logging failure into a
/// second denial of a request the access graph already decided.
fn record_decision(
    state: &BrokerState,
    scope: &crate::scope::BrokerScope,
    actor: &str,
    now: i64,
    op: &str,
    params: &serde_json::Value,
    result: &Result<serde_json::Value, OpError>,
) -> Option<String> {
    let root_key = state.reauth_root_key("audit: decision").ok()?;
    flush_unaudited_recoveries(state, root_key.expose_secret());
    // ADR-164 review P2-2: rotate and revoke name a token, not a node; the record goes under the token's own node.
    let node_id = params
        .get("node")
        .and_then(|v| v.as_str())
        .or_else(|| {
            op.starts_with("agent.token_")
                .then(|| {
                    result
                        .as_ref()
                        .ok()
                        .and_then(|v| v.get("node"))
                        .and_then(|v| v.as_str())
                })
                .flatten()
        })
        .map(str::to_string)
        .unwrap_or_else(|| scope.node_id.clone());
    // ADR-055: generic and additive, the same "one call site, not every
    // dispatch arm" reasoning ADR-049 already applied to `node_id` — an op
    // whose params/response carry neither field simply leaves both `None`.
    // ADR-156: an op that creates an entry names it only in its answer (`entry.create`), so an allowed
    // record falls back to the answer's `entry` - `entry.history` then starts at the creation.
    let entry_id = params
        .get("entry")
        .and_then(|v| v.as_str())
        .or_else(|| {
            result
                .as_ref()
                .ok()
                .and_then(|v| v.get("entry"))
                .and_then(|v| v.as_str())
        })
        .map(str::to_string);
    let generation = result
        .as_ref()
        .ok()
        .and_then(|v| v.get("generation"))
        .and_then(|g| g.as_u64());
    let event = scrubbed(credmgr_store::audit::NewEvent {
        actor: actor.to_string(),
        action: op.to_string(),
        node_id: Some(node_id),
        entry_id,
        decision: Some(if result.is_ok() { "allow" } else { "deny" }.to_string()),
        // A denial records its error tag; an allowed op that carries a
        // human-written `reason` (ADR-071: `node.policy`) records that, and one
        // that addresses fields records their ids — never a label or a value
        // (ADR-078, `field_audit_detail`).
        detail: match result {
            // ADR-164 review P2-2: a refused rotate or revoke still names the token it was about.
            Err(e) if op.starts_with("agent.token_") => {
                let tag = error_tag(e).to_string();
                match params
                    .get("id")
                    .and_then(|v| v.as_str())
                    .filter(|id| is_agent_public_id_shaped(id))
                {
                    Some(id) => Some(format!("{tag}; token {id}")),
                    None => Some(tag),
                }
            }
            Err(e) => Some(error_tag(e).to_string()),
            Ok(answer) if op.starts_with("agent.token_") && op != "agent.token_status" => {
                crate::ops::agent_token_audit_detail(op, answer)
            }
            Ok(_) => {
                let reason = params
                    .get("reason")
                    .and_then(|r| r.as_str())
                    .map(|r| format!("reason: {}", r.chars().take(500).collect::<String>()));
                match (reason, field_audit_detail(params)) {
                    (Some(r), Some(f)) => Some(format!("{r}; {f}")),
                    (Some(r), None) => Some(r),
                    (None, f) => f,
                }
            }
        },
        generation,
    });
    let year_month = credmgr_store::audit::year_month_for(now);
    credmgr_store::audit::append(
        &state.paths,
        root_key.expose_secret(),
        &year_month,
        event,
        now,
    )
    .ok()
    .map(|record| record.id)
}

/// ADR-122: an extra audit record for one item of an op that does many writes in
/// one request (`entry.import_env`), so each write is on the trail by itself and
/// `entry.undo`-style lookups by entry id find it. Same actor, same file, same
/// best-effort rule as [`record_decision`]; `detail` is a fixed word chosen by the
/// op, never anything a caller typed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_item_event(
    state: &BrokerState,
    scope: &crate::scope::BrokerScope,
    now: i64,
    action: &str,
    node_id: &str,
    entry_id: &str,
    generation: Option<u64>,
    detail: &str,
) -> Option<String> {
    let root_key = state.reauth_root_key("audit: item").ok()?;
    let event = scrubbed(credmgr_store::audit::NewEvent {
        actor: audit_actor(state, scope),
        action: action.to_string(),
        node_id: Some(node_id.to_string()),
        entry_id: Some(entry_id.to_string()),
        decision: Some("allow".to_string()),
        detail: Some(detail.to_string()),
        generation,
    });
    let year_month = credmgr_store::audit::year_month_for(now);
    credmgr_store::audit::append(
        &state.paths,
        root_key.expose_secret(),
        &year_month,
        event,
        now,
    )
    .ok()
    .map(|record| record.id)
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_secs() as i64
}

/// `02 §3` point 1, as a standalone predicate so it's testable without a
/// real second-uid process (which a local test harness cannot spawn without
/// root): the owning uid is a parameter, not read from the live process.
pub fn peer_is_owner(peer: &PeerInfo, owning_uid: u32) -> bool {
    peer.uid == owning_uid
}

/// Handle exactly one connection to completion — the peer-uid gate, then a
/// request/response loop until EOF or a framing error. Split out from
/// [`run`] so tests can drive it directly against a `UnixStream` pair
/// without a listener thread.
pub fn serve_connection(state: &Arc<BrokerState>, stream: UnixStream) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    let peer_info = match peer::identify_peer(fd) {
        Ok(p) => p,
        Err(_) => {
            // cannot identify the peer — refuse silently, close.
            crate::diag_log::event(
                "peer",
                &[("result", crate::diag_log::Value::Str("unidentified"))],
            );
            return Ok(());
        }
    };
    if !peer_is_owner(&peer_info, peer::owning_uid()) {
        crate::diag_log::event(
            "peer",
            &[("result", crate::diag_log::Value::Str("not_owner"))],
        );
        // "connection closed before the first frame is read" (10 §1).
        return Ok(());
    }

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    // K-10 (a), ADR-156: one request line is read under a cap, and the bytes
    // (which carry values and passphrases) are wiped before the buffer is reused.
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    loop {
        bytes.zeroize();
        bytes.clear();
        match read_request_line(&mut reader, &mut bytes, REQUEST_LINE_MAX)? {
            LineRead::Eof => return Ok(()),
            LineRead::TooLong => {
                crate::diag_log::event(
                    "frame",
                    &[("error", crate::diag_log::Value::Str("too_long"))],
                );
                let body = protocol::to_wire(
                    "?",
                    &Err(OpError::Malformed(format!(
                        "a request line is at most {} MiB; this connection is closed",
                        REQUEST_LINE_MAX / (1024 * 1024)
                    ))),
                );
                writeln!(writer, "{body}")?;
                // The rest of the oversized line cannot be framed again.
                return Ok(());
            }
            LineRead::Line => {}
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            crate::diag_log::event(
                "frame",
                &[("error", crate::diag_log::Value::Str("not_utf8"))],
            );
            let body = protocol::to_wire(
                "?",
                &Err(OpError::Malformed("a request line is UTF-8 JSON".into())),
            );
            writeln!(writer, "{body}")?;
            continue;
        };
        let trimmed = text.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        let mut request: Request = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                crate::diag_log::event(
                    "frame",
                    &[("error", crate::diag_log::Value::Str("not_json"))],
                );
                let body = protocol::to_wire("?", &Err(OpError::Malformed(e.to_string())));
                writeln!(writer, "{body}")?;
                continue;
            }
        };
        let (response_body, audit_id) = handle_request(state, &peer_info, &request);
        let mut wire = protocol::to_wire(&request.id, &response_body);
        // K-23 (b), ADR-156: the parsed request held passphrases and values as
        // plain strings; wipe them before they are freed.
        protocol::wipe_strings(&mut request.params);
        if let Some(token) = request.token.as_mut() {
            token.zeroize();
        }
        // `10_API_AND_MCP.md §1`: "returns its id, so a caller can cite
        // exactly what it did" — best-effort (`record_decision` itself, e.g.
        // a locked vault), so a caller that gets no `audit` field learned
        // nothing false, just less than it could have.
        if let Some(id) = &audit_id {
            wire["audit"] = serde_json::Value::String(id.clone());
        }
        writeln!(writer, "{wire}")?;
        // ADR-164 review P2-5: the answer can hold a secret (a new agent bearer, a revealed value); wipe the copies
        // this function owns once written. The writer's and the kernel's buffers are out of reach (K-10).
        protocol::wipe_strings(&mut wire);
        let mut response_body = response_body;
        if let Ok(v) = response_body.as_mut() {
            protocol::wipe_strings(v);
        }
    }
}

/// K-10 (a), ADR-156: the most bytes one request line may hold, newline
/// included. Twice the 64 MiB `entry.create_batch` limit, so a full batch
/// still fits after JSON escaping of ordinary text; a batch whose values are
/// mostly escaped characters may be refused here before its own check.
pub const REQUEST_LINE_MAX: usize = 128 * 1024 * 1024;

/// What [`read_request_line`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum LineRead {
    /// End of stream before any byte of a new line.
    Eof,
    /// One line (or a final unterminated one) is in the buffer.
    Line,
    /// More than `limit` bytes arrived without a newline; the buffer holds a
    /// prefix only and the stream cannot be framed again.
    TooLong,
}

/// Read one newline-terminated line into `buf`, never holding more than
/// `limit + 1` bytes of it. `pub` so the limit can be tested small.
pub fn read_request_line<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    limit: usize,
) -> io::Result<LineRead> {
    let n = reader
        .by_ref()
        .take(limit as u64 + 1)
        .read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(LineRead::Eof);
    }
    if buf.len() > limit && buf.last() != Some(&b'\n') {
        return Ok(LineRead::TooLong);
    }
    Ok(LineRead::Line)
}

/// `pub` (not just crate-private) so the isolation suite can drive the real
/// scope-resolution → dispatch → rate-limit wiring without a socket. Returns
/// the audit record id alongside the op result — a second return value
/// rather than folding it into `OpResult` itself, because `OpError` is a
/// closed, exhaustively-matched enum every test in this workspace already
/// matches directly (`matches!(err, OpError::NodeAccessDenied { .. })`);
/// adding a field to every variant just to carry one incidental id would
/// touch every such assertion for no benefit to what they're actually
/// testing.
pub fn handle_request(
    state: &Arc<BrokerState>,
    peer_info: &PeerInfo,
    request: &Request,
) -> (Result<serde_json::Value, OpError>, Option<String>) {
    handle_request_at(state, peer_info, request, now_epoch(), Instant::now())
}

/// ADR-068: ops a request may still make with a dead token — reporting
/// state, logging in again, bootstrapping, and locking. Everything else
/// answers `session_expired`.
const TOKENLESS_OK_OPS: &[&str] = &[
    "vault.status",
    "vault.unlock",
    "vault.gate_verify",
    "vault.gate_recover",
    // ADR-163: the forgotten-passphrase way in is, like the unlock, made by someone with no live login.
    "vault.recover",
    "vault.init_begin",
    "vault.init_confirm",
    "vault.lock",
];

/// Same wiring as `handle_request`, with both of its clocks taken as
/// parameters instead of stamped fresh. A seam for
/// `phase5_gate.rs::item2_failed_gate_attempts_back_off_and_share_the_
/// passphrase_counter`, the only test in this workspace that exercises
/// `AuthBackoff`'s 30-second lockout through this function: that mechanism
/// is keyed on `std::time::Instant`, a clock `ops::dispatch` never touches
/// (only `handle_request` wires it), so the fixed-epoch-`now` pattern the
/// rest of this file's tests use for TOTP timing doesn't reach it. The
/// original test called `Instant::now()` twice — once via `record_failure`
/// on the 5th consecutive failure, once via the next call's
/// `remaining_lockout` check — and raced OS scheduling between them: under
/// CPU contention the thread could be descheduled for longer than the 30s
/// window itself, making the lockout appear to have already expired
/// (`PROJECT_MAP.md §5.10`). Passing one fixed `Instant`, read once and
/// reused for every call, makes the decision race-free without weakening
/// what the test exercises — everything below is identical to
/// `handle_request`.
pub fn handle_request_at(
    state: &Arc<BrokerState>,
    peer_info: &PeerInfo,
    request: &Request,
    now: i64,
    clock: Instant,
) -> (Result<serde_json::Value, OpError>, Option<String>) {
    // ADR-076: every request holds the barrier for its whole life — the audit
    // record it writes at the end included. A root-key rotation holds it alone,
    // so nothing can be signed under the old root key between the rotation's
    // plan and its switch, and the rotation's own audit record is written
    // under the new one. Every request starts shared; a rotation is upgraded to
    // exclusive below, only once the caller has passed the cheap checks.
    // ADR-159: timed for the diagnostic log only; `clock` above stays the caller's fixed instant.
    let started = Instant::now();
    let mut _barrier = state.request_barrier(false);
    let (scope, anomaly) = scope::resolve_scope_at(
        &state.registry.read().expect("registry poisoned"),
        &state.tokens,
        peer_info,
        request.token.as_deref(),
        now,
    );
    // ADR-077: named once, before dispatch, from the session's public id —
    // never from the bearer (see `audit_actor`).
    let actor = match dead_agent_actor(state, &scope, request.token.as_deref()) {
        Some(dead) => dead,
        None => audit_actor(state, &scope),
    };
    if let Some(anomaly) = &anomaly {
        record_anomaly(state, &scope, &actor, anomaly, now);
    }

    // ADR-043: every request is activity, for both the vault-wide idle clock
    // and this request's own node's timer — touched before dispatch so even
    // a denied request (still a live human/agent doing something) resets
    // the clock, not just successful ones.
    //
    // ADR-090: except a token-less look at `vault.status` or `vault.approval_get`. A Lock screen asks both
    // every five seconds, and a vault another client unlocked must still go idle: a question nobody is
    // logged in to ask is not use of the vault.
    let passive = request.token.is_none()
        && matches!(request.op.as_str(), "vault.status" | "vault.approval_get");
    if !passive {
        state.touch_activity(&scope.node_id, now);
    }
    // ADR-065 (review L6): a live login session keeps its own idle clock, so
    // an owner token nobody is using expires even while agents keep the
    // vault busy.
    if state.is_owner_session(&scope) || state.is_project_login(&scope) {
        if let Some(token) = scope.token_id.as_deref() {
            state.touch_session(token, now);
        }
    }

    // ADR-044: `vault.unlock` is gated on the auth-failure backoff *before*
    // ever touching the keystore — an unnecessary Argon2id hash is exactly
    // the CPU cost a lockout should avoid. `vault.gate_verify` shares the
    // same uid-keyed check (`07 §5`: "shared counter with the passphrase
    // path so an attacker cannot alternate") — this is that promise kept,
    // not a new mechanism.
    // ADR-064: `vault.gate_recover` takes the passphrase and the root
    // recovery code — the same brute-force surface as unlock, so the same
    // per-uid backoff.
    // ADR-076: `maintenance.rotate_root` takes the passphrase and answers
    // `wrong_passphrase` — a passphrase-guessing oracle for anyone holding a
    // session token (K-6), so it shares the same per-uid backoff.
    // ADR-088: a decision made with the unlock factors guesses the same
    // passphrase and code `vault.unlock` does, so it shares the same backoff.
    let is_auth_path = request.op == "vault.unlock"
        || request.op == "vault.gate_verify"
        || request.op == "vault.gate_recover"
        // ADR-163: the recovery-code unlock guesses at a code and a second factor; same counter, so an attacker
        // cannot spend five guesses on each door in turn.
        || request.op == "vault.recover"
        || request.op == "maintenance.rotate_root"
        // ADR-156: a passphrase change proves the current passphrase the same way.
        || request.op == "vault.set_passphrase"
        // ADR-135: a node's own code is guessed at exactly like the vault's, and shares the backoff.
        || request.op == "node.gate_verify"
        || request.op == "node.gate_remove"
        // ADR-150: `session.confirm` with a passphrase guesses the vault passphrase from inside a login; the
        // Touch ID form is held back by the same lockout so a locked-out uid cannot confirm at all.
        || request.op == "session.confirm"
        // ADR-165 (review P1-1, P2-4): turning the machine lock on proves the passphrase and the recovery code;
        // turning it off proves the passphrase when it is sent. Both guess at what `vault.unlock` guards.
        // Review N1: only the bind's `prepare` proves anything; its `commit` checks the code it just showed
        // this login (a retyping, which guesses at nothing) and `cancel` proves nothing.
        || (request.op == "keystore.bind"
            && request.params.get("phase").and_then(|p| p.as_str()) == Some("prepare"))
        || (request.op == "keystore.unbind" && request.params.get("passphrase").is_some())
        || (request.op == "vault.approval_decide" && request.params.get("passphrase").is_some());
    let locked_out = is_auth_path
        .then(|| state.auth_backoff.remaining_lockout(peer_info.uid, clock))
        .flatten();
    // ADR-068: a token was presented and `resolve_scope` did not find it, so
    // `scope` is the caller's cwd fallback, not the login it believes it
    // holds. Refuse instead of serving the request under that narrower
    // scope — except for the ops that exist to report or re-establish a
    // session, and `vault.lock`, which must always work.
    let dead_token = request.token.is_some()
        && scope.token_id.is_none()
        && !TOKENLESS_OK_OPS.contains(&request.op.as_str());
    // ADR-076 (review P3): a rotation drains every in-flight request and holds
    // off the next, so asking for it must cost something. Only a live login
    // session that is neither backed off nor carrying a dead token gets to stop
    // the world; a token-less peer, an agent, a locked-out uid or a stale token
    // is refused further down while sharing the barrier like any other request.
    // (Whether the session may actually rotate — human, `Admin`, second factor,
    // presence — is `ops.rs`'s decision; this only gates who may *wait*.)
    // ADR-130: `node.rekey` swaps a node's key and rewrites its files; no other request may read an
    // envelope while that happens, so it runs alone the same way.
    // ADR-165: a machine-lock bind or unbind rewrites `root.wrap.pass`, the file every passphrase check reads;
    // it runs alone the same way.
    if (request.op == "maintenance.rotate_root"
        || request.op == "vault.set_passphrase"
        || request.op == "node.rekey"
        // ADR-158: `entry.move` changes two manifests and the files they name; it runs alone too.
        || request.op == "entry.move"
        || request.op == "keystore.bind"
        || request.op == "keystore.unbind"
        // ADR-169: a doctor plan is a run of `entry.move`s; it runs alone for the whole plan.
        || request.op == "vault.doctor_apply")
        && locked_out.is_none()
        && !dead_token
        && state.is_owner_session(&scope)
    {
        drop(_barrier);
        _barrier = state.request_barrier(true);
    }
    // ADR-163: `vault.recover` is a root rotation too, made by someone with no login (the vault is locked, so
    // little is in flight). It waits for the world whenever the uid is not backed off — whether or not the
    // vault looks locked now. Review P2-b: asking `is_locked()` here raced an auto-lock between this check and
    // the dispatch, which would have run the rotation under a shared barrier. An open vault refuses the op at
    // once (`AlreadyUnlocked`), so a caller on one only waits for the requests already in flight.
    if request.op == "vault.recover" && locked_out.is_none() && !dead_token {
        drop(_barrier);
        _barrier = state.request_barrier(true);
    }
    let result = match locked_out {
        Some(remaining) => Err(OpError::RateLimited {
            retry_after_seconds: remaining.as_secs().max(1),
        }),
        None if dead_token => Err(OpError::SessionExpired),
        None => {
            // ADR-148 §P1-5: `_peer` is the server's to fill — a client's value is always removed, and the
            // Touch ID unlock is given the description of the process that is actually asking.
            let params = with_peer_param(&request.op, &request.params, peer_info);
            guard_against_panic(&request.op, || {
                ops::dispatch(state, &scope, now, &request.op, &params)
            })
        }
    };

    if is_auth_path {
        match &result {
            // ADR-150 (review P1): a successful `session.confirm` never resets the counter. Its caller already
            // holds a login; letting a confirm clear the backoff would let that login guess node and vault gate
            // codes without limit by confirming between guesses. It records failures only.
            Ok(_) if request.op == "session.confirm" => {}
            Ok(_) => state.auth_backoff.record_success(peer_info.uid),
            Err(OpError::WrongPassphrase) | Err(OpError::GateVerificationFailed) => {
                state.auth_backoff.record_failure(peer_info.uid, clock);
            }
            // ADR-163: a wrong recovery code is a failed guess. (`recovery_code_mismatch` elsewhere is
            // `vault.init_confirm`'s "you copied it down wrong", which guesses at nothing.)
            Err(OpError::RecoveryCodeMismatch)
                if request.op == "vault.recover" || request.op == "keystore.bind" =>
            {
                state.auth_backoff.record_failure(peer_info.uid, clock);
            }
            // ADR-148 §P1-5: a dismissed or locked-out Touch ID prompt is a failed attempt too. Otherwise a
            // caller could put the prompt in front of the person again and again, for free, until a tired
            // tap lets it through.
            Err(OpError::PresenceFailed {
                operation,
                reason: "cancelled" | "locked_out",
            }) if operation == "vault.unlock" => {
                state.auth_backoff.record_failure(peer_info.uid, clock);
            }
            // ADR-150 (review P3-b): the same for `session.confirm`. Its Touch ID prompt is shown by the client,
            // so the broker sees a failed check as a proof that does not verify (`invalid`); a cancel or lockout
            // reported in its name counts too.
            Err(OpError::PresenceFailed {
                operation,
                reason: "cancelled" | "locked_out" | "invalid",
            }) if operation == "session.confirm" => {
                state.auth_backoff.record_failure(peer_info.uid, clock);
            }
            // `two_factor_required` is neither: the passphrase was correct
            // (factor 1 passed) but authentication is not yet complete, so
            // it must touch the counter in neither direction — resetting it
            // here would let an attacker who already holds the passphrase
            // call `vault.unlock` before every single TOTP guess and never
            // trip the lockout `07 §5`/ADR-044 exist to enforce.
            _ => {}
        }
    }

    if let Err(OpError::NodeAccessDenied { target, .. }) = &result {
        // ADR-156: the trip is no longer thrown away. It counts as an unseen alarm (`vault.status` tells the
        // owner's login) and is written to the audit trail, so the owner can see when it happened.
        if target != &scope.node_id && state.rate_limiter.record_denial(peer_info.uid, clock) {
            record_cross_node_alarm(state, &scope, &actor, target, now);
        }
    }

    let audit_id = record_decision(
        state,
        &scope,
        &actor,
        now,
        &request.op,
        &request.params,
        &result,
    );
    // ADR-159: the op's own label (never the caller's text), `ok` or the static error code, and the time.
    crate::diag_log::request(
        &request.op,
        result.as_ref().map(|_| ()).map_err(error_tag),
        started.elapsed(),
        passive,
    );
    // ADR-163: every recovery attempt reaches the audit trail. One made while the vault is locked has no root
    // key to sign a record with, so it waits in memory (time, actor, outcome; no secret) and the next request
    // that writes a record writes it first.
    if request.op == "vault.recover" && audit_id.is_none() {
        let (decision, reason) = match &result {
            Ok(_) => ("allow", "completion_pending"),
            Err(e) => ("deny", error_tag(e)),
        };
        state.note_unaudited_recovery(crate::state::UnauditedRecovery {
            at: now,
            actor: actor.clone(),
            decision,
            reason,
        });
    }
    (result, audit_id)
}

/// ADR-163: write the recovery attempts that were made while the vault was locked, at the time each was made,
/// before the record that found a root key to sign with. Best effort, like every audit write.
fn flush_unaudited_recoveries(state: &BrokerState, root_key: &[u8; 32]) {
    let (attempts, dropped) = state.take_unaudited_recoveries();
    for attempt in attempts {
        let event = scrubbed(credmgr_store::audit::NewEvent {
            actor: attempt.actor,
            action: "vault.recover".to_string(),
            node_id: Some(credmgr_core::registry::GLOBAL_ID.to_string()),
            entry_id: None,
            decision: Some(attempt.decision.to_string()),
            detail: Some(format!(
                "{}; made while the vault was locked, recorded at the next unlock",
                attempt.reason
            )),
            generation: None,
        });
        let year_month = credmgr_store::audit::year_month_for(attempt.at);
        let _ =
            credmgr_store::audit::append(&state.paths, root_key, &year_month, event, attempt.at);
    }
    if dropped > 0 {
        let now = now_epoch();
        let event = scrubbed(credmgr_store::audit::NewEvent {
            actor: "system:vault.recover".to_string(),
            action: "vault.recover".to_string(),
            node_id: Some(credmgr_core::registry::GLOBAL_ID.to_string()),
            entry_id: None,
            decision: Some("deny".to_string()),
            detail: Some(format!(
                "{dropped} more recovery attempts made while the vault was locked were not itemised"
            )),
            generation: None,
        });
        let year_month = credmgr_store::audit::year_month_for(now);
        let _ = credmgr_store::audit::append(&state.paths, root_key, &year_month, event, now);
    }
}

/// ADR-148 §P1-5: the params `ops::dispatch` sees. [`ops::PEER_PARAM`] is removed from whatever the client sent
/// and, for `vault.unlock`, set to [`crate::peer::describe`] of the connecting process — the requester named
/// in the Touch ID dialog. Every other op's params are passed through unchanged (no copy when there is
/// nothing to remove).
fn with_peer_param<'a>(
    op: &str,
    params: &'a serde_json::Value,
    peer_info: &PeerInfo,
) -> std::borrow::Cow<'a, serde_json::Value> {
    let carries = params.get(ops::PEER_PARAM).is_some();
    if op != "vault.unlock" && !carries {
        return std::borrow::Cow::Borrowed(params);
    }
    let mut owned = params.clone();
    if let Some(map) = owned.as_object_mut() {
        map.remove(ops::PEER_PARAM);
        if op == "vault.unlock" {
            map.insert(
                ops::PEER_PARAM.to_string(),
                serde_json::Value::String(crate::peer::describe(peer_info)),
            );
        }
    }
    std::borrow::Cow::Owned(owned)
}

/// ADR-077 (MX-1): one op that panics must not take its caller's connection
/// down with no answer at all. The connection thread used to die mid-request —
/// the client saw a closed socket, the audit log recorded nothing, and (had the
/// panic happened under a lock) the rest of the daemon would have followed it.
/// A panic inside an op is now answered as a typed `internal` refusal, and the
/// request is audited like any other denial. The panic itself is **not**
/// swallowed: the default hook has already written it, with its location, to
/// the daemon's log before this returns, so it stays loud.
///
/// This is a safety net, not a licence — the panic MX-1 found is fixed at its
/// source (`credmgr_core::totp`). `AssertUnwindSafe` is sound because the
/// broker's shared state sits behind `std` locks, which poison when a panic
/// unwinds through a held guard: every later use of that lock then fails
/// loudly at its `expect("… poisoned")` instead of reading a half-written
/// value. Catching the panic changes what the *caller* is told, not what the
/// state allows. (MX-1 itself panicked with no lock held, so nothing was
/// poisoned and the daemon carried on.)
fn guard_against_panic(
    op: &str,
    run: impl FnOnce() -> Result<serde_json::Value, OpError>,
) -> Result<serde_json::Value, OpError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).unwrap_or_else(|_| {
        Err(OpError::Internal(format!(
            "{op} failed unexpectedly; the broker logged the cause"
        )))
    })
}

/// How often the auto-lock ticker checks idle thresholds (ADR-043) — well
/// under the 5-minute critical-node floor (ADR-030), so a timer never
/// overshoots by more than this.
const AUTOLOCK_TICK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// `10 §1.1`: the socket lives in a `0700` folder. `atomic::ensure_dir` sets that mode only on a folder it
/// creates, so a `run/` folder that already existed with a looser mode kept it (wiring audit 2026-11-20). The
/// folder is tightened here, before anything binds in it; a folder this process cannot change refuses the start.
pub fn secure_socket_dir(socket_path: &Path) -> io::Result<()> {
    match socket_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => {
            std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        }
        _ => Ok(()),
    }
}

/// Bind and serve forever, one OS thread per connection. `run/` must already
/// exist (Phase 2's `atomic::ensure_dir` creates it); [`secure_socket_dir`]
/// makes it `0700` whatever mode it had, and the socket is `0600` right after
/// the bind.
pub fn run(state: Arc<BrokerState>, socket_path: &Path) -> io::Result<()> {
    if socket_path.exists() {
        // Review M4: a socket that still answers belongs to a live broker for
        // this vault. Two brokers over one vault would each write it through
        // from their own view and overwrite one another — refuse to start
        // rather than steal the socket. Only a dead socket is replaced.
        if std::os::unix::net::UnixStream::connect(socket_path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "another credmgrd is already serving {} — stop it first",
                    socket_path.display()
                ),
            ));
        }
        std::fs::remove_file(socket_path)?;
    }
    secure_socket_dir(socket_path)?;
    let listener = UnixListener::bind(socket_path)?;
    // `0600`, owner-only (`02 §2`).
    std::fs::set_permissions(
        socket_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;

    // ADR-043's idle half of auto-lock — the sleep/screen-lock/session-end
    // half has no timer at all, it's `BrokerState::external_lock_signal`,
    // called directly by whatever native code observes those events.
    let autolock_state = Arc::clone(&state);
    std::thread::spawn(move || loop {
        std::thread::sleep(AUTOLOCK_TICK_INTERVAL);
        autolock_state.tick_autolock(now_epoch());
    });

    for incoming in listener.incoming() {
        let stream = incoming?;
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let _ = serve_connection(&state, stream);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_line_over_the_limit_is_cut_off_and_one_at_the_limit_is_read() {
        let mut buf = Vec::new();
        let mut at_limit = io::Cursor::new(b"0123456\nnext\n".to_vec());
        assert_eq!(
            read_request_line(&mut at_limit, &mut buf, 8).unwrap(),
            LineRead::Line
        );
        assert_eq!(buf, b"0123456\n");
        buf.clear();
        assert_eq!(
            read_request_line(&mut at_limit, &mut buf, 8).unwrap(),
            LineRead::Line
        );
        assert_eq!(buf, b"next\n");
        buf.clear();
        assert_eq!(
            read_request_line(&mut at_limit, &mut buf, 8).unwrap(),
            LineRead::Eof
        );

        let mut over = io::Cursor::new(vec![b'x'; 64]);
        buf.clear();
        assert_eq!(
            read_request_line(&mut over, &mut buf, 8).unwrap(),
            LineRead::TooLong
        );
        assert_eq!(buf.len(), 9, "never more than limit + 1 bytes are held");

        let mut unterminated = io::Cursor::new(b"{}".to_vec());
        buf.clear();
        assert_eq!(
            read_request_line(&mut unterminated, &mut buf, 8).unwrap(),
            LineRead::Line
        );
    }

    /// ADR-077 (MX-1): an op that panics is answered, not propagated. The
    /// panic message still goes to stderr through the default hook (that is how
    /// the endpoint matrix counts panics), so this test prints one on purpose.
    #[test]
    fn an_op_that_panics_is_answered_as_internal_and_a_good_one_is_untouched() {
        let answered = guard_against_panic("totp.code", || panic!("deliberate, from the test"));
        match answered {
            Err(OpError::Internal(message)) => {
                assert!(message.contains("totp.code"), "{message}");
                assert!(
                    !message.contains("deliberate"),
                    "the cause stays in the log"
                );
            }
            other => panic!("expected an internal refusal, got {other:?}"),
        }
        let fine = guard_against_panic("whoami", || Ok(serde_json::json!({ "n": 1 })));
        assert_eq!(fine.unwrap()["n"], 1);
        let refused = guard_against_panic("whoami", || Err(OpError::NotFound("x".into())));
        assert!(matches!(refused, Err(OpError::NotFound(_))));
    }

    // ADR-078: an allowed call that addresses fields records their ids and
    // nothing else.
    #[test]
    fn field_audit_detail_records_ids_only() {
        use serde_json::json;
        assert_eq!(field_audit_detail(&json!({ "node": "a" })), None);
        assert_eq!(
            field_audit_detail(&json!({ "field": "f_0a1b2c3d" })).as_deref(),
            Some("field: f_0a1b2c3d")
        );
        assert_eq!(
            field_audit_detail(&json!({ "fieldIds": ["f_0a1b2c3d", "f_00000000"] })).as_deref(),
            Some("fields: f_0a1b2c3d,f_00000000")
        );
        // Both keys on one call are both recorded.
        assert_eq!(
            field_audit_detail(&json!({ "field": "f_0a1b2c3d", "fieldIds": ["f_11111111"] }))
                .as_deref(),
            Some("field: f_0a1b2c3d; fields: f_11111111")
        );
    }

    #[test]
    fn field_audit_detail_never_copies_anything_that_is_not_an_id() {
        use serde_json::json;
        // A label (or a value) in `field`, or anywhere in `fieldIds`, is not
        // an id: it is dropped, not logged.
        for params in [
            json!({ "field": "marker-label-xyz" }),
            json!({ "field": "F_0A1B2C3D" }),
            json!({ "field": "f_0a1b2c3" }),
            json!({ "field": "f_0a1b2c3d4" }),
            json!({ "field": 7 }),
            json!({ "fieldIds": ["marker-label-xyz"] }),
            json!({ "fieldIds": ["f_0a1b2c3d", "marker-label-xyz"] }),
            json!({ "fieldIds": [] }),
            json!({ "fieldIds": "f_0a1b2c3d" }),
        ] {
            assert_eq!(field_audit_detail(&params), None, "{params}");
        }
        // The objects that carry labels and values are never read.
        let heavy = json!({
            "fields": [{ "label": "marker-label-xyz", "value": "marker-value-xyz" }],
            "patch": { "label": "marker-label-xyz", "value": "marker-value-xyz" },
            "value": "marker-value-xyz", "label": "marker-label-xyz",
            "field": "f_0a1b2c3d",
        });
        let detail = field_audit_detail(&heavy).unwrap();
        assert_eq!(detail, "field: f_0a1b2c3d");
        assert!(!detail.contains("marker"));
    }

    #[test]
    fn field_audit_detail_caps_a_long_id_list() {
        use serde_json::json;
        let ids: Vec<String> = (0..40).map(|i| format!("f_{i:08x}")).collect();
        let detail = field_audit_detail(&json!({ "fieldIds": ids })).unwrap();
        assert!(detail.ends_with(" +8 more"), "{detail}");
        assert!(detail.contains("f_0000001f"), "the 32nd id is listed");
        assert!(!detail.contains("f_00000020"), "the 33rd is not");
    }

    #[test]
    fn peer_uid_gate_rejects_any_non_owning_uid() {
        let peer = PeerInfo {
            uid: 502,
            pid: 1,
            cwd: None,
        };
        assert!(!peer_is_owner(&peer, 501));
        assert!(peer_is_owner(&peer, 502));
    }

    /// Wiring audit 2026-11-20: a `run/` folder that already existed with a looser mode was left as it was,
    /// so the socket did not sit in the `0700` folder `10 §1.1` promises.
    #[test]
    fn a_pre_existing_loose_run_folder_is_made_owner_only_before_the_bind() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let run = dir.path().join("run");
        std::fs::create_dir(&run).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755)).unwrap();
        secure_socket_dir(&run.join("broker.sock")).unwrap();
        let mode = std::fs::metadata(&run).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "run/ is {mode:o}");
    }
}
