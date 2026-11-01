//! The UDS server. Newline-delimited JSON (`10_API_AND_MCP.md §1`), one
//! thread per connection. `02_ARCHITECTURE.md §3`: **every connection is
//! identified before the token is even read** — `LOCAL_PEERCRED` first,
//! hard gate, then the request frame.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
fn error_tag(err: &OpError) -> &'static str {
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
    let node_id = params
        .get("node")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| scope.node_id.clone());
    // ADR-055: generic and additive, the same "one call site, not every
    // dispatch arm" reasoning ADR-049 already applied to `node_id` — an op
    // whose params/response carry neither field simply leaves both `None`.
    let entry_id = params
        .get("entry")
        .and_then(|v| v.as_str())
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
            Err(e) => Some(error_tag(e).to_string()),
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
        Err(_) => return Ok(()), // cannot identify the peer — refuse silently, close.
    };
    if !peer_is_owner(&peer_info, peer::owning_uid()) {
        // "connection closed before the first frame is read" (10 §1).
        return Ok(());
    }

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(()); // EOF
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        let request: Request = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let body = protocol::to_wire("?", &Err(OpError::Malformed(e.to_string())));
                writeln!(writer, "{body}")?;
                continue;
            }
        };
        let (response_body, audit_id) = handle_request(state, &peer_info, &request);
        let mut wire = protocol::to_wire(&request.id, &response_body);
        // `10_API_AND_MCP.md §1`: "returns its id, so a caller can cite
        // exactly what it did" — best-effort (`record_decision` itself, e.g.
        // a locked vault), so a caller that gets no `audit` field learned
        // nothing false, just less than it could have.
        if let Some(id) = &audit_id {
            wire["audit"] = serde_json::Value::String(id.clone());
        }
        writeln!(writer, "{wire}")?;
    }
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
    let mut _barrier = state.request_barrier(false);
    let (scope, anomaly) = scope::resolve_scope(
        &state.registry.read().expect("registry poisoned"),
        &state.tokens,
        peer_info,
        request.token.as_deref(),
    );
    // ADR-077: named once, before dispatch, from the session's public id —
    // never from the bearer (see `audit_actor`).
    let actor = audit_actor(state, &scope);
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
    if state.is_owner_session(&scope) {
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
        || request.op == "maintenance.rotate_root"
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
    if request.op == "maintenance.rotate_root"
        && locked_out.is_none()
        && !dead_token
        && state.is_owner_session(&scope)
    {
        drop(_barrier);
        _barrier = state.request_barrier(true);
    }
    let result = match locked_out {
        Some(remaining) => Err(OpError::RateLimited {
            retry_after_seconds: remaining.as_secs().max(1),
        }),
        None if dead_token => Err(OpError::SessionExpired),
        None => guard_against_panic(&request.op, || {
            ops::dispatch(state, &scope, now, &request.op, &request.params)
        }),
    };

    if is_auth_path {
        match &result {
            Ok(_) => state.auth_backoff.record_success(peer_info.uid),
            Err(OpError::WrongPassphrase) | Err(OpError::GateVerificationFailed) => {
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
        if target != &scope.node_id {
            state.rate_limiter.record_denial(peer_info.uid, clock);
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
    (result, audit_id)
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

/// Bind and serve forever, one OS thread per connection. `~/.credmgr/run/`
/// must already be `0700` and the socket path `0600` on creation — Phase 2's
/// `atomic::` helpers own directory modes; this function only creates the
/// listener itself.
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
}
