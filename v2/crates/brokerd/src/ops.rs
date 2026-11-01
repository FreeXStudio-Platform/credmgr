//! Operation dispatch — `docs/10_API_AND_MCP.md §1`'s op list, the Phase 3
//! subset. Every op that touches a node goes through
//! `credmgr_core::access::resolve` — **none re-implements authorisation**
//! (`06_ACCESS_GRAPH.md`'s opening line, and the whole point of ADR-001).
//!
//! **Phase 3 scope note.** What ships here covers `entry.create`/
//! `entry.update` (the pending-tray split, F-1/F-9), `vault.pending_list/
//! accept/discard` (`18_ENDPOINT_INDEX.md`'s op names for the review tray),
//! `vault.node_lock/node_unlock` (F-7, exposing `BrokerState::lock_node`/
//! `unlock_node`, already built), and `node.seal`/`node.restore`/
//! `node.reparent` (F-4/F-8).
//!
//! **`node.seal`/`node.restore`/`node.reparent`'s gate, adapted to what
//! Phase 3 actually has.** `04_CRYPTO_AND_KEYS.md §6`'s key-lifecycle table
//! specs seal as "unlock + 2FA + presence", restore (≤7d) as "unlock + 2FA",
//! and reparent as "unlock + 2FA + presence + reason". Phase 5 builds 2FA;
//! Phase 5 also builds the native shell that can ever set
//! `presence_attested: true` (`resolve_capability`'s own doc, below,
//! explains why it is hardcoded `false` here). Two different Phase-3
//! answers follow from that, both already established by this session's
//! `node_lock`/`node_unlock`:
//! - seal/restore substitute `Capability::Admin` for the missing 2FA factor
//!   (same "the factor Phase 3 actually has" pattern) and do **not** wait on
//!   presence, so they are real and testable now (I-21).
//! - reparent's positive path genuinely needs presence, which cannot exist
//!   on any Phase 3 transport — so it is unconditionally refused today, on
//!   the only surfaces Phase 3 has, which is exactly F-8's stated shape
//!   ("CLI, MCP and non-native UI paths all refuse") (I-23). Nothing about
//!   this dispatch arm needs to change when Phase 5 makes the positive path
//!   reachable — it already checks `presence_attested`, there is just
//!   nowhere yet that can set it `true`.
//!
//! **Multi-field entries (ADR-078).** The Phase 3 simplification that used to be
//! recorded here — one `value: string` per entry — is gone. An entry's plaintext
//! is a field document (`credmgr_core::fields`) sealed as an envelope of version
//! 2; `entry.create`, `entry.update`, `entry.rotate` and the four `field.*` ops
//! write it, `entry.get` reads its metadata, `entry.reveal` and `totp.code` read
//! its values. A version-1 envelope — every entry written up to `2.0.0-alpha.6`
//! — is a legacy single value and is read in place as a one-field document;
//! nothing is migrated and the first write to such an entry re-seals it as
//! version 2. The old single-value call shapes (`value`, `label`) still mean what
//! they always did. The broker never parses the bulk-paste grammar: clients parse
//! with `credmgr_core::parser`, preview, and send the previewed fields verbatim.
//! `entry_doc.rs` holds the broker-side glue; a label or a value never appears in
//! an error message, an audit line or the plaintext manifest.

use std::collections::HashSet;

use rand_core::{OsRng, RngCore};
use secrecy::SecretBox;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use credmgr_core::access::{self, AccessContext, Origin, Target};
use credmgr_core::envelope;
use credmgr_core::fields::{self, EntryDoc, FieldInput, FieldPatch, FieldReplace};
use credmgr_core::inference::{EntryType, Sensitivity};
use credmgr_core::names::{self, canonical_name};
use credmgr_core::registry::{
    validate_node_id, validate_registry, AgentAccess, Capability, Grant, GrantTarget, Node,
    NodeKind, NodePolicy, SiblingVisibility, TwoFactorRequirement, GLOBAL_ID, ORPHAN_ID,
};

use credmgr_store::manifest::ManifestEntry;

use crate::entry_doc::{self, CreateBody, EntryEdit};
use crate::protocol::OpError;
use crate::scope::BrokerScope;
use crate::state::{
    ApprovalDecideError, ApprovalVerdict, BrokerState, GateEnrollError, GateRecoverError,
    GateVerifyError, PendingApproval, PendingEntry, SealedNodeRecord, UnlockError,
    VaultInitConfirmError, VaultInitError, GATE_SCOPE_VAULT,
};

/// ADR-072: the reserved envelope id a node's note is sealed under — never an
/// entry id (those are `e_` + hex), so a note and an entry can never be
/// swapped for one another, and the node id in the AAD keeps a note from being
/// moved to another node (`03_DATA_MODEL.md §4`).
const NOTE_ENVELOPE_ID: &str = "notes";
/// ADR-073: the most entries one `entry.create_batch` call may create.
const BATCH_MAX: usize = 500;
/// A note is context, not a document store: 64 KiB of markdown.
const NOTE_MAX_BYTES: usize = 64 * 1024;

/// ADR-084: whether `name` is already taken, comparing canonical forms (case,
/// NFKC, bidi/zero-width controls and look-alike letters folded) — never the
/// bytes the person typed. `canon` is `canonical_name(name)`, computed once.
fn canon_taken<'a>(canon: &str, mut existing: impl Iterator<Item = &'a str>) -> bool {
    existing.any(|n| canonical_name(n) == canon)
}

/// ADR-084: the reply's additive `warnings` list for a name that mixes Latin
/// with Greek or Cyrillic — accepted, never refused. Absent when there is none.
fn name_warnings(body: &mut Value, names_typed: &[&str]) {
    if names_typed.iter().any(|n| names::mixes_scripts(n)) {
        body["warnings"] = json!([names::WARN_MIXED_SCRIPT]);
    }
}

/// ADR-083: an entry count below this is hidden too, from a reader who may not
/// see names — a one- or two-entry node would otherwise reveal its size.
const PRIVATE_COUNT_FLOOR: u64 = 3;

/// ADR-083: `privateNames` hides names from everyone except the vault owner's
/// login session — agents, MCP and grantees alike. Decided once here and asked
/// by every surface that would put a node label, entry name or note on the
/// wire, so the rule cannot drift between them.
fn hides_names(state: &BrokerState, scope: &BrokerScope, private_names: bool) -> bool {
    private_names && !state.is_owner_session(scope)
}

fn node_hides_names(state: &BrokerState, scope: &BrokerScope, node_id: &str) -> bool {
    let private = state
        .registry
        .read()
        .expect("registry poisoned")
        .nodes
        .get(node_id)
        .is_some_and(|n| n.policy.private_names);
    hides_names(state, scope, private)
}

/// ADR-090: one waiting approval request as `vault.approval_get` describes it.
///
/// Names come from the node registry and the manifest that are already in memory
/// — nothing is decrypted and no key is touched, so this works on a locked vault
/// exactly as it does on an unlocked one. A node with `privateNames` has its
/// label and its entry's name withheld from everyone but the owner's login
/// session (ADR-083); on a locked vault nobody is that session, so they are
/// withheld there. A name that simply is not in memory is `null`, not an error.
/// The requester's directory is the owner's to see and no one else's.
fn approval_view(state: &BrokerState, a: &PendingApproval, owner: bool, now: i64) -> Value {
    let (label, private) = {
        let registry = state.registry.read().expect("registry poisoned");
        match registry.nodes.get(&a.node_id) {
            Some(n) => (Some(n.label.clone()), n.policy.private_names),
            None => (None, false),
        }
    };
    // The caller decided `owner` once with `is_owner_session`, the same test
    // `hides_names` applies.
    let hidden = private && !owner;
    let entry_name = manifest_entry(state, &a.node_id, &a.entry_id).map(|e| e.name);
    let mut view = json!({
        "request": a.id,
        "node": a.node_id,
        "entry": a.entry_id,
        "nodeLabel": if hidden { Value::Null } else { json!(label) },
        "entryName": if hidden { Value::Null } else { json!(entry_name) },
        "command": "entry.reveal",
        "state": match a.decision {
            None => "pending",
            Some(true) => "approved",
            Some(false) => "denied",
        },
        "expiresIn": (a.expires_at - now).max(0),
        "requestedAt": a.created,
    });
    if hidden {
        view["nameHidden"] = json!(true);
    }
    if owner {
        view["cwd"] = json!(a.cwd);
    }
    view
}

/// ADR-083: the count a name-blind reader may see — `None` below the floor.
fn visible_count(n: u64) -> Option<u64> {
    (n >= PRIVATE_COUNT_FLOOR).then_some(n)
}

/// What a `requireTwoFactor` check protects (ADR-085): a **value** leaving the
/// vault, or any **read** of the node.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GateKind {
    Reveal,
    Read,
}

/// ADR-085 (4.3): `requireTwoFactor` on a node, enforced. `never` asks for
/// nothing; `reveal` (the default) asks before a value is released; `always`
/// also asks before any read of the node. Asked only when the vault's gate is
/// confirmed (with no second factor enrolled there is nothing to ask for, and a
/// refusal would lock the owner out). Satisfied by the owner's own login (it
/// passed the gate to exist) or by a live elevation — a fresh `vault.gate_verify`
/// within the window. Otherwise `two_factor_required`.
fn second_factor_gate(
    state: &BrokerState,
    scope: &BrokerScope,
    node_id: &str,
    kind: GateKind,
    now: i64,
) -> Result<(), OpError> {
    let level = state
        .registry
        .read()
        .expect("registry poisoned")
        .nodes
        .get(node_id)
        .map(|n| n.policy.require_two_factor);
    let asks = match level {
        Some(TwoFactorRequirement::Always) => true,
        Some(TwoFactorRequirement::Reveal) => kind == GateKind::Reveal,
        _ => false,
    };
    if !asks
        || !state.is_gate_confirmed(GATE_SCOPE_VAULT)
        || state.is_owner_session(scope)
        || state.is_elevated(GATE_SCOPE_VAULT, now)
    {
        return Ok(());
    }
    Err(OpError::TwoFactorRequired {
        challenge: "totp".to_string(),
        scope: GATE_SCOPE_VAULT.to_string(),
        expires_in: u32::try_from(state.elevation_seconds()).unwrap_or(300),
    })
}

/// The `notes` capability gate — held as a ceiling and resolved against the
/// node. `03 §4`: separate from `read`, never implied by it.
fn notes_gate(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    now: i64,
) -> Result<(), OpError> {
    if !scope.holds(Capability::Notes) {
        return Err(OpError::CapabilityNotHeld {
            capability: Capability::Notes,
        });
    }
    let decision = resolve_capability(state, scope, target_node, Capability::Notes, now);
    if !decision.is_allow() {
        return Err(access_denied_error(
            state,
            scope,
            target_node,
            Capability::Notes,
            rule_name(decision),
            now,
        ));
    }
    Ok(())
}

/// ADR-071: a node label a human reads — trimmed, 1–120 characters, no
/// control characters. The id never changes; only the label does.
const NODE_LABEL_MAX: usize = 120;

/// ADR-092 (B-batch 2): an entry name a human reads is at most this many
/// characters (the same bound a field label has). `canonical_name` folds the whole
/// string and the comparison runs it against every name in the node, so an
/// unbounded name is an unbounded amount of work for one request.
const ENTRY_NAME_MAX: usize = 200;

/// The check every route that takes a NEW entry name shares. It counts characters,
/// never reads past the cap (a megabyte of text is not walked to be refused) and
/// names the bound, not the text.
fn valid_entry_name(raw: &str, what: &str) -> Result<(), OpError> {
    if raw.chars().take(ENTRY_NAME_MAX + 1).count() > ENTRY_NAME_MAX {
        return Err(OpError::Malformed(format!(
            "{what} is at most {ENTRY_NAME_MAX} characters"
        )));
    }
    Ok(())
}

fn valid_node_label(raw: &str) -> Result<String, OpError> {
    let label = raw.trim();
    if label.is_empty()
        || label.chars().count() > NODE_LABEL_MAX
        || label.chars().any(char::is_control)
    {
        return Err(OpError::Malformed(format!(
            "label must be 1–{NODE_LABEL_MAX} characters with no control characters"
        )));
    }
    Ok(label.to_string())
}

/// ADR-071: the gate every node-settings edit shares with
/// `node.set_workdirs` — never an agent, `Capability::Admin` held as a
/// ceiling, and `resolve` for `admin` against the node being changed.
fn human_admin_on(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    now: i64,
) -> Result<(), OpError> {
    if scope.origin == Origin::Agent || !scope.holds(Capability::Admin) {
        return Err(OpError::CapabilityNotHeld {
            capability: Capability::Admin,
        });
    }
    let decision = resolve_capability(state, scope, target_node, Capability::Admin, now);
    if !decision.is_allow() {
        return Err(access_denied_error(
            state,
            scope,
            target_node,
            Capability::Admin,
            rule_name(decision),
            now,
        ));
    }
    Ok(())
}

/// `serde`'s default reads an absent field and an explicit `null` the same
/// way; `lockAfterSeconds` needs them apart (absent = unchanged, `null` =
/// clear the per-node timer).
fn present<'de, T, D>(d: D) -> Result<Option<T>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(d).map(Some)
}

/// ADR-071: `node.policy`'s partial patch — every field optional, anything
/// unknown refused, so a typo can never be silently ignored.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyPatch {
    sibling_visibility: Option<SiblingVisibility>,
    descendant_read: Option<bool>,
    require_two_factor: Option<TwoFactorRequirement>,
    #[serde(default, deserialize_with = "present")]
    lock_after_seconds: Option<Option<u32>>,
    private_names: Option<bool>,
    agent_access: Option<AgentAccess>,
}

impl PolicyPatch {
    /// The camelCase names of the fields this patch sets.
    fn fields(&self) -> Vec<&'static str> {
        let mut f = Vec::new();
        if self.sibling_visibility.is_some() {
            f.push("siblingVisibility");
        }
        if self.descendant_read.is_some() {
            f.push("descendantRead");
        }
        if self.require_two_factor.is_some() {
            f.push("requireTwoFactor");
        }
        if self.lock_after_seconds.is_some() {
            f.push("lockAfterSeconds");
        }
        if self.private_names.is_some() {
            f.push("privateNames");
        }
        if self.agent_access.is_some() {
            f.push("agentAccess");
        }
        f
    }

    /// `06_ACCESS_GRAPH.md §10.1`: turning on `descendantRead` (R5) or
    /// making children share (R6) widens who can read what — the same effect
    /// re-parenting has (§6a) — so it needs the full presence gate.
    fn widens_reach(&self, current: &NodePolicy) -> bool {
        (self.descendant_read == Some(true) && !current.descendant_read)
            || (self.sibling_visibility == Some(SiblingVisibility::Shared)
                && current.sibling_visibility == SiblingVisibility::Isolated)
    }

    fn apply(&self, policy: &mut NodePolicy) {
        if let Some(v) = self.sibling_visibility {
            policy.sibling_visibility = v;
        }
        if let Some(v) = self.descendant_read {
            policy.descendant_read = v;
        }
        if let Some(v) = self.require_two_factor {
            policy.require_two_factor = v;
        }
        if let Some(v) = self.lock_after_seconds {
            policy.lock_after_seconds = v;
        }
        if let Some(v) = self.private_names {
            policy.private_names = v;
        }
        if let Some(v) = self.agent_access {
            policy.agent_access = v;
        }
    }
}

/// ADR-066: `params.workdirs` → the canonical, absolute, existing directory
/// paths `03_DATA_MODEL.md §1` requires. Canonicalised with the filesystem
/// because the broker compares them against the kernel's own resolved cwd of
/// the calling process (`peer.rs`) — `/tmp/x` would never match a caller the
/// kernel reports in `/private/tmp/x`. `/` is refused: it would scope every
/// process on the machine to one node. Uniqueness across nodes is left to
/// `validate_registry`, the one place that invariant is already enforced.
fn canonical_workdirs(value: &Value) -> Result<Vec<String>, OpError> {
    let Some(items) = value.as_array() else {
        return Err(OpError::Malformed(
            "params.workdirs must be an array of absolute directory paths".into(),
        ));
    };
    let mut out: Vec<String> = Vec::new();
    for item in items {
        let raw = item.as_str().ok_or_else(|| {
            OpError::Malformed("params.workdirs must contain only strings".into())
        })?;
        let path = std::path::Path::new(raw);
        if !path.is_absolute() {
            return Err(OpError::Malformed(format!(
                "workdir {raw:?} is not absolute"
            )));
        }
        let canonical = std::fs::canonicalize(path)
            .map_err(|e| OpError::Malformed(format!("workdir {raw:?} cannot be resolved: {e}")))?;
        if !canonical.is_dir() {
            return Err(OpError::Malformed(format!(
                "workdir {raw:?} is not a directory"
            )));
        }
        let canonical = canonical.to_string_lossy().into_owned();
        if canonical == "/" {
            return Err(OpError::Malformed(
                "the filesystem root cannot be a workdir — it would scope every process to one node"
                    .into(),
            ));
        }
        // Review L4: the home directory (or anything above it) would scope
        // every project the user has to this one node — refused for the same
        // reason `/` is.
        if let Some(home) = std::env::var_os("HOME").and_then(|h| std::fs::canonicalize(h).ok()) {
            let home = home.to_string_lossy().into_owned();
            if home == canonical || home.starts_with(&format!("{canonical}/")) {
                return Err(OpError::Malformed(format!(
                    "workdir {raw:?} is your home directory or above it — it would scope every \
                     project to one node; bind the project's own directory instead"
                )));
            }
        }
        if !out.contains(&canonical) {
            out.push(canonical);
        }
    }
    Ok(out)
}

/// ADR-065 — the vault owner's reach. A real login session (a token minted
/// by `vault.unlock`/`vault.gate_verify`, ADR-056 — never a fixture's, never
/// an agent's) is evaluated **as the target node itself**. Rules R0 (orphan:
/// native + presence only) and R1 (locked blocks reveal/update) sit before
/// R2 in `resolve()`'s precedence, so both still bind the owner exactly as
/// they bind anyone; what changes is only that "parents do not read their
/// children" (R8 for a global-scoped subject) stops locking the vault's own
/// owner out of their own projects — ADR-047's named "whole vault graph"
/// gap. Every other scope, including every agent's, is unchanged.
fn subject_for(state: &BrokerState, scope: &BrokerScope, target_node: &str) -> access::Scope {
    let node_id = if target_node != ORPHAN_ID && state.is_owner_session(scope) {
        target_node.to_string()
    } else {
        scope.node_id.clone()
    };
    access::Scope {
        node_id,
        origin: scope.origin,
        presence_attested: false,
    }
}

/// `resolve()` needs an `Origin`/presence pair; Phase 3 has no native
/// transport yet (Phase 5's Tauri shell), so `presence_attested` is always
/// `false` here — R0's orphan carve-out is therefore unreachable via this
/// dispatcher, which is the correct, conservative default until presence is
/// real (`06 §1` R0: "No grant, policy, or token can override").
fn resolve_capability(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    capability: Capability,
    now: i64,
) -> access::Decision {
    let registry = state.registry.read().expect("registry poisoned");
    let locked_nodes = state.locked_nodes.read().expect("locked_nodes poisoned");
    let ctx = AccessContext {
        registry: &registry,
        vault_locked: state.is_locked(),
        locked_nodes: &locked_nodes,
        now,
    };
    let subject = subject_for(state, scope, target_node);
    access::resolve(
        &ctx,
        &subject,
        &Target::Node(target_node.to_string()),
        capability,
    )
}

/// Whether `capability` on `target_node` would be `Allow` if no lock — vault-
/// wide or node-level — were in effect at all (ADR-042). Used only to decide
/// whether an R1 denial is approval-eligible: a locked target that was never
/// reachable in the first place must not turn into a notification, the same
/// "re-scan to enrich, never to change the decision" shape
/// `find_expired_grant_note` below already uses for R8.
fn would_be_allowed_ignoring_lock(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    capability: Capability,
    now: i64,
) -> bool {
    let registry = state.registry.read().expect("registry poisoned");
    let ctx = AccessContext {
        registry: &registry,
        vault_locked: false,
        locked_nodes: &HashSet::new(),
        now,
    };
    let subject = subject_for(state, scope, target_node);
    access::resolve(
        &ctx,
        &subject,
        &Target::Node(target_node.to_string()),
        capability,
    )
    .is_allow()
}

/// The manifest's entry for `entry_id` on `node`, if the node lists it.
fn manifest_entry(state: &BrokerState, node: &str, entry_id: &str) -> Option<ManifestEntry> {
    state
        .manifests
        .read()
        .expect("manifests poisoned")
        .get(node)
        .and_then(|body| body.entries.iter().find(|e| e.id == entry_id).cloned())
}

/// Opens the one entry envelope with an already-unwrapped node private key —
/// shared by the ordinary unlocked-reveal path and the approval-on-demand
/// path (ADR-042), which obtain that key two different ways but decrypt
/// identically once they have it. ADR-078: the result is the entry's field
/// document; a legacy (version-1) value is read in place as one field, and the
/// manifest entry (when the node lists one) is what pins its projection.
fn open_entry_doc(
    state: &BrokerState,
    target_node: &str,
    entry_id: &str,
    node_priv: &x25519_dalek::StaticSecret,
) -> Result<EntryDoc, OpError> {
    let stored = manifest_entry(state, target_node, entry_id);
    entry_doc::load(state, target_node, entry_id, node_priv, stored.as_ref()).map(|l| l.doc)
}

/// The value an approval releases, decrypted at the moment it is approved
/// (ADR-079, 4a) — never at the requester's retry. Approving is the one point at
/// which a human is present and a root key is known to be resident (the caller
/// has just refused a wholly locked live vault), so that is where the key is
/// used, once; the retry then only hands over what is already staged and never
/// derives a key. The root key and the node key are zeroised when this returns.
fn stage_approved_value(
    state: &BrokerState,
    pending: &PendingApproval,
) -> Result<secrecy::SecretBox<String>, OpError> {
    use secrecy::ExposeSecret;
    let root_key = state
        .reauth_root_key("approval-on-demand decide")
        .map_err(|_| {
            if state.is_durable() {
                // A live vault has no root key to give once it is locked: the
                // lock won the race against this decision.
                OpError::VaultLocked
            } else {
                OpError::Internal("could not re-derive the root key for an approval".into())
            }
        })?;
    stage_approved_value_with(state, pending, root_key.expose_secret())
}

/// [`stage_approved_value`] for a caller that already holds a root key — the
/// session's (an owner decision) or the one a locked vault's two factors just
/// yielded (ADR-088, `decide_with_factors`).
fn stage_approved_value_with(
    state: &BrokerState,
    pending: &PendingApproval,
    root_key: &[u8; 32],
) -> Result<secrecy::SecretBox<String>, OpError> {
    let node_priv = state
        .unwrap_node_key_with_root(&pending.node_id, root_key)
        .ok_or_else(|| OpError::Internal("could not unwrap the node key for an approval".into()))?;
    let doc = open_entry_doc(state, &pending.node_id, &pending.entry_id, &node_priv)?;
    // ADR-078: an approval covers the entry, so what is staged is its whole field
    // document in the canonical encoding (a legacy single value is pinned into
    // one by `fields::from_legacy`, so the staged text is self-describing and the
    // retry needs no manifest and no key). The plaintext lives only in a
    // `SecretBox`, which zeroises it on every path that ends the request.
    let encoded = zeroize::Zeroizing::new(fields::encode(&doc).map_err(entry_doc::edit_error)?);
    let text = String::from_utf8(encoded.to_vec())
        .map_err(|_| OpError::Internal("a staged approval was not valid text".into()))?;
    Ok(secrecy::SecretBox::new(Box::new(text)))
}

/// Approval-on-demand's `entry.reveal` branch (ADR-042): finds or creates
/// the live request for `(target_node, entry_id)` and reacts to whatever
/// state it is already in — still pending (return `approval_pending` again,
/// same request id), denied (or voided by a lock), or approved (consume it and
/// return what was staged when it was approved, with the vault still locked
/// throughout — no key is derived here, ADR-079). ADR-078: what is staged is the
/// whole entry (its field document), an approval covers the entry, and
/// `field_ids` only narrows what the approved reveal returns.
///
/// A **wholly locked live vault** answers `vault_locked` before anything else
/// (ADR-079, 4a): the only principal that can decide an approval is the owner
/// session, which the lock revoked, and the value would need a root key the
/// locked vault does not hold — so an `approval_pending` would be a promise
/// nothing could keep, and no request is created for it. Fail-closed stays the
/// default; a node-level lock on an unlocked vault, and in-memory fixtures, take
/// the approval path as before.
/// An opaque, in-memory identity for "who asked": the scope's node and a digest of its token (when it has one; the token
/// itself is never kept). The work folder is deliberately not part of it: a caller can reach any subdirectory of its
/// folder, so it would mint requesters at will and flood the table (re-verification NEW-P2-a); a node, and a token, are
/// things a caller cannot multiply.
fn approval_request_key(scope: &BrokerScope) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    scope.token_id.hash(&mut h);
    format!("{}|{:016x}", scope.node_id, h.finish())
}

fn reveal_via_approval(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    entry_id: &str,
    field_ids: Option<&[String]>,
    now: i64,
) -> Result<Value, OpError> {
    // ADR-088 (4b): a wholly locked live vault no longer answers `vault_locked`
    // here — the request is recorded, because a person can now decide it with the
    // unlock factors while the vault stays locked (`decide_with_factors`).
    // Only for an entry that exists: a request is a slot per (node, entry), so an
    // agent that invents ids cannot grow the table past the number of real entries.
    if manifest_entry(state, target_node, entry_id).is_none() {
        return Err(OpError::NotFound(format!(
            "no entry {entry_id} on node {target_node}"
        )));
    }
    // One slot per (node, entry, requester): a second caller makes its own request and is decided on its own
    // (audit P1-1). The request remembers the fields it asked for, and what it releases never goes beyond them.
    let request_key = approval_request_key(scope);
    let asked: Option<Vec<String>> = field_ids.map(|ids| {
        let mut v: Vec<String> = ids.to_vec();
        v.sort_unstable();
        v.dedup();
        v
    });
    let approval = state.approval_for_reveal(
        target_node,
        entry_id,
        scope.bound_workdir.clone(),
        &request_key,
        asked.clone(),
        now,
    );
    // Undecided and past its TTL: `07 §5a` — "defaults to deny" — reported
    // exactly once, then discarded so the next reveal starts a clean cycle
    // rather than silently reusing (and re-extending) a timed-out request.
    if approval.decision.is_none() && now >= approval.expires_at {
        state.discard_approval(&approval.id);
        return Err(OpError::ApprovalDenied {
            request: approval.id,
            reason: "expired",
        });
    }

    match approval.decision {
        Some(true) => {
            use secrecy::ExposeSecret;
            // The entry's document was opened, with a key, when the human
            // approved (`stage_approved_value`); the retry only decodes what was
            // staged and narrows it by `field_ids`. The answer is built FIRST,
            // from a read that does not consume the approval: a request that
            // cannot be answered (an unknown field id) is refused and the human's
            // one-time approval stays usable until its TTL (C1).
            let built = state.with_approved(&approval.id, now, |staged| {
                let doc = fields::decode(staged.expose_secret().as_bytes())
                    .map_err(|_| OpError::Internal("a staged approval did not decode".into()))?;
                entry_doc::reveal_json(target_node, entry_id, &doc, field_ids)
            });
            let expired = |state: &BrokerState| {
                // Raced with expiry between the calls above — vanishingly
                // unlikely at a 120s TTL, but honest: report it the same way a
                // fresh timeout would, and clean up the same way too. (A lock
                // landing in that same gap ends up here as well: it voided the
                // staged value, so nothing is released either way, and `expired`
                // is the safe thing to say.)
                state.discard_approval(&approval.id);
                OpError::ApprovalDenied {
                    request: approval.id.clone(),
                    reason: "expired",
                }
            };
            let Some(answer) = built else {
                return Err(expired(state));
            };
            let answer = answer?;
            // An approval given for some fields is not a licence for others (audit P1-1): a request that reaches past
            // them is refused here, after its field ids were checked, and leaves the approval usable by the request it
            // was given for.
            let inside = match (&approval.fields, &asked) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(allowed), Some(want)) => want.iter().all(|w| allowed.contains(w)),
            };
            if !inside {
                return Err(OpError::Malformed(
                    "that approval was given for other fields; ask for those fields (or request the entry again once it is used)"
                        .into(),
                ));
            }
            // Consume it now that there is an answer to give. A lock that lands
            // between the build and this line voids the staged value: nothing is
            // released and `expired` is reported.
            if state.take_approved(&approval.id, now).is_none() {
                return Err(expired(state));
            }
            Ok(answer)
        }
        Some(false) => {
            state.discard_approval(&approval.id);
            Err(OpError::ApprovalDenied {
                request: approval.id,
                // ADR-079 (4a): an approval the vault's lock voided is not a
                // refusal by the human — say which it was.
                reason: if approval.voided_by_lock {
                    "locked"
                } else {
                    "denied"
                },
            })
        }
        None => Err(OpError::ApprovalPending {
            request: approval.id,
            expires_in: (approval.expires_at - now).max(0) as u32,
            message: if state.is_durable() && state.is_locked() {
                "The vault is locked. The operator can approve this single request with their \
                 passphrase and authenticator code (credmgr approve <request>) without unlocking."
            } else {
                "The vault is locked. The operator has been notified and can approve this single request."
            }
            .to_string(),
        }),
    }
}

/// `resolve()` reports only a rule number, not *why* R8 fell all the way
/// through — but I-7 wants an expired grant reported as expired rather than
/// indistinguishable from "no grant ever existed". This re-scans for a
/// same-shape grant that would have matched had it not expired, purely to
/// enrich the denial message; it changes no access decision.
fn find_expired_grant_note(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    capability: Capability,
    now: i64,
) -> Option<String> {
    let registry = state.registry.read().expect("registry poisoned");
    registry.grants.iter().find_map(|grant| {
        let expired = grant.expires_at.is_some_and(|e| e <= now);
        let would_match = grant.from == scope.node_id
            && grant.scope.contains(&capability)
            && grant.to.node_id() == target_node;
        (expired && would_match).then(|| {
            format!(
                " (a grant from '{}' to '{target_node}' expired at {})",
                scope.node_id,
                grant.expires_at.unwrap()
            )
        })
    })
}

fn access_denied_error(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    capability: Capability,
    rule: &'static str,
    now: i64,
) -> OpError {
    let expired_note = find_expired_grant_note(state, scope, target_node, capability, now);
    OpError::NodeAccessDenied {
        subject: scope.node_id.clone(),
        target: target_node.to_string(),
        capability,
        rule,
        message: format!(
            "Node '{target_node}' is not readable from node '{}'.{}",
            scope.node_id,
            expired_note.unwrap_or_default(),
        ),
        remedy: format!(
            "A human can create a grant: credmgr grant {} --to {target_node} --scope read --reason \"...\"",
            scope.node_id
        ),
    }
}

fn rule_name(d: access::Decision) -> &'static str {
    match d.rule() {
        access::Rule::R0 => "R0",
        access::Rule::R1 => "R1",
        access::Rule::R2 => "R2",
        access::Rule::R3 => "R3",
        access::Rule::R4 => "R4",
        access::Rule::R5 => "R5",
        access::Rule::R6 => "R6",
        access::Rule::R7 => "R7",
        access::Rule::R8 => "R8",
    }
}

fn resolve_entry_capability(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    entry_id: &str,
    capability: Capability,
    now: i64,
) -> access::Decision {
    let registry = state.registry.read().expect("registry poisoned");
    let locked_nodes = state.locked_nodes.read().expect("locked_nodes poisoned");
    let ctx = AccessContext {
        registry: &registry,
        vault_locked: state.is_locked(),
        locked_nodes: &locked_nodes,
        now,
    };
    let subject = subject_for(state, scope, target_node);
    let target = Target::Entry {
        node_id: target_node.to_string(),
        entry_id: entry_id.to_string(),
    };
    access::resolve(&ctx, &subject, &target, capability)
}

/// `06_ACCESS_GRAPH.md §1b`: "an entry grant is not a directory listing".
/// A node-kind grant (or R2..R6) makes the whole node visible via the plain
/// node-level `resolve()` call the caller already tried; when that alone
/// denies, an entry-level grant can still make `list`/`read` succeed for
/// *exactly* the entries it names — checked here by asking `resolve()`
/// about each entry individually (`Target::Entry`), the same function and
/// the same R7 grant-matching logic, at a finer target. No grant logic is
/// reimplemented here.
fn narrow_entries<'a>(
    state: &BrokerState,
    scope: &BrokerScope,
    target_node: &str,
    capability: Capability,
    entries: &'a [credmgr_store::manifest::ManifestEntry],
    now: i64,
) -> Vec<&'a credmgr_store::manifest::ManifestEntry> {
    entries
        .iter()
        .filter(|e| {
            resolve_entry_capability(state, scope, target_node, &e.id, capability, now).is_allow()
        })
        .collect()
}

/// `"e_" + 12 hex` (`03_DATA_MODEL.md §3`), same construction as
/// `token.rs::new_token_id` — a fresh random id per call, not derived from
/// anything about the entry's content.
fn new_entry_id() -> String {
    let mut bytes = [0u8; 6];
    OsRng.fill_bytes(&mut bytes);
    let mut s = String::from("e_");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Whether `node_id` is locked right now — vault-wide or individually
/// (`06_ACCESS_GRAPH.md §1a`).
fn node_is_locked(state: &BrokerState, node_id: &str) -> bool {
    state.is_locked() || state.is_node_locked(node_id)
}

/// ADR-077 (G3): the refusal for "`node_id` is locked right now", in the one
/// place that decides which kind of locked it is. The whole vault being locked
/// is `vault_locked` — the login is over, and the desktop bridge drops its
/// session on it. Only this node being locked, on a vault that is otherwise
/// unlocked, is `node_locked`: same remedy shape, different meaning, and it
/// must never end a session that is still good.
fn locked_refusal(state: &BrokerState, node_id: &str) -> OpError {
    if state.is_locked() {
        OpError::VaultLocked
    } else {
        OpError::NodeLocked {
            node: node_id.to_string(),
        }
    }
}

/// What creating one entry produced (`entry.create`, and each item of
/// `entry.create_batch`).
struct Created {
    entry_id: String,
    /// It went to the locked-write tray rather than into the manifest.
    pending: bool,
    /// The node's generation after the write; `None` for a tray entry, which
    /// has not entered the manifest yet.
    generation: Option<u64>,
    field_ids: Vec<String>,
}

impl Created {
    fn to_json(&self, target_node: &str) -> Value {
        let mut body = json!({
            "node": target_node, "entry": self.entry_id, "pending": self.pending,
            "fieldCount": self.field_ids.len(), "fieldIds": self.field_ids,
        });
        if let Some(generation) = self.generation {
            body["generation"] = json!(generation);
        }
        body
    }
}

/// Seals a finished field document as a new entry (ADR-078) — the body shared
/// by `entry.create` and every item of `entry.create_batch`, so sealing, the
/// locked-write tray and the envelope digest are one implementation. The
/// caller has already checked the `create` capability.
///
/// Sealing only ever needs the node's PUBLIC key (asymmetric,
/// `04_CRYPTO_AND_KEYS.md §3`) — this runs identically whether the vault is
/// locked or not, which is exactly what makes `create` safe to permit while
/// locked. A locked node's entry goes to the tray, with the manifest metadata
/// the document projects to beside it (ADR-069); nothing about a field — label,
/// type or value — is in that metadata.
fn create_entry(
    state: &BrokerState,
    target_node: &str,
    name: &str,
    doc: &EntryDoc,
    now: i64,
) -> Result<Created, OpError> {
    // F-9: held for the whole check-then-write sequence below, so a
    // concurrent create/update on the same node can never interleave with
    // this one.
    let node_lock = state.node_write_lock(target_node);
    let _guard = node_lock.lock().expect("node write lock poisoned");

    // "a name not already in the node" (`06 §3`) — checked against both the
    // accepted manifest and the pending tray, so two locked-vault creates of
    // the same name don't both succeed only to collide later at accept time.
    let canon = canonical_name(name);
    let name_taken = state
        .manifests
        .read()
        .expect("manifests poisoned")
        .get(target_node)
        .is_some_and(|m| canon_taken(&canon, m.entries.iter().map(|e| e.name.as_str())))
        || canon_taken(
            &canon,
            state
                .list_pending(target_node)
                .iter()
                .map(|p| p.name.as_str()),
        );
    if name_taken {
        return Err(OpError::EntryExists {
            node: target_node.to_string(),
            name: name.to_string(),
        });
    }

    let entry_id = new_entry_id();
    // Review of 2026-09-24 (gap G-12, ADR-067): the manifest's `sha256` is the
    // digest of the *sealed envelope* (never of the plaintext — an unkeyed
    // digest in a same-user-readable file is an offline brute-force oracle).
    let (sealed, sha256) = entry_doc::seal_doc(state, target_node, &entry_id, doc)?;
    let p = fields::project(doc);
    let field_ids = doc.field_ids();

    if node_is_locked(state, target_node) {
        let path = state.paths.pending_env(target_node, &entry_id);
        credmgr_store::atomic::write(&path, &sealed)
            .map_err(|e| OpError::Internal(format!("writing pending entry: {e}")))?;
        let pending = PendingEntry {
            id: entry_id.clone(),
            name: name.to_string(),
            entry_type: p.entry_type,
            sensitivity: p.sensitivity,
            field_count: p.field_count,
            sha256,
            created: now,
        };
        // ADR-069: the tray's metadata beside the envelope, so a restart does
        // not forget what the ciphertext was.
        state
            .write_pending_meta(target_node, &pending)
            .map_err(|e| {
                let _ = std::fs::remove_file(&path);
                OpError::Internal(format!("writing pending entry metadata: {e}"))
            })?;
        state.add_pending(target_node, pending);
        Ok(Created {
            entry_id,
            pending: true,
            generation: None,
            field_ids,
        })
    } else {
        let path = state.paths.entry_env(target_node, &entry_id);
        credmgr_store::atomic::write(&path, &sealed)
            .map_err(|e| OpError::Internal(format!("writing entry: {e}")))?;
        let generation = state.insert_manifest_entry(
            target_node,
            ManifestEntry {
                id: entry_id.clone(),
                name: name.to_string(),
                r#ref: state.next_ref(),
                entry_type: p.entry_type,
                sensitivity: p.sensitivity,
                field_count: p.field_count,
                sha256,
                modified: now,
                expires_at: None,
                rotated_at: None,
                has_totp: p.has_totp,
            },
        );
        Ok(Created {
            entry_id,
            pending: false,
            generation: Some(generation),
            field_ids,
        })
    }
}

/// Which of the changing ops is running — they share one body and differ only
/// in what they keep.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mutation {
    /// `entry.update`: replaces, keeps no history (as it always has).
    Update,
    /// `entry.rotate`: keeps the previous envelope and stamps `rotatedAt`.
    Rotate,
    /// `field.add` / `update` / `remove` / `reorder` (ADR-078): keep the
    /// previous envelope, so `entry.undo` can put the change back, but are not a
    /// rotation and leave `rotatedAt` alone.
    Field,
}

/// The result of a change: the node's new generation and the entry's document
/// as it now stands (the answer's `fieldCount` / `fieldIds` come from it).
struct Mutated {
    generation: u64,
    doc: EntryDoc,
}

/// The body of `entry.update`, `entry.rotate` and the four `field.*` ops
/// (ADR-078): `update` capability (R1 → `vault_locked` / `node_locked`), the
/// node's write lock, the entry must exist, F-9's generation check, then
/// **read-modify-write** — open the current document with the node key, apply
/// `edit` to it (a pure function that either returns a valid document or an
/// error and writes nothing), seal the result as a version-2 envelope, retain
/// history where `mode` says to, and update the manifest from the document's
/// projection. The ops already required the node unlocked; reading what is
/// being replaced is what keeps labels, ids and overrides across an edit.
#[allow(clippy::too_many_arguments)]
fn mutate_entry(
    state: &BrokerState,
    scope: &BrokerScope,
    now: i64,
    target_node: &str,
    entry_id: &str,
    expected_generation: u64,
    mode: Mutation,
    edit: impl FnOnce(&EntryDoc) -> Result<EntryDoc, OpError>,
) -> Result<Mutated, OpError> {
    if !scope.holds(Capability::Update) {
        return Err(OpError::CapabilityNotHeld {
            capability: Capability::Update,
        });
    }
    let decision = resolve_capability(state, scope, target_node, Capability::Update, now);
    if !decision.is_allow() {
        // R1 is specifically the locked-vault/locked-node denial — wire it to
        // `vault_locked` (whole vault) or `node_locked` (this node alone,
        // ADR-077), not a generic access denial, so a caller can tell "not
        // yours" from "not right now" (I-18).
        if decision.rule() == access::Rule::R1 {
            return Err(locked_refusal(state, target_node));
        }
        return Err(access_denied_error(
            state,
            scope,
            target_node,
            Capability::Update,
            rule_name(decision),
            now,
        ));
    }

    let node_lock = state.node_write_lock(target_node);
    let _guard = node_lock.lock().expect("node write lock poisoned");

    let (current_generation, prior) = {
        let manifests = state.manifests.read().expect("manifests poisoned");
        match manifests.get(target_node) {
            Some(body) => (
                body.generation,
                body.entries.iter().find(|e| e.id == entry_id).cloned(),
            ),
            None => (0, None),
        }
    };
    let Some(prior) = prior else {
        return Err(OpError::NotFound(format!(
            "no entry {entry_id} on node {target_node}"
        )));
    };
    if expected_generation != current_generation {
        return Err(OpError::Conflict {
            node_id: target_node.to_string(),
            expected_generation,
            current_generation,
        });
    }

    let Some(node_priv) = state.hot_node_key(target_node) else {
        return Err(locked_refusal(state, target_node));
    };
    let loaded = entry_doc::load(state, target_node, entry_id, &node_priv, Some(&prior))?;
    let next = edit(&loaded.doc)?;
    let (sealed, sha256) = entry_doc::seal_doc(state, target_node, entry_id, &next)?;

    if mode != Mutation::Update {
        // ADR-055: the pre-change envelope and the signed pre-change manifest
        // snapshot, side by side — `entry.undo` needs both to restore a change
        // correctly, not merely prove a prior value existed.
        entry_doc::retain_history(
            state,
            target_node,
            entry_id,
            &prior,
            current_generation,
            now,
        )?;
    }
    credmgr_store::atomic::write(&state.paths.entry_env(target_node, entry_id), &sealed)
        .map_err(|e| OpError::Internal(format!("writing entry: {e}")))?;

    let p = fields::project(&next);
    let generation = state
        .update_manifest_entry(target_node, entry_id, |e| {
            e.entry_type = p.entry_type;
            e.sensitivity = p.sensitivity;
            e.field_count = p.field_count;
            e.has_totp = p.has_totp;
            e.sha256 = sha256;
            e.modified = now;
            if mode == Mutation::Rotate {
                e.rotated_at = Some(now);
            }
        })
        .expect("presence already checked above, under the same held write lock");

    Ok(Mutated {
        generation,
        doc: next,
    })
}

/// `{node, entry, generation, fieldCount, fieldIds}` — the answer of every
/// changing op — plus whatever extra keys the op adds.
fn mutated_json(target_node: &str, entry_id: &str, m: &Mutated) -> Value {
    let mut body = json!({ "node": target_node, "entry": entry_id, "generation": m.generation });
    body["fieldCount"] = json!(m.doc.fields.len());
    body["fieldIds"] = json!(m.doc.field_ids());
    body
}

/// `entry.restore`'s `"keep-both"` naming, matching V1's `changelog.js`
/// undo-delete exactly: `"<name> old"`, then `"<name> old 2"`, `"<name> old
/// 3"`, … until a name this node doesn't already hold turns up.
fn free_restored_name(state: &BrokerState, node_id: &str, original_name: &str) -> String {
    let manifests = state.manifests.read().expect("manifests poisoned");
    let taken: HashSet<String> = manifests
        .get(node_id)
        .map(|m| m.entries.iter().map(|e| canonical_name(&e.name)).collect())
        .unwrap_or_default();
    let mut candidate = format!("{original_name} old");
    let mut n = 2;
    while taken.contains(&canonical_name(&candidate)) {
        candidate = format!("{original_name} old {n}");
        n += 1;
    }
    candidate
}

/// The restore mechanics shared by `entry.restore`'s own dispatch arm and
/// `entry.undo`'s `entry.remove`-branch (ADR-055) — capability, lock, and
/// generation checks are each caller's own job (their auth-check shape
/// differs: `entry.restore` checks `params.node` directly, `entry.undo`
/// checks it only after resolving an audit id), everything from "read the
/// archive" onward is identical, so there is exactly one implementation.
fn do_entry_restore(
    state: &BrokerState,
    target_node: &str,
    entry_id: &str,
    mode: &str,
    hide_names: bool,
    now: i64,
) -> Result<Value, OpError> {
    use secrecy::ExposeSecret;
    let root_key = state.reauth_root_key("entry restore").map_err(|_| {
        OpError::Internal(
            "could not re-derive the root key to read the removed entry archive".into(),
        )
    })?;
    let rk = root_key.expose_secret();

    // Decide collision handling from the retained snapshot *before*
    // touching disk — a refused `"replace"` must never move a file.
    let snapshot = credmgr_store::entry_archive::peek(&state.paths, rk, target_node, entry_id, now)
        .map_err(|e| match e {
            credmgr_store::StoreError::EntryArchiveNotFound { .. } => {
                OpError::NotFound(format!("no removed entry {entry_id} on node {target_node}"))
            }
            credmgr_store::StoreError::EntryArchiveExpired { .. } => OpError::EntryRemovalExpired {
                node: target_node.to_string(),
                entry: entry_id.to_string(),
            },
            other => OpError::Internal(format!("reading removed entry archive: {other}")),
        })?;

    let snapshot_canon = canonical_name(&snapshot.name);
    let name_taken = state
        .manifests
        .read()
        .expect("manifests poisoned")
        .get(target_node)
        .is_some_and(|m| canon_taken(&snapshot_canon, m.entries.iter().map(|e| e.name.as_str())));
    let restored_name = if name_taken {
        if mode == "replace" {
            return Err(OpError::EntryExists {
                node: target_node.to_string(),
                // ADR-083: a reader that may not see names is not told the removed entry's.
                name: if hide_names {
                    String::new()
                } else {
                    snapshot.name.clone()
                },
            });
        }
        free_restored_name(state, target_node, &snapshot.name)
    } else {
        snapshot.name.clone()
    };

    let mut restored_entry =
        credmgr_store::entry_archive::restore(&state.paths, rk, target_node, entry_id, now)
            .map_err(|e| OpError::Internal(format!("restoring removed entry: {e}")))?;
    restored_entry.name.clone_from(&restored_name);
    restored_entry.modified = now;

    let generation = state.insert_manifest_entry(target_node, restored_entry);

    Ok(json!({
        "node": target_node, "entry": entry_id,
        "restoredName": if hide_names { Value::Null } else { json!(restored_name) },
        "generation": generation,
    }))
}

/// `entry.undo`'s retained-history branch (ADR-055, extended by ADR-078 to the
/// field operations): writes back the exact ciphertext and manifest metadata
/// retained at `pre_rotate_generation` — and, symmetrically with every ordinary
/// rotate, retains what is *currently* live (about to be superseded again) into
/// a fresh history slot at the node's current generation, so undoing an undo
/// works exactly the same way, forever, with no special case.
///
/// `action` is the op being undone (`entry.rotate`, `field.add`, …): the system
/// audit line this writes is recorded under **that** name, so undo-of-undo finds
/// it and takes this same branch. `stamp_rotated` is true only for
/// `entry.rotate` — a field edit is not a rotation and must not move `rotatedAt`.
/// The snapshot restores `fieldCount` and `hasTotp` as well as type, sensitivity
/// and digest (it used to restore only the latter three, which would have left a
/// wrong `fieldCount` after undoing a field edit).
fn undo_rotate(
    state: &BrokerState,
    target_node: &str,
    entry_id: &str,
    pre_rotate_generation: u64,
    action: &str,
    stamp_rotated: bool,
    now: i64,
) -> Result<Value, OpError> {
    use secrecy::ExposeSecret;
    let root_key = state.reauth_root_key("entry undo: rotate").map_err(|_| {
        OpError::Internal("could not re-derive the root key to undo the rotation".into())
    })?;
    let rk = root_key.expose_secret();

    let restored_ciphertext = credmgr_store::atomic::read(&state.paths.entry_history_env(
        target_node,
        entry_id,
        pre_rotate_generation,
    ))
    .map_err(|_| {
        OpError::NotFound(format!(
            "no retained rotation history for entry {entry_id} at generation {pre_rotate_generation}"
        ))
    })?;
    let (restored_snapshot, recorded_at) = credmgr_store::rotation_history::load_with_time(
        &state.paths,
        rk,
        target_node,
        entry_id,
        pre_rotate_generation,
    )
    .map_err(|e| OpError::Internal(format!("reading retained rotation snapshot: {e}")))?;
    // ADR-086: a field edit can be taken back for seven days — the same window
    // a removed entry has. (A rotation's undo has never had a limit, and keeps
    // none.) Measured from when the edit was made.
    if action.starts_with("field.")
        && now - recorded_at > credmgr_store::archive::RECOVERY_WINDOW_SECONDS
    {
        return Err(OpError::NotUndoable {
            id: entry_id.to_string(),
            reason: "a field edit can be undone for seven days only",
        });
    }

    let (current_generation, current_entry) = {
        let manifests = state.manifests.read().expect("manifests poisoned");
        let body = manifests.get(target_node).ok_or_else(|| {
            OpError::NotFound(format!("no entry {entry_id} on node {target_node}"))
        })?;
        let entry = body
            .entries
            .iter()
            .find(|e| e.id == entry_id)
            .cloned()
            .ok_or_else(|| {
                OpError::NotFound(format!("no entry {entry_id} on node {target_node}"))
            })?;
        (body.generation, entry)
    };

    // Retain the current (about-to-be-superseded-again) ciphertext and
    // snapshot — always at a strictly lower generation than
    // `current_generation` (generations only advance), so this can never
    // collide with the slot just read from above.
    let current_path = state.paths.entry_env(target_node, entry_id);
    let current_ciphertext = credmgr_store::atomic::read(&current_path)
        .map_err(|e| OpError::Internal(format!("reading current entry to undo: {e}")))?;
    credmgr_store::atomic::write(
        &state
            .paths
            .entry_history_env(target_node, entry_id, current_generation),
        &current_ciphertext,
    )
    .map_err(|e| OpError::Internal(format!("retaining pre-undo history: {e}")))?;
    credmgr_store::rotation_history::save(
        &state.paths,
        rk,
        target_node,
        &current_entry,
        current_generation,
        now,
    )
    .map_err(|e| OpError::Internal(format!("retaining pre-undo snapshot: {e}")))?;

    credmgr_store::atomic::write(&current_path, &restored_ciphertext)
        .map_err(|e| OpError::Internal(format!("writing undone entry: {e}")))?;

    let generation = state
        .update_manifest_entry(target_node, entry_id, |e| {
            e.entry_type = restored_snapshot.entry_type;
            e.sensitivity = restored_snapshot.sensitivity;
            e.field_count = restored_snapshot.field_count;
            e.has_totp = restored_snapshot.has_totp;
            e.sha256.clone_from(&restored_snapshot.sha256);
            e.modified = now;
            if stamp_rotated {
                e.rotated_at = Some(now);
            }
        })
        .ok_or_else(|| OpError::NotFound(format!("no entry {entry_id} on node {target_node}")))?;

    // Mechanically, undoing a rotate *is* a rotate — a new value (the
    // restored one) replacing the current one, history retained. Recording
    // it under the *original* action (not the generic wrapper's own
    // "entry.undo" line for this same request, which still gets appended
    // separately by `server::record_decision`) is what lets a *later*
    // `entry.undo` resolve an id pointing at *this* change and undo it in
    // turn — "undoing an undo works the same way, forever" (ADR-055) is
    // true only because this record exists to be found.
    let event = credmgr_store::audit::NewEvent {
        actor: "system:entry.undo".to_string(),
        action: action.to_string(),
        node_id: Some(target_node.to_string()),
        entry_id: Some(entry_id.to_string()),
        decision: Some("allow".to_string()),
        detail: None,
        generation: Some(generation),
    };
    let year_month = credmgr_store::audit::year_month_for(now);
    let _ = credmgr_store::audit::append(&state.paths, rk, &year_month, event, now);

    Ok(json!({
        "node": target_node, "entry": entry_id,
        "generation": generation, "undoneToGeneration": pre_rotate_generation,
        "fieldCount": restored_snapshot.field_count,
    }))
}

/// ADR-088 (4b): a person decides one approval request with the unlock factors —
/// passphrase, then (when a gate is enrolled) a fresh authenticator code, never a
/// recovery code — while the vault **stays locked**. No session, token, elevation
/// or hot key is created: the root key the passphrase yields opens the one value
/// being released (staged exactly as an owner decision stages it), signs one audit
/// record, and is dropped. Only while the vault is locked: an unlocked vault is
/// decided with the owner session. A wrong factor is a normal authentication
/// failure (the server's per-uid backoff counts it) and decides nothing.
fn decide_with_factors(
    state: &BrokerState,
    request_id: &str,
    approved: bool,
    passphrase: &Value,
    code: Option<&Value>,
    now: i64,
) -> Result<Value, OpError> {
    use crate::state::ApprovalFactorError;
    let passphrase = passphrase
        .as_str()
        .ok_or_else(|| OpError::Malformed("params.passphrase must be text".into()))?;
    let code = match code {
        None | Some(Value::Null) => None,
        Some(Value::String(c)) => Some(c.as_str()),
        Some(_) => return Err(OpError::Malformed("params.code must be text".into())),
    };
    if !(state.is_durable() && state.is_locked()) {
        return Err(OpError::Malformed(
            "a passphrase decides an approval only while the vault is locked — \
             unlocked, decide with your session"
                .into(),
        ));
    }
    let lock_epoch = state.lock_epoch();
    let Some(pending) = state.peek_approval(request_id, now) else {
        return Err(OpError::NotFound(format!(
            "no pending approval {request_id}"
        )));
    };
    if pending.decision.is_some() {
        return Err(OpError::Malformed(format!(
            "approval {request_id} was already decided"
        )));
    }
    let root = state
        .approval_factors(SecretBox::new(Box::new(passphrase.to_string())), code, now)
        .map_err(|e| match e {
            ApprovalFactorError::WrongPassphrase => OpError::WrongPassphrase,
            ApprovalFactorError::SecondFactorRequired => OpError::TwoFactorRequired {
                challenge: "totp".to_string(),
                scope: GATE_SCOPE_VAULT.to_string(),
                expires_in: crate::state::GATE_UNLOCK_TTL_SECONDS as u32,
            },
            ApprovalFactorError::WrongCode => OpError::GateVerificationFailed,
            ApprovalFactorError::RotationRecovery => OpError::Internal(
                "an interrupted root-key rotation could not be finished; nothing was decided"
                    .into(),
            ),
        })?;
    use secrecy::ExposeSecret;
    let rk = root.expose_secret();
    if state.is_gate_confirmed(GATE_SCOPE_VAULT) {
        // The authenticator step just spent must not be acceptable again after a
        // restart (`07 §5`'s replay rule).
        state.persist_spent_step(rk, now).map_err(|e| {
            OpError::Internal(format!("recording the spent authenticator step: {e}"))
        })?;
    }
    let verdict = if approved {
        ApprovalVerdict::Approve {
            staged: stage_approved_value_with(state, &pending, rk)?,
            lock_epoch,
        }
    } else {
        ApprovalVerdict::Deny
    };
    // One audit record, signed under the key the factors yielded — the generic
    // per-request record needs a resident root key a locked vault does not have,
    // so a decision made this way would otherwise leave no trace at all. It is
    // written BEFORE the value is released and its failure refuses the decision:
    // a release with no record is worse than no release.
    let record = |decision: &str, detail: &str| {
        credmgr_store::audit::append(
            &state.paths,
            rk,
            &credmgr_store::audit::year_month_for(now),
            credmgr_store::audit::NewEvent {
                actor: "Factors".to_string(),
                action: "vault.approval_decide".to_string(),
                node_id: Some(pending.node_id.clone()),
                entry_id: Some(pending.entry_id.clone()),
                decision: Some(decision.to_string()),
                detail: Some(detail.to_string()),
                generation: None,
            },
            now,
        )
    };
    record(
        "allow",
        if approved {
            "approved with the unlock factors; the vault stayed locked"
        } else {
            "denied with the unlock factors; the vault stayed locked"
        },
    )
    .map_err(|e| {
        OpError::Internal(format!(
            "could not record the decision, so none was made: {e}"
        ))
    })?;
    let outcome = state.decide_approval(request_id, verdict, now);
    if outcome.is_err() {
        let _ = record(
            "deny",
            "the decision above did not take effect (the request was gone, decided or voided)",
        );
    }
    match outcome {
        Ok(()) => Ok(json!({
            "request": request_id, "node": pending.node_id,
            "entry": pending.entry_id, "approved": approved,
            "authorisedBy": "factors",
        })),
        Err(ApprovalDecideError::NotFound) => Err(OpError::NotFound(format!(
            "no pending approval {request_id}"
        ))),
        Err(ApprovalDecideError::AlreadyDecided) => Err(OpError::Malformed(format!(
            "approval {request_id} was already decided"
        ))),
        Err(ApprovalDecideError::LockedMeanwhile) => Err(OpError::VaultLocked),
    }
}

/// ADR-056: the ceiling a real login session mints. Every `Capability`
/// variant, exhaustively — the one caller this token represents (a
/// passphrase-and-TOTP-authenticated operator) already "can read anything,
/// including orphaned data" by definition (`05_THREAT_MODEL.md §5`), so the
/// token's own ceiling withholds nothing; `resolve()` per node/op is still
/// the thing that actually decides each request, exactly as for any other
/// scope.
fn all_capabilities() -> Vec<Capability> {
    vec![
        Capability::List,
        Capability::Read,
        Capability::Reveal,
        Capability::Create,
        Capability::Update,
        Capability::Notes,
        Capability::Admin,
    ]
}

/// ADR-056: a successful full unlock — either `vault.unlock` with no gate
/// enrolled, or `vault.gate_verify` completing one that is — mints the real,
/// non-fixture token `ADR-047` found nothing on any transport could ever
/// construct. `Origin::HumanUi`, not `Origin::Native`: completing a real
/// unlock is "something stronger than asked nicely for `Capability::Admin`",
/// but `Origin::Native` additionally requires a live presence attestation
/// (R0) that no transport through Phase 5 can supply — minting it here would
/// overclaim. `node_id: GLOBAL_ID`, `bound_workdir: None` (a login session is
/// not "this project's" token the way a cwd-matched agent scope is; flagging
/// every `cd` as a workdir-mismatch anomaly would train the operator to
/// ignore the signal that matters). Registered with `state` so `lock()` can
/// revoke it — a login session does not outlive the unlock it came from.
fn mint_session_token(state: &BrokerState, now: i64) -> Value {
    let token = state
        .tokens
        .issue(GLOBAL_ID, all_capabilities(), Origin::HumanUi, None);
    state.register_session_token(&token.id, now);
    json!(token.id)
}

/// ADR-076 — what `maintenance.rotate_root` answers once a transport can
/// attest presence: runs [`BrokerState::rotate_root`] and shapes the outcome
/// for the wire. Kept out of the dispatch arm, which today stops at
/// `presence_required`, so the logic behind the presence wall is exercised by
/// tests rather than left as dead code (`maintenance.doctor
/// --rebuild-registry` is the precedent, and `maintenance.rs` says why).
///
/// `recoveryCode` is the new root recovery code, shown **once** — the previous
/// one no longer opens anything — and is the only secret in the response.
/// `notResigned` lists artefacts that did not verify under the old root key
/// and were deliberately left untouched (a tampered or truncated audit month,
/// say): the rotation does not re-sign them, so they keep failing
/// `maintenance.verify` — the evidence a rotation must not destroy. That holds
/// for a month nothing is appended to; appending to a month signs its tip over
/// the log as it stands (`audit::append`, for every request), so the month the
/// rotation's own record lands in is signed again, and its `reason` says so.
///
/// `completionPending` is `true` when the rotation committed and then could
/// not finish moving its files: the new key and the new code are already the
/// live ones (so the code is returned — it is never shown again), the vault
/// has locked itself, and the next unlock completes the move. Every failure
/// *before* the commit is an error, and changed nothing.
///
/// **A pending completion also says the broker locked itself**, in the one
/// place the bridge's `Session` already looks on every op: `meta.vaultLocked`
/// (the same field `graph.snapshot` carries). Without it the bridge would keep
/// presenting a login the broker has just revoked until the next call failed
/// with `vault_locked`. There is deliberately **no** top-level `locked` key —
/// the bridge reads that as the vault's state only on `vault.status`-shaped
/// answers, and a rotation answer is not one.
pub fn rotate_root_response(
    state: &BrokerState,
    passphrase: &str,
    now: i64,
) -> Result<Value, OpError> {
    use crate::state::RotateRootError;
    let outcome = state
        .rotate_root(SecretBox::new(Box::new(passphrase.to_string())), now)
        .map_err(|e| match e {
            RotateRootError::Locked => OpError::VaultLocked,
            RotateRootError::WrongPassphrase => OpError::WrongPassphrase,
            other => OpError::Internal(other.to_string()),
        })?;
    let mut response = json!({
        "rotated": true,
        "recoveryCode": outcome.recovery_code,
        "nodesRewrapped": outcome.nodes_rewrapped,
        "vaultGeneration": outcome.vault_generation,
        "filesReplaced": outcome.files_replaced,
        "artifactsResigned": outcome.artifacts_resigned,
        "completionPending": outcome.completion_pending,
        "notResigned": outcome
            .skipped
            .iter()
            .map(|s| json!({ "kind": s.kind, "id": s.id, "reason": s.reason }))
            .collect::<Vec<_>>(),
    });
    if outcome.completion_pending {
        response["meta"] = json!({ "vaultLocked": true });
    }
    Ok(response)
}

/// Ops whose success changes what a disk-backed vault must remember
/// (ADR-063). After any of them succeeds, [`dispatch`] writes the live vault
/// through to disk. Deliberately absent: reads; `vault.lock`/`unlock` and the
/// per-node locks (lock state is not persisted — every vault starts locked);
/// `vault.gate_enroll_begin` (a staged enrolment gates nothing until
/// confirmed); `vault.init_*` and `vault.gate_recover` (they write for
/// themselves, holding the root key); and `maintenance.doctor`, which writes
/// the registry itself when it repairs. Also absent, since ADR-079: `node.seal`
/// and `node.restore`, which are commit protocols — the registry write is their
/// commit point, made **inside** the op (`state/seal.rs`), with the file moves
/// before and after it ordered around that write. A generic persist after the
/// op would be a second write that proves nothing and could mask a failure.
pub const PERSISTED_OPS: &[&str] = &[
    "entry.create",
    "entry.update",
    "entry.rotate",
    "entry.remove",
    "entry.restore",
    "entry.undo",
    "field.add",
    "field.update",
    "field.remove",
    "field.reorder",
    "vault.pending_accept",
    "vault.gate_enroll_confirm",
    "vault.gate_verify",
    "node.create",
    "node.set_workdirs",
    "node.update",
    "node.policy",
    "notes.write",
    "entry.create_batch",
    "node.reparent",
    "grant.create",
    "grant.revoke",
];

/// Dispatch one op, then — on a disk-backed vault, for an op that changes
/// what the vault must remember — write the result through to disk
/// (ADR-063). If that write fails the caller is told so as an `internal`
/// error: the change is live in this process but was **not** saved, and
/// reporting success would be a lie a restart would expose.
pub fn dispatch(
    state: &BrokerState,
    scope: &BrokerScope,
    now: i64,
    op: &str,
    params: &Value,
) -> Result<Value, OpError> {
    let value = dispatch_op(state, scope, now, op, params)?;
    // Locked: the only writes a locked vault accepts go to the pending tray,
    // whose ciphertext and metadata sidecar `entry.create` already wrote
    // (ADR-069) — and there is no root key to sign anything with.
    // Persisting here used to turn every locked `entry.create` into an
    // `internal` error for a write that had succeeded (review M2).
    if PERSISTED_OPS.contains(&op) && state.is_durable() && !state.is_locked() {
        state.persist(now).map_err(|e| {
            OpError::Internal(format!(
                "{op} succeeded but the vault could not be saved to disk: {e}"
            ))
        })?;
    }
    Ok(value)
}

fn dispatch_op(
    state: &BrokerState,
    scope: &BrokerScope,
    now: i64,
    op: &str,
    params: &Value,
) -> Result<Value, OpError> {
    match op {
        // ADR-077 (G2): `initialized` is additive — a client that has no vault
        // yet (first run) is told so, instead of being shown a lock screen
        // there is nothing behind. It answers "is there a vault on disk to
        // open", which is true from `vault.init_confirm` on and across
        // restarts, and false while an init is merely pending.
        //
        // ADR-090: `pendingApprovals` is a bare count of the requests still waiting
        // for a person (unexpired, undecided). It names no node, no entry and no
        // requester, so it is safe on an op anyone on the socket may call.
        "vault.status" => Ok(json!({
            "locked": state.is_locked(),
            "initialized": state.is_durable() || state.paths.registry().exists(),
            "pendingApprovals": state.pending_approvals(now).len(),
        })),

        // ADR-063: with a passphrase, the live unlock — prove it, load the
        // vault from disk if this process has not, then the gate. Without
        // one, the pre-ADR-063 path against whatever keystore the broker
        // already holds (a test fixture's; the daemon's inert placeholder
        // refuses every passphrase, which is the safe reading of "none sent").
        "vault.unlock" => {
            let outcome = match params["passphrase"].as_str() {
                Some(passphrase) => state
                    .unlock_with_passphrase(SecretBox::new(Box::new(passphrase.to_string())), now)
                    .map_err(|e| match e {
                        UnlockError::WrongPassphrase => OpError::WrongPassphrase,
                        UnlockError::Integrity(e) => OpError::Internal(format!(
                            "the vault on disk failed its integrity check and was not opened: {e}"
                        )),
                    }),
                None => state.unlock(now).map_err(|_| OpError::WrongPassphrase),
            };
            match outcome? {
                false => Ok(json!({ "locked": false, "token": mint_session_token(state, now) })),
                // `07 §3` steps 2-3: factor 1 passed, a confirmed gate exists —
                // the caller must complete `vault.gate_verify` next. No token
                // yet — the login isn't complete until the second factor lands.
                true => Err(OpError::TwoFactorRequired {
                    challenge: "totp".to_string(),
                    scope: GATE_SCOPE_VAULT.to_string(),
                    expires_in: crate::state::GATE_UNLOCK_TTL_SECONDS as u32,
                }),
            }
        }

        // ADR-064 — the last door (`07_TWO_FACTOR.md §4`): passphrase plus
        // the printed root recovery code together reset a lost gate. No
        // capability check, deliberately — the caller is locked out by
        // definition; the two factors *are* the authorisation, and
        // `server.rs` puts this op behind the same per-uid auth backoff as
        // `vault.unlock`. Which factor failed is never said.
        "vault.gate_recover" => {
            let passphrase = params["passphrase"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.passphrase is required".into()))?;
            let code = params["recoveryCode"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.recoveryCode is required".into()))?;
            match state.gate_recover(SecretBox::new(Box::new(passphrase.to_string())), code, now) {
                Ok(had_gate) => Ok(json!({ "gateReset": had_gate })),
                Err(GateRecoverError::WrongFactors) => Err(OpError::WrongPassphrase),
                Err(GateRecoverError::Store(e)) => Err(OpError::Internal(format!(
                    "the gate could not be reset: {e}"
                ))),
            }
        }

        // `07 §3` step 3: completes an unlock that returned
        // `two_factor_required`. Shares `AuthBackoff`'s uid-keyed lockout
        // with `vault.unlock` (`server::handle_request` wires both) —
        // "shared counter with the passphrase path so an attacker cannot
        // alternate" (`07 §5`, ADR-044).
        "vault.gate_verify" => {
            let code = params["code"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.code is required".into()))?;
            // ADR-085: an owner session that is already logged in is not finishing
            // a login — it is stepping up (a node's `requireTwoFactor` asked for a
            // second factor). Same code check, same backoff; it mints no token.
            if state.is_owner_session(scope) {
                return match state.gate_step_up(GATE_SCOPE_VAULT, code, now) {
                    Ok(()) => Ok(json!({
                        "locked": false, "elevated": true,
                        "expiresIn": state.elevation_seconds(),
                    })),
                    // No gate enrolled: there is no second factor to prove. That is a
                    // malformed ask, not a failed login, and must not feed the backoff.
                    Err(GateVerifyError::NoChallengePending) => Err(OpError::Malformed(
                        "no second factor is enrolled - there is nothing to verify".into(),
                    )),
                    Err(GateVerifyError::WrongCode) => Err(OpError::GateVerificationFailed),
                };
            }
            match state.gate_verify(GATE_SCOPE_VAULT, code, now) {
                Ok(()) => Ok(json!({ "locked": false, "token": mint_session_token(state, now) })),
                Err(GateVerifyError::NoChallengePending | GateVerifyError::WrongCode) => {
                    Err(OpError::GateVerificationFailed)
                }
            }
        }

        // `07 §4` steps 1-2. `Capability::Admin` on `global`, the same
        // "the factor Phase 3 actually has" substitution `node.seal`/
        // `vault.node_lock` already make (ADR-041/042 note).
        "vault.gate_enroll_begin" => {
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            let decision = resolve_capability(state, scope, GLOBAL_ID, Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    GLOBAL_ID,
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }
            // ADR-064 (review M3): replacing a gate that is in force needs the
            // second factor it guards, fresh — the elevation window a
            // successful `vault.gate_verify` opens (`07 §5`). Without it,
            // anything holding the owner's login could swap in an
            // authenticator of its own, durably. A first enrolment has no
            // gate to prove, so it needs none.
            if state.is_gate_confirmed(GATE_SCOPE_VAULT)
                && !state.is_elevated(GATE_SCOPE_VAULT, now)
            {
                return Err(OpError::TwoFactorRequired {
                    challenge: "totp".to_string(),
                    scope: GATE_SCOPE_VAULT.to_string(),
                    expires_in: 0,
                });
            }
            let uri = state.gate_enroll_begin(GATE_SCOPE_VAULT);
            Ok(json!({ "otpauthUri": uri }))
        }

        // `07 §4` steps 3-4: one successful code activates the enrolment
        // and returns the 10 recovery codes, once.
        "vault.gate_enroll_confirm" => {
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            let decision = resolve_capability(state, scope, GLOBAL_ID, Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    GLOBAL_ID,
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }
            // ADR-064 (review M3): replacing a gate that is in force needs the
            // second factor it guards, fresh — the elevation window a
            // successful `vault.gate_verify` opens (`07 §5`). Without it,
            // anything holding the owner's login could swap in an
            // authenticator of its own, durably. A first enrolment has no
            // gate to prove, so it needs none.
            if state.is_gate_confirmed(GATE_SCOPE_VAULT)
                && !state.is_elevated(GATE_SCOPE_VAULT, now)
            {
                return Err(OpError::TwoFactorRequired {
                    challenge: "totp".to_string(),
                    scope: GATE_SCOPE_VAULT.to_string(),
                    expires_in: 0,
                });
            }
            let code = params["code"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.code is required".into()))?;
            match state.gate_enroll_confirm(GATE_SCOPE_VAULT, code, now) {
                Ok(recovery_codes) => Ok(json!({ "recoveryCodes": recovery_codes })),
                Err(GateEnrollError::NotEnrolling) => Err(OpError::GateNotEnrolling),
                Err(GateEnrollError::WrongCode) => Err(OpError::GateVerificationFailed),
            }
        }

        "vault.lock" => {
            state.lock();
            Ok(json!({ "locked": true }))
        }

        // ADR-061: vault bootstrap, step 1. No capability check —
        // `resolve_scope` already gives an unauthenticated pre-vault
        // connection nothing but `List` on `GLOBAL_ID` (there is no
        // registry yet to hold `Admin` over), so the only gate that matters
        // is "does a vault already exist", which `begin_init` itself
        // enforces.
        "vault.init_begin" => {
            let passphrase = params["passphrase"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.passphrase is required".into()))?;
            let passphrase = secrecy::SecretBox::new(Box::new(passphrase.to_string()));
            match state.begin_init(passphrase, now) {
                Ok(recovery_code) => Ok(json!({ "recoveryCode": recovery_code })),
                Err(VaultInitError::AlreadyInitialized) => Err(OpError::VaultAlreadyInitialized),
                Err(VaultInitError::InsideGitWorkingTree) => {
                    Err(OpError::VaultInsideGitWorkingTree)
                }
            }
        }

        // ADR-061: vault bootstrap, step 2 — writes the vault to disk on a
        // matching recovery code.
        "vault.init_confirm" => {
            let recovery_code = params["recoveryCode"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.recoveryCode is required".into()))?;
            match state.confirm_init(recovery_code, now) {
                Ok(()) => Ok(json!({ "initialized": true })),
                Err(VaultInitConfirmError::AlreadyInitialized) => {
                    Err(OpError::VaultAlreadyInitialized)
                }
                Err(VaultInitConfirmError::NotPending | VaultInitConfirmError::Expired) => {
                    Err(OpError::VaultInitNotPending)
                }
                Err(VaultInitConfirmError::RecoveryCodeMismatch) => {
                    Err(OpError::RecoveryCodeMismatch)
                }
                Err(VaultInitConfirmError::Store(e)) => {
                    Err(OpError::Internal(format!("writing vault: {e}")))
                }
            }
        }

        "whoami" => {
            // [Pass 2 · F-6] Names only reachable nodes — the naive
            // "list everything, flag reachability" shape would hand the
            // caller every project name on the machine (I-22).
            let node_ids: Vec<String> = state
                .registry
                .read()
                .expect("registry poisoned")
                .nodes
                .keys()
                .cloned()
                .collect();
            let mut reachable = Vec::new();
            for node_id in &node_ids {
                if resolve_capability(state, scope, node_id, Capability::List, now).is_allow() {
                    reachable.push(node_id.clone());
                }
            }
            Ok(json!({
                "node": scope.node_id,
                "capabilities": scope.capabilities,
                "reachable": reachable,
            }))
        }

        // ADR-087 (4.6): the password generator. The value is made here, by the
        // operating system's random source, and nowhere else (never in page
        // JavaScript); the caller puts it into a field through the broker
        // (`field.add`, `field.update`, `entry.create`) and shows it masked. Needs
        // `create` or `update` — a generator is a step towards writing — and is
        // not an MCP tool (the tool count stays 15). The value is in this answer
        // only: it is never audited, and nothing about it is stored.
        "util.generate" => {
            use credmgr_core::generate::{self, GenerateError};
            if !(scope.holds(Capability::Create) || scope.holds(Capability::Update)) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Create,
                });
            }
            if let Some(obj) = params.as_object() {
                if let Some(k) = obj
                    .keys()
                    .find(|k| !["length", "symbols", "pronounceable"].contains(&k.as_str()))
                {
                    return Err(OpError::Malformed(format!(
                        "params.{k} is not a generator option (length, symbols, pronounceable)"
                    )));
                }
            }
            let flag = |key: &str, given: Option<&Value>, default: bool| -> Result<bool, OpError> {
                match given {
                    None | Some(Value::Null) => Ok(default),
                    Some(Value::Bool(b)) => Ok(*b),
                    Some(_) => Err(OpError::Malformed(format!(
                        "params.{key} must be true or false"
                    ))),
                }
            };
            let length_param = params.get("length").filter(|v| !v.is_null());
            let length = match length_param {
                None => generate::DEFAULT_LENGTH,
                Some(v) => v
                    .as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .ok_or_else(|| {
                        OpError::Malformed("params.length must be a whole number".into())
                    })?,
            };
            let options = generate::Params {
                length,
                symbols: flag("symbols", params.get("symbols"), true)?,
                pronounceable: flag("pronounceable", params.get("pronounceable"), false)?,
            };
            let made = generate::generate(options, &mut OsRng).map_err(|e| match e {
                GenerateError::LengthOutOfRange { .. } => OpError::Malformed(format!(
                    "params.length must be {}–{}",
                    generate::MIN_LENGTH,
                    generate::MAX_LENGTH
                )),
            })?;
            Ok(json!({
                "value": made.value.as_str(),
                "length": options.length,
                "symbols": options.symbols,
                "pronounceable": options.pronounceable,
                "entropyBits": made.entropy_bits,
            }))
        }

        "node.list" => {
            if !scope.holds(Capability::List) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::List,
                });
            }
            let node_ids: Vec<String> = state
                .registry
                .read()
                .expect("registry poisoned")
                .nodes
                .keys()
                .cloned()
                .collect();
            let mut visible = Vec::new();
            for node_id in &node_ids {
                if resolve_capability(state, scope, node_id, Capability::List, now).is_allow() {
                    visible.push(node_id.clone());
                }
            }
            Ok(json!({ "nodes": visible }))
        }

        // Phase 6: the UI's one-request graph contract
        // (`design/graph-engine/VAULT_GRAPH_SPEC.md §2`: "The canvas is fed
        // one object... must render correctly while the vault is fully
        // locked"). Deliberately a new op rather than reshaping
        // `node.list`'s existing `{ "nodes": [ids...] }` — the CLI's
        // `cmd_list`/`cmd_node` already read that shape as plain strings
        // (`crates/cli/src/main.rs`), and the `"Operations"` line in
        // `10_API_AND_MCP.md §1` is representative rather than exhaustive
        // (`whoami` is a real, wired op and isn't listed there either).
        //
        // Same visibility filter as `node.list`/`whoami` (I-22's "only
        // reachable nodes" shape) so a scope that cannot even `list` a node
        // never sees it appear in the graph at all — not dimmed, absent.
        "graph.snapshot" => {
            if !scope.holds(Capability::List) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::List,
                });
            }
            let registry = state.registry.read().expect("registry poisoned");
            let manifests = state.manifests.read().expect("manifests poisoned");
            let node_ids: Vec<String> = registry.nodes.keys().cloned().collect();
            let mut visible = Vec::new();
            for node_id in &node_ids {
                if resolve_capability(state, scope, node_id, Capability::List, now).is_allow() {
                    visible.push(node_id.clone());
                }
            }
            let visible_set: HashSet<&str> = visible.iter().map(String::as_str).collect();

            let owner = state.is_owner_session(scope);
            let mut nodes = Vec::with_capacity(visible.len());
            let mut links = Vec::new();
            for node_id in &visible {
                let node = registry
                    .nodes
                    .get(node_id)
                    .expect("id came from this same registry's own key set");
                let counts = manifests.get(node_id).map(|m| m.counts).unwrap_or_default();
                let locked = state.is_locked() || state.is_node_locked(node_id);
                // `07_TWO_FACTOR.md §2`: `requireTwoFactor` governs whether
                // *reveal* on this node needs gate 2FA at all; §4's "refusal
                // to build a lockout" means a node cannot carry `reveal`/
                // `always` unless the vault-wide gate already exists, so
                // "policy requires it but no gate is enrolled at all" is not
                // a reachable state to represent honestly here — only the
                // enrolled-but-unconfirmed vs. confirmed distinction is.
                let twofa = if node.policy.require_two_factor
                    == credmgr_core::registry::TwoFactorRequirement::Never
                {
                    "none"
                } else if state.is_gate_confirmed(GATE_SCOPE_VAULT) {
                    "required"
                } else {
                    "enrolled"
                };
                let mut row = if node.policy.private_names && !owner {
                    // ADR-083: an opaque row — the id and the shape of the graph,
                    // never the label; the entry count only from three up, and
                    // no TOTP count at all.
                    let shown = visible_count(u64::from(counts.entries));
                    let mut row = json!({
                        "id": node_id,
                        "nameHidden": true,
                        "name": Value::Null,
                        "label": Value::Null,
                        "kind": node.kind,
                        "depth": node.depth,
                        "parentId": node.parent_id,
                        "entryCount": shown,
                        "counts": { "entries": shown, "totp": Value::Null },
                        "gate": { "locked": locked, "twofa": twofa },
                        "health": Value::Null,
                    });
                    if shown.is_none() {
                        row["countHidden"] = json!(true);
                    }
                    row
                } else {
                    json!({
                        "id": node_id,
                        "label": node.label,
                        "kind": node.kind,
                        "depth": node.depth,
                        "parentId": node.parent_id,
                        "counts": { "entries": counts.entries, "totp": counts.totp },
                        "gate": { "locked": locked, "twofa": twofa },
                        // No integrity/expiry computation exists yet (Phase 7);
                        // `null` is documented as "the common case", not a stub.
                        "health": Value::Null,
                    })
                };
                if node.policy.private_names && owner {
                    // The owner sees everything, and a badge saying it is private.
                    row["nameHidden"] = json!(true);
                }
                nodes.push(row);
                if let Some(parent_id) = &node.parent_id {
                    if visible_set.contains(parent_id.as_str()) {
                        links.push(json!({
                            "source": parent_id,
                            "target": node_id,
                            "kind": "structural",
                            "direction": "down",
                        }));
                    }
                }
            }
            let mut meta = json!({ "generatedAt": now, "vaultLocked": state.is_locked() });
            // ADR-080 (C1): the nodes that are sealed and still restorable — id,
            // label and the window, nothing else — so an app can list them after
            // a lock or a restart. Human sessions that may restore (admin) only;
            // for an agent the key is absent, not empty, and the response is
            // exactly what it was before.
            if scope.origin != Origin::Agent && scope.holds(Capability::Admin) {
                meta["sealed"] = Value::Array(
                    state
                        .sealed_node_summaries()
                        .into_iter()
                        .map(|(id, label, sealed_at)| {
                            json!({
                                "id": id,
                                "label": label,
                                "sealedAt": sealed_at,
                                "expiresAt": sealed_at + credmgr_store::archive::RECOVERY_WINDOW_SECONDS,
                            })
                        })
                        .collect(),
                );
            }
            Ok(json!({
                "nodes": nodes,
                "links": links,
                "meta": meta,
            }))
        }

        // `10_API_AND_MCP.md §1`'s `audit.tail` — plaintext, like
        // `registry.json`, so this needs no root key and works while locked
        // (`07 §2`'s "List / read metadata" row: no gate at all). Same
        // reachable-node visibility filter as `node.list`/`graph.snapshot`
        // (I-22's shape) so a record about a node this scope cannot even
        // `list` never appears — not redacted, absent. `18_ENDPOINT_INDEX.md
        // §1.6`: "always redacted for agents" names `Origin::Agent`
        // specifically, not "every non-native origin" — `human-ui`/`cli`/
        // `native` are each a human at the keyboard, `agent` is the one
        // origin an LLM caller (the MCP surface) can carry. `06 §4`'s own
        // resolution order currently hardcodes `Origin::Agent` for both of
        // its no-explicit-token cases, so in practice every call through a
        // real transport today gets the redacted shape — full detail is
        // reachable only via an explicitly-issued non-agent token, which
        // nothing on a real transport does yet (ADR-047's named gap).
        // `credmgr_recent_changes`'s own doc names exactly the four fields
        // the redacted feed carries.
        "audit.tail" => {
            if !scope.holds(Capability::List) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::List,
                });
            }
            let requested = params.get("limit").and_then(Value::as_u64).unwrap_or(50);
            let limit = requested.clamp(1, 500) as usize;
            let records = credmgr_store::audit::tail(&state.paths, limit)
                .map_err(|e| OpError::Internal(e.to_string()))?;
            let visible: Vec<Value> = records
                .into_iter()
                .filter(|r| match &r.node_id {
                    None => true,
                    Some(node_id) => {
                        resolve_capability(state, scope, node_id, Capability::List, now).is_allow()
                    }
                })
                .map(|r| {
                    // ADR-077: a build before this one recorded the caller's
                    // bearer token as `actor` (and inside an anomaly's
                    // `detail`). Those lines are still in old audit files —
                    // rewriting them would break the hash chain — so what
                    // leaves the process is redacted here. New records never
                    // contain a bearer, and this is a no-op for them.
                    let actor = crate::token::redact_bearer_tokens(&r.actor);
                    if scope.origin == Origin::Agent {
                        json!({
                            "id": r.id, "timestamp": r.timestamp,
                            "actor": actor, "action": r.action,
                        })
                    } else {
                        // ADR-083: a non-owner, non-agent reader of a private node
                        // gets the record without the entry it names or the free
                        // text recorded beside it.
                        let blind = r
                            .node_id
                            .as_deref()
                            .is_some_and(|n| node_hides_names(state, scope, n));
                        let detail = (!blind)
                            .then(|| r.detail.as_deref().map(crate::token::redact_bearer_tokens))
                            .flatten();
                        json!({
                            "id": r.id, "timestamp": r.timestamp, "actor": actor,
                            "action": r.action, "node": r.node_id, "decision": r.decision,
                            "detail": detail, "entry": if blind { None } else { r.entry_id.clone() },
                            "generation": r.generation,
                        })
                    }
                })
                .collect();
            Ok(json!({ "records": visible }))
        }

        // `18_ENDPOINT_INDEX.md §1.6`: "full record needs presence" — the
        // same honest gap `node.reparent` already names and tests for real
        // (ADR-047; `grant.create` names the identical requirement in the
        // docs but has no broker op behind it yet, so it is not a built
        // precedent, just the same documented shape): no Phase 3/4/5
        // transport can ever set `presence_attested: true`, so the positive
        // path — an unredacted single record by id — is unconditionally
        // refused here, on every surface this build has, until Phase 5's
        // native shell exists.
        // Checking the capability first (rather than looking the id up and
        // refusing regardless) keeps this consistent with every other
        // capability-gated op: a caller that never held `admin` learns
        // nothing about whether the id even exists.
        "audit.get" => {
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            Err(OpError::PresenceRequired {
                operation: "audit.get".to_string(),
            })
        }

        "entry.list" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            if !scope.holds(Capability::List) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::List,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::List, now);
            let manifests = state.manifests.read().expect("manifests poisoned");
            let entries = manifests
                .get(target_node)
                .map(|m| m.entries.as_slice())
                .unwrap_or(&[]);
            let visible = if decision.is_allow() {
                entries.iter().collect::<Vec<_>>()
            } else {
                narrow_entries(state, scope, target_node, Capability::List, entries, now)
            };
            if visible.is_empty() && !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::List,
                    rule_name(decision),
                    now,
                ));
            }
            second_factor_gate(state, scope, target_node, GateKind::Read, now)?;
            if node_hides_names(state, scope, target_node) {
                // ADR-083: the node is a count and nothing else.
                let generation = manifests
                    .get(target_node)
                    .map(|m| m.generation)
                    .unwrap_or(0);
                let shown = visible_count(visible.len() as u64);
                let mut body = json!({
                    "node": target_node, "ids": [], "names": [], "entries": [],
                    "nameHidden": true, "count": shown, "generation": generation,
                });
                if shown.is_none() {
                    body["countHidden"] = json!(true);
                }
                return Ok(body);
            }
            let ids: Vec<&str> = visible.iter().map(|e| e.id.as_str()).collect();
            let names: Vec<&str> = visible.iter().map(|e| e.name.as_str()).collect();
            // ADR-077 (G1): the same entries again with the metadata the signed
            // manifest already holds in the clear — and nothing else. No field
            // label, no value, no hash: `visible` is the very list `ids` and
            // `names` come from (list-gated, then `narrow_entries` for a caller
            // with only per-entry grants), so a caller sees metadata for exactly
            // the entries it could already name. `rotatedAt`/`expiresAt` are
            // `null` when the manifest records none.
            //
            // **Human sessions only** (orchestrator decision, 2026-10-02, for
            // 2.0.0-beta.1): an `Origin::Agent` caller — the origin an LLM can
            // carry, i.e. the MCP surface and every tokenless cwd-scoped
            // process — keeps exactly the response it had before ADR-077
            // (`node`, `ids`, `names`, `generation`); the key is absent, not
            // empty. `06 §3` describes `list` as "names, refs, types, counts"
            // for an agent; type/sensitivity/rotation/expiry metadata is for the
            // person at the keyboard until that reading is decided deliberately.
            let entries_metadata: Option<Vec<Value>> = (scope.origin != Origin::Agent).then(|| {
                visible
                    .iter()
                    .map(|e| {
                        json!({
                            "id": e.id, "name": e.name, "type": e.entry_type,
                            "sensitivity": e.sensitivity, "fieldCount": e.field_count,
                            "hasTotp": e.has_totp,
                            "modified": e.modified, "rotatedAt": e.rotated_at,
                            "expiresAt": e.expires_at,
                        })
                    })
                    .collect()
            });
            // Phase 4: a client that wants to `entry.update` needs the
            // manifest's current generation to satisfy F-9's optimistic
            // concurrency check (`entry.update` requires `params.generation`)
            // — without it, no caller could ever perform a first update, only
            // ever learn a generation *after* one succeeds. Additive field,
            // no existing caller reads a fixed response shape (checked:
            // `isolation.rs`'s `entry.list` assertions index `ids`/`names`
            // only).
            let generation = manifests
                .get(target_node)
                .map(|m| m.generation)
                .unwrap_or(0);
            let mut body = json!({
                "node": target_node, "ids": ids, "names": names,
                "generation": generation,
            });
            if let Some(entries_metadata) = entries_metadata {
                body["entries"] = Value::Array(entries_metadata);
            }
            Ok(body)
        }

        // `10_API_AND_MCP.md §2/§3.1`: `credmgr search <term>` / `credmgr_search`,
        // capability `list`. Scans entry *names* only (the plaintext manifest,
        // never envelope contents) across every node in the registry, but —
        // this is the whole point of I-3 — only entries this scope could
        // already `entry.list` are ever compared against `term`. A node the
        // caller cannot reach contributes zero candidate rows, so a match
        // that exists only in an out-of-scope node and a term that matches
        // nowhere at all produce the identical `{ "results": [] }" — no
        // branch here can make the result count itself a leak.
        "search" => {
            let term = params["term"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.term is required".into()))?;
            if !scope.holds(Capability::List) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::List,
                });
            }
            let term_lower = term.to_lowercase();
            let node_ids: Vec<String> = state
                .registry
                .read()
                .expect("registry poisoned")
                .nodes
                .keys()
                .cloned()
                .collect();
            let manifests = state.manifests.read().expect("manifests poisoned");
            let mut results = Vec::new();
            for node_id in &node_ids {
                let decision = resolve_capability(state, scope, node_id, Capability::List, now);
                let entries = manifests
                    .get(node_id)
                    .map(|m| m.entries.as_slice())
                    .unwrap_or(&[]);
                let visible = if decision.is_allow() {
                    entries.iter().collect::<Vec<_>>()
                } else {
                    narrow_entries(state, scope, node_id, Capability::List, entries, now)
                };
                // ADR-083: a name-blind reader's search never matches on, or
                // returns, a name of a private node. ADR-085: nor does it read a
                // node that is asking for a second factor on every read.
                if node_hides_names(state, scope, node_id)
                    || second_factor_gate(state, scope, node_id, GateKind::Read, now).is_err()
                {
                    continue;
                }
                for entry in visible {
                    if entry.name.to_lowercase().contains(&term_lower) {
                        results.push(json!({
                            "node": node_id,
                            "id": entry.id,
                            "name": entry.name,
                        }));
                    }
                }
            }
            Ok(json!({ "results": results }))
        }

        "entry.reveal" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;
            // ADR-078: narrow the answer to these fields (each must exist).
            let field_ids = entry_doc::opt_string_list(params.get("fieldIds"), "fieldIds")?;
            if !scope.holds(Capability::Reveal) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Reveal,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Reveal, now);
            if !decision.is_allow() {
                // R1 (locked) is not a flat denial for `reveal` — a target
                // that would otherwise be readable gets a one-tap approval
                // path instead (`06 §5` R1 row, `07 §5a`, ADR-042). A target
                // that was never reachable regardless of lock state (R8, no
                // grant) is an ordinary denial — locking the vault must not
                // turn an unreachable node into a notification.
                if decision.rule() == access::Rule::R1
                    && would_be_allowed_ignoring_lock(
                        state,
                        scope,
                        target_node,
                        Capability::Reveal,
                        now,
                    )
                {
                    return reveal_via_approval(
                        state,
                        scope,
                        target_node,
                        entry_id,
                        field_ids.as_deref(),
                        now,
                    );
                }
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Reveal,
                    rule_name(decision),
                    now,
                ));
            }
            second_factor_gate(state, scope, target_node, GateKind::Reveal, now)?;
            let Some(node_priv) = state.hot_node_key(target_node) else {
                return Err(locked_refusal(state, target_node));
            };
            let doc = open_entry_doc(state, target_node, entry_id, &node_priv)?;
            entry_doc::reveal_json(target_node, entry_id, &doc, field_ids.as_deref())
        }

        // ADR-078: one entry's metadata — field ids, labels, types, masking and
        // the entry's own type/sensitivity — and **never a value** (`10 §1.4`
        // row 7). Labels are encrypted with the values, so this needs the node
        // key: a locked vault or node is refused (`vault_locked` /
        // `node_locked`) with no approval path — labels are not worth a prompt.
        // `read` capability, resolved against the node exactly as `entry.update`
        // resolves `update`; a pending (tray) entry is not in the manifest yet
        // and is `not_found`.
        "entry.get" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;
            if !scope.holds(Capability::Read) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Read,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Read, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Read,
                    rule_name(decision),
                    now,
                ));
            }
            second_factor_gate(state, scope, target_node, GateKind::Read, now)?;
            let Some(node_priv) = state.hot_node_key(target_node) else {
                return Err(locked_refusal(state, target_node));
            };
            let (generation, entry) = {
                let manifests = state.manifests.read().expect("manifests poisoned");
                let body = manifests.get(target_node);
                (
                    body.map_or(0, |b| b.generation),
                    body.and_then(|b| b.entries.iter().find(|e| e.id == entry_id).cloned()),
                )
            };
            let Some(entry) = entry else {
                return Err(OpError::NotFound(format!(
                    "no entry {entry_id} on node {target_node}"
                )));
            };
            let loaded = entry_doc::load(state, target_node, entry_id, &node_priv, Some(&entry))?;
            let mut body = entry_doc::get_json(target_node, &entry, generation, &loaded.doc);
            if node_hides_names(state, scope, target_node) {
                // ADR-083: the entry's name and its field labels are names.
                body["name"] = Value::Null;
                body["nameHidden"] = json!(true);
                if let Some(rows) = body["fields"].as_array_mut() {
                    for row in rows {
                        row["label"] = Value::Null;
                    }
                }
            }
            Ok(body)
        }

        // `07 §6`'s seed/code split, "the important part": a stored TOTP
        // item's *code* is `reveal`-gated exactly like any other entry
        // value — but the stored value itself is the base32 *seed*, and
        // this op never returns it, only the current 6-digit code computed
        // from it.
        "totp.code" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;
            // ADR-078: which field holds the seed, on an entry with several.
            let field = entry_doc::opt_str(&params["field"], "field")?;
            if !scope.holds(Capability::Reveal) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Reveal,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Reveal, now);
            if !decision.is_allow() {
                // Deliberately NOT `reveal_via_approval` on a locked-but-
                // otherwise-reachable target (unlike `entry.reveal` above):
                // that path's response shape is the raw entry value, and
                // this op exists specifically so the raw TOTP seed is never
                // returned to anything (`07 §6`) — reusing the approval
                // path here would leak the seed through a differently-named
                // channel the moment the vault is locked. `totp.code` on a
                // locked vault is an ordinary denial, full stop.
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Reveal,
                    rule_name(decision),
                    now,
                ));
            }
            second_factor_gate(state, scope, target_node, GateKind::Reveal, now)?;
            let Some(node_priv) = state.hot_node_key(target_node) else {
                return Err(locked_refusal(state, target_node));
            };
            // ADR-078: the seed is one field's value — the one `field` names,
            // else the entry's only field, else its single TOTP-seed field; an
            // entry with no clear answer is refused rather than guessed at.
            let doc = open_entry_doc(state, target_node, entry_id, &node_priv)?;
            let chosen = entry_doc::select_totp_field(&doc, field)?;
            // The class `entry.reveal` withholds is the class a code is computed from (audit P0-1): a field that is
            // not typed as a seed is neither hidden from a reveal nor used here, so the two can never disagree.
            if fields::effective_type(chosen) != credmgr_core::inference::FieldType::TotpSeed {
                return Err(OpError::Malformed(
                    "that field is not a TOTP seed; its owner can set its type to totp-seed".into(),
                ));
            }
            let seed_base32 = chosen.value.clone();
            // ADR-077 (MX-1): what is stored is whatever was pasted, so every way
            // it can fail to be a usable seed is a *refusal the caller can act
            // on* — never a panic (an 80-bit seed used to kill the connection
            // thread here) and never `internal`, which says "the broker is
            // broken". The message names what is wrong with the value, never the
            // value itself.
            let totp = credmgr_core::totp::Totp::from_stored_secret(
                &seed_base32,
                credmgr_core::totp::TotpAlgorithm::Sha1,
                credmgr_core::totp::DEFAULT_DIGITS,
                credmgr_core::totp::DEFAULT_PERIOD,
            )
            .map_err(|e| match e {
                credmgr_core::error::CryptoError::InvalidTotpSecret => {
                    OpError::Malformed("the stored value is not a base32 TOTP seed".into())
                }
                credmgr_core::error::CryptoError::TotpSecretTooShort { bits } => {
                    OpError::Malformed(format!(
                        "the stored TOTP seed is {bits} bits; codes are computed only from seeds \
                         of at least 80 bits (16 base32 characters)"
                    ))
                }
                _ => OpError::Internal("the stored TOTP seed could not be used".into()),
            })?;
            let code = totp.code(now.max(0) as u64);
            Ok(json!({ "node": target_node, "entry": entry_id, "code": code }))
        }

        // `07 §6`: "Nothing in the API returns a seed to a non-native
        // transport." `10_API_AND_MCP.md §3.2`: "No TOTP seed." Gated the
        // same way `node.reparent`'s positive path is (`Capability::Admin`
        // substituting for the missing 2FA factor, then an unconditional
        // `PresenceRequired` — no Phase 3/4 transport can ever set
        // `presence_attested: true`, so this op is unreachable end-to-end
        // on every transport that exists today, which is exactly correct).
        "totp.seed" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;
            // ADR-078: accepted so the op's shape matches `totp.code`'s; the op
            // still answers `presence_required` whichever field is meant.
            let _field = entry_doc::opt_str(&params["field"], "field")?;
            if !scope.holds(Capability::Reveal) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Reveal,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Reveal, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Reveal,
                    rule_name(decision),
                    now,
                ));
            }
            Err(OpError::PresenceRequired {
                operation: "totp.seed".to_string(),
            })
        }

        // F-1: permitted even while locked — `resolve()`'s R1 only denies
        // `reveal`/`update`, never `create` (`06_ACCESS_GRAPH.md §1`).
        // ADR-073: many entries into one node in one call — the `.env` import
        // and a many-entry paste. Everything that can be checked is checked
        // before the first write: the `create` gate, every name, uniqueness
        // inside the batch and against the node and its tray, and (ADR-078,
        // which made the items multi-field) every item's body — a malformed
        // field, a label with a control character, a document over 16 MiB — and
        // the batch's total encoded size (64 MiB). Each item is then created by
        // the very function `entry.create` uses, so sealing, the locked-write
        // tray and the envelope digest are shared, not copied. A failure part-way
        // (a full disk) stops the batch and reports exactly what was created, as
        // a success, so what was created is saved.
        "entry.create_batch" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let items = params["entries"]
                .as_array()
                .ok_or_else(|| OpError::Malformed("params.entries is required".into()))?;
            if items.is_empty() || items.len() > BATCH_MAX {
                return Err(OpError::Malformed(format!(
                    "params.entries must hold 1–{BATCH_MAX} entries"
                )));
            }
            if !scope.holds(Capability::Create) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Create,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Create, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Create,
                    rule_name(decision),
                    now,
                ));
            }
            let mut parsed: Vec<(&str, EntryDoc)> = Vec::with_capacity(items.len());
            let mut seen: HashSet<String> = HashSet::new();
            let mut total_bytes: usize = 0;
            for (i, item) in items.iter().enumerate() {
                let name = item["name"]
                    .as_str()
                    .filter(|n| !n.is_empty())
                    .ok_or_else(|| OpError::Malformed(format!("entries[{i}].name is required")))?;
                valid_entry_name(name, &format!("entries[{i}].name"))?;
                if !seen.insert(canonical_name(name)) {
                    return Err(OpError::Malformed(format!(
                        "entries[{i}]: the name {name:?} appears twice in this batch"
                    )));
                }
                // Each item takes the body `entry.create` takes. A refusal here
                // names the item's index and never what it carried.
                let at = |what: &str| format!("entries[{i}].{what}");
                let doc = CreateBody {
                    value: entry_doc::opt_str(&item["value"], &at("value"))?,
                    label: entry_doc::opt_str(&item["label"], &at("label"))?,
                    fields: entry_doc::opt_list::<FieldInput>(
                        item.get("fields"),
                        &at("fields"),
                        entry_doc::FIELD_INPUT_KEYS,
                    )?,
                    entry_type: entry_doc::parse_override::<EntryType>(
                        item.get("entryType"),
                        &at("entryType"),
                    )?,
                    sensitivity: entry_doc::parse_override::<Sensitivity>(
                        item.get("sensitivity"),
                        &at("sensitivity"),
                    )?,
                }
                .into_doc()
                .map_err(|e| match e {
                    OpError::Malformed(m) => OpError::Malformed(format!("entries[{i}]: {m}")),
                    other => other,
                })?;
                total_bytes = total_bytes.saturating_add(entry_doc::encoded_len(&doc)?);
                if total_bytes > entry_doc::BATCH_MAX_BYTES {
                    return Err(OpError::Malformed(format!(
                        "params.entries hold more than {} MiB in all; split the batch",
                        entry_doc::BATCH_MAX_BYTES / (1024 * 1024)
                    )));
                }
                parsed.push((name, doc));
            }
            {
                let manifests = state.manifests.read().expect("manifests poisoned");
                let existing = manifests.get(target_node);
                let pending = state.list_pending(target_node);
                if let Some((name, _)) = parsed.iter().find(|(name, _)| {
                    let canon = canonical_name(name);
                    existing.is_some_and(|m| {
                        canon_taken(&canon, m.entries.iter().map(|e| e.name.as_str()))
                    }) || canon_taken(&canon, pending.iter().map(|p| p.name.as_str()))
                }) {
                    return Err(OpError::EntryExists {
                        node: target_node.to_string(),
                        name: (*name).to_string(),
                    });
                }
            }
            let total = parsed.len();
            let mut created = Vec::with_capacity(total);
            let mut generation = Value::Null;
            let mut failed = Value::Null;
            for (i, (name, doc)) in parsed.into_iter().enumerate() {
                match create_entry(state, target_node, name, &doc, now) {
                    Ok(c) => {
                        if let Some(g) = c.generation {
                            generation = json!(g);
                        }
                        created.push(json!({
                            "name": name,
                            "entry": c.entry_id,
                            "pending": c.pending,
                            "fieldCount": c.field_ids.len(),
                        }));
                    }
                    Err(e) => {
                        failed = json!({ "index": i, "name": name, "error": format!("{e:?}") });
                        break;
                    }
                }
            }
            let mut body = json!({
                "node": target_node,
                "created": created,
                "complete": failed.is_null(),
                "failed": failed,
                "total": total,
                "generation": generation,
            });
            let typed: Vec<&str> = items.iter().filter_map(|i| i["name"].as_str()).collect();
            name_warnings(&mut body, &typed);
            Ok(body)
        }

        "entry.create" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let name = params["name"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.name is required".into()))?;
            valid_entry_name(name, "params.name")?;
            // ADR-078: exactly one of `value` (with an optional `label`) and
            // `fields`; `entryType` / `sensitivity` pin the entry's own type and
            // sensitivity (`"auto"` or absent = inferred from the fields).
            let value = entry_doc::opt_str(&params["value"], "value")?;
            let label = entry_doc::opt_str(&params["label"], "label")?;
            let fields = entry_doc::opt_list::<FieldInput>(
                params.get("fields"),
                "fields",
                entry_doc::FIELD_INPUT_KEYS,
            )?;
            let entry_type =
                entry_doc::parse_override::<EntryType>(params.get("entryType"), "entryType")?;
            let sensitivity =
                entry_doc::parse_override::<Sensitivity>(params.get("sensitivity"), "sensitivity")?;
            let doc = CreateBody {
                value,
                label,
                fields,
                entry_type,
                sensitivity,
            }
            .into_doc()?;

            if !scope.holds(Capability::Create) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Create,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Create, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Create,
                    rule_name(decision),
                    now,
                ));
            }

            let created = create_entry(state, target_node, name, &doc, now)?;
            let mut body = created.to_json(target_node);
            name_warnings(&mut body, &[name]);
            Ok(body)
        }

        // F-1: requires the vault (and the node) unlocked — "a legitimate
        // update implies you could have read what you are replacing"
        // (`06_ACCESS_GRAPH.md §3`). F-9: generation-checked, conflict on a
        // stale value rather than a silent overwrite. ADR-078: a read-modify-
        // write of the entry's field document — `value` (with `field` naming
        // one field when the entry has several) replaces one value, `fields`
        // replaces the whole list, `entryType` / `sensitivity` set or clear the
        // entry's own overrides; keeps no history, as it never did.
        "entry.update" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;
            let expected_generation = params["generation"]
                .as_u64()
                .ok_or_else(|| OpError::Malformed("params.generation is required".into()))?;
            let value = entry_doc::opt_str(&params["value"], "value")?;
            let label = entry_doc::opt_str(&params["label"], "label")?;
            let field = entry_doc::opt_str(&params["field"], "field")?;
            let fields = entry_doc::opt_list::<FieldReplace>(
                params.get("fields"),
                "fields",
                entry_doc::FIELD_REPLACE_KEYS,
            )?;
            let entry_type =
                entry_doc::parse_override::<EntryType>(params.get("entryType"), "entryType")?;
            let sensitivity =
                entry_doc::parse_override::<Sensitivity>(params.get("sensitivity"), "sensitivity")?;
            let edit = EntryEdit::new(value, label, field, fields, entry_type, sensitivity)?;

            let mutated = mutate_entry(
                state,
                scope,
                now,
                target_node,
                entry_id,
                expected_generation,
                Mutation::Update,
                |doc| edit.apply(doc),
            )?;
            Ok(mutated_json(target_node, entry_id, &mutated))
        }

        // ADR-048: replace the value and retain the previous ciphertext.
        // Same policy gate as `entry.update` ("a legitimate rotation implies
        // you could have read what you are replacing") — `Capability::
        // Update`, R1 -> `VaultLocked`, F-9 generation-checked. Unlike
        // `entry.update`, the old envelope is kept (a plain file copy — no
        // decrypt/re-encrypt needed; rotate never reads the entry's
        // plaintext any more than create/update do, it only seals a new
        // value to the node's PUBLIC key) so a future `entry.history` can
        // show it. Nothing restores from this history yet — see BUILD_LOG.
        "entry.rotate" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;
            let expected_generation = params["generation"]
                .as_u64()
                .ok_or_else(|| OpError::Malformed("params.generation is required".into()))?;
            // Same body as `entry.update` (ADR-078).
            let value = entry_doc::opt_str(&params["value"], "value")?;
            let label = entry_doc::opt_str(&params["label"], "label")?;
            let field = entry_doc::opt_str(&params["field"], "field")?;
            let fields = entry_doc::opt_list::<FieldReplace>(
                params.get("fields"),
                "fields",
                entry_doc::FIELD_REPLACE_KEYS,
            )?;
            let entry_type =
                entry_doc::parse_override::<EntryType>(params.get("entryType"), "entryType")?;
            let sensitivity =
                entry_doc::parse_override::<Sensitivity>(params.get("sensitivity"), "sensitivity")?;
            let edit = EntryEdit::new(value, label, field, fields, entry_type, sensitivity)?;

            // ADR-055: the previous envelope AND the signed pre-rotate manifest
            // snapshot are retained under the pre-rotate generation, side by
            // side — `entry.undo` needs both to restore a rotate correctly.
            let mutated = mutate_entry(
                state,
                scope,
                now,
                target_node,
                entry_id,
                expected_generation,
                Mutation::Rotate,
                |doc| edit.apply(doc),
            )?;
            let mut body = mutated_json(target_node, entry_id, &mutated);
            body["rotatedAt"] = json!(now);
            Ok(body)
        }

        // ADR-078: the four field operations. Each is a read-modify-write of one
        // entry's field document under the `update` capability — the same gate,
        // lock, generation check and history as `entry.rotate`, so each is
        // undoable through `entry.undo` — and none is a rotation (`rotatedAt`
        // stays put). Each answers `{node, entry, generation, fieldCount,
        // fieldIds}`.
        //
        // `field.add` appends (or inserts at `position`) fields — "paste more"
        // adds, it never replaces (`08 §7`) — and also answers `added`, the ids
        // it minted, in order.
        "field.add" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;
            let expected_generation = params["generation"]
                .as_u64()
                .ok_or_else(|| OpError::Malformed("params.generation is required".into()))?;
            let inputs = entry_doc::opt_list::<FieldInput>(
                params.get("fields"),
                "fields",
                entry_doc::FIELD_INPUT_KEYS,
            )?
            .ok_or_else(|| OpError::Malformed("params.fields is required".into()))?;
            let position = entry_doc::opt_index(params.get("position"), "position")?;

            let mut added: Vec<String> = Vec::new();
            let mutated = mutate_entry(
                state,
                scope,
                now,
                target_node,
                entry_id,
                expected_generation,
                Mutation::Field,
                |doc| {
                    let (next, ids) =
                        fields::add(doc, inputs, position).map_err(entry_doc::edit_error)?;
                    added = ids;
                    Ok(next)
                },
            )?;
            let mut body = mutated_json(target_node, entry_id, &mutated);
            body["added"] = json!(added);
            Ok(body)
        }

        // `field.update` changes one field: `patch` carries any of `label`,
        // `value`, `type`, `masked`; `type` / `masked` take `"auto"` to go back to
        // inferring. A changed value or label re-infers an un-pinned type; a
        // pinned type sticks.
        "field.update" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;
            let expected_generation = params["generation"]
                .as_u64()
                .ok_or_else(|| OpError::Malformed("params.generation is required".into()))?;
            let field = params["field"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.field is required".into()))?;
            let patch_param = params
                .get("patch")
                .ok_or_else(|| OpError::Malformed("params.patch is required".into()))?;
            let patch: FieldPatch =
                entry_doc::parse_object(patch_param, "patch", entry_doc::FIELD_PATCH_KEYS)?;
            let is_agent = scope.origin == Origin::Agent || !scope.holds(Capability::Admin);

            let mutated = mutate_entry(
                state,
                scope,
                now,
                target_node,
                entry_id,
                expected_generation,
                Mutation::Field,
                |doc| {
                    // A seed cannot be retyped away from the seed class by anyone but the owner: the type decides what a
                    // reveal withholds, so a retype by an agent would turn a protected seed into a readable value
                    // (final audit, re-verification). Only a retype is checked; changing the value is the caller's own write.
                    if is_agent && !matches!(patch.field_type, credmgr_core::fields::Override::Keep)
                    {
                        if let Some(current) = doc.field(field) {
                            if fields::effective_type(current)
                                == credmgr_core::inference::FieldType::TotpSeed
                            {
                                return Err(OpError::CapabilityNotHeld {
                                    capability: Capability::Admin,
                                });
                            }
                        }
                    }
                    fields::patch(doc, field, patch).map_err(entry_doc::edit_error)
                },
            )?;
            Ok(mutated_json(target_node, entry_id, &mutated))
        }

        // `field.remove` drops one field. An entry keeps at least one: removing
        // the last is refused (remove the entry instead). Recoverable with
        // `entry.undo`.
        "field.remove" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;
            let expected_generation = params["generation"]
                .as_u64()
                .ok_or_else(|| OpError::Malformed("params.generation is required".into()))?;
            let field = params["field"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.field is required".into()))?;

            let mutated = mutate_entry(
                state,
                scope,
                now,
                target_node,
                entry_id,
                expected_generation,
                Mutation::Field,
                |doc| fields::remove(doc, field).map_err(entry_doc::edit_error),
            )?;
            Ok(mutated_json(target_node, entry_id, &mutated))
        }

        // `field.reorder`: `order` must list every current field id exactly once.
        "field.reorder" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;
            let expected_generation = params["generation"]
                .as_u64()
                .ok_or_else(|| OpError::Malformed("params.generation is required".into()))?;
            let order = entry_doc::opt_string_list(params.get("order"), "order")?
                .ok_or_else(|| OpError::Malformed("params.order is required".into()))?;

            let mutated = mutate_entry(
                state,
                scope,
                now,
                target_node,
                entry_id,
                expected_generation,
                Mutation::Field,
                |doc| fields::reorder(doc, &order).map_err(entry_doc::edit_error),
            )?;
            Ok(mutated_json(target_node, entry_id, &mutated))
        }

        // ADR-048: soft delete into a 7-day recovery archive. Same policy
        // gate as `entry.update`/`entry.rotate` — `Capability::Update`, R1
        // -> `VaultLocked`, F-9 generation-checked. Unlike `node.seal`,
        // removing an entry never leaves its owning node, so no node key
        // (hot or otherwise) is ever touched — only the root key, to sign
        // the archive's integrity record (`crates/store::entry_archive`).
        "entry.remove" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;
            let expected_generation = params["generation"]
                .as_u64()
                .ok_or_else(|| OpError::Malformed("params.generation is required".into()))?;

            if !scope.holds(Capability::Update) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Update,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Update, now);
            if !decision.is_allow() {
                if decision.rule() == access::Rule::R1 {
                    return Err(locked_refusal(state, target_node));
                }
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Update,
                    rule_name(decision),
                    now,
                ));
            }

            let node_lock = state.node_write_lock(target_node);
            let _guard = node_lock.lock().expect("node write lock poisoned");

            let (current_generation, snapshot) = {
                let manifests = state.manifests.read().expect("manifests poisoned");
                match manifests.get(target_node) {
                    Some(body) => (
                        body.generation,
                        body.entries.iter().find(|e| e.id == entry_id).cloned(),
                    ),
                    None => (0, None),
                }
            };
            let Some(snapshot) = snapshot else {
                return Err(OpError::NotFound(format!(
                    "no entry {entry_id} on node {target_node}"
                )));
            };
            if expected_generation != current_generation {
                return Err(OpError::Conflict {
                    node_id: target_node.to_string(),
                    expected_generation,
                    current_generation,
                });
            }

            use secrecy::ExposeSecret;
            let root_key = state.reauth_root_key("entry remove").map_err(|_| {
                OpError::Internal(
                    "could not re-derive the root key to archive the removed entry".into(),
                )
            })?;
            credmgr_store::entry_archive::remove(
                &state.paths,
                root_key.expose_secret(),
                target_node,
                &snapshot,
                now,
            )
            .map_err(|e| OpError::Internal(format!("archiving removed entry: {e}")))?;

            state.remove_manifest_entries(target_node, std::slice::from_ref(&entry_id.to_string()));
            let generation = state
                .manifests
                .read()
                .expect("manifests poisoned")
                .get(target_node)
                .map(|b| b.generation)
                .unwrap_or(current_generation);

            Ok(
                json!({ "node": target_node, "entry": entry_id, "removed": true, "generation": generation }),
            )
        }

        // ADR-048: undo an `entry.remove` within its 7-day window. `mode`
        // mirrors V1's `changelog.js` undo-delete collision handling: a
        // live entry may since have reclaimed the removed name.
        // `"replace"` (the default) refuses outright rather than silently
        // overwriting whatever now holds that name; `"keep-both"` restores
        // it as `"<name> old"` (or `"<name> old N"` on a further collision)
        // so neither entry is ever lost. Addressed by `{node, entry}`
        // directly — `entry.undo` (ADR-055) is the id-addressed wrapper
        // `10_API_AND_MCP.md` documents; its `entry.remove` branch is a
        // thin call into `do_entry_restore`, the exact mechanics this arm
        // also calls, so there is one implementation, not two.
        "entry.restore" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;
            let expected_generation = params["generation"]
                .as_u64()
                .ok_or_else(|| OpError::Malformed("params.generation is required".into()))?;
            let mode = params["mode"].as_str().unwrap_or("replace");
            if mode != "replace" && mode != "keep-both" {
                return Err(OpError::Malformed(format!(
                    "params.mode must be \"replace\" or \"keep-both\", got {mode:?}"
                )));
            }

            if !scope.holds(Capability::Update) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Update,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Update, now);
            if !decision.is_allow() {
                if decision.rule() == access::Rule::R1 {
                    return Err(locked_refusal(state, target_node));
                }
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Update,
                    rule_name(decision),
                    now,
                ));
            }

            let node_lock = state.node_write_lock(target_node);
            let _guard = node_lock.lock().expect("node write lock poisoned");

            let current_generation = state
                .manifests
                .read()
                .expect("manifests poisoned")
                .get(target_node)
                .map(|b| b.generation)
                .unwrap_or(0);
            if expected_generation != current_generation {
                return Err(OpError::Conflict {
                    node_id: target_node.to_string(),
                    expected_generation,
                    current_generation,
                });
            }

            let hide = node_hides_names(state, scope, target_node);
            do_entry_restore(state, target_node, entry_id, mode, hide, now)
        }

        // ADR-055: `entry.undo`, addressed by `{node, id}` where `id` is an
        // `audit.tail`/`audit.get` record id — the id-addressed op
        // `10_API_AND_MCP.md §1`/`§3.1` document. `node` is required
        // up front (not derived from the record) so authorisation happens
        // *before* the lookup, matching every other mutating op and
        // `audit.get`'s own "capability first" ordering — a caller without
        // access to `node` learns nothing about whether `id` is real or
        // belongs to a different node (both cases: `not_found`).
        // `Capability::Update`, R1 -> `VaultLocked`, F-9 generation-checked,
        // identical gate to `rotate`/`remove`/`restore`. Same `mode`
        // (`replace`/`keep-both`) as `entry.restore`, used only for the
        // `entry.remove` branch.
        "entry.undo" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let record_id = params["id"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.id is required".into()))?;
            let expected_generation = params["generation"]
                .as_u64()
                .ok_or_else(|| OpError::Malformed("params.generation is required".into()))?;
            let mode = params["mode"].as_str().unwrap_or("replace");
            if mode != "replace" && mode != "keep-both" {
                return Err(OpError::Malformed(format!(
                    "params.mode must be \"replace\" or \"keep-both\", got {mode:?}"
                )));
            }

            if !scope.holds(Capability::Update) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Update,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Update, now);
            if !decision.is_allow() {
                if decision.rule() == access::Rule::R1 {
                    return Err(locked_refusal(state, target_node));
                }
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Update,
                    rule_name(decision),
                    now,
                ));
            }

            let node_lock = state.node_write_lock(target_node);
            let _guard = node_lock.lock().expect("node write lock poisoned");

            let current_generation = state
                .manifests
                .read()
                .expect("manifests poisoned")
                .get(target_node)
                .map(|b| b.generation)
                .unwrap_or(0);
            if expected_generation != current_generation {
                return Err(OpError::Conflict {
                    node_id: target_node.to_string(),
                    expected_generation,
                    current_generation,
                });
            }

            let record = credmgr_store::audit::get(&state.paths, record_id)
                .map_err(|e| OpError::Internal(format!("looking up audit record: {e}")))?
                .ok_or_else(|| OpError::NotFound(format!("no audit record {record_id}")))?;

            // A record naming a different node (or no node at all) is
            // indistinguishable from a bogus id — never a hint about what
            // exists elsewhere.
            if record.node_id.as_deref() != Some(target_node) {
                return Err(OpError::NotFound(format!("no audit record {record_id}")));
            }
            if record.decision.as_deref() != Some("allow") {
                return Err(OpError::NotUndoable {
                    id: record_id.to_string(),
                    reason: "that action was denied or never completed",
                });
            }

            let undone = match record.action.as_str() {
                "entry.remove" => {
                    let entry_id = record.entry_id.as_deref().ok_or_else(|| {
                        OpError::Internal(format!(
                            "audit record {record_id} for entry.remove has no entryId"
                        ))
                    })?;
                    let hide = node_hides_names(state, scope, target_node);
                    do_entry_restore(state, target_node, entry_id, mode, hide, now).map(|mut v| {
                        v["restored"] = json!({
                            "action": "entry.remove", "entry": entry_id,
                            "name": v["restoredName"].clone(),
                        });
                        v
                    })
                }
                // ADR-078: a field edit keeps the same retained history a
                // rotation does, so it is undone the same way. One pattern per
                // line, so the guards that count this match's arms stay legible.
                "entry.rotate" | "field.add" | "field.update" | "field.remove"
                | "field.reorder" => {
                    let action = record.action.as_str();
                    let entry_id = record.entry_id.as_deref().ok_or_else(|| {
                        OpError::Internal(format!(
                            "audit record {record_id} for {action} has no entryId"
                        ))
                    })?;
                    let post_change_generation = record.generation.ok_or_else(|| {
                        OpError::Internal(format!(
                            "audit record {record_id} for {action} has no generation"
                        ))
                    })?;
                    let pre_change_generation = post_change_generation.saturating_sub(1);
                    undo_rotate(
                        state,
                        target_node,
                        entry_id,
                        pre_change_generation,
                        action,
                        action == "entry.rotate",
                        now,
                    )
                    .map(|mut v| {
                        v["restored"] = json!({
                            "action": action, "entry": entry_id,
                            "fieldCount": v["fieldCount"].clone(),
                        });
                        v
                    })
                }
                _ => Err(OpError::NotUndoable {
                    id: record_id.to_string(),
                    reason: "only entry.rotate, entry.remove and the field edits \
                             (field.add, field.update, field.remove, field.reorder) can be undone",
                }),
            };
            // ADR-086 (4.5): additive `ok` and `restored` — what the window needs to
            // say "restored" and what was put back; the old keys are unchanged.
            undone.map(|mut v| {
                v["ok"] = json!(true);
                v
            })
        }

        // `18_ENDPOINT_INDEX.md`'s op names for the locked-write review tray
        // (F-1). Listing works regardless of lock state (the tray's
        // metadata is plaintext, like the manifest); accepting and
        // discarding are the human review step `09_UI_UX_SPEC.md §7`
        // describes as happening "at unlock".
        "vault.pending_list" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            if !scope.holds(Capability::Read) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Read,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Read, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Read,
                    rule_name(decision),
                    now,
                ));
            }
            second_factor_gate(state, scope, target_node, GateKind::Read, now)?;
            let hidden = node_hides_names(state, scope, target_node);
            let items: Vec<Value> = state
                .list_pending(target_node)
                .iter()
                .map(|p| {
                    json!({
                        // ADR-083: a name-blind reader sees the tray's shape only.
                        "entry": p.id, "name": if hidden { Value::Null } else { json!(p.name) },
                        "type": p.entry_type,
                        "sensitivity": p.sensitivity, "fieldCount": p.field_count,
                        "created": p.created,
                    })
                })
                .collect();
            let mut body = json!({ "node": target_node, "pending": items });
            if hidden {
                body["nameHidden"] = json!(true);
            }
            Ok(body)
        }

        "vault.pending_accept" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;

            if !scope.holds(Capability::Create) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Create,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Create, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Create,
                    rule_name(decision),
                    now,
                ));
            }
            if node_is_locked(state, target_node) {
                return Err(locked_refusal(state, target_node));
            }

            let node_lock = state.node_write_lock(target_node);
            let _guard = node_lock.lock().expect("node write lock poisoned");

            // Peek without removing yet — a rejected accept (name collision)
            // must leave the tray exactly as it was.
            let pending_entry = state
                .list_pending(target_node)
                .into_iter()
                .find(|p| p.id == entry_id)
                .ok_or_else(|| {
                    OpError::NotFound(format!("no pending entry {entry_id} on node {target_node}"))
                })?;

            let pending_canon = canonical_name(&pending_entry.name);
            let name_taken = state
                .manifests
                .read()
                .expect("manifests poisoned")
                .get(target_node)
                .is_some_and(|m| {
                    canon_taken(&pending_canon, m.entries.iter().map(|e| e.name.as_str()))
                });
            if name_taken {
                return Err(OpError::EntryExists {
                    node: target_node.to_string(),
                    name: pending_entry.name,
                });
            }

            // ADR-078: open the pending envelope BEFORE it moves, with the node
            // key (the node is unlocked — checked above), and take the entry's
            // type, sensitivity, field count and `hasTotp` from the document it
            // actually holds. The tray's `.meta.json` sidecar is unsigned and is
            // untrusted input by design (ADR-069): it supplies only the name and
            // the arrival time, so a tampered `fieldCount` can never reach the
            // signed manifest. An envelope that does not open is refused as
            // `internal` and the tray is left exactly as it was.
            let pending_path = state.paths.pending_env(target_node, entry_id);
            let bytes = credmgr_store::atomic::read(&pending_path)
                .map_err(|e| OpError::Internal(format!("reading pending entry: {e}")))?;
            let Some(node_priv) = state.hot_node_key(target_node) else {
                return Err(locked_refusal(state, target_node));
            };
            let projection = {
                // A version-1 pending envelope (one left in the tray by an alpha
                // build) is a raw value: it keeps the sidecar's type and
                // sensitivity, which is all its projection is.
                let stored = ManifestEntry {
                    id: pending_entry.id.clone(),
                    name: pending_entry.name.clone(),
                    r#ref: 0,
                    entry_type: pending_entry.entry_type,
                    sensitivity: pending_entry.sensitivity,
                    field_count: pending_entry.field_count,
                    sha256: String::new(),
                    modified: pending_entry.created,
                    expires_at: None,
                    rotated_at: None,
                    has_totp: false,
                };
                let loaded =
                    entry_doc::open_bytes(&bytes, target_node, entry_id, &node_priv, Some(&stored))
                        .map_err(|_| {
                            OpError::Internal(
                        "the pending entry does not open, or is not a valid entry document; \
                         it was left in the tray"
                            .into(),
                    )
                        })?;
                fields::project(&loaded.doc)
            };

            state.take_pending(target_node, entry_id);
            let final_path = state.paths.entry_env(target_node, entry_id);
            credmgr_store::atomic::write(&final_path, &bytes)
                .map_err(|e| OpError::Internal(format!("writing accepted entry: {e}")))?;
            state.remove_pending_files(target_node, entry_id);

            let generation = state.insert_manifest_entry(
                target_node,
                ManifestEntry {
                    id: pending_entry.id,
                    name: pending_entry.name,
                    r#ref: state.next_ref(),
                    entry_type: projection.entry_type,
                    sensitivity: projection.sensitivity,
                    field_count: projection.field_count,
                    // The digest of the bytes just moved — never the sidecar's.
                    sha256: sha256_hex(&bytes),
                    modified: pending_entry.created,
                    expires_at: None,
                    rotated_at: None,
                    has_totp: projection.has_totp,
                },
            );

            Ok(json!({
                "node": target_node, "entry": entry_id,
                "accepted": true, "generation": generation,
            }))
        }

        "vault.pending_discard" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let entry_id = params["entry"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.entry is required".into()))?;

            if !scope.holds(Capability::Create) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Create,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Create, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Create,
                    rule_name(decision),
                    now,
                ));
            }
            if node_is_locked(state, target_node) {
                return Err(locked_refusal(state, target_node));
            }

            let node_lock = state.node_write_lock(target_node);
            let _guard = node_lock.lock().expect("node write lock poisoned");

            let pending_entry = state.take_pending(target_node, entry_id).ok_or_else(|| {
                OpError::NotFound(format!("no pending entry {entry_id} on node {target_node}"))
            })?;
            state.remove_pending_files(target_node, &pending_entry.id);

            Ok(json!({ "node": target_node, "entry": entry_id, "discarded": true }))
        }

        // F-7 (`06_ACCESS_GRAPH.md §1a`): a node can be locked independently
        // of the vault. Human-only, like every other `admin` op — Phase 5's
        // 2FA gate ("unlocking it costs the node's gate factor") isn't built
        // yet, so `Capability::Admin` is the whole gate for now, same
        // "adapted to the factor Phase 3 actually has" pattern as
        // `BrokerState::unlock`.
        "vault.node_lock" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }
            state.lock_node(target_node);
            Ok(json!({ "node": target_node, "locked": true }))
        }

        "vault.node_unlock" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }
            state.unlock_node(target_node);
            Ok(json!({ "node": target_node, "locked": false }))
        }

        // F-15 (`07_TWO_FACTOR.md §5a`, ADR-042): records the human decision
        // on a request `entry.reveal` created. Gated on `Capability::Admin`
        // against the request's *own* node — same "the human factor,
        // adapted to what Phase 3 can assert" substitution `vault.node_lock`/
        // `node.seal`/`node.restore` already make for the presence Phase 5's
        // native shell will eventually supply instead. Does not itself
        // return the value — the original caller gets it by retrying
        // `entry.reveal` (`07 §5a`'s documented retry shape).
        //
        // ADR-079 (4a): approving **stages** the value — it is decrypted here,
        // while the human is present and a root key is known to be resident, and
        // the retry only hands it over. Deciding on a wholly locked live vault is
        // `vault_locked` and releases nothing: with no owner session and no root
        // key, an approval could be neither decided nor completed, so none is
        // taken (a denial included — an undecided request is denied by default
        // when its TTL ends).
        "vault.approval_decide" => {
            let request_id = params["request"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.request is required".into()))?;
            let approved = params["approved"]
                .as_bool()
                .ok_or_else(|| OpError::Malformed("params.approved is required".into()))?;
            // ADR-088 (4b): `passphrase` (and `code`) present means the decision is
            // authorised by the unlock factors themselves, not by a session — the
            // only way to decide while the vault is locked.
            if let Some(passphrase) = params.get("passphrase") {
                return decide_with_factors(
                    state,
                    request_id,
                    approved,
                    passphrase,
                    params.get("code"),
                    now,
                );
            }
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            // Read the lock epoch **before** looking at the lock state or at any
            // key: a lock that lands after this point is caught when the value is
            // stored (`decide_approval`), one that landed before it is caught by
            // the check below.
            let lock_epoch = state.lock_epoch();
            if state.is_durable() && state.is_locked() {
                return Err(OpError::VaultLocked);
            }
            let Some(pending) = state.peek_approval(request_id, now) else {
                return Err(OpError::NotFound(format!(
                    "no pending approval {request_id}"
                )));
            };
            let decision =
                resolve_capability(state, scope, &pending.node_id, Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    &pending.node_id,
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }
            // An already-decided request cannot be decided again; refuse it before
            // decrypting a value that would only be thrown away.
            if pending.decision.is_some() {
                return Err(OpError::Malformed(format!(
                    "approval {request_id} was already decided"
                )));
            }
            let verdict = if approved {
                ApprovalVerdict::Approve {
                    staged: stage_approved_value(state, &pending)?,
                    lock_epoch,
                }
            } else {
                ApprovalVerdict::Deny
            };
            match state.decide_approval(request_id, verdict, now) {
                Ok(()) => Ok(json!({
                    "request": request_id, "node": pending.node_id,
                    "entry": pending.entry_id, "approved": approved,
                })),
                Err(ApprovalDecideError::NotFound) => Err(OpError::NotFound(format!(
                    "no pending approval {request_id}"
                ))),
                Err(ApprovalDecideError::AlreadyDecided) => Err(OpError::Malformed(format!(
                    "approval {request_id} was already decided"
                ))),
                // The vault locked while this was being decided; nothing was stored.
                Err(ApprovalDecideError::LockedMeanwhile) => Err(OpError::VaultLocked),
            }
        }

        // ADR-090: the person deciding an approval sees what is being asked
        // before deciding it. Read-only; works on a locked vault; never decrypts.
        //
        // Without `request` it lists every request still waiting (the window's
        // lock screen has no id to ask for); with one it describes that request,
        // or `not_found` when it never existed, expired, or was taken.
        //
        // Who may ask: on an unlocked vault only the owner's login session (an
        // agent or grantee has no business reading the owner's pending prompts).
        // A locked vault has no session, so there the answer is the same for any
        // caller on the socket — and it is no more than that caller could already
        // learn: the request id is not a credential (a decision needs the
        // passphrase), and names are withheld for `privateNames` nodes.
        "vault.approval_get" => {
            let locked = state.is_durable() && state.is_locked();
            let owner = state.is_owner_session(scope);
            if !locked && !owner {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            match params.get("request") {
                None | Some(Value::Null) => {
                    let pending: Vec<Value> = state
                        .pending_approvals(now)
                        .iter()
                        .map(|a| approval_view(state, a, owner, now))
                        .collect();
                    Ok(json!({ "pending": pending }))
                }
                Some(request) => {
                    let request_id = request.as_str().ok_or_else(|| {
                        OpError::Malformed("params.request must be a string".into())
                    })?;
                    let Some(a) = state.peek_approval(request_id, now) else {
                        return Err(OpError::NotFound(format!(
                            "no pending approval {request_id}"
                        )));
                    };
                    Ok(approval_view(state, &a, owner, now))
                }
            }
        }

        // ADR-051: `node.create` (`18_ENDPOINT_INDEX.md`'s row for it, never
        // implemented before this session — success criterion 6 in
        // `01_CONCEPT.md §7` names "a fresh V2 vault, created and populated
        // only through its own CLI/MCP/broker" as a Phase 7 demonstration
        // requirement, and there was no live path to create the *nodes* half
        // of that at all). Same substitution this module's own header
        // comment already established for seal/restore, not reparent's: a
        // brand-new, empty node has no existing data whose reachability
        // silently shifts (that is specifically what makes reparent "a grant
        // by another name", `06_ACCESS_GRAPH.md §6a`) and R8 isolates it from
        // every other node the instant it exists, with zero configuration —
        // so `Capability::Admin`, resolved against the *parent*, stands in
        // for the missing 2FA factor and this executes for real in Phase 3,
        // exactly like `node.seal`/`node.restore` (I-21's pattern) rather
        // than being unconditionally refused like `node.reparent`/
        // `grant.create`. See ADR-051 for the full reasoning.
        "node.create" => {
            let new_id = params["id"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.id is required".into()))?;
            let label = valid_node_label(
                params["label"]
                    .as_str()
                    .ok_or_else(|| OpError::Malformed("params.label is required".into()))?,
            )?;
            let label = label.as_str();
            let parent_id = params["parentId"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.parentId is required".into()))?;

            // ADR-079 (F-e): a node id is joined into filesystem paths, so it is
            // [a-z0-9][a-z0-9_-]{0,63} and none of the four reserved names.
            validate_node_id(new_id).map_err(OpError::Malformed)?;
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            let decision = resolve_capability(state, scope, parent_id, Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    parent_id,
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }
            // ADR-066: optional directories that auto-scope an agent to the
            // new node — parsed only once the caller is authorised (review
            // L4). Absent means none, exactly as before.
            let workdirs = match params.get("workdirs") {
                None | Some(Value::Null) => Vec::new(),
                Some(v) => canonical_workdirs(v)?,
            };
            // Review H2: the root key is obtained *before* the registry is
            // touched. It used to be fetched after the node was inserted, so a
            // failure there left a node with no key in the registry — which
            // every later write then failed on, and which a restarted broker
            // could not load.
            let root_key = state.reauth_root_key("node create").map_err(|_| {
                OpError::Internal("could not re-derive the root key to create a node".into())
            })?;

            // ADR-079 (F-d): the id of a sealed node stays spoken for while its
            // archive exists — a new node of that id would put its files where
            // the archive's are, and the restore that follows would fail halfway.
            if state.is_id_sealed(new_id) || state.paths.archive_dir(new_id).exists() {
                return Err(OpError::Malformed(format!(
                    "{new_id} is the id of a sealed node whose archive still exists — restore it, \
                     or choose another id"
                )));
            }
            // ADR-089 (4.11): not while a seal or restore is between its first memory
            // change and its commit — a child created under a node being sealed, or
            // a directory claimed from one being restored, would be committed beside
            // a registry that contradicts it. Held for the check and the insert only.
            let one_writer = state.hold_persist_lock();
            let mut registry = state.registry.write().expect("registry poisoned");
            if registry.nodes.contains_key(new_id) {
                return Err(OpError::Malformed(format!(
                    "a node named {new_id} already exists"
                )));
            }
            let Some(parent) = registry.nodes.get(parent_id) else {
                return Err(OpError::NotFound(format!("no node {parent_id}")));
            };
            let (kind, depth) = match parent.depth {
                0 => (NodeKind::Project, 1),
                1 => (NodeKind::Sub, 2),
                _ => {
                    return Err(OpError::Malformed(format!(
                        "{parent_id} is already at the depth cap — it cannot take children \
                         (03_DATA_MODEL.md §1)"
                    )))
                }
            };
            let candidate = Node {
                id: new_id.to_string(),
                label: label.to_string(),
                kind,
                depth,
                parent_id: Some(parent_id.to_string()),
                workdirs,
                policy: NodePolicy::default(),
            };

            // Reuse `crates/core`'s own invariant checker rather than
            // re-deriving "what makes a node shape valid" a second time here
            // — validate against a scratch clone so a rejected candidate
            // never touches the live registry.
            let mut candidate_registry = (*registry).clone();
            candidate_registry
                .nodes
                .insert(new_id.to_string(), candidate.clone());
            let violations = validate_registry(&candidate_registry);
            if !violations.is_empty() {
                return Err(OpError::Malformed(format!(
                    "would violate a registry invariant: {violations:?}"
                )));
            }

            // Real node key, real wrap under the root key — a created node
            // is immediately usable by `entry.create`, not a placeholder
            // waiting for a second step. Keyed before it is registered, so no
            // reader ever sees the node without its key.
            state.seed_node_key(&root_key, new_id);
            registry.nodes.insert(new_id.to_string(), candidate);
            drop(registry);
            drop(one_writer);

            let mut body = json!({ "node": new_id, "created": true });
            name_warnings(&mut body, &[label]);
            Ok(body)
        }

        // ADR-066: bind (or re-bind, or clear) the directories that
        // auto-scope an agent to `node`. Human-only: it needs `Admin` on the
        // node, which no agent scope ever holds (`capabilities_for_agent_access`),
        // and it refuses an agent origin outright besides — re-pointing a
        // directory is re-pointing every agent launched in it.
        "node.set_workdirs" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            if target_node == ORPHAN_ID {
                return Err(OpError::Malformed("orphan cannot have workdirs".into()));
            }
            if scope.origin == Origin::Agent {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }
            let workdirs = canonical_workdirs(&params["workdirs"])?;
            // ADR-089 (4.11): see `node.create`.
            let _one_writer = state.hold_persist_lock();
            let mut registry = state.registry.write().expect("registry poisoned");
            if !registry.nodes.contains_key(target_node) {
                return Err(OpError::NotFound(format!("no node {target_node}")));
            }
            let mut candidate = (*registry).clone();
            workdirs.clone_into(
                &mut candidate
                    .nodes
                    .get_mut(target_node)
                    .expect("presence checked above")
                    .workdirs,
            );
            let violations = validate_registry(&candidate);
            if !violations.is_empty() {
                return Err(OpError::Malformed(format!(
                    "would violate a registry invariant: {violations:?}"
                )));
            }
            *registry = candidate;
            Ok(json!({ "node": target_node, "workdirs": workdirs }))
        }

        // ADR-071: rename a node. The id — what grants, workdirs, manifests
        // and every agent's scope refer to — never changes; only the label a
        // human reads. Human-only, the `node.set_workdirs` gate.
        "node.update" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let label = valid_node_label(
                params["label"]
                    .as_str()
                    .ok_or_else(|| OpError::Malformed("params.label is required".into()))?,
            )?;
            // `22_ORG_VAULT_SYNC_AND_LICENSING.md` §1: GLOBAL is singular and
            // unrenamable; orphan is off-tree (`03_DATA_MODEL.md` §2).
            if target_node == ORPHAN_ID || target_node == GLOBAL_ID {
                return Err(OpError::Malformed(format!(
                    "{target_node} cannot be renamed"
                )));
            }
            human_admin_on(state, scope, target_node, now)?;
            let mut registry = state.registry.write().expect("registry poisoned");
            let node = registry
                .nodes
                .get_mut(target_node)
                .ok_or_else(|| OpError::NotFound(format!("no node {target_node}")))?;
            node.label.clone_from(&label);
            let mut body = json!({ "node": target_node, "label": label });
            name_warnings(&mut body, &[&label]);
            Ok(body)
        }

        // ADR-071: `06_ACCESS_GRAPH.md §10.1`'s single policy operation — a
        // partial patch, a mandatory reason (recorded in the audit record),
        // the admin gate, and presence for the two fields that widen reach.
        // Presence is not attestable on any transport yet, so those answer
        // `presence_required`, exactly as `grant.create` and
        // `node.reparent` do; the patch is all-or-nothing.
        "node.policy" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let reason = params["reason"]
                .as_str()
                .map(str::trim)
                .filter(|r| !r.is_empty())
                .ok_or_else(|| {
                    OpError::Malformed(
                        "params.reason is required — a policy change records why".into(),
                    )
                })?;
            if reason.chars().count() > 500 {
                return Err(OpError::Malformed(
                    "params.reason is limited to 500 characters".into(),
                ));
            }
            if target_node == ORPHAN_ID {
                return Err(OpError::Malformed(
                    "orphan's policy is fixed by design".into(),
                ));
            }
            let patch: PolicyPatch = serde_json::from_value(params["policy"].clone())
                .map_err(|e| OpError::Malformed(format!("params.policy: {e}")))?;
            let changed = patch.fields();
            if changed.is_empty() {
                return Err(OpError::Malformed(
                    "params.policy sets no field — nothing to change".into(),
                ));
            }
            human_admin_on(state, scope, target_node, now)?;
            let mut registry = state.registry.write().expect("registry poisoned");
            let current = registry
                .nodes
                .get(target_node)
                .ok_or_else(|| OpError::NotFound(format!("no node {target_node}")))?
                .policy
                .clone();
            if patch.widens_reach(&current) {
                return Err(OpError::PresenceRequired {
                    operation: "node.policy".to_string(),
                });
            }
            let mut candidate = (*registry).clone();
            let node = candidate
                .nodes
                .get_mut(target_node)
                .expect("presence checked above");
            patch.apply(&mut node.policy);
            let policy = node.policy.clone();
            let violations = validate_registry(&candidate);
            if !violations.is_empty() {
                return Err(OpError::Malformed(format!(
                    "would violate a registry invariant: {violations:?}"
                )));
            }
            *registry = candidate;
            drop(registry);
            // `07_TWO_FACTOR.md §5`: elevations are dropped on a node
            // policy change, as they are on lock.
            state.drop_elevations();
            Ok(json!({
                "node": target_node,
                "policy": policy,
                "changed": changed,
                "reason": reason,
                // Honest about enforcement (ADR-071): the list of policy fields
                // that are stored and reported and that nothing acts on. Empty
                // since ADR-083 (`privateNames`) and ADR-085 (`requireTwoFactor`)
                // were built; the key stays so a client that reads it keeps working.
                "notEnforced": Vec::<&str>::new(),
            }))
        }

        // ADR-072: a node's note — markdown, one per node, sealed under the
        // node key like an entry (`03_DATA_MODEL.md §4`). Needs `notes`,
        // which never rides along with `read`. The file must match the digest
        // the signed manifest records for it, so an older note file restored
        // over the current one is refused rather than served.
        "notes.read" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            notes_gate(state, scope, target_node, now)?;
            second_factor_gate(state, scope, target_node, GateKind::Read, now)?;
            let Some(node_priv) = state.hot_node_key(target_node) else {
                return Err(locked_refusal(state, target_node));
            };
            // ADR-083: a note is free text about the node — a name-blind reader
            // is told it exists and gets none of it. The generation stays, so a
            // reader that holds `notes` can still write one (F-9).
            if node_hides_names(state, scope, target_node) {
                return Ok(json!({
                    "node": target_node, "markdown": Value::Null, "modified": Value::Null,
                    "nameHidden": true,
                    "generation": state.manifest_generation(target_node).unwrap_or(0),
                }));
            }
            // ADR-077: the manifest generation a following `notes.write` must be
            // based on (`notes.write` takes the same optimistic-concurrency
            // `generation` as `entry.update`, F-9). Returned here so a caller that
            // holds `notes` but not `list` — the capability `entry.list` is gated
            // on — can still write a note: it is the very number `notes.write`'s
            // own `conflict` already tells such a caller, so nothing new is
            // exposed. Read BEFORE the note itself, so a write landing in between
            // can only make the caller's generation stale (its write is refused
            // as a conflict), never newer than the text it saw.
            let generation = state.manifest_generation(target_node).unwrap_or(0);
            let recorded = state.manifest_notes_digest(target_node);
            let path = state.paths.notes_env(target_node);
            let bytes = match credmgr_store::atomic::read(&path) {
                Ok(bytes) => bytes,
                Err(_) if recorded.is_none() => {
                    return Ok(json!({
                        "node": target_node, "markdown": "", "modified": null,
                        "generation": generation,
                    }));
                }
                Err(_) => {
                    return Err(OpError::Internal(
                        "the manifest records a note but its file is missing".into(),
                    ))
                }
            };
            if recorded.as_deref() != Some(sha256_hex(&bytes).as_str()) {
                return Err(OpError::Internal(
                    "the note file does not match the digest its manifest records".into(),
                ));
            }
            let plaintext = envelope::open(&bytes, &node_priv, target_node, NOTE_ENVELOPE_ID)
                .map_err(|_| OpError::Internal("the note envelope failed to open".into()))?;
            use secrecy::ExposeSecret;
            let note: Value = serde_json::from_slice(plaintext.expose_secret())
                .map_err(|_| OpError::Internal("the note is not in the expected shape".into()))?;
            Ok(json!({
                "node": target_node,
                "markdown": note["markdown"],
                "modified": note["modified"],
                "generation": generation,
            }))
        }

        // ADR-072: replace a node's note. An empty `markdown` removes it.
        // Optimistic concurrency on the manifest generation, exactly as
        // `entry.update` (F-9). Needs the node unlocked — a note is not a
        // locked-write tray item.
        "notes.write" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            let markdown = params["markdown"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.markdown is required".into()))?;
            let expected_generation = params["generation"]
                .as_u64()
                .ok_or_else(|| OpError::Malformed("params.generation is required".into()))?;
            if markdown.len() > NOTE_MAX_BYTES {
                return Err(OpError::Malformed(format!(
                    "a note is limited to {NOTE_MAX_BYTES} bytes"
                )));
            }
            if target_node == ORPHAN_ID {
                return Err(OpError::Malformed("orphan has no note".into()));
            }
            notes_gate(state, scope, target_node, now)?;
            if node_is_locked(state, target_node) {
                return Err(locked_refusal(state, target_node));
            }
            let node_pub = state
                .node_public_key(target_node)
                .ok_or_else(|| OpError::NotFound(format!("no node {target_node}")))?;
            let node_lock = state.node_write_lock(target_node);
            let _guard = node_lock.lock().expect("node write lock poisoned");
            let current_generation = state.manifest_generation(target_node).unwrap_or(0);
            if expected_generation != current_generation {
                return Err(OpError::Conflict {
                    node_id: target_node.to_string(),
                    expected_generation,
                    current_generation,
                });
            }
            let path = state.paths.notes_env(target_node);
            let (generation, cleared) = if markdown.is_empty() {
                let _ = std::fs::remove_file(&path);
                (state.set_manifest_notes(target_node, None), true)
            } else {
                let payload = serde_json::to_vec(&json!({ "markdown": markdown, "modified": now }))
                    .expect("a note always serialises");
                let sealed = envelope::seal(&payload, &node_pub, target_node, NOTE_ENVELOPE_ID)
                    .map_err(|_| OpError::Internal("failed to seal the note".into()))?;
                credmgr_store::atomic::write(&path, &sealed)
                    .map_err(|e| OpError::Internal(format!("writing the note: {e}")))?;
                (
                    state.set_manifest_notes(target_node, Some(sha256_hex(&sealed))),
                    false,
                )
            };
            Ok(json!({
                "node": target_node,
                "generation": generation,
                "modified": if cleared { Value::Null } else { json!(now) },
                "cleared": cleared,
            }))
        }

        // F-4: seal re-encrypts every entry to ORPHAN.pub and retains the
        // originals + node key in `archive/` for 7 days
        // (`crates/store::archive::seal`). See this module's doc for why the
        // gate is `Capability::Admin` alone, not presence too.
        "node.seal" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            if target_node == GLOBAL_ID || target_node == ORPHAN_ID {
                return Err(OpError::Malformed(format!(
                    "{target_node} cannot be sealed"
                )));
            }
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }

            let node_snapshot = {
                let registry = state.registry.read().expect("registry poisoned");
                registry.nodes.get(target_node).cloned()
            }
            .ok_or_else(|| OpError::NotFound(format!("no node {target_node}")))?;

            // Re-sealing needs the node's PRIVATE key (decrypt, then reseal
            // under orphan's public key) — unlike create/update, seal
            // genuinely requires the vault unlocked, for real.
            let Some(node_priv) = state.hot_node_key(target_node) else {
                return Err(locked_refusal(state, target_node));
            };
            use secrecy::ExposeSecret;

            // Fixed lock ordering (lexicographic) so a concurrent op that
            // also needs both locks can never deadlock against this one.
            let (first_id, second_id) = if target_node < ORPHAN_ID {
                (target_node, ORPHAN_ID)
            } else {
                (ORPHAN_ID, target_node)
            };
            let first_lock = state.node_write_lock(first_id);
            let second_lock = state.node_write_lock(second_id);
            let _first_guard = first_lock.lock().expect("node write lock poisoned");
            let _second_guard = second_lock.lock().expect("node write lock poisoned");

            // ADR-079: on a vault that lives on disk, seal is a commit protocol
            // (`state/seal.rs`) — the orphan node is created lazily if this vault
            // has none, and the registry write that records the seal is made here,
            // inside the op, between the files written before it and the moves
            // made after it.
            if state.is_durable() {
                let outcome = state.seal_node_durable(target_node, &node_priv, now)?;
                let mut sealed = json!({ "node": target_node, "sealed": true });
                if outcome.archive_move_pending {
                    sealed["archiveMovePending"] = json!(true);
                }
                return Ok(sealed);
            }

            let orphan_pub = state
                .node_public_key(ORPHAN_ID)
                .ok_or_else(|| OpError::Internal("orphan has no public key registered".into()))?;

            let manifest_entries: Vec<ManifestEntry> = state
                .manifests
                .read()
                .expect("manifests poisoned")
                .get(target_node)
                .map(|m| m.entries.clone())
                .unwrap_or_default();

            let mut orphan_entry_ids = Vec::with_capacity(manifest_entries.len());
            for entry in &manifest_entries {
                let path = state.paths.entry_env(target_node, &entry.id);
                let bytes = credmgr_store::atomic::read(&path)
                    .map_err(|e| OpError::Internal(format!("reading entry to seal: {e}")))?;
                // ADR-078: either payload kind (a legacy value or a field
                // document) is opened and resealed as the same kind.
                let (kind, plaintext) =
                    envelope::open_any(&bytes, &node_priv, target_node, &entry.id).map_err(
                        |_| OpError::Internal("failed to open entry being sealed".into()),
                    )?;
                let resealed = envelope::seal_as(
                    kind,
                    plaintext.expose_secret(),
                    &orphan_pub,
                    ORPHAN_ID,
                    &entry.id,
                )
                .map_err(|_| {
                    OpError::Internal("failed to reseal entry under the orphan key".into())
                })?;
                let orphan_path = state.paths.entry_env(ORPHAN_ID, &entry.id);
                credmgr_store::atomic::write(&orphan_path, &resealed)
                    .map_err(|e| OpError::Internal(format!("writing sealed entry: {e}")))?;

                // Names are unique per-node (`03_DATA_MODEL.md §3`) and
                // orphan is a node too — disambiguate on the rare collision
                // between two different sealed nodes' entry names rather
                // than silently dropping one.
                let name = {
                    let entry_canon = canonical_name(&entry.name);
                    let taken = state
                        .manifests
                        .read()
                        .expect("manifests poisoned")
                        .get(ORPHAN_ID)
                        .is_some_and(|m| {
                            canon_taken(&entry_canon, m.entries.iter().map(|e| e.name.as_str()))
                        });
                    if taken {
                        format!("{} ({target_node})", entry.name)
                    } else {
                        entry.name.clone()
                    }
                };
                state.insert_manifest_entry(
                    ORPHAN_ID,
                    ManifestEntry {
                        id: entry.id.clone(),
                        name,
                        r#ref: state.next_ref(),
                        entry_type: entry.entry_type,
                        sensitivity: entry.sensitivity,
                        field_count: entry.field_count,
                        // F5a: the digest of the RESEALED envelope just written
                        // under orphan, not the pre-seal one (ADR-067).
                        sha256: sha256_hex(&resealed),
                        modified: now,
                        expires_at: entry.expires_at,
                        rotated_at: entry.rotated_at,
                        has_totp: entry.has_totp,
                    },
                );
                orphan_entry_ids.push(entry.id.clone());
            }

            // Retain the ORIGINAL ciphertexts by moving them into the 7-day
            // archive — this, not anything computed above, is what makes a
            // day-6 restore byte-identical (`crates/store::archive` moves
            // real files, it recomputes nothing).
            let root_key = state.reauth_root_key("node seal").map_err(|_| {
                OpError::Internal("could not re-derive the root key to seal".into())
            })?;
            credmgr_store::archive::seal(&state.paths, root_key.expose_secret(), target_node, now)
                .map_err(|e| OpError::Internal(format!("archiving sealed node: {e}")))?;

            state.remove_node(target_node);
            let manifest_snapshot = state.take_manifest(target_node);
            let key_material = state.take_node_key_material(target_node);
            // F-8/06 §6: "Grants ... do not survive seal". The audit log
            // (ADR-049) is written generically by `server::handle_request`
            // for every dispatched op, not per-arm here — this call site
            // only needs to make the revocation itself real.
            state.revoke_grants_touching(target_node);

            state.record_sealed(
                target_node,
                SealedNodeRecord {
                    node: node_snapshot,
                    manifest: manifest_snapshot,
                    orphan_entry_ids,
                    key_material,
                    sealed_at: now,
                },
            );

            Ok(json!({ "node": target_node, "sealed": true }))
        }

        // F-4: a move back from the retained archive, "one click" within the
        // 7-day window — not an unseal, so it costs one Admin-gated call
        // rather than presence + a fresh code per item
        // (`09_UI_UX_SPEC.md §9`).
        "node.restore" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            // [Phase 8 audit] `Capability::Admin` on the token used to be the
            // WHOLE gate here, on the reasoning that a sealed node has no
            // registry entry left to resolve() against. That was a real
            // cross-node hole: `node.seal` resolves Admin against the target,
            // so an Admin token scoped to an unrelated project could not seal
            // `a` — but could *restore* it, unilaterally undoing a security
            // action it was never allowed to take and putting values that were
            // deliberately made human-only back into agent reach. Proven, not
            // reasoned about: `tests/isolation.rs::i21b_…` failed with
            // `Ok({"restored": true})` before this check existed.
            //
            // The fix is the same call `node.seal` makes, against the same id.
            // It resolves correctly *because* the node is absent, not in spite
            // of it: `Registry::is_strict_ancestor` returns false for an
            // unknown node, so R4/R5/R6 cannot fire and the only rule that can
            // still allow is R2 (subject == target — the node restoring
            // itself, which is exactly how I-21's legitimate path works).
            // Everything else lands on R8, default deny.
            //
            // Deliberately NOT resolved against the sealed node's parent the
            // way `node.create` (ADR-051) resolves against `parentId`: for a
            // depth-1 node that parent is Global, and R3 allows *every* node
            // every capability against Global — so a parent-based check would
            // have re-admitted precisely the caller this closes out. ADR-051's
            // permissiveness is sound for its own case (a brand-new empty node
            // shifts no existing data's reachability) and wrong for this one.
            let decision = resolve_capability(state, scope, target_node, Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }
            // ADR-079: on a vault that lives on disk the seal record is in the signed
            // registry and restore is the commit protocol's reverse (`state/seal.rs`).
            if state.is_durable() {
                let (first_id, second_id) = if target_node < ORPHAN_ID {
                    (target_node, ORPHAN_ID)
                } else {
                    (ORPHAN_ID, target_node)
                };
                let first_lock = state.node_write_lock(first_id);
                let second_lock = state.node_write_lock(second_id);
                let _first_guard = first_lock.lock().expect("node write lock poisoned");
                let _second_guard = second_lock.lock().expect("node write lock poisoned");
                let outcome = state.restore_node_durable(target_node, now)?;
                let mut restored = json!({ "node": target_node, "restored": true });
                if !outcome.workdirs_dropped.is_empty() {
                    restored["workdirsDropped"] = json!(outcome.workdirs_dropped);
                }
                return Ok(restored);
            }
            let Some(record) = state.sealed_record(target_node) else {
                return Err(OpError::NotFound(format!("no sealed node {target_node}")));
            };

            use secrecy::ExposeSecret;
            let root_key = state.reauth_root_key("node restore").map_err(|_| {
                OpError::Internal("could not re-derive the root key to restore".into())
            })?;
            match credmgr_store::archive::restore(
                &state.paths,
                root_key.expose_secret(),
                target_node,
                now,
            ) {
                Ok(()) => {}
                Err(credmgr_store::StoreError::ArchiveExpired { .. }) => {
                    return Err(OpError::ArchiveExpired {
                        node: target_node.to_string(),
                    });
                }
                Err(credmgr_store::StoreError::ArchiveNotFound { .. }) => {
                    return Err(OpError::NotFound(format!(
                        "no archive for sealed node {target_node}"
                    )));
                }
                Err(e) => {
                    return Err(OpError::Internal(format!("restoring archive: {e}")));
                }
            }

            // Only past this point does the seal actually undo — a day-8
            // attempt above already returned, leaving the record, the
            // archive and the orphan copies exactly as they were.
            state.remove_manifest_entries(ORPHAN_ID, &record.orphan_entry_ids);
            for id in &record.orphan_entry_ids {
                let _ = std::fs::remove_file(state.paths.entry_env(ORPHAN_ID, id));
            }
            state.insert_node(record.node.clone());
            if let Some(manifest) = record.manifest.clone() {
                state.set_manifest(target_node, manifest);
            }
            if let Some((wrapped, public)) = record.key_material.clone() {
                state.restore_node_key_material(target_node, wrapped, public);
            }
            state.discard_sealed_record(target_node);

            Ok(json!({ "node": target_node, "restored": true }))
        }

        // F-8 (`06_ACCESS_GRAPH.md §6a`): re-parenting changes the ancestor
        // set and is treated as scope-widening — the full grant gate, which
        // on Phase 3 always refuses (see this module's doc). Still validates
        // and authorises everything short of presence, so nothing about this
        // arm needs to change once Phase 5 can supply it.
        "node.reparent" => {
            let target_node = params["node"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.node is required".into()))?;
            params["newParent"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.newParent is required".into()))?;
            let reason = params["reason"].as_str().unwrap_or("");
            if target_node == GLOBAL_ID || target_node == ORPHAN_ID {
                return Err(OpError::Malformed(format!(
                    "{target_node} cannot be re-parented"
                )));
            }
            if reason.len() < 8 {
                return Err(OpError::Malformed(
                    "params.reason must be at least 8 characters (06_ACCESS_GRAPH.md §6)".into(),
                ));
            }
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            let decision = resolve_capability(state, scope, target_node, Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    target_node,
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }
            Err(OpError::PresenceRequired {
                operation: "node.reparent".to_string(),
            })
        }

        // ADR-050: `grant.list`/`create`/`revoke` (`10_API_AND_MCP.md §1`,
        // `18_ENDPOINT_INDEX.md §1.3`). `03_DATA_MODEL.md §6`: `Grant.to` is
        // "the node being opened" — the node whose confidentiality boundary
        // widens — so `Capability::Admin` is checked against `to`, not
        // `from`, for all three ops: administering B's exposure is B's
        // administrator's call, not X's. Metadata only, never a value —
        // `Grant` carries no secret by construction — so this needs no root
        // key and works while locked, the same `List / read metadata` shape
        // `audit.tail` already established.
        "grant.list" => {
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            // Clone-then-drop the read guard before calling
            // `resolve_capability`, which takes its own `registry.read()` —
            // `std::sync::RwLock` is not guaranteed reentrant-safe for a
            // second read while a writer is queued, so nesting the two
            // guards (unlike `entry.list`'s `narrow_entries`, which locks a
            // *different* `RwLock`) is a latent deadlock this avoids by
            // construction.
            let grants: Vec<Grant> = state
                .registry
                .read()
                .expect("registry poisoned")
                .grants
                .clone();
            let visible: Vec<Value> = grants
                .iter()
                .filter(|g| {
                    resolve_capability(state, scope, g.to.node_id(), Capability::Admin, now)
                        .is_allow()
                })
                .map(|g| serde_json::to_value(g).expect("Grant serialises"))
                .collect();
            Ok(json!({ "grants": visible }))
        }

        // `07_TWO_FACTOR.md §2`: "Create / modify a grant" needs a live
        // global AND target-node gate session plus presence — Phase 3 has
        // neither a per-node gate-session tracker for admin ops nor any
        // transport that can ever set `presence_attested: true`, so exactly
        // like `node.reparent`, `Capability::Admin` stands in for the whole
        // 2FA apparatus and the positive path is unconditionally refused.
        // Every other invariant is validated for real first — nothing about
        // this arm needs to change once Phase 5 supplies a real presence
        // attestation.
        "grant.create" => {
            let from = params["from"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.from is required".into()))?;
            let to: GrantTarget = serde_json::from_value(params["to"].clone()).map_err(|_| {
                OpError::Malformed(
                    "params.to must be { kind: \"node\"|\"entry\", nodeId, entryId? }".into(),
                )
            })?;
            let reason = params["reason"].as_str().unwrap_or("");
            if reason.len() < 8 {
                return Err(OpError::Malformed(
                    "params.reason must be at least 8 characters (03_DATA_MODEL.md §6)".into(),
                ));
            }
            // `03_DATA_MODEL.md §6`: "A grant to orphan is rejected. A grant
            // from orphan is rejected."
            if from == ORPHAN_ID || to.node_id() == ORPHAN_ID {
                return Err(OpError::Malformed(
                    "a grant cannot name orphan as either endpoint (03_DATA_MODEL.md §6)".into(),
                ));
            }
            let requested_scope: Vec<Capability> = match params.get("scope") {
                Some(v) => serde_json::from_value(v.clone()).map_err(|_| {
                    OpError::Malformed("params.scope must be an array of capabilities".into())
                })?,
                None => return Err(OpError::Malformed("params.scope is required".into())),
            };
            // `03_DATA_MODEL.md §6`'s own type is `('read' | 'reveal' |
            // 'notes')[]` — `list`/`create`/`update`/`admin` are never
            // grantable, by the type the doc itself specifies.
            if requested_scope.is_empty()
                || requested_scope.iter().any(|c| {
                    !matches!(c, Capability::Read | Capability::Reveal | Capability::Notes)
                })
            {
                return Err(OpError::Malformed(
                    "params.scope may only contain read, reveal or notes (03_DATA_MODEL.md §6)"
                        .into(),
                ));
            }
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            let decision = resolve_capability(state, scope, to.node_id(), Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    to.node_id(),
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }
            Err(OpError::PresenceRequired {
                operation: "grant.create".to_string(),
            })
        }

        // `06_ACCESS_GRAPH.md §6`: "Revocation is one click and takes effect
        // on the next request — no re-encryption"; `09_UI_UX_SPEC.md §10`:
        // a one-click Revoke with no 2FA field in the mockup;
        // `06 §6`: "Revoking is available in both Pro and Lite ... removing
        // one is safety and is always reachable." Revoking only narrows what
        // a node can reach, so unlike `grant.create` it does not wait on
        // presence — `Capability::Admin` on the exposed (`to`) node is the
        // whole gate, the same substitution `node.seal`/`node.restore`
        // already make for a destructive-looking-but-safe action, and it
        // genuinely executes.
        "grant.revoke" => {
            let grant_id = params["id"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.id is required".into()))?;
            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            let target_node = {
                let registry = state.registry.read().expect("registry poisoned");
                registry
                    .grants
                    .iter()
                    .find(|g| g.id == grant_id)
                    .map(|g| g.to.node_id().to_string())
            }
            .ok_or_else(|| OpError::NotFound(format!("no grant {grant_id}")))?;

            let decision = resolve_capability(state, scope, &target_node, Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    &target_node,
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }
            let removed = state
                .revoke_grant(grant_id)
                .ok_or_else(|| OpError::NotFound(format!("no grant {grant_id}")))?;
            Ok(json!({ "id": removed.id, "revoked": true }))
        }

        // ADR-054: `maintenance.verify` — read-only, `Capability::List`
        // filtered to the caller's reachable nodes (the identical
        // `resolve_capability` per-node filter `audit.tail`/`graph.snapshot`
        // already use). Reads the registry and every reachable node's
        // manifest fresh from **disk** (not `state.registry`/
        // `state.manifests`) — the whole point is checking what is
        // durably persisted, not the in-memory cache; a node whose file is
        // missing, tampered, or out of sync with the registry's recorded
        // binding is reported, never silently skipped or panicked on.
        "maintenance.verify" => {
            if !scope.holds(Capability::List) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::List,
                });
            }
            use secrecy::ExposeSecret;
            let root_key = state
                .reauth_root_key("maintenance verify")
                .map_err(|_| OpError::VaultLocked)?;
            let root_key = root_key.expose_secret();

            let disk_registry = match credmgr_store::registry_file::load(&state.paths, root_key) {
                Ok(r) => r,
                Err(e) => {
                    return Ok(json!({
                        "ok": false, "nodesChecked": 0,
                        "errors": [{ "node": Value::Null, "detail": e.to_string() }],
                        "warnings": [],
                    }))
                }
            };

            let node_ids: Vec<String> = {
                let registry = state.registry.read().expect("registry poisoned");
                registry.nodes.keys().cloned().collect()
            };
            let mut nodes_checked = 0u64;
            let mut errors: Vec<Value> = Vec::new();
            let mut warnings: Vec<Value> = Vec::new();
            for node_id in node_ids {
                if !resolve_capability(state, scope, &node_id, Capability::List, now).is_allow() {
                    continue;
                }
                nodes_checked += 1;
                let manifest_doc =
                    match credmgr_store::manifest::load(&state.paths, root_key, &node_id) {
                        Ok(m) => m,
                        Err(e) => {
                            errors.push(json!({ "node": node_id, "detail": e.to_string() }));
                            continue;
                        }
                    };
                if let Err(e) = credmgr_store::manifest::verify_cross_binding(
                    &disk_registry,
                    &node_id,
                    &manifest_doc,
                ) {
                    errors.push(json!({ "node": node_id, "detail": e.to_string() }));
                }
                match credmgr_store::verify::find_dangling(
                    &state.paths,
                    &node_id,
                    &manifest_doc.body,
                ) {
                    Ok(report) => {
                        for id in report.dangling_envelopes {
                            warnings.push(json!({
                                "node": node_id,
                                "detail": format!("dangling envelope: entry {id} has a file on disk but no manifest record"),
                            }));
                        }
                        for id in report.missing_envelopes {
                            errors.push(json!({
                                "node": node_id,
                                "detail": format!("missing envelope: manifest names entry {id} but its file is absent"),
                            }));
                        }
                    }
                    Err(e) => errors.push(json!({ "node": node_id, "detail": e.to_string() })),
                }
                // ADR-072: the note file, the same way.
                match credmgr_store::verify::find_note_mismatch(
                    &state.paths,
                    &node_id,
                    &manifest_doc.body,
                ) {
                    Ok(Some(problem)) => {
                        errors
                            .push(json!({ "node": node_id, "detail": format!("note: {problem}") }));
                    }
                    Ok(None) => {}
                    Err(e) => errors.push(json!({ "node": node_id, "detail": e.to_string() })),
                }
                // ADR-067: each envelope's bytes against the digest the
                // HMAC-verified manifest recorded for it.
                match credmgr_store::verify::find_digest_mismatches(
                    &state.paths,
                    &node_id,
                    &manifest_doc.body,
                ) {
                    Ok(ids) => {
                        for id in ids {
                            errors.push(json!({
                                "node": node_id,
                                "detail": format!("envelope digest mismatch: entry {id}'s file is not the one its manifest recorded (tampered, corrupted, or an interrupted update)"),
                            }));
                        }
                    }
                    Err(e) => errors.push(json!({ "node": node_id, "detail": e.to_string() })),
                }
            }
            // ADR-079: the orphan node's cold key and the seal records — the
            // owner's business, not an agent's: a sealed node's id and label are
            // not something a scoped caller is shown.
            if state.is_durable() && state.is_owner_session(scope) {
                for finding in state.orphan_findings(root_key, &disk_registry) {
                    let entry = json!({ "node": finding.node, "detail": finding.detail });
                    if finding.is_error {
                        errors.push(entry);
                    } else {
                        warnings.push(entry);
                    }
                }
            }
            Ok(json!({
                "ok": errors.is_empty(),
                "nodesChecked": nodes_checked,
                "errors": errors,
                "warnings": warnings,
            }))
        }

        // ADR-054: `maintenance.doctor` — `Capability::Admin` resolved per
        // node being healed (`node.seal`/`node.create`'s established
        // self-admin pattern). `params.apply` defaults `true` (V1's dry-run
        // default is inverted here — every fix this op performs is a
        // provably safe resync of already-self-verifying data, unlike V1's
        // broader fix set, so there is no fix a default-apply could get
        // wrong that `apply:false` would have caught). Fixes exactly one
        // class of problem: a manifest that verifies under its **own** HMAC
        // but whose `(generation, hmac)` the registry has stale — safe,
        // because the manifest itself already proves what it claims. A
        // manifest that fails its own HMAC is left alone and reported
        // unfixable — re-signing tampered content would launder the tamper,
        // never doctor's job.
        //
        // `params.rebuildRegistry: true` switches to F-10's door out of a
        // refused-to-open vault. `PresenceRequired` unconditionally, on the
        // only surfaces this build has (`audit.get`/`grant.create`/
        // `node.reparent`'s established shape) — the real diff/apply logic
        // this would run lives in already-independently-tested
        // `maintenance::load_rebuild_candidate` + `credmgr_store::rebuild::
        // {diff, apply}`, not inlined here as permanently-unreachable dead
        // code past the presence wall. Nothing about this arm needs to
        // change once Phase 5's native shell can supply a real attestation
        // — only the hardcoded refusal is removed.
        "maintenance.doctor" => {
            let apply = params.get("apply").and_then(Value::as_bool).unwrap_or(true);
            let rebuild = params
                .get("rebuildRegistry")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            if rebuild {
                if params.get("passphrase").and_then(Value::as_str).is_none() {
                    return Err(OpError::Malformed(
                        "params.passphrase is required for rebuildRegistry".into(),
                    ));
                }
                if !scope.holds(Capability::Admin) {
                    return Err(OpError::CapabilityNotHeld {
                        capability: Capability::Admin,
                    });
                }
                let decision = resolve_capability(state, scope, GLOBAL_ID, Capability::Admin, now);
                if !decision.is_allow() {
                    return Err(access_denied_error(
                        state,
                        scope,
                        GLOBAL_ID,
                        Capability::Admin,
                        rule_name(decision),
                        now,
                    ));
                }
                return Err(OpError::PresenceRequired {
                    operation: "maintenance.doctor --rebuild-registry".to_string(),
                });
            }

            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            use secrecy::ExposeSecret;
            let root_key = state
                .reauth_root_key("maintenance doctor")
                .map_err(|_| OpError::VaultLocked)?;
            let root_key = root_key.expose_secret();

            let mut disk_registry = match credmgr_store::registry_file::load(&state.paths, root_key)
            {
                Ok(r) => r,
                Err(e) => {
                    return Ok(json!({
                        "applied": false, "fixCount": 0, "fixes": [],
                        "unfixable": [{ "node": Value::Null, "detail": format!("{e} — restore the vault and state directories from a copy; rebuildRegistry needs presence, which no transport provides yet") }],
                    }))
                }
            };

            let node_ids: Vec<String> = {
                let registry = state.registry.read().expect("registry poisoned");
                registry.nodes.keys().cloned().collect()
            };
            let mut fixes: Vec<Value> = Vec::new();
            let mut unfixable: Vec<Value> = Vec::new();

            for node_id in node_ids {
                if !resolve_capability(state, scope, &node_id, Capability::Admin, now).is_allow() {
                    continue;
                }
                let manifest_doc =
                    match credmgr_store::manifest::load(&state.paths, root_key, &node_id) {
                        Ok(m) => m,
                        Err(e) => {
                            unfixable.push(json!({ "node": node_id, "detail": e.to_string() }));
                            continue;
                        }
                    };
                if credmgr_store::manifest::verify_cross_binding(
                    &disk_registry,
                    &node_id,
                    &manifest_doc,
                )
                .is_err()
                {
                    fixes.push(json!({
                        "node": node_id, "type": "cross-binding-resync",
                        "generation": manifest_doc.body.generation,
                    }));
                    if apply {
                        disk_registry.manifests.insert(
                            node_id.clone(),
                            credmgr_store::registry_file::ManifestBinding {
                                generation: manifest_doc.body.generation,
                                manifest_hmac: manifest_doc.hmac.clone(),
                            },
                        );
                    }
                }
            }
            if apply && !fixes.is_empty() {
                // ADR-063 (review M4): the one registry write outside
                // `persist` takes the same lock and leaves `persist`'s view of
                // the document current, so neither can overwrite the other.
                state
                    .with_persist_lock(|| {
                        credmgr_store::registry_file::save(&state.paths, root_key, &disk_registry)
                    })
                    .map_err(|e| OpError::Internal(format!("saving resynced registry: {e}")))?;
                if state.is_durable() {
                    state
                        .refresh_registry_meta(root_key)
                        .map_err(|e| OpError::Internal(format!("re-reading the registry: {e}")))?;
                }
            }

            // ADR-079: the orphan node — created if this vault (an older build's)
            // has none, its cold key regenerated while nothing is sealed to the
            // old one, the rows an interrupted seal left removed. Admin on the
            // whole vault: the orphan itself is R0-denied to every scope.
            if state.is_durable()
                && resolve_capability(state, scope, GLOBAL_ID, Capability::Admin, now).is_allow()
            {
                let (orphan_fixes, orphan_unfixable) = state.doctor_orphan(root_key, apply, now)?;
                fixes.extend(orphan_fixes);
                unfixable.extend(orphan_unfixable);

                // ADR-089 (K-7 WP6): destroying the retained originals of a seal whose
                // seven days are over is irreversible, so it is asked for by name and
                // is never part of a plain doctor run. `apply: false` lists what a run
                // would remove and removes nothing.
                let purge = match params.get("purgeExpiredSeals") {
                    None | Some(Value::Null) => false,
                    Some(Value::Bool(b)) => *b,
                    Some(_) => {
                        return Err(OpError::Malformed(
                            "params.purgeExpiredSeals must be true or false".into(),
                        ))
                    }
                };
                if purge {
                    if apply {
                        for p in state.purge_expired_seals(now)? {
                            fixes.push(json!({
                                "node": p.id, "type": "purged-expired-seal",
                                "sealedAt": p.sealed_at, "archiveRemoved": p.archive_removed,
                            }));
                        }
                    } else {
                        for (id, sealed_at) in state.expired_seals(now) {
                            fixes.push(json!({
                                "node": id, "type": "would-purge-expired-seal",
                                "sealedAt": sealed_at,
                            }));
                        }
                    }
                }
            }

            Ok(json!({
                "applied": apply,
                "fixCount": fixes.len(),
                "fixes": fixes,
                "unfixable": unfixable,
            }))
        }

        // ADR-076: `maintenance.rotate_root` — `04 §6`'s "Rotate root key":
        // "unlock + 2FA + presence". Human-only (never `Origin::Agent`, and on
        // the MCP forbidden list), `Capability::Admin` against `global`, the
        // gate's second factor fresh when a gate is enrolled, and presence —
        // which no transport can attest yet (ADR-047), so this answers
        // `presence_required` after every check that can be made without it,
        // exactly as `maintenance.doctor --rebuild-registry` and
        // `node.reparent` do. The rotation itself is `BrokerState::rotate_root`
        // behind `rotate_root_response`, tested directly; the day a transport
        // can attest presence, the final `Err` below becomes
        // `return rotate_root_response(state, passphrase, now)`.
        "maintenance.rotate_root" => {
            let passphrase = params["passphrase"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.passphrase is required".into()))?;
            if passphrase.is_empty() {
                return Err(OpError::Malformed(
                    "params.passphrase must not be empty".into(),
                ));
            }
            human_admin_on(state, scope, GLOBAL_ID, now)?;
            if state.is_gate_confirmed(GATE_SCOPE_VAULT)
                && !state.is_elevated(GATE_SCOPE_VAULT, now)
            {
                return Err(OpError::TwoFactorRequired {
                    challenge: "totp".to_string(),
                    scope: GATE_SCOPE_VAULT.to_string(),
                    expires_in: 0,
                });
            }
            Err(OpError::PresenceRequired {
                operation: "maintenance.rotate_root".to_string(),
            })
        }

        // ADR-054: `maintenance.backup` — `Capability::Admin` resolved
        // against `GLOBAL_ID` (a whole-vault snapshot has no single owning
        // node; this inherits R3's known unqualified-capability
        // permissiveness, ADR-051's "not fixed here" gap — currently inert,
        // same reasoning `node.create`'s parent check already accepted,
        // revisited for real once ADR-056's session mechanism can issue a
        // live Admin token). `store::backup::create_backup` selects and
        // packs the plaintext bundle (unchanged, ADR-039); this op supplies
        // the encryption call ADR-039 always left for later, to an
        // operator-supplied passphrase (never a recovery-code-derived key —
        // see ADR-054's own "Rejected" section for why: no live vault-create
        // path writes `root.wrap.recovery` yet, and depending on one here
        // would silently assume a Phase 6 flow that hasn't shipped).
        "maintenance.backup" => {
            let passphrase_str = params["passphrase"]
                .as_str()
                .ok_or_else(|| OpError::Malformed("params.passphrase is required".into()))?;
            if passphrase_str.is_empty() {
                return Err(OpError::Malformed(
                    "params.passphrase must not be empty".into(),
                ));
            }
            let retain = params.get("retain").and_then(Value::as_u64).unwrap_or(14) as usize;

            if !scope.holds(Capability::Admin) {
                return Err(OpError::CapabilityNotHeld {
                    capability: Capability::Admin,
                });
            }
            let decision = resolve_capability(state, scope, GLOBAL_ID, Capability::Admin, now);
            if !decision.is_allow() {
                return Err(access_denied_error(
                    state,
                    scope,
                    GLOBAL_ID,
                    Capability::Admin,
                    rule_name(decision),
                    now,
                ));
            }

            let plaintext = credmgr_store::backup::create_backup(&state.paths)
                .map_err(|e| OpError::Internal(format!("selecting backup files: {e}")))?;
            let passphrase = secrecy::SecretBox::new(Box::new(passphrase_str.to_string()));
            let ciphertext = credmgr_keystore::backup_passphrase::encrypt_with_passphrase(
                &passphrase,
                &plaintext,
            );

            let name = crate::maintenance::backup_file_name(now);
            let out_path = state.paths.backups_dir().join(name);
            credmgr_store::atomic::write(&out_path, &ciphertext)
                .map_err(|e| OpError::Internal(format!("writing backup: {e}")))?;

            let pruned = crate::maintenance::prune_backups(&state.paths, retain);

            Ok(json!({
                "path": out_path.to_string_lossy(),
                "retain": retain,
                "pruned": pruned,
            }))
        }

        other => Err(OpError::Malformed(format!("unknown op: {other}"))),
    }
}
