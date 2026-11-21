//! ADR-174 (2): an agent reads its OWN node's note (never another node's, never writes one), through the
//! broker's `notes.read` under its own scope. The MCP tool `credmgr_notes_read` is a pass-through to this op.
//!
//! * An agent holding `list` and `read` reads its own node's note; the note round-trips from the owner.
//! * An agent can never write a note (`notes.write` needs `notes`, which an agent never holds).
//! * An agent of one node cannot read another node's note, nor learn what it says.
//! * A note follows the high-sensitivity reveal rules (ADR-156): Guarded and Strict nodes keep it from an
//!   agent; only an Open node hands it over.
//! * On an Open node the agent meets the node's second factor as for a reveal (not the weaker read check).
//! * A node that hides its names answers that a note exists and gives none of it.
//! * An agent without `read` is refused.

mod f1_support;

use serde_json::json;

use credmgr_brokerd::protocol::OpError;
use credmgr_brokerd::scope::BrokerScope;
use credmgr_brokerd::state::BrokerState;
use credmgr_core::access::Origin;
use credmgr_core::registry::{Capability, SecurityLevel};

use f1_support::*;

fn agent(node: &str, caps: Vec<Capability>) -> BrokerScope {
    BrokerScope {
        node_id: node.to_string(),
        capabilities: caps,
        origin: Origin::Agent,
        token_id: None,
        bound_workdir: None,
    }
}

fn write_note(state: &BrokerState, owner: &BrokerScope, node: &str, text: &str) {
    let g = generation(state, owner, node);
    call(
        state,
        owner,
        NOW,
        "notes.write",
        json!({ "node": node, "markdown": text, "generation": g }),
    )
    .expect("notes.write");
}

/// Puts `acme` at a level straight in the registry: lowering a level through `node.policy` needs a presence
/// proof the fixture vault cannot give (the same shortcut `security_levels.rs` takes).
fn force_level(state: &BrokerState, level: SecurityLevel) {
    state
        .registry
        .write()
        .unwrap()
        .nodes
        .get_mut("acme")
        .unwrap()
        .policy
        .security_level = level;
}

#[test]
fn an_agent_reads_its_own_nodes_note_and_never_writes_one() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    force_level(&state, SecurityLevel::Open);
    write_note(&state, &owner, "acme", "deploy via the blue pipeline");

    let bot = agent("acme", vec![Capability::List, Capability::Read]);
    let note = call(&state, &bot, NOW, "notes.read", json!({ "node": "acme" })).unwrap();
    assert_eq!(note["markdown"], "deploy via the blue pipeline", "{note}");

    // The same for a read-write agent; neither can write.
    let rw = agent(
        "acme",
        vec![
            Capability::List,
            Capability::Read,
            Capability::Create,
            Capability::Update,
        ],
    );
    let g = generation(&state, &owner, "acme");
    for who in [&bot, &rw] {
        let w = call(
            &state,
            who,
            NOW,
            "notes.write",
            json!({ "node": "acme", "markdown": "agent was here", "generation": g }),
        );
        assert!(matches!(w, Err(OpError::CapabilityNotHeld { .. })), "{w:?}");
    }
    let still = call(&state, &bot, NOW, "notes.read", json!({ "node": "acme" })).unwrap();
    assert_eq!(still["markdown"], "deploy via the blue pipeline");
}

#[test]
fn an_agent_cannot_read_another_nodes_note() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    force_level(&state, SecurityLevel::Open);
    create_node(&state, &owner, "beta");
    write_note(&state, &owner, "acme", "acme note");
    write_note(&state, &owner, "beta", "beta-only-secret-text");

    let bot = agent("acme", vec![Capability::List, Capability::Read]);
    for target in ["beta", "global"] {
        let r = call(&state, &bot, NOW, "notes.read", json!({ "node": target }));
        let err = r.expect_err("another node's note is refused");
        assert!(
            !format!("{err:?}").contains("beta-only-secret-text"),
            "{err:?}"
        );
    }
    // A token-confined agent is refused too.
    let token = state
        .tokens
        .issue("acme", vec![Capability::Read], Origin::Agent, None);
    let confined = scope_of(&state, &token.id);
    assert!(call(
        &state,
        &confined,
        NOW,
        "notes.read",
        json!({ "node": "beta" })
    )
    .is_err());
}

#[test]
fn an_agent_without_read_is_refused() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    force_level(&state, SecurityLevel::Open);
    write_note(&state, &owner, "acme", "text");
    let bot = agent("acme", vec![Capability::List]);
    let r = call(&state, &bot, NOW, "notes.read", json!({ "node": "acme" }));
    assert!(matches!(r, Err(OpError::CapabilityNotHeld { .. })), "{r:?}");
}

#[test]
fn guarded_and_strict_nodes_keep_their_note_from_an_agent_and_only_open_hands_it_over() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    write_note(&state, &owner, "acme", "the root password is hunter2");
    let bot = agent("acme", vec![Capability::List, Capability::Read]);
    // The default level is Guarded, and a note is high-sensitivity text: refused.
    for level in [SecurityLevel::Guarded, SecurityLevel::Sealed] {
        force_level(&state, level);
        let r = call(&state, &bot, NOW, "notes.read", json!({ "node": "acme" }));
        let err = r.expect_err("Guarded and Strict keep the note from an agent");
        assert!(
            !format!("{err:?}").contains("hunter2"),
            "{level:?}: {err:?}"
        );
        // The owner still reads it.
        let own = call(&state, &owner, NOW, "notes.read", json!({ "node": "acme" })).unwrap();
        assert_eq!(own["markdown"], "the root password is hunter2");
    }
    force_level(&state, SecurityLevel::Open);
    let r = call(&state, &bot, NOW, "notes.read", json!({ "node": "acme" })).unwrap();
    assert_eq!(r["markdown"], "the root password is hunter2");
}

#[test]
fn an_open_nodes_note_asks_an_agent_for_the_second_factor_as_a_reveal_does() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    force_level(&state, SecurityLevel::Open);
    write_note(&state, &owner, "acme", "needs the factor");
    let totp = enrol_gate(&state, &owner);
    let bot = agent("acme", vec![Capability::List, Capability::Read]);
    // `requireTwoFactor` defaults to `reveal`, which asks before a value leaves; a note read by an agent
    // is held to the same, not to the read-level check that would let it through.
    let r = call(&state, &bot, NOW, "notes.read", json!({ "node": "acme" }));
    assert!(matches!(r, Err(OpError::TwoFactorRequired { .. })), "{r:?}");
    // A person's read of the same note is unchanged (the owner's login passed the gate to exist).
    assert!(call(&state, &owner, NOW, "notes.read", json!({ "node": "acme" })).is_ok());
    // Fresh factor: the agent reads.
    step_up(&state, &owner, &totp, NOW + 60);
    let r = call(
        &state,
        &bot,
        NOW + 61,
        "notes.read",
        json!({ "node": "acme" }),
    )
    .unwrap();
    assert_eq!(r["markdown"], "needs the factor");
}

#[test]
fn a_node_that_hides_its_names_hides_its_note_from_an_agent() {
    let (_v, state) = created_vault(None);
    let owner = login(&state);
    create_node(&state, &owner, "acme");
    force_level(&state, SecurityLevel::Open);
    write_note(&state, &owner, "acme", "private text");
    call(
        &state,
        &owner,
        NOW,
        "node.policy",
        json!({ "node": "acme", "reason": "hide", "policy": { "privateNames": true } }),
    )
    .expect("node.policy");
    let bot = agent("acme", vec![Capability::List, Capability::Read]);
    let r = call(&state, &bot, NOW, "notes.read", json!({ "node": "acme" })).unwrap();
    assert_eq!(r["nameHidden"], true, "{r}");
    assert!(!r.to_string().contains("private text"), "{r}");
}
