//! ADR-135 — a node's own second factor. The gate machinery was always keyed by scope (the `gate`,
//! `gate_replay` and `elevations` maps take any string, and `registry.json` stores one `gate.twofa` per
//! node); the vault's gate is the scope `global`. A node with a confirmed gate of its own is asked for
//! **that** gate's code, by the owner too, and the code opens that node only.

use credmgr_core::registry::GLOBAL_ID;
use credmgr_store::error::StoreError;

use super::BrokerState;

impl BrokerState {
    /// Whether `node_id` has a confirmed second factor of its own (never true for the vault's `global`).
    pub fn node_has_own_gate(&self, node_id: &str) -> bool {
        node_id != GLOBAL_ID && self.is_gate_confirmed(node_id)
    }

    /// The gate scope whose code opens `node_id`: its own when it has one, else the vault's.
    pub fn gate_scope_for_node(&self, node_id: &str) -> String {
        if self.node_has_own_gate(node_id) {
            node_id.to_string()
        } else {
            super::GATE_SCOPE_VAULT.to_string()
        }
    }

    /// Remove `scope`'s gate (confirmed or half-enrolled), its pending re-enrolment and its elevation, and
    /// write the vault through. For a holder who has just proved the factor being removed. Returns whether
    /// a confirmed gate was in force.
    pub fn gate_drop(&self, scope: &str, now: i64) -> Result<bool, StoreError> {
        let had = self
            .gate
            .write()
            .expect("gate poisoned")
            .remove(scope)
            .is_some_and(|g| g.confirmed);
        self.gate_pending
            .write()
            .expect("gate pending poisoned")
            .remove(scope);
        self.elevations
            .write()
            .expect("elevations poisoned")
            .remove(scope);
        self.persist(now)?;
        Ok(had)
    }
}
