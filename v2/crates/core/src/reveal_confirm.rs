//! ADR-150 — "confirm before showing secrets": the vault policy that makes the owner's own login prove a
//! person is still at the keyboard (Touch ID or the vault passphrase) before the broker hands it a secret
//! value. Pure: the policy, the requirement it sets for one value, whether a change weakens it, and whether a
//! recorded confirmation meets a requirement at a given moment. The broker holds the confirmations and the
//! clock; nothing here reads either.
//!
//! The policy lives on the `global` node's policy (`revealConfirm`), inside the signed registry. Absent —
//! every registry written before ADR-150 — reads as [`RevealConfirm::default`]: off.

use serde::{Deserialize, Serialize};

use crate::inference::Sensitivity;

/// The trust-window lengths a policy may name, in seconds: 1, 5, 15 and 60 minutes.
pub const WINDOW_CHOICES: [u32; 4] = [60, 300, 900, 3600];
/// The trust window a policy has when none was chosen: five minutes.
pub const DEFAULT_WINDOW_SECONDS: u32 = 300;
/// How long a confirmation stays usable for a request that needs a *fresh* one: one gated request in
/// "every time" mode, or a change that weakens this policy.
pub const FRESH_SECONDS: i64 = 60;

/// When the owner's login is asked to confirm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConfirmMode {
    /// Never (the default): a login shows secrets as it always has.
    #[default]
    Off,
    /// Once, then not again for the trust window.
    Window,
    /// Before every value: one confirmation per request.
    EveryTime,
}

/// Which values the policy covers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConfirmScope {
    /// Every value (the default).
    #[default]
    All,
    /// Only entries whose sensitivity is high or critical.
    High,
}

/// The wire names of the policy's fields. `node.policy` refuses any other key in a request (a typo must not be
/// silently dropped); the registry reader ignores unknown keys (below).
pub const FIELDS: [&str; 3] = ["mode", "windowSeconds", "scope"];

/// The policy (`global.policy.revealConfirm`). Unknown keys are ignored when it is read (review P3-g): a registry
/// written by a newer version with an extra field still loads, as `NodePolicy` itself does; the known fields are
/// still typed and range-checked, and `node.policy` keeps requests strict against [`FIELDS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealConfirm {
    pub mode: ConfirmMode,
    #[serde(default = "default_window")]
    pub window_seconds: u32,
    #[serde(default)]
    pub scope: ConfirmScope,
}

fn default_window() -> u32 {
    DEFAULT_WINDOW_SECONDS
}

impl Default for RevealConfirm {
    fn default() -> Self {
        RevealConfirm {
            mode: ConfirmMode::Off,
            window_seconds: DEFAULT_WINDOW_SECONDS,
            scope: ConfirmScope::All,
        }
    }
}

/// What one value needs before it may be shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Nothing.
    None,
    /// A confirmation made within this many seconds.
    Within(u32),
    /// A confirmation made within [`FRESH_SECONDS`] and not yet used.
    Fresh,
}

impl Need {
    /// Strength, for comparing two policies: `None` < `Within(long)` < `Within(short)` < `Fresh`.
    fn rank(self) -> (u8, i64) {
        match self {
            Need::None => (0, 0),
            Need::Within(s) => (1, -i64::from(s)),
            Need::Fresh => (2, 0),
        }
    }
}

/// A confirmation the broker recorded for one login session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confirmation {
    /// Unix epoch seconds.
    pub at: i64,
    /// Already used by a request that needed a fresh one.
    pub spent: bool,
}

impl RevealConfirm {
    pub fn is_default(&self) -> bool {
        *self == RevealConfirm::default()
    }

    /// The policy is well formed: the window is one of [`WINDOW_CHOICES`].
    pub fn validate(&self) -> Result<(), String> {
        if !WINDOW_CHOICES.contains(&self.window_seconds) {
            return Err(format!(
                "revealConfirm.windowSeconds must be one of {WINDOW_CHOICES:?}"
            ));
        }
        Ok(())
    }

    /// What showing a value of `sensitivity` needs under this policy.
    pub fn need(&self, sensitivity: Sensitivity) -> Need {
        let covered = match self.scope {
            ConfirmScope::All => true,
            ConfirmScope::High => sensitivity >= Sensitivity::High,
        };
        match (self.mode, covered) {
            (ConfirmMode::Off, _) | (_, false) => Need::None,
            (ConfirmMode::Window, true) => Need::Within(self.window_seconds),
            (ConfirmMode::EveryTime, true) => Need::Fresh,
        }
    }

    /// Whether moving from `self` to `next` asks less for any value. Turning the policy off, a longer window,
    /// "every time" to "window" and "all" to "high" all weaken; the reverse of each strengthens.
    pub fn weakened_by(&self, next: &RevealConfirm) -> bool {
        [
            Sensitivity::Low,
            Sensitivity::Medium,
            Sensitivity::High,
            Sensitivity::Critical,
        ]
        .iter()
        .any(|s| next.need(*s).rank() < self.need(*s).rank())
    }

    /// How long a confirmation made now stays good for a gated value, for the answer of `session.confirm`.
    pub fn confirmation_lifetime(&self) -> u32 {
        match self.mode {
            ConfirmMode::Window => self.window_seconds,
            _ => FRESH_SECONDS as u32,
        }
    }

    /// Whether this policy, at the edge of `high`, would gate a value of `from` and not one of `to` — an edit
    /// that lowers an entry's sensitivity across that edge takes the entry out of the policy's reach.
    pub fn lowering_escapes(&self, from: Sensitivity, to: Sensitivity) -> bool {
        self.need(from) != Need::None && self.need(to) == Need::None
    }
}

/// Whether `held` meets `need` at `now`, and whether meeting it uses the confirmation up.
/// `(satisfied, consume)`.
pub fn satisfied(need: Need, held: Option<Confirmation>, now: i64) -> (bool, bool) {
    match need {
        Need::None => (true, false),
        Need::Within(secs) => match held {
            Some(c) => (now >= c.at && now - c.at < i64::from(secs), false),
            None => (false, false),
        },
        Need::Fresh => match held {
            Some(c) if !c.spent && now >= c.at && now - c.at < FRESH_SECONDS => (true, true),
            _ => (false, false),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(mode: ConfirmMode, window: u32, scope: ConfirmScope) -> RevealConfirm {
        RevealConfirm {
            mode,
            window_seconds: window,
            scope,
        }
    }

    #[test]
    fn absent_reads_as_off_and_needs_nothing() {
        let d: RevealConfirm = serde_json::from_str(r#"{"mode":"off"}"#).unwrap();
        assert!(d.is_default());
        for s in [Sensitivity::Low, Sensitivity::Critical] {
            assert_eq!(d.need(s), Need::None);
        }
    }

    #[test]
    fn wire_shape_is_camel_case_and_forward_compatible() {
        let v = serde_json::to_value(p(ConfirmMode::EveryTime, 900, ConfirmScope::High)).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"mode":"everyTime","windowSeconds":900,"scope":"high"})
        );
        // An unknown (future) key is ignored; the known ones are still read and typed.
        let read: RevealConfirm =
            serde_json::from_str(r#"{"mode":"window","windowSeconds":900,"future":1}"#).unwrap();
        assert_eq!(read, p(ConfirmMode::Window, 900, ConfirmScope::All));
        assert!(serde_json::from_str::<RevealConfirm>(r#"{"mode":"sometimes"}"#).is_err());
        assert!(
            serde_json::from_str::<RevealConfirm>(r#"{"mode":"window","windowSeconds":"x"}"#)
                .is_err()
        );
        assert!(p(ConfirmMode::Window, 61, ConfirmScope::All)
            .validate()
            .is_err());
        assert!(p(ConfirmMode::Window, 3600, ConfirmScope::All)
            .validate()
            .is_ok());
    }

    #[test]
    fn high_scope_lets_low_and_medium_through() {
        let pol = p(ConfirmMode::Window, 300, ConfirmScope::High);
        assert_eq!(pol.need(Sensitivity::Low), Need::None);
        assert_eq!(pol.need(Sensitivity::Medium), Need::None);
        assert_eq!(pol.need(Sensitivity::High), Need::Within(300));
        assert_eq!(pol.need(Sensitivity::Critical), Need::Within(300));
        assert!(pol.lowering_escapes(Sensitivity::High, Sensitivity::Medium));
        assert!(!pol.lowering_escapes(Sensitivity::Critical, Sensitivity::High));
    }

    #[test]
    fn weakening_is_any_value_asked_less() {
        let off = RevealConfirm::default();
        let w5 = p(ConfirmMode::Window, 300, ConfirmScope::All);
        let w60 = p(ConfirmMode::Window, 3600, ConfirmScope::All);
        let every = p(ConfirmMode::EveryTime, 300, ConfirmScope::All);
        let every_high = p(ConfirmMode::EveryTime, 300, ConfirmScope::High);
        assert!(!off.weakened_by(&w5));
        assert!(w5.weakened_by(&off));
        assert!(w5.weakened_by(&w60));
        assert!(!w60.weakened_by(&w5));
        assert!(!w5.weakened_by(&every));
        assert!(every.weakened_by(&w5));
        assert!(every.weakened_by(&every_high));
        assert!(w5.weakened_by(&every_high)); // low values lose their prompt
        assert!(!w5.weakened_by(&w5));
    }

    #[test]
    fn window_and_fresh_confirmations() {
        let c = Confirmation {
            at: 1000,
            spent: false,
        };
        assert_eq!(satisfied(Need::Within(300), Some(c), 1299), (true, false));
        assert_eq!(satisfied(Need::Within(300), Some(c), 1300), (false, false));
        assert_eq!(satisfied(Need::Within(300), None, 1000), (false, false));
        assert_eq!(satisfied(Need::Fresh, Some(c), 1059), (true, true));
        assert_eq!(satisfied(Need::Fresh, Some(c), 1060), (false, false));
        let spent = Confirmation {
            at: 1000,
            spent: true,
        };
        assert_eq!(satisfied(Need::Fresh, Some(spent), 1001), (false, false));
        // A spent confirmation still counts for a window: spending matters to fresh needs only.
        assert_eq!(
            satisfied(Need::Within(300), Some(spent), 1001),
            (true, false)
        );
        // A clock that moved backwards never satisfies.
        assert_eq!(satisfied(Need::Within(300), Some(c), 999), (false, false));
        assert_eq!(satisfied(Need::None, None, 0), (true, false));
    }
}
