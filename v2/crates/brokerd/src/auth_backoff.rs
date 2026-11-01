//! Exponential auth-failure backoff — `07_TWO_FACTOR.md §5`: 5 failures →
//! 30s lock, doubling (30s → 1m → 2m → 4m → 8m → 16m → 32m), capped at
//! **1 hour** (ADR-070, superseding ADR-044's 15-minute cap: the operator's
//! crypto-hardening spec asks for V1's pattern). Per scope. Shared counter
//! with the passphrase path so an attacker cannot alternate (ADR-044). Distinct from `rate_limit::RateLimiter`, which
//! answers a different question (cross-node-denial anomaly detection,
//! `05_THREAT_MODEL.md §7`) off a different input.
//!
//! Phase 3 has exactly one auth path, `vault.unlock`'s keystore passphrase
//! — this type is built mechanism-agnostic (keyed by uid, not by "which
//! factor failed") specifically so Phase 5's TOTP verification feeds the
//! same counter without this type changing shape.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const FAILURES_BEFORE_BACKOFF: u32 = 5;
const BACKOFF_SCHEDULE_SECONDS: [u64; 7] = [30, 60, 120, 240, 480, 960, 1920];
const BACKOFF_CAP_SECONDS: u64 = 3600;

#[derive(Debug, Default, Clone, Copy)]
struct FailureState {
    consecutive_failures: u32,
    locked_until: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct AuthBackoff {
    by_uid: Mutex<HashMap<u32, FailureState>>,
}

impl AuthBackoff {
    pub fn new() -> Self {
        AuthBackoff::default()
    }

    /// Zero before the 5th consecutive failure; `30s, 1m, 2m, 4m, 8m, 16m,
    /// 32m` for the 5th through 11th, `1h` (the cap) for every one after.
    fn backoff_for(consecutive_failures: u32) -> Duration {
        if consecutive_failures < FAILURES_BEFORE_BACKOFF {
            return Duration::ZERO;
        }
        let step = (consecutive_failures - FAILURES_BEFORE_BACKOFF) as usize;
        let secs = BACKOFF_SCHEDULE_SECONDS
            .get(step)
            .copied()
            .unwrap_or(BACKOFF_CAP_SECONDS);
        Duration::from_secs(secs.min(BACKOFF_CAP_SECONDS))
    }

    /// `None` if `uid` may attempt now; `Some(remaining)` if a backoff from
    /// an earlier failure is still in effect.
    pub fn remaining_lockout(&self, uid: u32, now: Instant) -> Option<Duration> {
        let by_uid = self.by_uid.lock().expect("auth backoff poisoned");
        let until = by_uid.get(&uid)?.locked_until?;
        (now < until).then(|| until - now)
    }

    /// Records a failed auth attempt for `uid`. Returns the new lockout
    /// duration (zero before the 5th consecutive failure).
    pub fn record_failure(&self, uid: u32, now: Instant) -> Duration {
        let mut by_uid = self.by_uid.lock().expect("auth backoff poisoned");
        let state = by_uid.entry(uid).or_default();
        state.consecutive_failures += 1;
        let backoff = Self::backoff_for(state.consecutive_failures);
        state.locked_until = (!backoff.is_zero()).then(|| now + backoff);
        backoff
    }

    /// A successful auth clears the counter — the schedule is about
    /// *consecutive* failures, not a lifetime tally.
    pub fn record_success(&self, uid: u32) {
        self.by_uid
            .lock()
            .expect("auth backoff poisoned")
            .remove(&uid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_lockout_before_the_fifth_consecutive_failure() {
        let backoff = AuthBackoff::new();
        let now = Instant::now();
        for _ in 0..4 {
            let d = backoff.record_failure(501, now);
            assert!(d.is_zero());
        }
        assert!(backoff.remaining_lockout(501, now).is_none());
    }

    #[test]
    fn schedule_matches_07_5_exactly() {
        let backoff = AuthBackoff::new();
        let now = Instant::now();
        // Failures 1-4: below threshold, no lockout at all.
        for _ in 0..4 {
            assert!(backoff.record_failure(501, now).is_zero());
        }
        // Failures 5-13: 30s, 1m, 2m, 4m, 8m, 16m, 32m, then capped at 1h (ADR-070).
        let expected = [30u64, 60, 120, 240, 480, 960, 1920, 3600, 3600];
        for &secs in &expected {
            let d = backoff.record_failure(501, now);
            assert_eq!(d, Duration::from_secs(secs));
        }
    }

    #[test]
    fn locked_out_uid_reports_remaining_time_until_the_window_elapses() {
        let backoff = AuthBackoff::new();
        let now = Instant::now();
        for _ in 0..5 {
            backoff.record_failure(501, now);
        }
        let remaining = backoff
            .remaining_lockout(501, now + Duration::from_secs(10))
            .expect("still within the 30s window");
        assert_eq!(remaining, Duration::from_secs(20));

        assert!(backoff
            .remaining_lockout(501, now + Duration::from_secs(30))
            .is_none());
    }

    #[test]
    fn success_clears_the_counter() {
        let backoff = AuthBackoff::new();
        let now = Instant::now();
        for _ in 0..4 {
            backoff.record_failure(501, now);
        }
        backoff.record_success(501);
        // Back to zero — the 5th call after a success is failure #1 again,
        // not #5, so it must not trip the backoff.
        let d = backoff.record_failure(501, now);
        assert!(d.is_zero());
    }

    #[test]
    fn lockouts_are_per_uid() {
        let backoff = AuthBackoff::new();
        let now = Instant::now();
        for _ in 0..5 {
            backoff.record_failure(501, now);
        }
        assert!(backoff.remaining_lockout(501, now).is_some());
        assert!(backoff.remaining_lockout(502, now).is_none());
    }
}
