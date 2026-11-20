//! Cross-node denial rate limiting — `05_THREAT_MODEL.md §7`: "≥5 cross-node
//! denials in 10 minutes" raises an anomaly. One counter, shared across
//! every auth path (token, cwd-derived, unknown) per `02_ARCHITECTURE.md`'s
//! "shares its counter across auth paths" exit-gate item — keyed by uid so
//! one caller's noise doesn't starve another's budget, but not by node, so
//! an attacker can't dodge the limiter by spreading guesses across targets.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(600);
const THRESHOLD: usize = 5;

#[derive(Debug, Default)]
pub struct RateLimiter {
    denials_by_uid: Mutex<HashMap<u32, Vec<Instant>>>,
    /// ADR-156: trips nobody has looked at yet. In memory only — a restart clears it, and every trip is
    /// also on the audit trail (`anomaly.cross_node_denials`), which is the durable record.
    unseen_alarms: AtomicU64,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter::default()
    }

    /// Record a cross-node denial for `uid`. Returns `true` exactly on the
    /// request that pushes this uid's 10-minute window to the threshold —
    /// callers raise the anomaly event on that transition, not on every
    /// subsequent denial while still over it.
    pub fn record_denial(&self, uid: u32, now: Instant) -> bool {
        let mut map = self.denials_by_uid.lock().expect("rate limiter poisoned");
        let entries = map.entry(uid).or_default();
        entries.retain(|t| now.duration_since(*t) < WINDOW);
        entries.push(now);
        let tripped = entries.len() == THRESHOLD;
        if tripped {
            self.unseen_alarms.fetch_add(1, Ordering::SeqCst);
        }
        tripped
    }

    /// ADR-156: how many times the alarm tripped since it was last acknowledged.
    pub fn unseen_alarms(&self) -> u64 {
        self.unseen_alarms.load(Ordering::SeqCst)
    }

    /// ADR-156: the owner has seen the alarm; returns how many trips that covered.
    pub fn acknowledge_alarms(&self) -> u64 {
        self.unseen_alarms.swap(0, Ordering::SeqCst)
    }

    #[cfg(test)]
    pub fn count(&self, uid: u32, now: Instant) -> usize {
        let mut map = self.denials_by_uid.lock().expect("rate limiter poisoned");
        let entries = map.entry(uid).or_default();
        entries.retain(|t| now.duration_since(*t) < WINDOW);
        entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifth_denial_in_window_trips_the_anomaly_exactly_once() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        let mut tripped = 0;
        for _ in 0..7 {
            if limiter.record_denial(501, now) {
                tripped += 1;
            }
        }
        assert_eq!(tripped, 1);
        assert_eq!(
            limiter.unseen_alarms(),
            1,
            "a trip is an unseen alarm until acknowledged"
        );
        assert_eq!(limiter.acknowledge_alarms(), 1);
        assert_eq!(limiter.unseen_alarms(), 0);
        assert_eq!(limiter.count(501, now), 7);
    }

    #[test]
    fn denials_outside_the_window_do_not_count() {
        let limiter = RateLimiter::new();
        let old = Instant::now();
        for _ in 0..4 {
            limiter.record_denial(501, old);
        }
        let later = old + Duration::from_secs(601);
        assert_eq!(limiter.count(501, later), 0);
        assert!(!limiter.record_denial(501, later));
    }

    #[test]
    fn counters_are_per_uid() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        for _ in 0..5 {
            limiter.record_denial(501, now);
        }
        assert_eq!(limiter.count(502, now), 0);
    }
}
