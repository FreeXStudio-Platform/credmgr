//! ADR-130…134 — the small amount of live state the 2.0.0 broker features keep: the rate window of
//! `search.content` (ADR-132), the scrypt work factor of `node.export` (ADR-133), and the crash-injection
//! seams of `node.rekey` and `orphan.destroy` (compiled only with `test-utils`).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

#[derive(Default)]
pub struct StableState {
    /// Per caller: when its recent `search.content` calls were made (unix seconds).
    content_search: Mutex<HashMap<String, VecDeque<i64>>>,
    /// ADR-161: held while a `vault.doctor_scan` runs, so a second one waits instead of doubling the work.
    pub(crate) doctor_scan_running: Mutex<()>,
    /// ADR-161: a smaller entry cap for the doctor's scan, so a test can reach it without 10 000 entries.
    #[cfg(feature = "test-utils")]
    pub(crate) doctor_scan_cap: Mutex<Option<usize>>,
    #[cfg(feature = "test-utils")]
    pub(crate) rekey_fault: Mutex<Option<crate::state::RekeyFault>>,
    #[cfg(feature = "test-utils")]
    pub(crate) move_fault: Mutex<Option<crate::state::MoveFault>>,
    #[cfg(feature = "test-utils")]
    pub(crate) destroy_fault: Mutex<Option<crate::state::DestroyFault>>,
    #[cfg(feature = "test-utils")]
    export_log_n: Mutex<Option<u8>>,
}

impl StableState {
    /// Admit one `search.content` call for `key`, or say how many seconds until one would be admitted.
    /// A rejected call is **not** counted, so waiting out the window is always enough.
    pub fn content_search_admit(&self, key: &str, now: i64) -> Result<(), u64> {
        let mut windows = self
            .content_search
            .lock()
            .expect("content search window poisoned");
        let window = windows.entry(key.to_string()).or_default();
        while window
            .front()
            .is_some_and(|t| now - *t >= crate::ops::CONTENT_WINDOW_SECONDS)
        {
            window.pop_front();
        }
        if window.len() >= crate::ops::CONTENT_SEARCH_MAX_CALLS {
            let oldest = *window.front().expect("a full window has a front");
            let wait = crate::ops::CONTENT_WINDOW_SECONDS - (now - oldest);
            return Err(u64::try_from(wait.max(1)).unwrap_or(1));
        }
        window.push_back(now);
        // A caller that never comes back must not stay in the table forever.
        if windows.len() > 256 {
            windows.retain(|_, w| {
                w.back()
                    .is_some_and(|t| now - *t < crate::ops::CONTENT_WINDOW_SECONDS)
            });
        }
        Ok(())
    }

    /// The scrypt work factor (`log2 N`) a passphrase export uses.
    pub fn export_work_factor(&self) -> u8 {
        #[cfg(feature = "test-utils")]
        if let Some(n) = *self
            .export_log_n
            .lock()
            .expect("export work factor poisoned")
        {
            return n;
        }
        credmgr_core::age_format::DEFAULT_SCRYPT_LOG_N
    }

    /// Lower the export work factor so a test does not pay a second of scrypt per export (test seam).
    #[cfg(feature = "test-utils")]
    pub fn set_export_work_factor_for_test(&self, log_n: Option<u8>) {
        *self
            .export_log_n
            .lock()
            .expect("export work factor poisoned") = log_n;
    }
}
