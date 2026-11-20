//! ADR-156 (quick win 18): a 32-byte key held in memory the OS is asked not to
//! swap out.
//!
//! Each key gets its own page, allocated page-aligned, so `mlock` and `munlock`
//! act on that key alone (neither call is reference-counted: unlocking one key's
//! page must never unlock another's). On Linux the page is also marked
//! `MADV_DONTDUMP`, so a core dump leaves it out. A refused `mlock` (for example
//! a low `RLIMIT_MEMLOCK`) is not fatal: the key still works, the refusal is
//! counted ([`lock_failures`]) and said once on stderr.
//!
//! The bytes are zeroised in place by [`LockedKey::zeroize`] and again on drop,
//! before the page is unlocked and freed.
//!
//! This module carries the crate's third scoped `#![allow(unsafe_code)]`
//! (beside `peer.rs` and `state/rotate/vault_lock.rs`): a page-aligned
//! allocation and the `mlock`, `munlock` and `madvise` syscalls have no safe
//! wrapper in the MSRV's standard library, and the crate takes no new
//! dependency for them. Every `unsafe` block below states what makes it sound.
#![allow(unsafe_code)]

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};

static LOCK_FAILURES: AtomicU64 = AtomicU64::new(0);

/// How many key pages the OS refused to lock since the process started.
pub fn lock_failures() -> u64 {
    LOCK_FAILURES.load(Ordering::Relaxed)
}

fn page_size() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: sysconf has no preconditions.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if size > 0 {
            return size as usize;
        }
    }
    4096
}

/// A 32-byte secret on its own locked page.
pub struct LockedKey {
    ptr: NonNull<[u8; 32]>,
    layout: Layout,
    locked: bool,
}

// SAFETY: the page is owned uniquely by this value; access follows Rust's
// ordinary borrow rules through `&self` / `&mut self`.
unsafe impl Send for LockedKey {}
unsafe impl Sync for LockedKey {}

impl LockedKey {
    /// Copy `bytes` onto a fresh locked page. The caller wipes its own copy.
    pub fn new(bytes: &[u8; 32]) -> Self {
        let size = page_size().max(32);
        let layout = Layout::from_size_align(size, size).expect("a page is a valid layout");
        // SAFETY: the layout has a non-zero size.
        let raw = unsafe { alloc_zeroed(layout) };
        let Some(page) = NonNull::new(raw) else {
            std::alloc::handle_alloc_error(layout);
        };
        let ptr = page.cast::<[u8; 32]>();
        // SAFETY: the page is at least 32 bytes, page-aligned and exclusively ours.
        unsafe { ptr.as_ptr().write(*bytes) };
        let locked = lock_page(raw, size);
        LockedKey {
            ptr,
            layout,
            locked,
        }
    }

    /// The key from a `StaticSecret`, without leaving another copy behind.
    pub fn from_secret(secret: &x25519_dalek::StaticSecret) -> Self {
        let mut bytes = zeroize::Zeroizing::new(secret.to_bytes());
        let key = Self::new(&bytes);
        zeroize::Zeroize::zeroize(&mut *bytes);
        key
    }

    /// Whether the OS agreed to keep this page out of swap.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl zeroize::Zeroize for LockedKey {
    /// Overwrite the key with zeros, in place.
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut **self);
    }
}

#[cfg(unix)]
fn lock_page(raw: *mut u8, size: usize) -> bool {
    #[cfg(target_os = "linux")]
    // SAFETY: `raw` is a page-aligned allocation of `size` bytes owned by the caller.
    unsafe {
        libc::madvise(raw.cast(), size, libc::MADV_DONTDUMP);
    }
    // SAFETY: as above.
    let ok = unsafe { libc::mlock(raw.cast(), size) } == 0;
    if !ok && LOCK_FAILURES.fetch_add(1, Ordering::Relaxed) == 0 {
        eprintln!(
            "credmgrd: the OS refused to lock a key page in memory (mlock); keys still work but may be swapped out"
        );
    }
    ok
}

#[cfg(not(unix))]
fn lock_page(_raw: *mut u8, _size: usize) -> bool {
    LOCK_FAILURES.fetch_add(1, Ordering::Relaxed);
    false
}

impl std::ops::Deref for LockedKey {
    type Target = [u8; 32];
    fn deref(&self) -> &[u8; 32] {
        // SAFETY: valid for the life of `self`.
        unsafe { self.ptr.as_ref() }
    }
}

impl std::ops::DerefMut for LockedKey {
    fn deref_mut(&mut self) -> &mut [u8; 32] {
        // SAFETY: valid and uniquely borrowed for the life of `&mut self`.
        unsafe { self.ptr.as_mut() }
    }
}

impl Clone for LockedKey {
    fn clone(&self) -> Self {
        LockedKey::new(self)
    }
}

impl std::fmt::Debug for LockedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedKey")
            .field("bytes", &"<redacted>")
            .field("locked", &self.locked)
            .finish()
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
        let raw = self.ptr.as_ptr().cast::<u8>();
        #[cfg(unix)]
        if self.locked {
            // SAFETY: the same page `lock_page` locked.
            unsafe {
                libc::munlock(raw.cast(), self.layout.size());
            }
        }
        // SAFETY: allocated in `new` with this layout.
        unsafe { dealloc(raw, self.layout) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    #[test]
    fn a_key_round_trips_on_its_own_page_and_zeroises_in_place() {
        let mut key = LockedKey::new(&[7u8; 32]);
        assert_eq!(*key, [7u8; 32]);
        let addr = key.ptr.as_ptr() as usize;
        assert_eq!(
            addr % page_size(),
            0,
            "page-aligned, so mlock covers this key alone"
        );
        let copy = key.clone();
        assert_ne!(
            copy.ptr.as_ptr() as usize,
            addr,
            "a clone gets its own page"
        );
        key.zeroize();
        assert_eq!(*key, [0u8; 32]);
        assert_eq!(*copy, [7u8; 32]);
        assert!(!format!("{copy:?}").contains('7'));
    }

    #[test]
    fn the_page_is_locked_where_the_os_allows_it() {
        let key = LockedKey::new(&[1u8; 32]);
        // A container may refuse mlock (RLIMIT_MEMLOCK); then the refusal is counted, never fatal.
        assert!(key.is_locked() || lock_failures() > 0);
    }
}
