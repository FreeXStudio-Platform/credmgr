//! ADR-165 — the machine lock: ADR-144's smallest safe version, the file tier.
//!
//! A **device key** (32 random bytes from the OS CSPRNG, `<state>/machine/lock.key`, mode `0600`, outside the
//! vault folder) seals the passphrase wrap a second time. A bound `keys/root.wrap.pass` is
//!
//! ```text
//! MAGIC (8) ‖ key id (8) ‖ nonce (12) ‖ ChaCha20-Poly1305(device key, plain wrap, aad = MAGIC ‖ key id)
//! ```
//!
//! so "bound" is a property of the file itself and can never disagree with a flag. An unbound wrap is the
//! plain Argon2id wrap of [`crate::software`], byte for byte as it has always been, and is opened exactly as
//! before: this module never touches a file that does not start with [`MAGIC`].
//!
//! What it protects, stated plainly: a **copied vault folder** (a synced folder, a backup, a stolen USB disk)
//! can no longer be opened with the passphrase alone on another computer; it needs this Mac's device key or the
//! recovery code. What it does **not** protect: a stolen Mac, whose disk holds both the vault folder and the
//! device key (FileVault is the answer to that). Sealing the key to the Secure Enclave would change that and
//! needs a signed build; it is not this module.
//!
//! Only the passphrase wrap is sealed. `root.wrap.recovery` is not, by design: the recovery code must open the
//! vault on a new Mac, after a reinstall, or when the device key is lost (ADR-163, ADR-165).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// The first eight bytes of a sealed passphrase wrap.
pub const MAGIC: [u8; 8] = *b"CMMLOCK1";
/// A device key's id: the first eight bytes of a domain-separated SHA-256 of the key. Not secret.
pub const KEY_ID_LEN: usize = 8;
/// The device key's length.
pub const DEVICE_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// `MAGIC ‖ key id ‖ nonce`.
pub const HEADER_LEN: usize = MAGIC.len() + KEY_ID_LEN + NONCE_LEN;
/// The length of a plain passphrase wrap of a 32-byte root key: `salt (16) ‖ nonce (12) ‖ ct (32) ‖ tag (16)`
/// (`software.rs`). Every plain wrap any CredMgr ever wrote has exactly this length, so a plain wrap whose
/// random salt happens to begin with [`MAGIC`] (a 2^-64 chance) is still read as plain.
pub const PLAIN_PASS_WRAP_LEN: usize = 16 + 12 + 32 + 16;
const KEY_ID_LABEL: &[u8] = b"credmgr/v2/machine-lock/key-id\0";

/// What a `root.wrap.pass` file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapForm {
    /// Not bound: the plain Argon2id wrap, opened exactly as before ADR-165.
    Plain,
    /// Bound to the device key with this id.
    Sealed { key_id: [u8; KEY_ID_LEN] },
    /// Starts with [`MAGIC`] but is too short to be a sealed wrap: truncated or damaged.
    Damaged,
}

/// Why a sealed wrap could not be opened, or a device key could not be read or made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineLockError {
    /// The file is not sealed (there is nothing to open with a device key).
    NotSealed,
    /// The sealed wrap is truncated, or its authentication tag does not verify under the right key.
    Damaged,
    /// The wrap was sealed under a different device key (another Mac, or a key that was replaced).
    WrongDeviceKey,
    /// The device key file is not there.
    DeviceKeyMissing,
    /// The device key file is there but is not a 32-byte regular file, or cannot be read.
    DeviceKeyUnreadable(String),
    /// A device key could not be written.
    Io(String),
    /// ADR-165 review P0-1: this Mac bound the vault, the passphrase file on disk is now a plain wrap, and the
    /// root key that plain wrap yields does not open the vault — an older, pre-bind wrap was put back.
    PlainWhileBound,
}

impl std::fmt::Display for MachineLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MachineLockError::NotSealed => write!(f, "the passphrase wrap is not sealed"),
            MachineLockError::Damaged => write!(f, "the sealed passphrase wrap is damaged"),
            MachineLockError::WrongDeviceKey => {
                write!(f, "the passphrase wrap is sealed to another device key")
            }
            MachineLockError::DeviceKeyMissing => write!(f, "this Mac's device key is missing"),
            MachineLockError::DeviceKeyUnreadable(why) => {
                write!(f, "this Mac's device key cannot be read: {why}")
            }
            MachineLockError::Io(why) => write!(f, "the device key could not be written: {why}"),
            MachineLockError::PlainWhileBound => write!(
                f,
                "this Mac bound the vault, but its passphrase file is now an older unsealed one that does \
                 not open it"
            ),
        }
    }
}

impl std::error::Error for MachineLockError {}

impl MachineLockError {
    /// The stable wire word for this refusal (`machine_lock_refused`'s `reason`).
    pub fn reason(&self) -> &'static str {
        match self {
            MachineLockError::NotSealed => "not_sealed",
            MachineLockError::Damaged => "sealed_wrap_damaged",
            MachineLockError::WrongDeviceKey => "device_key_mismatch",
            MachineLockError::DeviceKeyMissing => "device_key_missing",
            MachineLockError::DeviceKeyUnreadable(_) => "device_key_unreadable",
            MachineLockError::Io(_) => "device_key_unwritable",
            MachineLockError::PlainWhileBound => "plain_wrap_while_bound",
        }
    }
}

/// Classify a `root.wrap.pass` file's bytes. Never fails: anything that does not begin with [`MAGIC`], or has
/// exactly the plain wrap's length, is [`WrapForm::Plain`] and goes to the Argon2id open unchanged.
pub fn classify(bytes: &[u8]) -> WrapForm {
    if !bytes.starts_with(&MAGIC) || bytes.len() == PLAIN_PASS_WRAP_LEN {
        return WrapForm::Plain;
    }
    if bytes.len() < HEADER_LEN + TAG_LEN + 1 {
        return WrapForm::Damaged;
    }
    let mut key_id = [0u8; KEY_ID_LEN];
    key_id.copy_from_slice(&bytes[MAGIC.len()..MAGIC.len() + KEY_ID_LEN]);
    WrapForm::Sealed { key_id }
}

/// Lower-case hex of a key id, for status answers and messages.
pub fn key_id_hex(id: &[u8; KEY_ID_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(KEY_ID_LEN * 2);
    for b in id {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

fn derive_key_id(key: &[u8; DEVICE_KEY_LEN]) -> [u8; KEY_ID_LEN] {
    let mut h = Sha256::new();
    h.update(KEY_ID_LABEL);
    h.update(key);
    let digest = h.finalize();
    let mut id = [0u8; KEY_ID_LEN];
    id.copy_from_slice(&digest[..KEY_ID_LEN]);
    id
}

/// This Mac's device key. Held in a [`SecretBox`] (zeroised on drop); never logged, never answered.
pub struct DeviceKey {
    key: SecretBox<[u8; DEVICE_KEY_LEN]>,
    id: [u8; KEY_ID_LEN],
}

impl DeviceKey {
    /// A fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; DEVICE_KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        let key = Self::from_bytes(&bytes);
        bytes.zeroize();
        key
    }

    pub fn from_bytes(bytes: &[u8; DEVICE_KEY_LEN]) -> Self {
        DeviceKey {
            key: SecretBox::new(Box::new(*bytes)),
            id: derive_key_id(bytes),
        }
    }

    pub fn id(&self) -> [u8; KEY_ID_LEN] {
        self.id
    }

    /// Read the device key at `path`. `Ok(None)` when no file is there; an error when something is there that
    /// is not a 32-byte regular file (a symlink, a directory, a truncated file). Such a file is never replaced:
    /// a key that is overwritten orphans every wrap sealed under it.
    ///
    /// ADR-165 review P2-3: the file is opened with `O_NOFOLLOW` and checked on the open descriptor, so a
    /// symlink swapped in between a look and a read is refused rather than read through. A key whose mode
    /// lets anyone else read it (a copy restored with the wrong mode) is narrowed to `0600` on the descriptor
    /// and used: refusing it would lock an owner who holds the passphrase out of the passphrase unlock.
    pub fn load(path: &Path) -> Result<Option<Self>, MachineLockError> {
        let mut file = match open_no_follow(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) if is_symlink_refusal(&e) => {
                return Err(MachineLockError::DeviceKeyUnreadable(
                    "it is a symbolic link, not a regular file".into(),
                ))
            }
            Err(e) => return Err(MachineLockError::DeviceKeyUnreadable(e.to_string())),
        };
        let meta = file
            .metadata()
            .map_err(|e| MachineLockError::DeviceKeyUnreadable(e.to_string()))?;
        if !meta.file_type().is_file() {
            return Err(MachineLockError::DeviceKeyUnreadable(
                "it is not a regular file".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                // Best effort: a read-only volume keeps its mode, and the key is still the key.
                let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
            }
        }
        let mut bytes = Vec::with_capacity(DEVICE_KEY_LEN + 1);
        // One byte more than a key, so a longer file is told apart from a key.
        let read = (&mut file)
            .take(DEVICE_KEY_LEN as u64 + 1)
            .read_to_end(&mut bytes);
        if let Err(e) = read {
            bytes.zeroize();
            return Err(MachineLockError::DeviceKeyUnreadable(e.to_string()));
        }
        if bytes.len() != DEVICE_KEY_LEN {
            let n = if bytes.len() > DEVICE_KEY_LEN {
                "more than 32".to_string()
            } else {
                bytes.len().to_string()
            };
            bytes.zeroize();
            return Err(MachineLockError::DeviceKeyUnreadable(format!(
                "it is {n} bytes, not {DEVICE_KEY_LEN}"
            )));
        }
        let mut arr = [0u8; DEVICE_KEY_LEN];
        arr.copy_from_slice(&bytes);
        bytes.zeroize();
        let key = Self::from_bytes(&arr);
        arr.zeroize();
        Ok(Some(key))
    }

    /// The device key at `path`, made first if there is none. The answer's flag says whether it was made now.
    ///
    /// Made durably before any wrap is sealed under it (written to a temporary file of its own — a unique name,
    /// created exclusively, mode `0600` — fsynced, then linked into place with `hard_link`, which never replaces
    /// an existing file, then the directory is fsynced), so a crash can leave a stray temporary file but never
    /// a sealed wrap whose key is not on disk. An existing key, or an unreadable file in its place, is never
    /// replaced. The key answered is always **the one read back from `path`** (review P2-1): two callers that
    /// race to make one both answer the key that won, never one that did not reach the disk.
    pub fn load_or_create(path: &Path) -> Result<(Self, bool), MachineLockError> {
        if let Some(key) = Self::load(path)? {
            return Ok((key, false));
        }
        let dir = path
            .parent()
            .ok_or_else(|| MachineLockError::Io("the device key path has no parent".into()))?;
        create_private_dir(dir)?;
        let made = Self::generate();
        let tmp = tmp_path(path);
        let write = (|| -> std::io::Result<()> {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
            }
            let mut f: File = opts.open(&tmp)?;
            f.write_all(made.key.expose_secret())?;
            f.sync_all()?;
            Ok(())
        })();
        if let Err(e) = write {
            let _ = fs::remove_file(&tmp);
            return Err(MachineLockError::Io(e.to_string()));
        }
        let linked = fs::hard_link(&tmp, path);
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => {}
            // Someone made one between our look and our link: that key wins, ours was never used.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(MachineLockError::Io(e.to_string())),
        }
        sync_dir(dir).map_err(|e| MachineLockError::Io(e.to_string()))?;
        let on_disk = Self::load(path)?.ok_or(MachineLockError::DeviceKeyMissing)?;
        let created = on_disk.id == made.id;
        Ok((on_disk, created))
    }
}

/// What `keystore.status` reports about the key file itself (review P2-3). Read without following a link.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyFileHealth {
    /// The file is owned by another user than the directory it sits in (the state directory's own `machine/`,
    /// which this user made).
    pub foreign_owner: bool,
    /// Its mode lets a group or others read or write it.
    pub mode_open: bool,
}

/// [`KeyFileHealth`] for the file at `path`; `None` when there is no regular file there.
pub fn key_file_health(path: &Path) -> Option<KeyFileHealth> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir_uid = path
            .parent()
            .and_then(|d| fs::symlink_metadata(d).ok())
            .map(|m| m.uid());
        Some(KeyFileHealth {
            foreign_owner: dir_uid.is_some_and(|uid| uid != meta.uid()),
            mode_open: meta.permissions().mode() & 0o077 != 0,
        })
    }
    #[cfg(not(unix))]
    {
        Some(KeyFileHealth::default())
    }
}

/// True for a `root.wrap.pass` that has the plain wrap's length and begins with [`MAGIC`]: either a plain wrap
/// whose random salt begins with the magic (a 2^-64 chance) or a sealed wrap cut down to 76 bytes. It is read
/// as plain, so an unbound vault opens exactly as before; when the passphrase does **not** open it, the caller
/// answers "the sealed wrap is damaged" (pointing to the recovery code) instead of "wrong passphrase", and
/// does not count a guess (review P2-5).
pub fn looks_like_truncated_seal(bytes: &[u8]) -> bool {
    bytes.len() == PLAIN_PASS_WRAP_LEN && bytes.starts_with(&MAGIC)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(std::io::Error::other("symbolic link"));
    }
    File::open(path)
}

#[cfg(unix)]
fn is_symlink_refusal(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_symlink_refusal(e: &std::io::Error) -> bool {
    e.to_string() == "symbolic link"
}

/// A temporary name of its own for each creator (pid and 64 random bits), so two creators never share one.
fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    name.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        key_id_hex(&nonce)
    ));
    path.with_file_name(name)
}

/// The key's directory: made with mode `0700` if it is not there, refused if it is a symbolic link or not a
/// directory, narrowed to `0700` if it is wider (review P2-3: `create_dir_all` and `set_permissions` follow a
/// symlinked directory and would put the key, and the chmod, wherever it points).
fn create_private_dir(dir: &Path) -> Result<(), MachineLockError> {
    let io = |e: std::io::Error| MachineLockError::Io(e.to_string());
    if let Some(parent) = dir.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(io)?;
        }
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io(e)),
    }
    let meta = fs::symlink_metadata(dir).map_err(io)?;
    if !meta.file_type().is_dir() {
        return Err(MachineLockError::Io(format!(
            "{} is not a directory (a symbolic link or a file is in its place)",
            dir.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Seal a plain passphrase wrap under `key`. The header is authenticated as associated data, so a key id
/// swapped in the file fails the tag rather than being believed.
pub fn seal(key: &DeviceKey, plain: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let mut out = Vec::with_capacity(HEADER_LEN + plain.len() + TAG_LEN);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&key.id);
    out.extend_from_slice(&nonce);
    let aad = out[..MAGIC.len() + KEY_ID_LEN].to_vec();
    let mut buffer = plain.to_vec();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.key.expose_secret()));
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut buffer)
        .expect("ChaCha20Poly1305 encryption of a small payload cannot fail");
    out.extend_from_slice(&buffer);
    out.extend_from_slice(&tag);
    buffer.zeroize();
    out
}

/// Open a sealed passphrase wrap with `key`, giving back the plain Argon2id wrap.
pub fn open(key: &DeviceKey, sealed: &[u8]) -> Result<Vec<u8>, MachineLockError> {
    let key_id = match classify(sealed) {
        WrapForm::Plain => return Err(MachineLockError::NotSealed),
        WrapForm::Damaged => return Err(MachineLockError::Damaged),
        WrapForm::Sealed { key_id } => key_id,
    };
    if key_id != key.id {
        return Err(MachineLockError::WrongDeviceKey);
    }
    let aad = &sealed[..MAGIC.len() + KEY_ID_LEN];
    let nonce = &sealed[MAGIC.len() + KEY_ID_LEN..HEADER_LEN];
    let body = &sealed[HEADER_LEN..];
    let (ct, tag) = body.split_at(body.len() - TAG_LEN);
    let mut buffer = ct.to_vec();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.key.expose_secret()));
    match cipher.decrypt_in_place_detached(
        Nonce::from_slice(nonce),
        aad,
        &mut buffer,
        Tag::from_slice(tag),
    ) {
        Ok(()) => Ok(buffer),
        Err(_) => {
            buffer.zeroize();
            Err(MachineLockError::Damaged)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain() -> Vec<u8> {
        (0..PLAIN_PASS_WRAP_LEN as u8).collect()
    }

    #[test]
    fn seal_then_open_gives_back_the_plain_wrap_and_the_file_says_it_is_bound() {
        let key = DeviceKey::generate();
        let sealed = seal(&key, &plain());
        assert_eq!(sealed.len(), HEADER_LEN + PLAIN_PASS_WRAP_LEN + TAG_LEN);
        assert_eq!(classify(&sealed), WrapForm::Sealed { key_id: key.id() });
        assert_eq!(open(&key, &sealed).unwrap(), plain());
    }

    #[test]
    fn a_plain_wrap_is_plain_even_when_its_salt_begins_with_the_magic() {
        assert_eq!(classify(&plain()), WrapForm::Plain);
        let mut lookalike = plain();
        lookalike[..8].copy_from_slice(&MAGIC);
        assert_eq!(classify(&lookalike), WrapForm::Plain);
        assert_eq!(classify(b""), WrapForm::Plain);
    }

    #[test]
    fn another_key_a_flipped_byte_a_swapped_key_id_and_truncation_are_refused() {
        let key = DeviceKey::generate();
        let other = DeviceKey::generate();
        let sealed = seal(&key, &plain());
        assert_eq!(open(&other, &sealed), Err(MachineLockError::WrongDeviceKey));
        for i in [HEADER_LEN, sealed.len() - 1, MAGIC.len() + KEY_ID_LEN] {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert_eq!(open(&key, &bad), Err(MachineLockError::Damaged), "byte {i}");
        }
        // The key id is authenticated: a file relabelled with this key's id fails the tag.
        let mut relabelled = seal(&other, &plain());
        relabelled[MAGIC.len()..MAGIC.len() + KEY_ID_LEN].copy_from_slice(&key.id());
        assert_eq!(open(&key, &relabelled), Err(MachineLockError::Damaged));
        assert_eq!(classify(&sealed[..HEADER_LEN]), WrapForm::Damaged);
        assert_eq!(
            open(&key, &sealed[..HEADER_LEN]),
            Err(MachineLockError::Damaged)
        );
        assert_eq!(
            open(&key, &sealed[..sealed.len() - 3]),
            Err(MachineLockError::Damaged)
        );
        assert_eq!(open(&key, &plain()), Err(MachineLockError::NotSealed));
    }

    #[test]
    fn the_device_key_is_made_once_with_mode_0600_and_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("machine").join("lock.key");
        assert!(DeviceKey::load(&path).unwrap().is_none());
        let (made, created) = DeviceKey::load_or_create(&path).unwrap();
        assert!(created);
        assert_eq!(fs::read(&path).unwrap().len(), DEVICE_KEY_LEN);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let dmode = fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dmode, 0o700);
        }
        let (again, created) = DeviceKey::load_or_create(&path).unwrap();
        assert!(!created);
        assert_eq!(again.id(), made.id());
        let strays: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "lock.key")
            .collect();
        assert!(strays.is_empty(), "temporary files left: {strays:?}");

        // A damaged key file is reported, not replaced.
        fs::write(&path, b"short").unwrap();
        assert!(matches!(
            DeviceKey::load_or_create(&path),
            Err(MachineLockError::DeviceKeyUnreadable(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"short");
    }

    /// Review P2-1: callers racing to make the key all answer the one key that reached the disk, so nothing is
    /// ever sealed under a key that is not there.
    #[test]
    fn racing_creators_all_answer_the_key_on_disk() {
        for _round in 0..20 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("machine").join("lock.key");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let path = path.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        let (key, created) = DeviceKey::load_or_create(&path).unwrap();
                        (key.id(), created)
                    })
                })
                .collect();
            let answers: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            let on_disk = DeviceKey::load(&path).unwrap().unwrap().id();
            assert!(answers.iter().all(|(id, _)| *id == on_disk), "{answers:?}");
            assert_eq!(answers.iter().filter(|(_, created)| *created).count(), 1);
            let entries = fs::read_dir(path.parent().unwrap()).unwrap().count();
            assert_eq!(entries, 1, "only lock.key is left");
        }
    }

    /// Review P2-3: a symbolic link at the key's path, or as its directory, is refused, never followed; a key
    /// with an open mode is narrowed to 0600 and still used.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_key_or_directory_is_refused_and_an_open_mode_is_narrowed() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("elsewhere.key");
        fs::write(&real, [7u8; DEVICE_KEY_LEN]).unwrap();
        let machine = dir.path().join("machine");
        fs::create_dir(&machine).unwrap();
        let path = machine.join("lock.key");
        symlink(&real, &path).unwrap();
        assert!(matches!(
            DeviceKey::load(&path),
            Err(MachineLockError::DeviceKeyUnreadable(why)) if why.contains("symbolic link")
        ));
        assert!(DeviceKey::load_or_create(&path).is_err());
        assert!(key_file_health(&path).is_none());

        // A symlinked key directory: nothing is created where it points.
        let target_dir = dir.path().join("target-dir");
        fs::create_dir(&target_dir).unwrap();
        let linked_machine = dir.path().join("machine2");
        symlink(&target_dir, &linked_machine).unwrap();
        assert!(DeviceKey::load_or_create(&linked_machine.join("lock.key")).is_err());
        assert_eq!(fs::read_dir(&target_dir).unwrap().count(), 0);

        // An open mode: used, and narrowed.
        fs::remove_file(&path).unwrap();
        fs::write(&path, [9u8; DEVICE_KEY_LEN]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            key_file_health(&path),
            Some(KeyFileHealth {
                foreign_owner: false,
                mode_open: true
            })
        );
        let key = DeviceKey::load(&path).unwrap().unwrap();
        assert_eq!(key.id(), DeviceKey::from_bytes(&[9u8; DEVICE_KEY_LEN]).id());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // A longer file is not a key.
        fs::write(&path, [1u8; DEVICE_KEY_LEN + 1]).unwrap();
        assert!(matches!(
            DeviceKey::load(&path),
            Err(MachineLockError::DeviceKeyUnreadable(_))
        ));
    }

    /// Review P2-5: a sealed wrap cut down to the plain wrap's length is recognisable, and a real plain wrap is
    /// not mistaken for one unless its salt happens to begin with the magic.
    #[test]
    fn a_seal_cut_to_the_plain_length_is_recognised() {
        let key = DeviceKey::generate();
        let sealed = seal(&key, &plain());
        let cut = &sealed[..PLAIN_PASS_WRAP_LEN];
        assert_eq!(
            classify(cut),
            WrapForm::Plain,
            "still opened as plain first"
        );
        assert!(looks_like_truncated_seal(cut));
        assert!(!looks_like_truncated_seal(&plain()));
        assert!(!looks_like_truncated_seal(&sealed));
    }
}
