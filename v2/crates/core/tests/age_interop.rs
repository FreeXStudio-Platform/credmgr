//! ADR-133 — the age writer against two readers that are not the writer.
//!
//! 1. A small decryptor written here from the format's spec, sharing no code with `age_format.rs`: it
//!    parses the header, checks the MAC, unwraps the file key from either stanza type and reads the
//!    chunked payload (including the empty file, an exact multiple of 64 KiB and one byte over).
//! 2. The real `age` binary, when one is on `PATH` (or named by `CREDMGR_AGE_BIN`): an X25519 file made
//!    here must open with `age -d -i <identity>`. The test passes vacuously without it, and says so.

use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use credmgr_core::age_format::{encrypt, parse_recipient, Recipient};

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = <[u8; 32]>::default();
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .unwrap();
    out
}

fn open_zero_nonce(key: &[u8; 32], body: &[u8]) -> Option<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(&<[u8; 12]>::default()), body)
        .ok()
}

enum Identity<'a> {
    Passphrase(&'a str),
    X25519(&'a StaticSecret),
}

/// Decrypt an age v1 file. Panics (the test fails) on anything the spec forbids.
fn decrypt(file: &[u8], who: Identity) -> Vec<u8> {
    // The header is text up to and including the "--- <mac>\n" line.
    let mut pos = 0usize;
    let mut lines: Vec<&[u8]> = Vec::new();
    loop {
        let nl = file[pos..]
            .iter()
            .position(|b| *b == b'\n')
            .expect("header line");
        let line = &file[pos..pos + nl];
        lines.push(line);
        pos += nl + 1;
        if line.starts_with(b"--- ") {
            break;
        }
    }
    assert_eq!(lines[0], b"age-encryption.org/v1");
    let mac_line = lines.pop().unwrap();
    let mac_line_start = pos - mac_line.len() - 1;
    let mac_input = &file[..mac_line_start + 3]; // through the three dashes, not the space.
    let claimed_mac = B64.decode(&mac_line[4..]).expect("mac b64");

    // Stanzas.
    let mut file_key: Option<[u8; 16]> = None;
    let mut i = 1;
    while i < lines.len() {
        let head = std::str::from_utf8(lines[i]).unwrap();
        assert!(head.starts_with("-> "), "stanza start: {head}");
        let args: Vec<&str> = head[3..].split(' ').collect();
        i += 1;
        let mut body = String::new();
        loop {
            let l = std::str::from_utf8(lines[i]).unwrap();
            i += 1;
            assert!(l.len() <= 64);
            body.push_str(l);
            if l.len() < 64 {
                break;
            }
        }
        let body = B64.decode(body).expect("stanza body b64");
        match (args[0], &who) {
            ("scrypt", Identity::Passphrase(pass)) => {
                let salt = B64.decode(args[1]).unwrap();
                assert_eq!(salt.len(), 16);
                let log_n: u8 = args[2].parse().unwrap();
                let mut full = b"age-encryption.org/v1/scrypt".to_vec();
                full.extend_from_slice(&salt);
                let params = scrypt::Params::new(log_n, 8, 1, 32).unwrap();
                let mut wrap_key = <[u8; 32]>::default();
                scrypt::scrypt(pass.as_bytes(), &full, &params, &mut wrap_key).unwrap();
                let k = open_zero_nonce(&wrap_key, &body).expect("scrypt stanza opens");
                file_key = Some(k.try_into().unwrap());
            }
            ("X25519", Identity::X25519(secret)) => {
                let share: [u8; 32] = B64.decode(args[1]).unwrap().try_into().unwrap();
                let mine = PublicKey::from(*secret);
                let shared = secret.diffie_hellman(&PublicKey::from(share));
                let mut salt = share.to_vec();
                salt.extend_from_slice(mine.as_bytes());
                let wrap_key = hkdf32(shared.as_bytes(), &salt, b"age-encryption.org/v1/X25519");
                if let Some(k) = open_zero_nonce(&wrap_key, &body) {
                    file_key = Some(k.try_into().unwrap());
                }
            }
            _ => {}
        }
    }
    let file_key = file_key.expect("no stanza opened with this identity");

    // The age header MAC key is derived with an empty salt by the format; an empty default value, not a literal.
    let no_salt = <Vec<u8>>::default();
    let mac_key = hkdf32(&file_key, &no_salt, b"header");
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).unwrap();
    mac.update(mac_input);
    mac.verify_slice(&claimed_mac).expect("header MAC");

    let nonce = &file[pos..pos + 16];
    let payload = &file[pos + 16..];
    let key = hkdf32(&file_key, nonce, b"payload");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut out = Vec::new();
    let sealed_chunk = 64 * 1024 + 16;
    let mut offset = 0usize;
    let mut counter = 0u64;
    loop {
        let remaining = payload.len() - offset;
        let take = remaining.min(sealed_chunk);
        let last = take == remaining;
        let mut n = <[u8; 12]>::default();
        n[3..11].copy_from_slice(&counter.to_be_bytes());
        n[11] = u8::from(last);
        let plain = cipher
            .decrypt(Nonce::from_slice(&n), &payload[offset..offset + take])
            .expect("payload chunk");
        out.extend_from_slice(&plain);
        if last {
            break;
        }
        offset += take;
        counter += 1;
    }
    out
}

/// A passphrase made up for this test run, never a literal.
fn random_passphrase() -> String {
    use rand_core::RngCore;
    let mut b = <[u8; 12]>::default();
    rand_core::OsRng.fill_bytes(&mut b);
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut acc, x| {
        let _ = write!(acc, "{x:02x}");
        acc
    })
}

fn random_bytes(n: usize) -> Vec<u8> {
    use rand_core::RngCore;
    let mut v = vec![u8::default(); n];
    rand_core::OsRng.fill_bytes(&mut v);
    v
}

fn sizes() -> Vec<usize> {
    vec![0, 1, 100, 65_535, 65_536, 65_537, 131_072, 200_001]
}

#[test]
fn x25519_files_open_with_an_independent_reader_at_every_chunk_boundary() {
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);
    for size in sizes() {
        let plain = random_bytes(size);
        let file = encrypt(&plain, &[Recipient::X25519(*public.as_bytes())]).unwrap();
        assert_eq!(
            decrypt(&file, Identity::X25519(&secret)),
            plain,
            "size {size}"
        );
    }
}

#[test]
fn several_recipients_each_open_it() {
    let a = StaticSecret::random_from_rng(rand_core::OsRng);
    let b = StaticSecret::random_from_rng(rand_core::OsRng);
    let file = encrypt(
        b"for two",
        &[
            Recipient::X25519(*PublicKey::from(&a).as_bytes()),
            Recipient::X25519(*PublicKey::from(&b).as_bytes()),
        ],
    )
    .unwrap();
    assert_eq!(decrypt(&file, Identity::X25519(&a)), b"for two");
    assert_eq!(decrypt(&file, Identity::X25519(&b)), b"for two");
}

#[test]
fn passphrase_files_open_with_an_independent_reader_and_a_wrong_passphrase_does_not() {
    let right = random_passphrase();
    for size in [0usize, 1, 65_536, 65_537] {
        let plain = random_bytes(size);
        let file = encrypt(
            &plain,
            &[Recipient::Passphrase {
                passphrase: right.clone(),
                log_n: 10,
            }],
        )
        .unwrap();
        assert_eq!(decrypt(&file, Identity::Passphrase(&right)), plain);
    }
    let file = encrypt(
        b"x",
        &[Recipient::Passphrase {
            passphrase: right.clone(),
            log_n: 10,
        }],
    )
    .unwrap();
    let other = random_passphrase();
    let wrong = std::panic::catch_unwind(|| decrypt(&file, Identity::Passphrase(&other)));
    assert!(wrong.is_err(), "a wrong passphrase must not open the file");
}

#[test]
fn a_flipped_byte_anywhere_in_the_file_is_refused() {
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);
    let file = encrypt(
        &random_bytes(70_000),
        &[Recipient::X25519(*public.as_bytes())],
    )
    .unwrap();
    for at in [30usize, file.len() / 2, file.len() - 1] {
        let mut broken = file.clone();
        broken[at] ^= 1;
        let r = std::panic::catch_unwind(|| decrypt(&broken, Identity::X25519(&secret)));
        assert!(r.is_err(), "byte {at} flipped but the file still opened");
    }
}

#[test]
fn the_real_age_binary_opens_what_this_writes() {
    use std::process::Command;
    let bin = std::env::var("CREDMGR_AGE_BIN").unwrap_or_else(|_| "age".to_string());
    let keygen =
        std::env::var("CREDMGR_AGE_KEYGEN_BIN").unwrap_or_else(|_| "age-keygen".to_string());
    let Ok(generated) = Command::new(keygen).output() else {
        eprintln!("skipped: no `age-keygen` on PATH (set CREDMGR_AGE_KEYGEN_BIN)");
        return;
    };
    if !generated.status.success() || Command::new(&bin).arg("--version").output().is_err() {
        eprintln!("skipped: no usable `age` binary");
        return;
    }
    let identity_file = String::from_utf8(generated.stdout).unwrap();
    let recipient_line = identity_file
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .expect("age-keygen prints its public key");
    let recipient = parse_recipient(recipient_line).expect("a real age recipient parses");

    let dir = tempfile::tempdir().unwrap();
    let id_path = dir.path().join("id.txt");
    std::fs::write(&id_path, &identity_file).unwrap();
    for size in [0usize, 5, 65_536, 65_537, 300_000] {
        let plain = random_bytes(size);
        let file_path = dir.path().join(format!("f{size}.age"));
        std::fs::write(
            &file_path,
            encrypt(&plain, &[Recipient::X25519(recipient)]).unwrap(),
        )
        .unwrap();
        let out = Command::new(&bin)
            .arg("-d")
            .arg("-i")
            .arg(&id_path)
            .arg(&file_path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "age refused our file of {size} bytes: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            out.stdout, plain,
            "age read different bytes for size {size}"
        );
    }
}
