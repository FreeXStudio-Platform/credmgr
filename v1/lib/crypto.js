'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const machineLock = require('./machine-lock');

// Vault home is resolved by lib/paths.js — platform user-data dir by default,
// NEVER the repository. See the design note in that file.
const CRED_DIR = require('./paths').vaultHome();
const CREDMGR_DIR = path.join(CRED_DIR, '.credmgr');

/**
 * Resolve the age binary — check PATH, then common homebrew locations.
 */
// Callers: ageBin() passes 'age', ageKeygenBin() passes 'age-keygen'.
// `name` is NEVER derived from user input, HTTP requests, or credential data —
// it is always a compile-time string literal chosen from a 2-element set.
// The path-traversal semgrep rule fires on the generic path.join(dir, arg)
// shape but there is no tainted data flow into this function.
function findAgeBinary(name) {
  const searchPaths = [
    '/opt/homebrew/bin',
    '/usr/local/bin',
    '/usr/bin',
    process.env.HOME + '/.local/bin',
  ];
  // Check if it's directly on PATH
  try {
    execFileSync('which', [name], { stdio: 'pipe' });
    return name;
  } catch (_) { /* not on PATH */ }
  for (const dir of searchPaths) {
    // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
    const full = path.join(dir, name);
    if (fs.existsSync(full)) return full;
  }
  throw new Error(`${name} not found. Install with: brew install age`);
}

let _agePath = null;
let _ageKeygenPath = null;

function ageBin() {
  if (!_agePath) _agePath = findAgeBinary('age');
  return _agePath;
}

function ageKeygenBin() {
  if (!_ageKeygenPath) _ageKeygenPath = findAgeBinary('age-keygen');
  return _ageKeygenPath;
}

/**
 * Load config to find key paths. Supports override via opts.
 */
function loadConfig(opts) {
  const configPath = (opts && opts.configPath) || path.join(CREDMGR_DIR, 'config.json');
  if (fs.existsSync(configPath)) {
    return JSON.parse(fs.readFileSync(configPath, 'utf8'));
  }
  return {
    keyPath: path.join(CREDMGR_DIR, 'master.key'),
    pubKeyPath: path.join(CREDMGR_DIR, 'master.pub'),
  };
}

/**
 * Generate a new age keypair. Returns { identityPath, publicKey }.
 */
function generateKeypair(opts) {
  const config = loadConfig(opts);
  const keyPath = (opts && opts.keyPath) || config.keyPath;
  const pubKeyPath = (opts && opts.pubKeyPath) || config.pubKeyPath;

  const dir = path.dirname(keyPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  const output = execFileSync(ageKeygenBin(), [], { encoding: 'utf8' });
  // output format:
  //   # created: ...
  //   # public key: age1...
  //   AGE-SECRET-KEY-...
  const lines = output.trim().split('\n');
  const pubLine = lines.find(l => l.includes('public key:'));
  const pubKey = pubLine ? pubLine.split('public key:')[1].trim() : null;
  const secretLine = lines.find(l => l.startsWith('AGE-SECRET-KEY-'));

  if (!pubKey || !secretLine) {
    throw new Error('Failed to parse age-keygen output');
  }

  fs.writeFileSync(keyPath, output, { mode: 0o600 });
  fs.writeFileSync(pubKeyPath, pubKey + '\n', { mode: 0o600 });

  return { identityPath: keyPath, publicKey: pubKey };
}

/**
 * Read the public key from the pub key file.
 */
function getPublicKey(opts) {
  const config = loadConfig(opts);
  const pubKeyPath = (opts && opts.pubKeyPath) || config.pubKeyPath;
  if (!fs.existsSync(pubKeyPath)) {
    throw new Error('Public key not found at ' + pubKeyPath + '. Run: credmgr init');
  }
  return fs.readFileSync(pubKeyPath, 'utf8').trim();
}

/**
 * Get the identity (private key) file path.
 */
function getIdentityPath(opts) {
  const config = loadConfig(opts);
  const keyPath = (opts && opts.keyPath) || config.keyPath;
  if (!fs.existsSync(keyPath)) {
    throw new Error('Master key not found at ' + keyPath + '. Run: credmgr init');
  }
  return keyPath;
}

/**
 * Encrypt a string and return the encrypted bytes as a Buffer.
 */
function encrypt(plaintext, opts) {
  const pubKey = getPublicKey(opts);
  const result = execFileSync(ageBin(), ['-r', pubKey, '-a'], {
    input: plaintext,
    maxBuffer: 50 * 1024 * 1024,
  });
  return result;
}

/**
 * Encrypt a string and write to a file.
 */
function encryptToFile(plaintext, outputPath, opts) {
  const encrypted = encrypt(plaintext, opts);
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(outputPath, encrypted, { mode: 0o600 });
}

/**
 * Decrypt an encrypted buffer/string and return plaintext.
 *
 * If machine-lock is enabled (see lib/machine-lock.js), the on-disk identity
 * file is not a usable age key by itself — resolveIdentity unwraps it into a
 * short-lived temp file scoped to just this one `age` invocation, then that
 * temp file is removed immediately (finally block), whether or not age
 * succeeded. A stolen vault.age + master.key pair fails here on any other
 * machine with a clear error, not a generic age failure.
 */
function decrypt(ciphertext, opts) {
  const identityPath = getIdentityPath(opts);
  const resolved = machineLock.resolveIdentity(identityPath, opts);
  try {
    const input = Buffer.isBuffer(ciphertext) ? ciphertext : Buffer.from(ciphertext);
    const result = execFileSync(ageBin(), ['-d', '-i', resolved.path], {
      input: input,
      encoding: 'utf8',
      maxBuffer: 50 * 1024 * 1024,
    });
    return result;
  } finally {
    resolved.cleanup();
  }
}

/**
 * Decrypt a .age file and return plaintext string.
 */
function decryptFile(filePath, opts) {
  if (!fs.existsSync(filePath)) {
    throw new Error('Encrypted file not found: ' + filePath);
  }
  const ciphertext = fs.readFileSync(filePath);
  return decrypt(ciphertext, opts);
}

/**
 * Decrypt and return the raw plaintext as a Buffer (no utf8 decode).
 * Required for binary payloads (e.g. backup tar archives) — round-tripping
 * binary bytes through a JS string corrupts anything ≥ 0x80.
 */
function decryptToBuffer(ciphertext, opts) {
  const identityPath = getIdentityPath(opts);
  const resolved = machineLock.resolveIdentity(identityPath, opts);
  try {
    const input = Buffer.isBuffer(ciphertext) ? ciphertext : Buffer.from(ciphertext);
    return execFileSync(ageBin(), ['-d', '-i', resolved.path], {
      input: input,
      maxBuffer: 50 * 1024 * 1024,
    });
  } finally {
    resolved.cleanup();
  }
}

/**
 * Decrypt a .age file and return the plaintext Buffer (binary-safe).
 */
function decryptFileToBuffer(filePath, opts) {
  if (!fs.existsSync(filePath)) {
    throw new Error('Encrypted file not found: ' + filePath);
  }
  return decryptToBuffer(fs.readFileSync(filePath), opts);
}

/**
 * Encrypt a file (e.g., SSH private key) to a .age output file.
 */
function encryptFile(inputPath, outputPath, opts) {
  if (!fs.existsSync(inputPath)) {
    throw new Error('Input file not found: ' + inputPath);
  }
  const plaintext = fs.readFileSync(inputPath, 'utf8');
  encryptToFile(plaintext, outputPath, opts);
}

/**
 * Generate a random hex ID (for credential IDs).
 */
function randomId(bytes) {
  return crypto.randomBytes(bytes || 8).toString('hex');
}

/**
 * SHA-256 hex digest of a string/buffer. Used for vault integrity checksums
 * (tamper/rollback/corruption detection) — a digest of the plaintext vault is
 * preimage-resistant, so publishing it in a sidecar leaks nothing.
 */
function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

/**
 * Write `contents` to a freshly-created, unpredictable, 0700 temp directory and
 * return the file path. Uses fs.mkdtempSync so there is no predictable path an
 * attacker can pre-create/symlink between mkdir and write (fixes the SSH-key and
 * deploy temp-file races). Caller is responsible for cleanup via cleanupTemp().
 */
function secureTempFile(basename, contents) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'credmgr-'));
  // Defense-in-depth: basename may derive from a credential name (argv) —
  // strip any path components so it can never escape the temp dir.
  const safe = path.basename(String(basename)).replace(/[^\w.@-]/g, '_') || 'tmp';
  const file = path.join(dir, safe);
  fs.writeFileSync(file, contents, { mode: 0o600 });
  return { dir, file };
}

/**
 * Remove a temp dir created by secureTempFile. Best-effort, never throws.
 */
function cleanupTemp(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
}

/**
 * Verify that age is installed and the master key exists.
 * Returns { ok: boolean, errors: string[] }.
 */
function verify(opts) {
  const errors = [];
  try { ageBin(); } catch (e) { errors.push(e.message); }
  try { getIdentityPath(opts); } catch (e) { errors.push(e.message); }
  try { getPublicKey(opts); } catch (e) { errors.push(e.message); }

  if (errors.length === 0) {
    // Test round-trip
    try {
      const test = 'credmgr-verify-' + Date.now();
      const enc = encrypt(test, opts);
      const dec = decrypt(enc, opts);
      if (dec.trim() !== test) {
        errors.push('Round-trip verification failed: decrypted value does not match');
      }
    } catch (e) {
      errors.push('Round-trip verification failed: ' + e.message);
    }
  }

  return { ok: errors.length === 0, errors };
}

module.exports = {
  generateKeypair,
  getPublicKey,
  getIdentityPath,
  encrypt,
  encryptToFile,
  decrypt,
  decryptFile,
  decryptToBuffer,
  decryptFileToBuffer,
  encryptFile,
  randomId,
  sha256,
  secureTempFile,
  cleanupTemp,
  verify,
  CRED_DIR,
  CREDMGR_DIR,
};
