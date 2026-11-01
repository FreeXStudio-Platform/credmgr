#!/usr/bin/env node
// scripts/emergency-decrypt.mjs — standalone, dependency-free disaster
// recovery. Given a vault directory, a node id, an entry id, and the
// 256-bit root recovery code, recovers that one entry's plaintext value
// with no Rust toolchain and no running `credmgrd`.
//
// `docs/04_CRYPTO_AND_KEYS.md §7`: "A 40-line script plus the root key
// recovers everything; that script ships as `scripts/emergency-decrypt.mjs`
// and is part of the test suite, so it cannot rot." `docs/14_DECISIONS.md`
// ADR-045 records why the root-recovery-code wrap needed no Argon2id/
// hardware dependency and could be built (and this script written) in
// Phase 4 rather than deferred to Phase 5.
//
// Every primitive below (HKDF-SHA512 with an empty salt, X25519 ECDH via a
// raw-scalar PKCS8 import, ChaCha20-Poly1305 with an explicit auth tag) was
// independently verified byte-for-byte against the Rust implementation
// before this file was written — see `crates/core/src/envelope.rs`'s
// `node_interop_vectors` test for the pinned vectors, and
// `crates/cli/tests/emergency_decrypt.rs` for the end-to-end proof against
// a real Rust-built fixture vault.
//
// Usage:
//   node emergency-decrypt.mjs --vault <dir> --node <id> --entry <entryId> [--pretty]
//
// Two envelope versions exist (ADR-078) and this script reads both:
//   version 1  the plaintext is one raw value (every entry written up to
//              2.0.0-alpha.6). It is printed exactly as it was sealed.
//   version 2  the plaintext is a field document: canonical JSON,
//              {"v":1,"fields":[{"id","label","value","type"?,"masked"?}, ...]}.
//              It is printed as that JSON, byte for byte (lossless — every label
//              and value, including multi-line keys, survives in its JSON
//              escapes), so any tool can parse the output. `--pretty` indents it
//              for a human; the content is identical.
// The version byte is inside the AAD, so a relabelled envelope fails
// authentication rather than being read as the wrong kind.
// The recovery code is read from $CREDMGR_RECOVERY_CODE if set, otherwise
// from stdin — never a CLI argument. A recovery code is exactly as much a
// bearer secret as a passphrase or an entry value, and the reasoning for
// keeping those out of argv (`docs/10_API_AND_MCP.md §2`: shell history,
// `ps` output, process listings) applies identically here.
//
// A vault caught in the middle of a root-key rotation (ADR-076). A rotation
// stages every replacement file under `<vault>/rotation-pending/`, writes one
// `COMMIT` record, then moves the files into place one by one. Cut off in that
// last stretch, the vault has some files under the NEW root key and some under
// the OLD — and reading the live files alone would answer "authentication
// failed" for either recovery code, which looks like a wrong code or a
// tampered vault. This script notices `COMMIT`, says so, and reads the way the
// rotation itself would finish: every file from its staged copy where one is
// still waiting, else from the live vault. That view is the NEW root key's
// vault, so the NEW recovery code opens it. If that does not work it tries the
// live files exactly as they stand (the OLD code opens them while nothing has
// moved yet), and if neither works it explains what to do instead of
// reporting a wrong code. `credmgrd` start-up, or any unlock, finishes the
// rotation for real.
//
// Only Node built-ins are imported (`node:fs`, `node:path`, `node:crypto`)
// — "dependency-free" means there is nothing an `npm install` could ever
// need to fetch for this file to run, on any machine with Node itself.

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import crypto from 'node:crypto';

const MAGIC = Buffer.from('CMV2');
// Envelope versions this script reads (`crates/core/src/envelope.rs`): 1 = the
// plaintext is one raw value, 2 = the plaintext is a field document (ADR-078).
const VERSION_RAW_VALUE = 1;
const VERSION_FIELD_DOCUMENT = 2;
const SUITE = 1;

// credmgr-allow: `1.3.101.110` below is the X25519 object identifier from RFC 8410,
// not an IPv4 address — it only matches the guard's routable-IP shape by coincidence.
// The fixed 16-byte PKCS8 DER prefix (RFC 8410) for a raw 32-byte X25519
// private key: SEQUENCE { version 0, AlgorithmIdentifier{OID 1.3.101.110},
// OCTET STRING { OCTET STRING { <32 raw bytes> } } }. Importing this way
// (rather than a JWK) needs no separately-supplied public key at all —
// `crypto.diffieHellman` only ever consumes the private scalar from this
// side, which is what lets this script skip re-deriving or looking up a
// node's public key just to decrypt with its private one.
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

function fail(message) {
  process.stderr.write(`emergency-decrypt: ${message}\n`);
  process.exit(1);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--vault') out.vault = argv[++i];
    else if (arg === '--node') out.node = argv[++i];
    else if (arg === '--entry') out.entry = argv[++i];
    else if (arg === '--pretty') out.pretty = true;
    else fail(`unknown argument: ${arg}`);
  }
  for (const key of ['vault', 'node', 'entry']) {
    if (!out[key]) fail(`--${key} is required (usage: --vault <dir> --node <id> --entry <id>)`);
  }
  return out;
}

function readStdinSync() {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

function readRecoveryCode() {
  const fromEnv = process.env.CREDMGR_RECOVERY_CODE;
  const raw = fromEnv !== undefined ? fromEnv : readStdinSync();
  const cleaned = raw.replace(/[\s-]/g, '');
  if (!/^[0-9a-fA-F]{64}$/.test(cleaned)) {
    fail(
      'recovery code must decode to 32 bytes of hex (64 hex digits; ' +
        'hyphens and whitespace are ignored) — read from $CREDMGR_RECOVERY_CODE or stdin',
    );
  }
  return Buffer.from(cleaned, 'hex');
}

function readFileOrFail(path) {
  try {
    return readFileSync(path);
  } catch (e) {
    fail(`could not read ${path}: ${e.message}`);
  }
}

// A key-material step that did not work out. Thrown rather than exited on so
// that a vault caught mid-rotation can try a second view of its files before
// the script gives up; outside that case `main` turns it straight into `fail`.
class WrapError extends Error {}

function readWrapFile(path) {
  try {
    return readFileSync(path);
  } catch (e) {
    throw new WrapError(`could not read ${path}: ${e.message}`);
  }
}

// HKDF-SHA512(ikm, salt=empty, info) — matches `credmgr_core::keys::derive_subkey`
// and `recovery::wrap_root_with_recovery_code` exactly. An empty salt Buffer
// is the correct match for Rust's `Hkdf::new(None, ikm)`: HMAC-SHA512 zero-
// pads any key shorter than its 128-byte block size, so an empty key and a
// 64-byte (HashLen) all-zero key — the two readings RFC 5869 could mean by
// "no salt" — collapse to the identical zero-padded HMAC key either way.
function deriveKey(ikm, info) {
  return Buffer.from(crypto.hkdfSync('sha512', ikm, Buffer.alloc(0), Buffer.from(info), 32));
}

// Opens a `nonce (12) || ciphertext (N) || tag (16)` blob — the wire format
// `RootRecoveryWrap`/`WrappedNodeKey::to_bytes` both write, and the format
// `root.wrap.recovery`/`keys/nodes/<id>.key` are stored in on disk.
function aeadOpenWrap(key, blob, context) {
  if (blob.length < 12 + 16) {
    throw new WrapError(`${context}: wrapped blob is too short to be genuine`);
  }
  const nonce = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ciphertext = blob.subarray(12, blob.length - 16);
  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  decipher.setAAD(Buffer.alloc(0), { plaintextLength: ciphertext.length });
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new WrapError(
      `${context}: authentication failed — wrong recovery code, wrong key, or a tampered file`,
    );
  }
}

function x25519PrivateKeyFromRaw(rawBytes) {
  return crypto.createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, rawBytes]),
    format: 'der',
    type: 'pkcs8',
  });
}

function x25519PublicKeyFromRaw(rawBytes) {
  return crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: rawBytes.toString('base64url') },
    format: 'jwk',
  });
}

// 16-byte, zero-padded UTF-8 field — mirrors `envelope::encode_node_id`.
function encodeNodeIdField(nodeId) {
  const bytes = Buffer.from(nodeId, 'utf8');
  if (bytes.length > 16) fail(`node id ${nodeId} exceeds 16 bytes as UTF-8`);
  const field = Buffer.alloc(16);
  bytes.copy(field);
  return field;
}

// Opens one CMV2 entry envelope — `crates/core/src/envelope.rs`'s `open_any`,
// reimplemented against `node:crypto` only. Byte layout: magic(4) ||
// version(1) || suite(1) || nodeId(16) || epk(32) || nonce(12) ||
// ciphertext(var) || tag(16). Returns `{ version, plaintext }`: the version
// byte is read from the envelope and goes into the AAD exactly as read, which is
// what authenticates the payload kind.
function openEnvelope(envelope, nodePrivRaw, nodeId, entryId) {
  const MIN_LEN = 4 + 1 + 1 + 16 + 32 + 12 + 16;
  if (envelope.length < MIN_LEN) fail('envelope is truncated');

  let offset = 0;
  const magic = envelope.subarray(offset, (offset += 4));
  if (!magic.equals(MAGIC)) fail('envelope: bad magic bytes');
  const version = envelope[offset]; offset += 1;
  if (version !== VERSION_RAW_VALUE && version !== VERSION_FIELD_DOCUMENT) {
    fail(`envelope: unsupported version ${version}`);
  }
  const suite = envelope[offset]; offset += 1;
  if (suite !== SUITE) fail(`envelope: unsupported cipher suite ${suite}`);
  const storedNodeIdField = envelope.subarray(offset, (offset += 16));
  const expectedNodeIdField = encodeNodeIdField(nodeId);
  if (!storedNodeIdField.equals(expectedNodeIdField)) {
    fail(`envelope: stored node id does not match the requested node '${nodeId}'`);
  }
  const epk = envelope.subarray(offset, (offset += 32));
  const nonce = envelope.subarray(offset, (offset += 12));
  const ciphertext = envelope.subarray(offset, envelope.length - 16);
  const tag = envelope.subarray(envelope.length - 16);

  const nodePriv = x25519PrivateKeyFromRaw(nodePrivRaw);
  const ephemeralPub = x25519PublicKeyFromRaw(epk);
  const shared = crypto.diffieHellman({ privateKey: nodePriv, publicKey: ephemeralPub });

  // The entry-key salt is `ephemeral.pub || node.pub` (`04 §3`) — the
  // node's own public key is derived from the private key we just built,
  // rather than requiring the caller to also supply or look it up.
  const nodePubJwk = crypto.createPublicKey(nodePriv).export({ format: 'jwk' });
  const nodePubRaw = Buffer.from(nodePubJwk.x, 'base64url');

  const entryKey = Buffer.from(
    crypto.hkdfSync(
      'sha512',
      shared,
      Buffer.concat([epk, nodePubRaw]),
      Buffer.from('credmgr/v2/entry'),
      32,
    ),
  );

  const aad = Buffer.concat([
    MAGIC,
    Buffer.from([version, SUITE]),
    expectedNodeIdField,
    Buffer.from(entryId, 'utf8'),
  ]);

  const decipher = crypto.createDecipheriv('chacha20-poly1305', entryKey, nonce, {
    authTagLength: 16,
  });
  decipher.setAAD(aad, { plaintextLength: ciphertext.length });
  decipher.setAuthTag(tag);
  try {
    return { version, plaintext: Buffer.concat([decipher.update(ciphertext), decipher.final()]) };
  } catch {
    fail('envelope: authentication failed — wrong node key, wrong ids, or a tampered/relocated file');
  }
}

// Which copy of a key file to read. 'live' is the file where it sits in the
// vault. 'staged' is the view a finished root-key rotation would leave: the
// rotation's own staged copy while one is still waiting to be moved into place,
// else the live file (already moved, or never part of the rotation).
function keyFilePath(vault, relParts, view) {
  if (view === 'staged') {
    const staged = join(vault, 'rotation-pending', 'vault', ...relParts);
    if (existsSync(staged)) return staged;
  }
  return join(vault, ...relParts);
}

// recovery code -> root key (root.wrap.recovery) -> this node's private key
// (keys/nodes/<id>.key), reading the files as `view` says. Throws `WrapError`.
function recoverNodeKey(args, recoveryCode, view) {
  const rootWrapBlob = readWrapFile(keyFilePath(args.vault, ['keys', 'root.wrap.recovery'], view));
  const rootWrapKey = deriveKey(recoveryCode, 'credmgr/v2/root-wrap-recovery');
  const rootKey = aeadOpenWrap(rootWrapKey, rootWrapBlob, 'root.wrap.recovery');
  if (rootKey.length !== 32) throw new WrapError('recovered root key is not 32 bytes — corrupt wrap?');

  const nodeKeyBlob = readWrapFile(
    keyFilePath(args.vault, ['keys', 'nodes', `${args.node}.key`], view),
  );
  const nodeWrapKey = deriveKey(rootKey, `credmgr/v2/node-wrap/${args.node}`);
  const nodePriv = aeadOpenWrap(nodeWrapKey, nodeKeyBlob, `keys/nodes/${args.node}.key`);
  if (nodePriv.length !== 32) throw new WrapError('recovered node key is not 32 bytes — corrupt wrap?');
  return nodePriv;
}

function midRotationFailure(firstFailure) {
  return (
    'this vault was caught in the middle of a root-key rotation (rotation-pending/COMMIT exists), ' +
    'so some of its files are under the new root key and some under the old one. That — not ' +
    `necessarily a wrong code — is why nothing opened (first failure: ${firstFailure}).\n` +
    '  * Use the NEW recovery code: the one that rotation printed when it ran.\n' +
    '  * Or finish the rotation first: start credmgrd, or unlock the vault once with its ' +
    'passphrase. That completes the move in a moment, and the vault then opens normally.\n' +
    '  * If the new recovery code was never shown to you, unlock with the passphrase to finish the ' +
    'rotation, then rotate the root key again to get a recovery code you hold.\n' +
    '  * Do not delete rotation-pending/: it holds the rotation\'s new files.'
  );
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const recoveryCode = readRecoveryCode();

  // A committed root-key rotation whose files were not all moved into place
  // (ADR-076): try the view its staged files give first (the NEW root key's
  // vault), then the live files exactly as they stand (the OLD code opens them
  // while nothing has moved yet).
  const midRotation = existsSync(join(args.vault, 'rotation-pending', 'COMMIT'));
  let nodePriv = null;
  let firstFailure = null;
  for (const view of midRotation ? ['staged', 'live'] : ['live']) {
    try {
      nodePriv = recoverNodeKey(args, recoveryCode, view);
      break;
    } catch (e) {
      if (!(e instanceof WrapError)) throw e;
      firstFailure = firstFailure ?? e.message;
    }
  }
  if (nodePriv === null) fail(midRotation ? midRotationFailure(firstFailure) : firstFailure);
  if (midRotation) {
    process.stderr.write(
      'emergency-decrypt: note: this vault is in the middle of a root-key rotation ' +
        '(rotation-pending/COMMIT exists). The value was read from the rotation\'s staged files ' +
        'and the live vault; start credmgrd or unlock the vault once to finish the rotation.\n',
    );
  }

  const envelope = readFileOrFail(
    join(args.vault, 'nodes', args.node, 'entries', `${args.entry}.env`),
  );
  const { version, plaintext } = openEnvelope(envelope, nodePriv, args.node, args.entry);

  let output = plaintext;
  if (version === VERSION_FIELD_DOCUMENT && args.pretty) {
    // Same document, indented. A version-2 plaintext has already authenticated,
    // so a parse failure here means a bug in whatever sealed it, not tampering.
    try {
      output = Buffer.from(JSON.stringify(JSON.parse(plaintext.toString('utf8')), null, 2), 'utf8');
    } catch {
      fail('this version-2 envelope authenticated, but its plaintext is not valid JSON — re-run without --pretty to see the raw bytes');
    }
  }

  process.stdout.write(output);
  if (output.length === 0 || output[output.length - 1] !== 0x0a) {
    process.stdout.write('\n');
  }
}

main();
