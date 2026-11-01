'use strict';

const assert = require('assert');
const store = require('../lib/store');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
  } catch (err) {
    failed++;
    console.error('FAIL: ' + name);
    console.error('  ' + err.message);
  }
}

// These tests run against the live store (post-migration).
// They use a unique test prefix to avoid polluting real data.

const TEST_PREFIX = '_TEST_' + Date.now() + '_';

// ─── set + get ─────────────────────────────────────────────────────────────

test('set: creates new credential', () => {
  const name = TEST_PREFIX + 'NEW_KEY';
  const entry = store.set(name, 'test-value-123');
  assert.ok(entry.id);
  assert.strictEqual(entry.name, name);
  assert.ok(entry.created);
});

test('get: retrieves credential with value', () => {
  const name = TEST_PREFIX + 'NEW_KEY';
  const result = store.get(name);
  assert.ok(result);
  assert.strictEqual(result.value, 'test-value-123');
  assert.strictEqual(result.metadata.name, name);
});

test('getMetadata: returns metadata only', () => {
  const name = TEST_PREFIX + 'NEW_KEY';
  const meta = store.getMetadata(name);
  assert.ok(meta);
  assert.strictEqual(meta.name, name);
  assert.ok(!meta.value); // value not in metadata
});

test('set: updates existing credential', () => {
  const name = TEST_PREFIX + 'NEW_KEY';
  const entry = store.set(name, 'updated-value');
  assert.strictEqual(entry.name, name);
  const result = store.get(name);
  assert.strictEqual(result.value, 'updated-value');
});

// ─── list + search ─────────────────────────────────────────────────────────

test('list: returns array of credentials', () => {
  const all = store.list();
  assert.ok(Array.isArray(all));
  assert.ok(all.length > 0);
});

test('list: filters by project', () => {
  const global = store.list({ project: 'global' });
  assert.ok(global.every(c => c.project === 'global'));
});

test('search: finds by name', () => {
  const name = TEST_PREFIX + 'NEW_KEY';
  const results = store.search(name);
  assert.ok(results.length > 0);
  assert.strictEqual(results[0].name, name);
});

test('search: returns empty for garbage query', () => {
  const results = store.search('xyzzyplugh_' + Date.now());
  assert.strictEqual(results.length, 0);
});

// ─── rotate ────────────────────────────────────────────────────────────────

test('rotate: changes value and sets rotated timestamp', () => {
  const name = TEST_PREFIX + 'NEW_KEY';
  const entry = store.rotate(name, 'rotated-value');
  assert.ok(entry);
  assert.ok(entry.rotated);
  const result = store.get(name);
  assert.strictEqual(result.value, 'rotated-value');
});

// ─── updateMetadata ────────────────────────────────────────────────────────

test('updateMetadata: changes tags and description', () => {
  const name = TEST_PREFIX + 'NEW_KEY';
  const updated = store.updateMetadata(name, {
    tags: ['test', 'automated'],
    description: 'Test credential',
  });
  assert.ok(updated);
  assert.deepStrictEqual(updated.tags, ['test', 'automated']);
  assert.strictEqual(updated.description, 'Test credential');
});

// ─── remove ────────────────────────────────────────────────────────────────

test('remove: soft-deletes credential', () => {
  const name = TEST_PREFIX + 'NEW_KEY';
  const ok = store.remove(name);
  assert.strictEqual(ok, true);
  const result = store.get(name);
  assert.strictEqual(result, null);
});

test('remove: returns false for missing credential', () => {
  const ok = store.remove('DOES_NOT_EXIST_' + Date.now());
  assert.strictEqual(ok, false);
});

// ─── stats ─────────────────────────────────────────────────────────────────

test('stats: returns valid statistics', () => {
  const s = store.stats();
  assert.ok(typeof s.total === 'number');
  assert.ok(typeof s.byProject === 'object');
  assert.ok(typeof s.byCategory === 'object');
  assert.ok(typeof s.projectCount === 'number');
});

// ─── exportEnv ─────────────────────────────────────────────────────────────

test('exportEnv: returns KEY=VALUE format', () => {
  const env = store.exportEnv('global');
  assert.ok(typeof env === 'string');
  // Should have at least one line with =
  assert.ok(env.includes('='));
});

// ─── verifyIntegrity ───────────────────────────────────────────────────────

test('verifyIntegrity: passes for healthy store', () => {
  const result = store.verifyIntegrity();
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.errors.length, 0);
});

// ─── listProjects ──────────────────────────────────────────────────────────

test('listProjects: returns project array', () => {
  const projects = store.listProjects();
  assert.ok(Array.isArray(projects));
  assert.ok(projects.length > 0);
  assert.ok(projects.some(p => p.id === 'global'));
});

test('removeProject: refuses while credentials still reference it, succeeds once empty', () => {
  const projectId = 'zz_test_teardown_' + Date.now();
  const name = TEST_PREFIX + 'TEARDOWN_CRED';
  store.set(name, 'v', { project: projectId });
  assert.ok(store.listProjects().some(p => p.id === projectId), 'setting a credential should implicitly create the project');

  assert.throws(() => store.removeProject(projectId), /still has 1 credential/);
  assert.ok(store.listProjects().some(p => p.id === projectId), 'refused removal must not touch the project list');

  store.remove(name);
  const result = store.removeProject(projectId);
  assert.strictEqual(result.removed, true);
  assert.ok(!store.listProjects().some(p => p.id === projectId), 'project must be gone once empty');
});

test('removeProject: refuses unknown id and the global project', () => {
  assert.throws(() => store.removeProject('not-a-real-project-id'), /not found/);
  assert.throws(() => store.removeProject('global'), /cannot be removed/);
});

// ─── detectFormat (via set) ────────────────────────────────────────────────

test('detectFormat: identifies hex key format', () => {
  const name = TEST_PREFIX + 'HEX_KEY';
  const entry = store.set(name, '0x' + 'a'.repeat(64));
  assert.strictEqual(entry.format, 'hex-key');
  store.remove(name);
});

test('detectFormat: identifies JWT format', () => {
  const name = TEST_PREFIX + 'JWT';
  const entry = store.set(name, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test');
  assert.strictEqual(entry.format, 'jwt');
  store.remove(name);
});

// ─── generateSecret ────────────────────────────────────────────────────────

test('generateSecret: honors length', () => {
  assert.strictEqual(store.generateSecret({ length: 40 }).length, 40);
  assert.strictEqual(store.generateSecret({ length: 12 }).length, 12);
});

test('generateSecret: hex type is hex-only', () => {
  const s = store.generateSecret({ length: 32, type: 'hex' });
  assert.ok(/^[0-9a-f]+$/.test(s), 'expected hex, got ' + s);
});

test('generateSecret: alnum type has no symbols', () => {
  const s = store.generateSecret({ length: 64, type: 'alnum' });
  assert.ok(/^[0-9a-zA-Z]+$/.test(s), 'expected alnum only');
});

test('generateSecret: two calls differ (randomness)', () => {
  assert.notStrictEqual(store.generateSecret({ length: 32 }), store.generateSecret({ length: 32 }));
});

// ─── vault integrity checksum ──────────────────────────────────────────────

test('verifyVaultChecksum: healthy store matches', () => {
  const r = store.verifyVaultChecksum();
  assert.ok(r.status === 'ok' || r.status === 'missing-checksum', 'got ' + r.status);
});

test('verifyIntegrity: reports checksum + warnings fields', () => {
  const r = store.verifyIntegrity();
  assert.ok('checksum' in r);
  assert.ok(Array.isArray(r.warnings));
});

// ─── importEnv ─────────────────────────────────────────────────────────────

test('importEnv: imports new + skips identical', () => {
  const a = TEST_PREFIX + 'IMP_A';
  const b = TEST_PREFIX + 'IMP_B';
  const content = a + '=val-a\n# comment\n' + b + '="val b"\n';
  const r1 = store.importEnv(content, { project: 'global' });
  assert.strictEqual(r1.imported, 2);
  assert.strictEqual(store.get(a).value, 'val-a');
  assert.strictEqual(store.get(b).value, 'val b'); // quotes stripped
  // Re-import identical → all skipped
  const r2 = store.importEnv(content, { project: 'global' });
  assert.strictEqual(r2.imported, 0);
  assert.strictEqual(r2.skipped, 2);
  store.remove(a); store.remove(b);
});

test('importEnv: conflict not overwritten without flag', () => {
  const a = TEST_PREFIX + 'IMP_C';
  store.set(a, 'original');
  const r = store.importEnv(a + '=different\n', { project: 'global' });
  assert.strictEqual(r.conflicts, 1);
  assert.strictEqual(store.get(a).value, 'original'); // unchanged
  store.remove(a);
});

// ─── history ───────────────────────────────────────────────────────────────

test('history: returns change trail for a credential, values redacted', () => {
  const n = TEST_PREFIX + 'HIST';
  store.set(n, 'v1');
  store.set(n, 'v2');
  const rows = store.history(n);
  assert.ok(rows.length >= 1);
  // No raw secret values leak by default
  assert.ok(rows.every(r => r.newValue === null || r.newValue === '[redacted]'));
  store.remove(n);
});

// ─── healStore (dry run — never mutates real store) ────────────────────────

test('healStore: dry run returns a report without applying', () => {
  const r = store.healStore(undefined, { apply: false });
  assert.strictEqual(r.applied, false);
  assert.ok(typeof r.fixCount === 'number');
  assert.ok(Array.isArray(r.fixes));
});

// ─── batchImport (flat + structured + wallet) ──────────────────────────────

test('batchImport: wallet items each become ONE structured entry with sub-fields', () => {
  const g = TEST_PREFIX + 'BATCH';
  const r = store.batchImport([
    { name: g + '_W1', chain: 'ethereum', address: '0x' + '1'.repeat(40), privateKey: '0x' + 'a'.repeat(64), seedPhrase: 'a b c d e f g h i j k l' },
    { name: g + '_W2', chain: 'bitcoin', address: 'bc1qxyz', mnemonic: 'm n o p q r s t u v w x' },
  ], { batchGroup: g });
  assert.strictEqual(r.added, 2);
  assert.strictEqual(r.errors, 0);
  // Each wallet is exactly one entry, structured, with its fields intact.
  const w1 = store.get(g + '_W1');
  assert.strictEqual(w1.metadata.format, 'structured');
  assert.strictEqual(w1.metadata.category, 'wallet');
  assert.strictEqual(w1.metadata.sensitivity, 'critical'); // has privateKey + seedPhrase
  const fields = JSON.parse(w1.value)._fields.map(f => f.label);
  assert.deepStrictEqual(fields, ['chain', 'address', 'privateKey', 'seedPhrase']);
  // mnemonic alias folded into a single seedPhrase field
  const w2 = store.get(g + '_W2');
  assert.ok(JSON.parse(w2.value)._fields.some(f => f.label === 'seedPhrase'));
  store.remove(g + '_W1'); store.remove(g + '_W2');
});

test('batchImport: explicit fields[] and flat value coexist in one batch', () => {
  const g = TEST_PREFIX + 'MIX';
  const r = store.batchImport([
    { name: g + '_STRUCT', fields: [{ label: 'apiKey', value: 'ak_1' }, { label: 'apiSecret', value: 'sec_1' }] },
    { name: g + '_FLAT', value: 'plain-token' },
    { name: g + '_BAD' }, // no value/fields/wallet keys
  ], {});
  assert.strictEqual(r.added, 2);
  assert.strictEqual(r.errors, 1);
  assert.strictEqual(store.getMetadata(g + '_STRUCT').format, 'structured');
  assert.strictEqual(store.get(g + '_FLAT').value, 'plain-token');
  store.remove(g + '_STRUCT'); store.remove(g + '_FLAT');
});

test('batchImport: dedupe — identical value skipped, different value is a conflict', () => {
  const g = TEST_PREFIX + 'DEDUP';
  store.batchImport([{ name: g, value: 'v1' }], {});
  const same = store.batchImport([{ name: g, value: 'v1' }], {});
  assert.strictEqual(same.skipped, 1);
  assert.strictEqual(same.added, 0);
  const diff = store.batchImport([{ name: g, value: 'v2' }], {});
  assert.strictEqual(diff.conflicts, 1);
  assert.strictEqual(diff.added, 0);
  const forced = store.batchImport([{ name: g, value: 'v2' }], { overwrite: true });
  assert.strictEqual(forced.added, 1);
  assert.strictEqual(store.get(g).value, 'v2');
  store.remove(g);
});

test('batchImport: dryRun reports true counts and writes nothing', () => {
  const g = TEST_PREFIX + 'DRYRUN';
  // Seed one real entry so the dry run has something to skip/conflict against.
  store.batchImport([{ name: g + '_EXISTING', value: 'same' }], {});

  const preview = store.batchImport([
    { name: g + '_NEW', value: 'v1' },               // would be added
    { name: g + '_EXISTING', value: 'same' },        // identical → would be skipped
    { name: g + '_EXISTING', value: 'different' },   // differs → would be a conflict
  ], { dryRun: true });

  assert.strictEqual(preview.added, 1);
  assert.strictEqual(preview.skipped, 1);
  assert.strictEqual(preview.conflicts, 1);
  assert.strictEqual(preview.dryRun, true);
  // Nothing was actually written for the "would be added" item.
  assert.strictEqual(store.get(g + '_NEW'), null);

  store.remove(g + '_EXISTING');
});

test('batchImport: a batch of wallets is N entries, never one blob', () => {
  const g = TEST_PREFIX + 'FLEET';
  const wallets = [];
  for (let i = 0; i < 5; i++) wallets.push({ name: g + '_' + i, address: '0x' + String(i).repeat(40), privateKey: '0x' + String(i).repeat(64) });
  const r = store.batchImport(wallets, { batchGroup: g });
  assert.strictEqual(r.added, 5);
  // Five distinct entries, all sharing the batchGroup tag.
  const tagged = store.list({ tag: r.batchGroup });
  assert.strictEqual(tagged.length, 5);
  wallets.forEach(w => store.remove(w.name));
});

// ─── Name splitting + suggestion grouping ───────────────────────────────────

test('splitNameStem: multi-word suffix + mixed separators + case', () => {
  const a = store.splitNameStem('test wallet 1 public key');
  assert.strictEqual(a.stem, 'test_wallet_1');
  assert.strictEqual(a.fieldLabel, 'publicKey');
  const b = store.splitNameStem('ACME_Email_USER');
  assert.strictEqual(b.fieldLabel, 'username');
  assert.strictEqual(b.stem.toUpperCase(), 'ACME_EMAIL');
  const c = store.splitNameStem('ACME_EMAIL_PASS');
  assert.strictEqual(c.fieldLabel, 'password');
  assert.strictEqual(c.stem.toUpperCase(), 'ACME_EMAIL');
  const d = store.splitNameStem('test wallet 1 seed phrase');
  assert.strictEqual(d.fieldLabel, 'seedPhrase');
  assert.strictEqual(d.stem, 'test_wallet_1');
});

test('findMergeSuggestions: case-insensitive stems, per-wallet grouping', () => {
  const g = TEST_PREFIX + 'SUGG';
  store.set(g + '_Email_USER', 'someone@example.com');
  store.set(g + '_EMAIL_PASS', 'hunter2-hunter2');
  store.set(g + ' wallet 1 public key', '0x' + 'a'.repeat(40));
  store.set(g + ' wallet 1 private key', '0x' + 'b'.repeat(64));
  store.set(g + ' wallet 1 seed phrase', 'alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu');
  store.set(g + ' wallet 2 public key', '0x' + 'c'.repeat(40));
  store.set(g + ' wallet 2 private key', '0x' + 'd'.repeat(64));

  const suggestions = store.findMergeSuggestions();
  const mergeSuggs = suggestions.filter(s => s.type === 'merge-candidates');

  // Note: stems are token-based, so the leading '_' of the test prefix is
  // not part of the stem key.
  const stemKey = suffix => (g + suffix).toUpperCase().replace(/^_+/, '');
  const emailGroup = mergeSuggs.find(s => s.suggestedName === stemKey('_EMAIL'));
  assert.ok(emailGroup, 'ACME_Email_USER + ACME_EMAIL_PASS should group despite case');
  assert.strictEqual(emailGroup.names.length, 2);
  assert.deepStrictEqual(emailGroup.suggestedFields.map(f => f.label).sort(), ['password', 'username']);

  const w1 = mergeSuggs.find(s => s.suggestedName === stemKey('_WALLET_1'));
  const w2 = mergeSuggs.find(s => s.suggestedName === stemKey('_WALLET_2'));
  assert.ok(w1, 'wallet 1 parts should form their own group');
  assert.ok(w2, 'wallet 2 parts should form their own group');
  assert.strictEqual(w1.names.length, 3);
  assert.strictEqual(w2.names.length, 2);
  assert.strictEqual(w1.walletLike, true);
  assert.strictEqual(w1.severity, 'high'); // has privateKey + seedPhrase
  assert.strictEqual(w1.suggestedCategory, 'wallet');

  [g + '_Email_USER', g + '_EMAIL_PASS',
   g + ' wallet 1 public key', g + ' wallet 1 private key', g + ' wallet 1 seed phrase',
   g + ' wallet 2 public key', g + ' wallet 2 private key'].forEach(n => store.remove(n));
});

test('findMergeSuggestions: dismissed groups are hidden and restorable', () => {
  const g = TEST_PREFIX + 'DISM';
  store.set(g + '_SVC_USER', 'someone@example.com');
  store.set(g + '_SVC_PASS', 'hunter2-hunter2');

  const before = store.findMergeSuggestions();
  const target = before.find(s => s.names.includes(g + '_SVC_USER'));
  assert.ok(target, 'expected a merge-candidates suggestion for the pair');
  assert.ok(target.key, 'suggestion must carry a stable key');

  const d = store.dismissSuggestion(target.key);
  assert.strictEqual(d.dismissed, true);

  // Recomputing from scratch (fresh scan, no client memory) must NOT bring
  // the dismissed group back — this is the actual bug being fixed: previously
  // dismissal was sessionStorage-only and the scan itself never remembered.
  const after = store.findMergeSuggestions();
  assert.ok(!after.some(s => s.key === target.key), 'dismissed suggestion must stay hidden on a fresh scan');

  // ...but it's still discoverable for a "manage dismissed" view, and via
  // includeDismissed for review.
  const dismissedList = store.listDismissedSuggestions();
  assert.ok(dismissedList.some(x => x.key === target.key));
  const withDismissed = store.findMergeSuggestions(null, { includeDismissed: true });
  assert.ok(withDismissed.some(s => s.key === target.key));

  // Undismiss brings it back.
  const u = store.undismissSuggestion(target.key);
  assert.strictEqual(u.restored, true);
  const restored = store.findMergeSuggestions();
  assert.ok(restored.some(s => s.key === target.key));

  // Dismiss again, then bulk-restore.
  store.dismissSuggestion(target.key);
  const bulk = store.restoreAllDismissedSuggestions();
  assert.ok(bulk.restored >= 1);
  assert.strictEqual(store.listDismissedSuggestions().length, 0);

  assert.throws(() => store.dismissSuggestion(), /suggestion key/);

  store.remove(g + '_SVC_USER');
  store.remove(g + '_SVC_PASS');
});

// ─── Auto-merge ──────────────────────────────────────────────────────────────

test('autoMerge: user+pass → one structured entry, sources archived', () => {
  const g = TEST_PREFIX + 'AM';
  const e1 = store.set(g + '_SVC_USER', 'admin@example.com');
  const e2 = store.set(g + '_SVC_PASS', 'p@ssw0rd-123456');
  const lowestRef = Math.min(e1.ref, e2.ref);

  const r = store.autoMerge([g + '_SVC_USER', g + '_SVC_PASS'], {});
  assert.strictEqual(r.archived.length, 2);
  // Token-based stem: the test prefix's leading '_' is not part of the name.
  assert.strictEqual(r.merged.name, (g + '_SVC').toUpperCase().replace(/^_+/, ''));
  assert.strictEqual(r.merged.ref, lowestRef); // keeps the lowest source ref

  const merged = store.get(r.merged.name);
  const fields = JSON.parse(merged.value)._fields;
  assert.deepStrictEqual(fields.map(f => f.label).sort(), ['password', 'username']);
  assert.strictEqual(fields.find(f => f.label === 'username').value, 'admin@example.com');
  assert.strictEqual(fields.find(f => f.label === 'password').value, 'p@ssw0rd-123456');

  // Sources are gone from the index
  assert.strictEqual(store.getMetadata(g + '_SVC_USER'), null);
  assert.strictEqual(store.getMetadata(g + '_SVC_PASS'), null);

  store.remove(r.merged.name);
});

test('autoMerge: wallet parts → wallet category, critical sensitivity', () => {
  const g = TEST_PREFIX + 'AMW';
  store.set(g + ' wallet 1 public key', '0x' + '1'.repeat(40), { sensitivity: 'low' });
  store.set(g + ' wallet 1 private key', '0x' + '2'.repeat(64), { sensitivity: 'low' });
  store.set(g + ' wallet 1 seed phrase', 'one two three four five six seven eight nine ten eleven twelve', { sensitivity: 'low' });

  const r = store.autoMerge(
    [g + ' wallet 1 public key', g + ' wallet 1 private key', g + ' wallet 1 seed phrase'],
    {}
  );
  assert.strictEqual(r.merged.category, 'wallet');
  assert.strictEqual(r.merged.sensitivity, 'critical'); // private key + seed force critical
  const fields = JSON.parse(store.get(r.merged.name).value)._fields;
  assert.deepStrictEqual(fields.map(f => f.label).sort(), ['privateKey', 'publicKey', 'seedPhrase']);
  store.remove(r.merged.name);
});

test('autoMerge: label collision keeps both values, identical values dedupe', () => {
  const g = TEST_PREFIX + 'AMC';
  store.set(g + '_A_TOKEN', 'same-token-value-1');
  store.set(g + '_B_TOKEN', 'same-token-value-1');      // identical → dedupe to one field
  store.set(g + '_C_TOKEN', 'different-token-value-2'); // same label, new value → token_2

  const r = store.autoMerge([g + '_A_TOKEN', g + '_B_TOKEN', g + '_C_TOKEN'], { newName: g + '_TOKENS' });
  const fields = JSON.parse(store.get(g + '_TOKENS').value)._fields;
  assert.strictEqual(fields.length, 2);
  assert.deepStrictEqual(fields.map(f => f.label).sort(), ['token', 'token_2']);
  store.remove(g + '_TOKENS');
});

test('autoMerge: rejects fewer than 2 sources and unknown names', () => {
  assert.throws(() => store.autoMerge([TEST_PREFIX + 'ONLY_ONE'], {}), /at least 2/);
  assert.throws(() => store.autoMerge([TEST_PREFIX + 'NOPE_A', TEST_PREFIX + 'NOPE_B'], {}), /not found/);
});

test('autoMerge: unknown-suffix names sharing a value-detected type stay distinguishable (Acme xpub bug)', () => {
  // Regression for: 13 Acme xpub-per-chain credentials auto-merged into
  // one record with 13 identically-labeled "xpub" fields — the chain suffix
  // (BTC/LTC/LIGHTNING) has no entry in FIELD_LABEL_MAP, so splitNameStem
  // falls back to known:false, and the old code let detectFieldLabelFromValue
  // fully REPLACE that fallback label instead of blending with it — every
  // xpub-shaped value detects as the same generic 'xpub' regardless of chain.
  const g = TEST_PREFIX + 'PBH';
  const xpubBtc = 'xpub' + '1'.repeat(100);
  const xpubLtc = 'xpub' + '2'.repeat(100);
  const xpubLn = 'xpub' + '3'.repeat(100);
  store.set(g + '_XPUB_BTC', xpubBtc);
  store.set(g + '_XPUB_LTC', xpubLtc);
  store.set(g + '_XPUB_LIGHTNING', xpubLn);

  const r = store.autoMerge([g + '_XPUB_BTC', g + '_XPUB_LTC', g + '_XPUB_LIGHTNING'], { newName: g + '_XPUB' });
  const fields = JSON.parse(store.get(g + '_XPUB').value)._fields;
  assert.strictEqual(fields.length, 3); // no accidental dedup/collision numbering
  assert.deepStrictEqual(
    fields.map(f => f.label).sort(),
    ['xpub_btc', 'xpub_lightning', 'xpub_ltc']
  );
  assert.strictEqual(fields.find(f => f.label === 'xpub_btc').value, xpubBtc);
  assert.strictEqual(fields.find(f => f.label === 'xpub_ltc').value, xpubLtc);
  assert.strictEqual(fields.find(f => f.label === 'xpub_lightning').value, xpubLn);
  store.remove(g + '_XPUB');
});

// ─── updateMetadata: rename safety ──────────────────────────────────────────

test('updateMetadata: rename onto an existing name throws', () => {
  const g = TEST_PREFIX + 'REN';
  store.set(g + '_ONE', 'v1');
  store.set(g + '_TWO', 'v2');
  assert.throws(() => store.updateMetadata(g + '_ONE', { name: g + '_TWO' }), /already exists/);
  store.remove(g + '_ONE');
  store.remove(g + '_TWO');
});

// ─── Schemas, value detection, batch auto-merge ─────────────────────────────

test('detectFieldLabelFromValue: recognizes common secret shapes', () => {
  assert.strictEqual(store.detectFieldLabelFromValue('0x' + 'a'.repeat(64)), 'privateKey');
  assert.strictEqual(store.detectFieldLabelFromValue('0x' + 'b'.repeat(40)), 'address');
  // credmgr-allow — the first 12 words of the BIP-39 English wordlist, in order.
  // A shape fixture for the detector, not a wallet: it derives no key anyone uses
  // and controls no funds. Kept deliberately recognisable so a reader can see at a
  // glance that it is a word list rather than somebody's recovery phrase.
  assert.strictEqual(store.detectFieldLabelFromValue('abandon ability able about above absent absorb abstract absurd abuse access accident'), 'seedPhrase');
  assert.strictEqual(store.detectFieldLabelFromValue("m/44'/60'/0'/0"), 'derivationPath');
  assert.strictEqual(store.detectFieldLabelFromValue('https://example.com/x'), 'url');
  assert.strictEqual(store.detectFieldLabelFromValue('user@example.com'), 'email');
  assert.strictEqual(store.detectFieldLabelFromValue('just-a-password'), null);
});

test('missingSchemaFields: flags an incomplete wallet, suggests columns', () => {
  const gaps = store.missingSchemaFields('wallet', [{ label: 'privateKey', value: 'x' }]);
  assert.strictEqual(gaps.missingRequired.length, 1); // no address/publicKey/xpub/zpub
  assert.ok(gaps.suggested.indexOf('address') !== -1);
  assert.ok(gaps.suggested.indexOf('accountIndex') !== -1);
  const ok = store.missingSchemaFields('wallet', [
    { label: 'address', value: 'x' }, { label: 'seedPhrase', value: 'y' },
  ]);
  assert.strictEqual(ok.missingRequired.length, 0);
  assert.strictEqual(store.missingSchemaFields('no-such-category', []), null);
});

test('autoMerge: wallet columns come out in schema order', () => {
  const g = TEST_PREFIX + 'ORD';
  store.set(g + ' wallet 9 seed phrase', 'one two three four five six seven eight nine ten eleven twelve');
  store.set(g + ' wallet 9 private key', '0x' + '9'.repeat(64));
  store.set(g + ' wallet 9 address', '0x' + '8'.repeat(40));
  const r = store.autoMerge(
    [g + ' wallet 9 seed phrase', g + ' wallet 9 private key', g + ' wallet 9 address'], {}
  );
  // Schema order: address before privateKey before seedPhrase — regardless
  // of the order the sources were listed in.
  assert.deepStrictEqual(r.fields.map(f => f.label), ['address', 'privateKey', 'seedPhrase']);
  store.remove(r.merged.name);
});

test('autoMergeAll: merges safe groups, skips ambiguous, dryRun writes nothing', () => {
  const g = TEST_PREFIX + 'ALL';
  store.set(g + '_SAFE_USER', 'u@example.com');
  store.set(g + '_SAFE_PASS', 'safe-pass-123456');
  store.set(g + '_AMBIG_FOO', 'not-a-known-suffix-1');
  store.set(g + '_AMBIG_BAR', 'not-a-known-suffix-2');

  const dry = store.autoMergeAll({ dryRun: true });
  assert.ok(dry.planned.some(p => p.names.indexOf(g + '_SAFE_USER') !== -1), 'safe group planned');
  assert.ok(dry.skipped.some(s => s.names.indexOf(g + '_AMBIG_FOO') !== -1), 'ambiguous group skipped');
  assert.ok(store.getMetadata(g + '_SAFE_USER'), 'dryRun must not write');

  const run = store.autoMergeAll({});
  const mergedName = (g + '_SAFE').toUpperCase().replace(/^_+/, '');
  assert.ok(run.merged.some(m => m.newName === mergedName), 'safe group merged');
  assert.strictEqual(store.getMetadata(g + '_SAFE_USER'), null);
  assert.ok(store.getMetadata(g + '_AMBIG_FOO'), 'ambiguous group untouched');

  store.remove(mergedName);
  store.remove(g + '_AMBIG_FOO');
  store.remove(g + '_AMBIG_BAR');
});

test('audit: flags structured wallets missing a required column', () => {
  const g = TEST_PREFIX + 'GAP';
  store.set(g + '_LONELY_WALLET', JSON.stringify({ _fields: [{ label: 'privateKey', value: '0x' + '5'.repeat(64) }] }), { category: 'wallet' });
  const result = store.audit({});
  const issue = result.issues.find(i => i.type === 'incomplete-record' && i.name === g + '_LONELY_WALLET');
  assert.ok(issue, 'incomplete wallet should be flagged');
  assert.ok(/address or publicKey/.test(issue.message));
  store.remove(g + '_LONELY_WALLET');
});

// ─── Daemon Token (agent access) ────────────────────────────────────────────

test('daemonToken: absent by default, rotate creates it, revoke removes it', () => {
  store.revokeDaemonToken(); // ensure clean slate regardless of test order
  assert.strictEqual(store.getDaemonToken(), null);

  const t1 = store.rotateDaemonToken();
  assert.ok(/^[0-9a-f]{64}$/.test(t1));
  assert.strictEqual(store.getDaemonToken(), t1);

  const t2 = store.rotateDaemonToken();
  assert.notStrictEqual(t2, t1); // rotate always issues a fresh token
  assert.strictEqual(store.getDaemonToken(), t2);

  store.revokeDaemonToken();
  assert.strictEqual(store.getDaemonToken(), null);
});

// ─── Aliases (v1.8 / plan 4.1) ──────────────────────────────────────────────

test('autoMerge records source names as aliases; alias get returns the FIELD value', () => {
  const g = TEST_PREFIX + 'ALIAS';
  const pk = '0x' + 'a'.repeat(64);
  const addr = '0x' + 'b'.repeat(40);
  store.set(g + '_WALLET_PRIVATE_KEY', pk);
  store.set(g + '_WALLET_ADDRESS', addr);

  const r = store.autoMerge([g + '_WALLET_PRIVATE_KEY', g + '_WALLET_ADDRESS'], { newName: g + '_WALLET' });
  const merged = store.getMetadata(g + '_WALLET');
  assert.ok(Array.isArray(merged.aliases), 'merged entry carries aliases');
  const aliasNames = merged.aliases.map(a => a.name);
  assert.ok(aliasNames.includes(g + '_WALLET_PRIVATE_KEY'), 'source name recorded as alias');
  assert.ok(aliasNames.includes(g + '_WALLET_ADDRESS'));

  // THE 4.1 acceptance: the old flat name still resolves — to the field value
  const viaAlias = store.get(g + '_WALLET_PRIVATE_KEY');
  assert.ok(viaAlias, 'get via alias resolves');
  assert.strictEqual(viaAlias.value, pk, 'alias with fieldLabel returns that field\'s value, not the JSON blob');
  assert.strictEqual(viaAlias.metadata.name, g + '_WALLET', 'metadata is the merged entry');
  assert.strictEqual(viaAlias.resolvedFromAlias, g + '_WALLET_PRIVATE_KEY');

  const viaAlias2 = store.get(g + '_WALLET_ADDRESS');
  assert.strictEqual(viaAlias2.value, addr);
  store.remove(g + '_WALLET');
});

test('exportEnv --aliases writes both spellings; default export does not', () => {
  const g = TEST_PREFIX + 'ALEXP';
  const proj = 'alias-export-test';
  const pk = '0x' + 'c'.repeat(64);
  store.set(g + '_X_PRIVATE_KEY', pk, { project: proj });
  store.set(g + '_X_ADDRESS', '0x' + 'd'.repeat(40), { project: proj });
  store.autoMerge([g + '_X_PRIVATE_KEY', g + '_X_ADDRESS'], { newName: g + '_X', project: proj });

  const plain = store.exportEnv(proj);
  assert.ok(!plain.includes(g + '_X_PRIVATE_KEY='), 'default export has no alias lines');

  const withAliases = store.exportEnv(proj, undefined, { includeAliases: true });
  assert.ok(withAliases.includes(g + '_X='), 'merged name exported');
  assert.ok(withAliases.includes(g + '_X_PRIVATE_KEY=' + pk), 'alias line carries the FIELD value');
  store.remove(g + '_X');
});

test('set: refuses a name that is an existing alias (collision rejection)', () => {
  const g = TEST_PREFIX + 'ALCOL';
  store.set(g + '_A_USER', 'u1');
  store.set(g + '_A_PASS', 'p1');
  store.autoMerge([g + '_A_USER', g + '_A_PASS'], { newName: g + '_A' });
  assert.throws(() => store.set(g + '_A_USER', 'shadow-value'), /alias of/);
  store.remove(g + '_A');
});

test('updateMetadata: alias validation — duplicates, self-name, cross-entry collisions', () => {
  const g = TEST_PREFIX + 'ALVAL';
  store.set(g + '_ONE', 'v1');
  store.set(g + '_TWO', 'v2');
  // Assign a manual alias
  store.updateMetadata(g + '_ONE', { aliases: [g + '_OLD_NAME'] });
  assert.strictEqual(store.get(g + '_OLD_NAME').value, 'v1');
  // Alias equal to a live credential name → reject
  assert.throws(() => store.updateMetadata(g + '_ONE', { aliases: [g + '_TWO'] }), /collides/);
  // Alias equal to the entry's own name → reject
  assert.throws(() => store.updateMetadata(g + '_ONE', { aliases: [g + '_ONE'] }), /own name/);
  // Alias already owned by another entry → reject
  assert.throws(() => store.updateMetadata(g + '_TWO', { aliases: [g + '_OLD_NAME'] }), /already an alias/);
  store.remove(g + '_ONE');
  store.remove(g + '_TWO');
});

test('aliases survive rename; renaming TO an own alias promotes it', () => {
  const g = TEST_PREFIX + 'ALREN';
  store.set(g + '_ORIG', 'v1');
  store.updateMetadata(g + '_ORIG', { aliases: [g + '_LEGACY'] });
  // Rename the credential — the alias must keep resolving
  store.updateMetadata(g + '_ORIG', { name: g + '_RENAMED' });
  assert.strictEqual(store.get(g + '_LEGACY').value, 'v1', 'alias survives rename');
  assert.strictEqual(store.get(g + '_LEGACY').metadata.name, g + '_RENAMED');
  // Renaming to its own alias: allowed, alias becomes the primary name
  store.updateMetadata(g + '_RENAMED', { name: g + '_LEGACY' });
  const meta = store.getMetadata(g + '_LEGACY');
  assert.ok(meta, 'promoted alias is now the primary name');
  assert.ok(!(meta.aliases || []).some(a => a.name === g + '_LEGACY'), 'promoted alias removed from alias list');
  store.remove(g + '_LEGACY');
});

test('search: finds credentials by alias', () => {
  const g = TEST_PREFIX + 'ALSRCH';
  store.set(g + '_MAIN', 'v1');
  store.updateMetadata(g + '_MAIN', { aliases: [g + '_TOTALLY_DIFFERENT_SPELLING'] });
  const hits = store.search(g + '_TOTALLY_DIFFERENT');
  assert.ok(hits.some(h => h.name === g + '_MAIN'), 'alias match surfaces the owning entry');
  store.remove(g + '_MAIN');
});

// ─── Fuzzy matching (v1.8 / plan 4.2 + 4.3) ────────────────────────────────

test('near-name: UPTIMEROBOT and UPTIME_ROBOT_MAIN group despite different stems', () => {
  const g = TEST_PREFIX;
  store.set(g + 'UPTIMEROBOT_API_KEY', 'ur-key-1-aaaaaa');
  store.set(g + 'UPTIME_ROBOT_MAIN_API_KEY', 'ur-key-2-bbbbbb');
  const suggestions = store.findMergeSuggestions({});
  const hit = suggestions.find(s => s.type === 'near-name' &&
    s.names.includes(g + 'UPTIMEROBOT_API_KEY') && s.names.includes(g + 'UPTIME_ROBOT_MAIN_API_KEY'));
  assert.ok(hit, 'separator/filler drift must produce a near-name suggestion');
  assert.strictEqual(hit.severity, 'low');
  store.remove(g + 'UPTIMEROBOT_API_KEY');
  store.remove(g + 'UPTIME_ROBOT_MAIN_API_KEY');
});

test('SENTRY_DNS / SENTRY_DSN typo pair is caught by the suggestion engine', () => {
  const g = TEST_PREFIX;
  store.set(g + 'SENTRY_DNS', 'https://sentry.example/111');
  store.set(g + 'SENTRY_DSN', 'https://sentry.example/222');
  const suggestions = store.findMergeSuggestions({});
  // Same stem after the unknown-suffix split → the exact-stem grouper covers
  // it; near-name exists for pairs where even the stems differ. Either way,
  // the typo pair MUST surface in some suggestion.
  const hit = suggestions.find(s =>
    (s.type === 'near-name' || s.type === 'merge-candidates') &&
    s.names.includes(g + 'SENTRY_DNS') && s.names.includes(g + 'SENTRY_DSN'));
  assert.ok(hit, 'typo pair must surface as a suggestion');
  store.remove(g + 'SENTRY_DNS');
  store.remove(g + 'SENTRY_DSN');
});

test('near-name: typo pair with UNRELATED stems (edit distance) is caught', () => {
  const g = TEST_PREFIX;
  // Different stems even after splitting: GRAFANA_CLOUD vs GRAFANNA_CLOUD
  store.set(g + 'GRAFANA_CLOUD_TOKEN', 'gc-token-1-aaaaaa');
  store.set(g + 'GRAFANNA_CLOUD_TOKEN', 'gc-token-2-bbbbbb');
  const suggestions = store.findMergeSuggestions({});
  const hit = suggestions.find(s => s.type === 'near-name' &&
    s.names.includes(g + 'GRAFANA_CLOUD_TOKEN') && s.names.includes(g + 'GRAFANNA_CLOUD_TOKEN'));
  assert.ok(hit, 'edit-distance-1 collapsed stems must produce a near-name suggestion');
  store.remove(g + 'GRAFANA_CLOUD_TOKEN');
  store.remove(g + 'GRAFANNA_CLOUD_TOKEN');
});

test('near-name suggestions are never auto-merged by autoMergeAll', () => {
  const g = TEST_PREFIX;
  store.set(g + 'FUZZY_ONE_THING', 'val-one-aaaaaa');
  store.set(g + 'FUZZYONE_THING', 'val-two-bbbbbb');
  const result = store.autoMergeAll({ dryRun: true }, {});
  const touched = [...result.planned, ...result.merged].some(p =>
    (p.names || p.sources || []).includes(g + 'FUZZY_ONE_THING'));
  assert.ok(!touched, 'autoMergeAll must only consume merge-candidates, never near-name');
  store.remove(g + 'FUZZY_ONE_THING');
  store.remove(g + 'FUZZYONE_THING');
});

test('near-duplicate-value: same secret with whitespace/quote drift is flagged, exact dupes are not double-reported', () => {
  const g = TEST_PREFIX;
  const secret = 'near-dup-secret-' + Date.now();
  store.set(g + 'RAW_SECRET_A', secret);
  store.set(g + 'QUOTED_SECRET_B', '"' + secret + '"');
  const suggestions = store.findMergeSuggestions({});
  const near = suggestions.find(s => s.type === 'near-duplicate-value' &&
    s.names.includes(g + 'RAW_SECRET_A') && s.names.includes(g + 'QUOTED_SECRET_B'));
  assert.ok(near, 'quote-wrapped copy of the same secret must be flagged');
  const exact = suggestions.find(s => s.type === 'exact-duplicate' &&
    s.names.includes(g + 'RAW_SECRET_A') && s.names.includes(g + 'QUOTED_SECRET_B'));
  assert.ok(!exact, 'raw-different values are NOT exact duplicates');
  store.remove(g + 'RAW_SECRET_A');
  store.remove(g + 'QUOTED_SECRET_B');
});

// ─── Summary ───────────────────────────────────────────────────────────────

console.log('\nstore.test.js: ' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exit(1);
