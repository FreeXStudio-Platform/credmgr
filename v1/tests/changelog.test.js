'use strict';

const assert = require('assert');
const store = require('../lib/store');
const changelog = require('../lib/changelog');

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

const TEST_PREFIX = '_CHANGELOG_TEST_' + Date.now() + '_';

// ─── Black-box guards + early purge ────────────────────────────────────────

test('deleteEntry: rejects malformed / path-like change ids', () => {
  assert.strictEqual(changelog.deleteEntry('../../etc/passwd').success, false);
  assert.strictEqual(changelog.deleteEntry('').success, false);
  assert.strictEqual(changelog.deleteEntry('foo/bar').success, false);
});

test('purgeAll: empties the archive early (no 7-day wait)', () => {
  changelog.log({
    action: 'delete',
    credentialId: 'purge-test-id',
    credentialName: TEST_PREFIX + 'PURGE_ME',
    previousValue: 'old-secret',
    newValue: null,
  });
  assert.ok(changelog.listChanges().length > 0);
  const r = changelog.purgeAll();
  assert.ok(r.purged > 0);
  assert.strictEqual(r.remaining, 0);
  assert.strictEqual(changelog.listChanges().length, 0);
});

// ─── log + listChanges ────────────────────────────────────────────────────

test('log: records a change and returns changeId', () => {
  const changeId = changelog.log({
    action: 'add',
    credentialId: 'test-id',
    credentialName: TEST_PREFIX + 'ITEM',
    previousValue: null,
    newValue: 'secret',
  });
  assert.ok(changeId);
  assert.ok(typeof changeId === 'string');
});

test('listChanges: returns recent changes', () => {
  const changes = changelog.listChanges();
  assert.ok(Array.isArray(changes));
  assert.ok(changes.length > 0);
  // Newest first
  if (changes.length >= 2) {
    assert.ok(changes[0].timestamp >= changes[1].timestamp);
  }
});

// ─── getChange ─────────────────────────────────────────────────────────────

test('getChange: retrieves specific change', () => {
  const changeId = changelog.log({
    action: 'modify',
    credentialId: 'test-id-2',
    credentialName: TEST_PREFIX + 'ITEM2',
    previousValue: 'old',
    newValue: 'new',
  });

  const change = changelog.getChange(changeId);
  assert.ok(change);
  assert.strictEqual(change.action, 'modify');
  assert.strictEqual(change.credentialName, TEST_PREFIX + 'ITEM2');
});

test('getChange: returns null for missing', () => {
  const change = changelog.getChange('nonexistent-change-id-' + Date.now());
  assert.strictEqual(change, null);
});

// ─── undo (modify) ────────────────────────────────────────────────────────

test('undo: restores modified credential', () => {
  const name = TEST_PREFIX + 'UNDO_MODIFY';

  // Create, then modify
  store.set(name, 'original-value');
  store.set(name, 'modified-value');

  // Find the modify change
  const changes = changelog.listChanges();
  const modifyChange = changes.find(c => c.credentialName === name && c.action === 'modify');
  assert.ok(modifyChange, 'Should find modify change');

  // Undo it
  const result = changelog.undo(modifyChange.changeId);
  assert.strictEqual(result.success, true);

  // Verify value restored
  const restored = store.get(name);
  assert.strictEqual(restored.value, 'original-value');

  // Cleanup
  store.remove(name);
});

// ─── undo (delete) ─────────────────────────────────────────────────────────

test('undo: restores deleted credential', () => {
  const name = TEST_PREFIX + 'UNDO_DELETE';

  store.set(name, 'delete-me-value');
  store.remove(name);

  // Find the delete change
  const changes = changelog.listChanges();
  const deleteChange = changes.find(c => c.credentialName === name && c.action === 'delete');
  assert.ok(deleteChange, 'Should find delete change');

  // Undo
  const result = changelog.undo(deleteChange.changeId);
  assert.strictEqual(result.success, true);

  // Verify restored
  const restored = store.get(name);
  assert.ok(restored);
  assert.strictEqual(restored.value, 'delete-me-value');

  // Cleanup
  store.remove(name);
});

test('undo: delete-undo with a name collision refuses under replace, succeeds under keep-both', () => {
  const name = TEST_PREFIX + 'UNDO_DELETE_COLLISION';

  store.set(name, 'accidentally-deleted-secret');
  store.remove(name);

  const changes = changelog.listChanges();
  const deleteChange = changes.find(c => c.credentialName === name && c.action === 'delete');
  assert.ok(deleteChange, 'Should find delete change');

  // Mistakenly reuse the same name for an unrelated new secret before the undo
  store.set(name, 'unrelated-new-secret');

  // Default (replace) mode must refuse rather than silently clobber the new one
  const refused = changelog.undo(deleteChange.changeId);
  assert.strictEqual(refused.success, false, 'must refuse a collision under replace mode');
  assert.ok(/keep-both/i.test(refused.message), 'message should point at keep-both');
  assert.strictEqual(store.get(name).value, 'unrelated-new-secret', 'new value must be untouched after refusal');

  // keep-both must restore the deleted one under a free name, keeping both
  const result = changelog.undo(deleteChange.changeId, undefined, { mode: 'keep-both' });
  assert.strictEqual(result.success, true, 'keep-both should succeed on a delete-undo collision: ' + result.message);
  assert.ok(result.restoredName && result.restoredName !== name, 'restored name must differ from the live one');

  assert.strictEqual(store.get(name).value, 'unrelated-new-secret', 'current credential must still be untouched');
  const restored = store.get(result.restoredName);
  assert.ok(restored, 'restored credential should exist');
  assert.strictEqual(restored.value, 'accidentally-deleted-secret', 'restored credential must hold the deleted value');

  // Cleanup
  store.remove(name);
  store.remove(result.restoredName);
});

// ─── undo (add) — POLICY: adds are permanent, undo must be rejected ────────

test('undo: refuses to remove added credential (adds are permanent)', () => {
  const name = TEST_PREFIX + 'UNDO_ADD';
  store.set(name, 'undo-add-value');

  const changes = changelog.listChanges();
  const addChange = changes.find(c => c.credentialName === name && c.action === 'add');
  assert.ok(addChange, 'Should find add change');

  const result = changelog.undo(addChange.changeId);
  assert.strictEqual(result.success, false, 'add-undo should be rejected');
  assert.ok(/cannot be undone/i.test(result.message), 'Reject reason should mention adds cannot be undone');

  // Credential must still exist
  const stillThere = store.get(name);
  assert.ok(stillThere && stillThere.value === 'undo-add-value', 'Credential must survive blocked undo');

  // Cleanup
  store.remove(name);
});

// ─── undo (keep-both) ──────────────────────────────────────────────────────

test('undo: keep-both restores previous value as <name> old', () => {
  const name = TEST_PREFIX + 'UNDO_KEEPBOTH';
  store.set(name, 'original-secret');
  store.set(name, 'rotated-secret'); // generates a 'modify' entry

  const changes = changelog.listChanges();
  const modifyChange = changes.find(c => c.credentialName === name && c.action === 'modify');
  assert.ok(modifyChange, 'Should find modify change');

  const result = changelog.undo(modifyChange.changeId, undefined, { mode: 'keep-both' });
  assert.strictEqual(result.success, true, 'keep-both should succeed');
  assert.ok(result.restoredName, 'Should report the restored name');

  // Current credential keeps the new value
  const current = store.get(name);
  assert.strictEqual(current.value, 'rotated-secret', 'Current must keep new value');

  // Restored credential exists with the old value
  const restored = store.get(result.restoredName);
  assert.ok(restored, 'Restored credential should exist');
  assert.strictEqual(restored.value, 'original-secret', 'Restored credential must hold old value');

  // Cleanup
  store.remove(name);
  store.remove(result.restoredName);
});

// ─── deleteEntry: per-item history purge ──────────────────────────────────

test('deleteEntry: permanently removes a changelog entry', () => {
  const name = TEST_PREFIX + 'DELETE_ENTRY';
  store.set(name, 'will-be-purged');

  const changes = changelog.listChanges();
  const target = changes.find(c => c.credentialName === name && c.action === 'add');
  assert.ok(target, 'Should find target entry');

  const result = changelog.deleteEntry(target.changeId);
  assert.strictEqual(result.success, true);

  const after = changelog.listChanges();
  const stillThere = after.find(c => c.changeId === target.changeId);
  assert.strictEqual(stillThere, undefined, 'Entry must be gone after deleteEntry');

  // Trying to undo a purged entry returns "not found"
  const undoAttempt = changelog.undo(target.changeId);
  assert.strictEqual(undoAttempt.success, false);

  // Cleanup
  store.remove(name);
});

// ─── detectActor ───────────────────────────────────────────────────────────

test('log: records actor', () => {
  const changes = changelog.listChanges();
  assert.ok(changes.length > 0);
  assert.ok(changes[0].actor);
});

// ─── Summary ───────────────────────────────────────────────────────────────

console.log('\nchangelog.test.js: ' + passed + ' passed, ' + failed + ' failed');
if (failed > 0) process.exit(1);
