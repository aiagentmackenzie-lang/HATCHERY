/**
 * The audit hash chain (D30).
 *
 * These tests tamper with a real SQLite `audit_log` directly — the way an attacker
 * with `sqlite3` would — and assert the verifier detects each class of edit at the
 * right row: a modified row, a deleted row, a row that does not link, and a
 * truncated tail. They also pin the canonical encoding, the bounded paging and the
 * "never throw" contract of the append path.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';

import {
  GENESIS_HASH,
  auditChainMeta,
  countAudit,
  entryHash,
  initAuditChain,
  listAudit,
  recordAudit,
  verifyAuditChain,
} from '../dist/security/audit.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.join(here, '..', 'src', 'db', 'schema.sql');

function freshDb() {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  initAuditChain(db);
  return db;
}

function append(db, overrides = {}) {
  const entry = {
    actor: 'admin',
    role: 'admin',
    authenticated: true,
    method: 'GET',
    path: '/api/tasks',
    statusCode: 200,
    action: 'request.allowed',
    ...overrides,
  };
  assert.equal(recordAudit(db, entry), true, 'appending to a healthy chain must succeed');
  return entry;
}

function appendMany(db, count) {
  for (let i = 0; i < count; i += 1) {
    append(db, { path: `/api/tasks/${i}`, detail: `row ${i}` });
  }
}

test('appending rows produces a valid chain that verifies from the genesis anchor', () => {
  const db = freshDb();
  appendMany(db, 5);

  const result = verifyAuditChain(db);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.first_broken, null);
  assert.equal(result.rows_checked, 5);
  assert.equal(result.complete, true);
  assert.equal(result.next_after_id, null);
  assert.equal(result.genesis, GENESIS_HASH);
  assert.equal(result.algorithm, 'sha256(json-array-v1)');
  assert.equal(result.head.id, 5);
  assert.equal(result.head.matches_meta, true);
  assert.equal(result.legacy.rows, 0);

  const rows = db.prepare('SELECT id, prev_hash, entry_hash FROM audit_log ORDER BY id').all();
  assert.equal(rows[0].prev_hash, GENESIS_HASH, 'the first row links to the documented genesis value');
  assert.match(rows[0].entry_hash, /^[0-9a-f]{64}$/);
  for (let i = 1; i < rows.length; i += 1) {
    assert.equal(rows[i].prev_hash, rows[i - 1].entry_hash, 'each row links to its predecessor');
  }

  // The meta head is the same head the verifier recomputed.
  const meta = auditChainMeta(db);
  assert.equal(Number(meta.head_id), rows[rows.length - 1].id);
  assert.equal(meta.head_hash, rows[rows.length - 1].entry_hash);
  assert.equal(Number(meta.chained_row_count), 5);
});

test('the entry hash covers exactly the documented stored fields', () => {
  const db = freshDb();
  append(db);
  const row = db.prepare('SELECT * FROM audit_log WHERE id = 1').get();

  // Independent implementation of the documented encoding: a JSON array of
  // [domain, id, prev_hash, actor, role, authenticated, method, path, status_code,
  //  action, detail, created_at]. If this ever drifts, verification of every
  // existing log breaks — which is exactly why it is pinned here.
  const canonical = JSON.stringify([
    'hatchery.audit.v1',
    row.id,
    row.prev_hash,
    row.actor,
    row.role,
    row.authenticated,
    row.method,
    row.path,
    row.status_code,
    row.action,
    row.detail,
    row.created_at,
  ]);
  const expected = createHash('sha256').update(canonical, 'utf8').digest('hex');
  assert.equal(row.entry_hash, expected);
  assert.equal(entryHash(row), expected);

  // No extra input: changing anything the hash does not cover must not change it.
  const withExtra = { ...row, token: 'secret', authorization: 'Bearer x' };
  assert.equal(entryHash(withExtra), expected);

  // And every covered field does change it.
  for (const field of ['actor', 'method', 'path', 'action', 'detail', 'created_at']) {
    assert.notEqual(
      entryHash({ ...row, [field]: `${row[field]}x` }),
      expected,
      `${field} must be part of the hash`,
    );
  }
  assert.notEqual(entryHash({ ...row, status_code: 500 }), expected);
  assert.notEqual(entryHash({ ...row, authenticated: 0 }), expected);
  assert.notEqual(entryHash({ ...row, id: row.id + 1 }), expected);
  assert.notEqual(entryHash({ ...row, prev_hash: 'f'.repeat(64) }), expected);
});

test('a modified row is detected as modified, at that row', () => {
  const db = freshDb();
  appendMany(db, 5);
  db.prepare('UPDATE audit_log SET status_code = 500 WHERE id = 3').run();

  const result = verifyAuditChain(db);
  assert.equal(result.ok, false);
  assert.equal(result.first_broken.id, 3);
  assert.equal(result.first_broken.classification, 'modified');
  assert.match(result.first_broken.detail, /no longer hashes/);
  assert.equal(result.rows_checked, 3, 'it stops at the first break rather than skipping it');
});

test('a deleted middle row is detected as deleted, at the row that no longer links', () => {
  const db = freshDb();
  appendMany(db, 5);
  db.prepare('DELETE FROM audit_log WHERE id = 3').run();

  const result = verifyAuditChain(db);
  assert.equal(result.ok, false);
  assert.equal(result.first_broken.id, 4);
  assert.equal(result.first_broken.classification, 'deleted');
  assert.match(result.first_broken.detail, /deleted/);
});

test('a row that does not link is detected as inserted', () => {
  const db = freshDb();
  appendMany(db, 3);

  // An attacker appends a row of their own with a plausible-looking but wrong
  // prev_hash, and a correctly computed hash over that wrong link.
  const bogusPrev = createHash('sha256').update('not in this chain').digest('hex');
  const info = db
    .prepare(
      `INSERT INTO audit_log (actor, role, authenticated, method, path, status_code, action, detail, created_at, prev_hash, entry_hash)
       VALUES ('admin', 'admin', 1, 'GET', '/api/secret', 200, 'request.allowed', NULL, ?, ?, NULL)`,
    )
    .run(new Date().toISOString(), bogusPrev);
  const id = Number(info.lastInsertRowid);
  const inserted = db.prepare('SELECT * FROM audit_log WHERE id = ?').get(id);
  db.prepare('UPDATE audit_log SET entry_hash = ? WHERE id = ?').run(entryHash(inserted), id);

  const result = verifyAuditChain(db);
  assert.equal(result.ok, false);
  assert.equal(result.first_broken.id, id);
  assert.equal(result.first_broken.classification, 'inserted');

  // The same conclusion when the inserted row's hash was not computed at all: the
  // link is checked first, so the classification is about causality, not the hash.
  const db2 = freshDb();
  appendMany(db2, 3);
  db2
    .prepare(
      `INSERT INTO audit_log (actor, role, authenticated, method, path, status_code, action, detail, created_at, prev_hash, entry_hash)
       VALUES ('admin', 'admin', 1, 'GET', '/api/secret', 200, 'request.allowed', NULL, ?, ?, ?)`,
    )
    .run(new Date().toISOString(), 'f'.repeat(64), 'e'.repeat(64));
  const result2 = verifyAuditChain(db2);
  assert.equal(result2.ok, false);
  assert.equal(result2.first_broken.classification, 'inserted');
});

test('deleting the last row is detected as truncation', () => {
  const db = freshDb();
  appendMany(db, 4);
  const head = auditChainMeta(db).head_id;
  db.prepare('DELETE FROM audit_log WHERE id = 4').run();

  const result = verifyAuditChain(db);
  assert.equal(result.ok, false);
  assert.equal(result.first_broken.classification, 'truncated');
  assert.equal(result.first_broken.id, Number(head));
  assert.match(result.first_broken.detail, /removed from the end/);
  assert.equal(result.head.matches_meta, false);
});

test('stripping a row\'s entry_hash is detected inside the chained region', () => {
  const db = freshDb();
  appendMany(db, 3);
  db.prepare('UPDATE audit_log SET entry_hash = NULL WHERE id = 2').run();

  const result = verifyAuditChain(db);
  assert.equal(result.ok, false);
  assert.equal(result.first_broken.id, 2);
  assert.equal(result.first_broken.classification, 'unhashed');
});

test('verification is bounded and resumable across pages', () => {
  const db = freshDb();
  appendMany(db, 10);

  const first = verifyAuditChain(db, { limitRows: 3 });
  assert.equal(first.ok, true);
  assert.equal(first.rows_checked, 3);
  assert.equal(first.complete, false);
  assert.equal(first.next_after_id, 3);

  const second = verifyAuditChain(db, { limitRows: 3, afterId: first.next_after_id });
  assert.equal(second.ok, true);
  assert.equal(second.rows_checked, 3);
  assert.equal(second.complete, false);
  assert.equal(second.next_after_id, 6);

  const third = verifyAuditChain(db, { limitRows: 3, afterId: second.next_after_id });
  assert.equal(third.rows_checked, 3);
  assert.equal(third.complete, false);
  assert.equal(third.next_after_id, 9);

  const last = verifyAuditChain(db, { limitRows: 3, afterId: third.next_after_id });
  assert.equal(last.rows_checked, 1);
  assert.equal(last.complete, true);
  assert.equal(last.ok, true);
  assert.equal(last.head.matches_meta, true);

  // A tamper inside a later page is still found when that page is checked.
  db.prepare('UPDATE audit_log SET actor = ? WHERE id = 9').run('someone-else');
  const tampered = verifyAuditChain(db, { limitRows: 3, afterId: 6 });
  assert.equal(tampered.ok, false);
  assert.equal(tampered.first_broken.id, 9);
  assert.equal(tampered.first_broken.classification, 'modified');
});

test('pre-chain rows are counted, not backfilled, and their loss is visible', () => {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  // Rows that predate D30: the columns exist in this schema but stayed NULL for
  // them, exactly as an ALTER TABLE migration leaves an existing database.
  for (let i = 0; i < 3; i += 1) {
    db.prepare(
      `INSERT INTO audit_log (actor, role, authenticated, method, path, status_code, action, detail, created_at)
       VALUES ('viewer', 'viewer', 1, 'GET', ?, 200, 'request.allowed', NULL, '2026-01-0' || ? )`,
    ).run(`/api/old/${i}`, i + 1);
  }
  initAuditChain(db); // the migration boundary is recorded here
  append(db, { path: '/api/new' });

  const result = verifyAuditChain(db);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.rows_checked, 1);
  assert.equal(result.legacy.rows, 3);
  assert.equal(result.legacy.anchor_row_count, 3);
  assert.equal(result.legacy.covered, false);
  assert.equal(result.legacy.altered, false);
  assert.equal(result.first_broken, null);

  // The new row links to genesis: the chain starts at an anchor, it does not
  // pretend to extend backwards through rows that were never hashed.
  const chained = db.prepare('SELECT id, prev_hash FROM audit_log WHERE entry_hash IS NOT NULL').all();
  assert.equal(chained.length, 1);
  assert.equal(chained[0].prev_hash, GENESIS_HASH);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM audit_log WHERE entry_hash IS NULL').get().n, 3);

  // Deleting a pre-chain row is detected, and reported as pre-chain, not skipped.
  db.prepare('DELETE FROM audit_log WHERE id = 2').run();
  const altered = verifyAuditChain(db);
  assert.equal(altered.ok, false);
  assert.equal(altered.first_broken.classification, 'deleted');
  assert.match(altered.first_broken.detail, /pre-chain rows changed/);
  assert.equal(altered.legacy.altered, true);
});

test('an append that cannot advance the chain fails loudly and writes nothing', () => {
  const db = freshDb();
  appendMany(db, 2);
  const before = countAudit(db);
  db.exec('DROP TABLE audit_chain_meta');

  // Never throws (D25: a locked database must not turn a request into a 500)...
  let returned;
  assert.doesNotThrow(() => {
    returned = recordAudit(db, { ...append0(), path: '/api/unlucky' });
  });
  // ...and reports that it could not advance, rather than pretending it did.
  assert.equal(returned, false);
  assert.equal(recordAudit(db, { ...append0(), path: '/api/unlucky-2' }), false);
  // ...and the failed append is rolled back, so the log is not left with an
  // unchained hole that verification would have to guess about.
  assert.equal(countAudit(db), before);
  const rows = db.prepare('SELECT COUNT(*) AS n FROM audit_log WHERE entry_hash IS NULL').get();
  assert.equal(rows.n, 0);
});

function append0() {
  return {
    actor: 'admin',
    role: 'admin',
    authenticated: true,
    method: 'GET',
    path: '/api/x',
    statusCode: 200,
    action: 'request.allowed',
  };
}

test('listing returns the chain columns and never reorders rows', () => {
  const db = freshDb();
  appendMany(db, 3);
  const rows = listAudit(db, { limit: 10 });
  assert.equal(rows.length, 3);
  assert.equal(rows[0].id, 3, 'newest first');
  assert.match(rows[0].entry_hash, /^[0-9a-f]{64}$/);
  assert.match(rows[0].prev_hash, /^[0-9a-f]{64}$/);
  assert.equal(rows[0].prev_hash, rows[1].entry_hash);
});

test('concurrent appends inside one process still produce one chain', () => {
  const db = freshDb();
  // better-sqlite3 is synchronous, so this pins the transaction: interleaved
  // callers (a hook, a route, the CLI helper) cannot both read the same head.
  for (let i = 0; i < 50; i += 1) {
    append(db, { path: `/api/burst/${i}` });
  }
  const result = verifyAuditChain(db);
  assert.equal(result.ok, true);
  assert.equal(result.rows_checked, 50);

  const duplicatePrev = db
    .prepare('SELECT prev_hash, COUNT(*) AS n FROM audit_log GROUP BY prev_hash HAVING n > 1')
    .all();
  assert.deepEqual(duplicatePrev, [], 'no two rows may share a prev_hash (that would be a fork)');
});
