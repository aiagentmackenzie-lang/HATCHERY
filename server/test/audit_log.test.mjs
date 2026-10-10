/**
 * Audit log tests (D25).
 *
 * What is stored matters, but so does what is not: no token, no header, no body.
 * These pin both the rows and the shape of the table.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';

import { countAudit, listAudit, recordAudit, shouldAudit } from '../dist/security/audit.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.join(here, '..', 'src', 'db', 'schema.sql');

function freshDb() {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  return db;
}

test('schema declares the audit_log table', () => {
  const db = freshDb();
  const columns = db.prepare('PRAGMA table_info(audit_log)').all().map((c) => c.name);
  assert.ok(columns.includes('actor'));
  assert.ok(columns.includes('role'));
  assert.ok(columns.includes('authenticated'));
  assert.ok(columns.includes('status_code'));
  assert.ok(columns.includes('action'));
});

test('the audit table has no column that could hold a credential or a body', () => {
  const db = freshDb();
  const columns = db.prepare('PRAGMA table_info(audit_log)').all().map((c) => c.name);
  for (const forbidden of ['token', 'authorization', 'headers', 'body', 'payload', 'secret']) {
    assert.ok(!columns.includes(forbidden), `audit_log must not store ${forbidden}`);
  }
});

test('recordAudit writes a row and listAudit returns it newest first', () => {
  const db = freshDb();
  recordAudit(db, {
    actor: 'admin', role: 'admin', authenticated: true,
    method: 'POST', path: '/api/submit', statusCode: 202, action: 'request.allowed',
  });
  recordAudit(db, {
    actor: 'viewer', role: 'viewer', authenticated: true,
    method: 'POST', path: '/api/submit', statusCode: 403, action: 'request.forbidden',
    detail: 'requires admin',
  });
  const rows = listAudit(db);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].actor, 'viewer');
  assert.equal(rows[0].status_code, 403);
  assert.equal(rows[1].action, 'request.allowed');
  assert.equal(countAudit(db), 2);
});

test('listAudit honours the limit and the actor filter', () => {
  const db = freshDb();
  for (let i = 0; i < 5; i += 1) {
    recordAudit(db, {
      actor: i % 2 === 0 ? 'admin' : 'viewer', role: 'admin', authenticated: true,
      method: 'GET', path: `/api/x/${i}`, statusCode: 200, action: 'request.allowed',
    });
  }
  assert.equal(listAudit(db, { limit: 2 }).length, 2);
  assert.equal(listAudit(db, { actor: 'viewer' }).length, 2);
  assert.equal(listAudit(db, { actor: 'nobody' }).length, 0);
});

test('an unauthenticated request is recorded as such, not as an admin action', () => {
  const db = freshDb();
  recordAudit(db, {
    actor: 'unknown', role: 'anonymous', authenticated: false,
    method: 'GET', path: '/api/audit', statusCode: 401, action: 'auth.denied',
  });
  const row = listAudit(db)[0];
  assert.equal(row.authenticated, 0);
  assert.equal(row.role, 'anonymous');
  assert.equal(row.action, 'auth.denied');
});

test('detail is truncated and audit never throws when the table is missing', () => {
  const db = new Database(':memory:');
  // no schema: the table does not exist, and recordAudit must swallow the error
  assert.doesNotThrow(() =>
    recordAudit(db, {
      actor: 'x', role: 'anonymous', authenticated: false,
      method: 'GET', path: '/x', statusCode: 200, action: 'request.allowed',
      detail: 'y'.repeat(1000),
    }),
  );

  const good = freshDb();
  recordAudit(good, {
    actor: 'x', role: 'anonymous', authenticated: false,
    method: 'GET', path: '/x', statusCode: 200, action: 'request.allowed',
    detail: 'y'.repeat(1000),
  });
  assert.ok((listAudit(good)[0].detail ?? '').length <= 300);
});

test('health and websocket are not audited', () => {
  assert.equal(shouldAudit('/api/health'), false);
  assert.equal(shouldAudit('/ws'), false);
  assert.equal(shouldAudit('/api/submit'), true);
  assert.equal(shouldAudit('/api/report?task=x'), true);
});
