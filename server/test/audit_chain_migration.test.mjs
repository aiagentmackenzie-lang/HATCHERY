/**
 * Migrating a pre-D30 database onto the audit hash chain (D30).
 *
 * The policy under test: existing `audit_log` rows are **not** backfilled and are
 * **not** claimed to be tamper-evident. The columns are added additively, the
 * migration records the pre-chain boundary once (`legacy_row_count`), and the chain
 * starts at the documented genesis anchor with the first row written after the
 * upgrade. The server must start, keep every old row, and verify honestly.
 *
 * This file is separate because `dist/db/index.js` resolves its database path once
 * per process; the migration has to be exercised through the real startup path
 * with `HATCHERY_DB_PATH` set before the import.
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');

/** A database as the pre-D30 schema left it: an audit table with no hash columns. */
function buildPreD30Database(dbPath) {
  const db = new Database(dbPath);
  db.exec(`
    CREATE TABLE audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT NOT NULL DEFAULT 'anonymous',
        role TEXT NOT NULL DEFAULT 'anonymous',
        authenticated INTEGER NOT NULL DEFAULT 0,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        status_code INTEGER,
        action TEXT,
        detail TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_audit_created ON audit_log(created_at);
    CREATE INDEX idx_audit_actor ON audit_log(actor);
  `);
  const insert = db.prepare(
    `INSERT INTO audit_log (actor, role, authenticated, method, path, status_code, action, detail, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  insert.run('admin', 'admin', 1, 'GET', '/api/tasks', 200, 'request.allowed', null, '2026-10-01 10:00:00');
  insert.run('viewer', 'viewer', 1, 'POST', '/api/submit', 403, 'request.forbidden', 'requires admin', '2026-10-01 10:00:01');
  insert.run('unknown', 'anonymous', 0, 'GET', '/api/audit', 401, 'auth.denied', 'missing or invalid token', '2026-10-01 10:00:02');
  db.close();
}

test('a pre-D30 database keeps its rows, anchors the chain and verifies honestly', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-migrate-'));
  const dbPath = path.join(dir, 'pre-d30.db');
  buildPreD30Database(dbPath);

  // The server's real startup path: schema, additive migration, chain anchor.
  process.env.HATCHERY_DB_PATH = dbPath;
  const { getDb } = await import('../dist/db/index.js');
  const { auditChainMeta, verifyAuditChain } = await import('../dist/security/audit.js');
  const { recordAudit } = await import('../dist/security/audit.js');

  const db = getDb();

  // Columns are added; no row is rewritten.
  const columns = db.prepare('PRAGMA table_info(audit_log)').all().map((column) => column.name);
  assert.ok(columns.includes('prev_hash'));
  assert.ok(columns.includes('entry_hash'));

  const legacyRows = db
    .prepare('SELECT id, actor, path, entry_hash, prev_hash FROM audit_log ORDER BY id')
    .all();
  assert.equal(legacyRows.length, 3, 'no pre-D30 row may be lost');
  for (const row of legacyRows) {
    assert.equal(row.entry_hash, null, 'old rows are not backfilled into the chain');
    assert.equal(row.prev_hash, null);
  }

  // The boundary is recorded once so a later deletion of a pre-chain row is
  // visible instead of being silently absorbed by the count.
  const meta = auditChainMeta(db);
  assert.equal(meta.chain_version, '1');
  assert.equal(meta.legacy_row_count, '3');
  assert.equal(meta.legacy_max_id, '3');
  assert.equal(meta.head_id, undefined, 'nothing is chained yet');

  // Verification before any new row: nothing chained, legacy reported, not "ok
  // because there is nothing to check".
  const before = verifyAuditChain(db);
  assert.equal(before.rows_checked, 0);
  assert.equal(before.legacy.rows, 3);
  assert.equal(before.legacy.covered, false);
  assert.equal(before.legacy.altered, false);
  assert.equal(before.first_broken, null);

  // The first post-migration row starts the chain at the documented anchor.
  assert.equal(
    recordAudit(db, {
      actor: 'admin',
      role: 'admin',
      authenticated: true,
      method: 'GET',
      path: '/api/tokens',
      statusCode: 200,
      action: 'request.allowed',
    }),
    true,
  );
  const first = db.prepare('SELECT id, prev_hash, entry_hash FROM audit_log WHERE id = 4').get();
  assert.match(first.entry_hash, /^[0-9a-f]{64}$/);
  assert.equal(first.prev_hash, '0'.repeat(64));

  const after = verifyAuditChain(db);
  assert.equal(after.ok, true, JSON.stringify(after));
  assert.equal(after.rows_checked, 1);
  assert.equal(after.legacy.rows, 3);
  assert.equal(after.legacy.anchor_row_count, 3);
  assert.equal(after.head.matches_meta, true);

  // Re-running the migration (any later startup, and any CLI invocation) must not
  // move the anchor or re-hash anything.
  const cli = spawnSync(process.execPath, ['scripts/token.mjs', 'list'], {
    cwd: serverRoot,
    env: { ...process.env, HATCHERY_DB_PATH: dbPath },
    encoding: 'utf-8',
  });
  assert.equal(cli.status, 0, cli.stderr);
  const again = auditChainMeta(db);
  assert.equal(again.legacy_row_count, '3');
  assert.equal(again.chain_first_id, '4');
  assert.equal(again.head_id, '4');
  assert.equal(verifyAuditChain(db).ok, true);
});

test('a pre-D30 database with rows starts the real server and verifies over HTTP', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-migrate-http-'));
  const dbPath = path.join(dir, 'pre-d30.db');
  buildPreD30Database(dbPath);

  // One chained row written by the CLI's own database path, then the server boots
  // against the same file.
  const created = spawnSync(
    process.execPath,
    ['scripts/token.mjs', 'create', '--role', 'admin', '--json'],
    {
      cwd: serverRoot,
      env: { ...process.env, HATCHERY_DB_PATH: dbPath },
      encoding: 'utf-8',
    },
  );
  assert.equal(created.status, 0, created.stderr);
  const admin = JSON.parse(created.stdout);

  const port = 61000 + Math.floor(Math.random() * 3000);
  const baseUrl = `http://127.0.0.1:${port}`;
  const proc = spawn(process.execPath, ['dist/index.js'], {
    cwd: serverRoot,
    env: {
      ...process.env,
      HATCHERY_PORT: String(port),
      HATCHERY_HOST: '127.0.0.1',
      HATCHERY_DB_PATH: dbPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  proc.stdout.on('data', (chunk) => {
    output += chunk.toString();
  });
  proc.stderr.on('data', (chunk) => {
    output += chunk.toString();
  });

  try {
    const deadline = Date.now() + 25000;
    let healthy = false;
    while (Date.now() < deadline && !healthy) {
      try {
        healthy = (await fetch(`${baseUrl}/api/health`)).ok;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
    }
    assert.ok(healthy, `server did not start on a pre-D30 database:\n${output}`);

    const response = await fetch(`${baseUrl}/api/audit/verify`, {
      headers: { authorization: `Bearer ${admin.token}` },
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.legacy.rows, 3);
    assert.equal(result.legacy.covered, false);
    assert.equal(result.legacy.anchor_row_count, 3);
    assert.equal(result.rows_checked, 1, 'the CLI write is the only chained row so far');

    // The old rows are still readable through the normal endpoint.
    const audit = await (
      await fetch(`${baseUrl}/api/audit?limit=10`, {
        headers: { authorization: `Bearer ${admin.token}` },
      })
    ).json();
    // 3 pre-chain rows, the CLI write, this verify's own audit row and its request
    // row: every new row is chained, the old ones are only counted.
    assert.equal(audit.count, 6);
    assert.ok(audit.entries.some((entry) => entry.path === '/api/submit'));
  } finally {
    proc.kill('SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 300));
    if (proc.exitCode === null) proc.kill('SIGKILL');
  }
});
