/**
 * Compaction crash-resume, concurrency and the failed-append path (D32).
 *
 * A retention feature that can lose evidence when it is interrupted is worse than no
 * retention at all. These tests interrupt a real compaction at each step, prove that a
 * second run completes it without double-archiving or losing a row, run a real burst of
 * appends against a real server *while* a real `compact` runs, and prove that a failed
 * audit append neither 500s the request nor disappears from the report.
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';

import {
  configureAuditKeyring,
  initAuditChain,
  recordAudit,
} from '../dist/security/audit.js';
import { resolveAuditKeyring } from '../dist/security/auditKey.js';
import { compactAudit, resolveRetentionPolicy } from '../dist/security/auditCompaction.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');
const schemaPath = path.join(here, '..', 'src', 'db', 'schema.sql');

function tempRoot(prefix = 'hatchery-resume-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function nestedDb(root) {
  return path.join(root, 'data', 'hatchery.db');
}

function cli(dbPath, args) {
  return spawnSync(process.execPath, [`scripts/${args[0]}.mjs`, ...args.slice(1)], {
    cwd: serverRoot,
    env: { ...process.env, HATCHERY_DB_PATH: dbPath },
    encoding: 'utf-8',
    timeout: 120000,
  });
}

function cliJson(dbPath, args) {
  const result = cli(dbPath, [...args, '--json']);
  assert.equal(result.status, 0, `${args.join(' ')} failed: ${result.stderr}`);
  return JSON.parse(result.stdout);
}

function seed(dbPath, count, label = 'row') {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });
  const ring = resolveAuditKeyring(dbPath);
  configureAuditKeyring(ring);
  const db = new Database(dbPath);
  try {
    db.pragma('journal_mode = WAL');
    db.pragma('busy_timeout = 5000');
    db.exec(fs.readFileSync(schemaPath, 'utf-8'));
    initAuditChain(db);
    for (let index = 0; index < count; index += 1) {
      assert.equal(
        recordAudit(db, {
          actor: 'operator:cli',
          role: 'admin',
          authenticated: false,
          method: 'CLI',
          path: `/seed/${label}/${index}`,
          statusCode: null,
          action: 'token.created',
          detail: `row ${index}`,
        }),
        true,
      );
    }
  } finally {
    db.close();
  }
  return ring;
}

function open(dbPath) {
  const ring = resolveAuditKeyring(dbPath);
  configureAuditKeyring(ring);
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  return db;
}

function meta(dbPath) {
  const db = new Database(dbPath, { readonly: true });
  try {
    return Object.fromEntries(
      db.prepare('SELECT key, value FROM audit_chain_meta').all().map((row) => [row.key, row.value]),
    );
  } finally {
    db.close();
  }
}

function rows(dbPath) {
  const db = new Database(dbPath, { readonly: true });
  try {
    return db.prepare('SELECT id, entry_hash FROM audit_log ORDER BY id').all();
  } finally {
    db.close();
  }
}

function archiveDir(dbPath) {
  return path.join(path.dirname(dbPath), 'audit-archives');
}

function archiveNames(dbPath) {
  const dir = archiveDir(dbPath);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).sort();
}

function allIds(dbPath) {
  const live = rows(dbPath).map((row) => row.id);
  const archived = [];
  for (const name of archiveNames(dbPath)) {
    if (!name.endsWith('.jsonl') && !name.endsWith('.jsonl.gz')) continue;
    const text = fs.readFileSync(path.join(archiveDir(dbPath), name), 'utf8');
    for (const line of text.split('\n')) {
      if (line.trim()) archived.push(JSON.parse(line).id);
    }
  }
  return { live, archived };
}

/**
 * Every id that existed before must still exist, exactly once, in the live segment or
 * an archive. The only id that may be new is the `audit.compacted` record itself.
 */
function assertNoRowLost(dbPath, before) {
  const after = allIds(dbPath);
  const all = [...after.live, ...after.archived];
  assert.equal(new Set(all).size, all.length, 'a row appears in both chains — double-archived');
  for (const id of before) {
    assert.ok(all.includes(id), `row ${id} was lost by the compaction`);
  }
  const extra = all.filter((id) => !before.includes(id));
  if (extra.length > 0) {
    assert.equal(extra.length, 1, `unexpected new rows: ${extra.join(', ')}`);
    const db = new Database(dbPath, { readonly: true });
    const row = db.prepare('SELECT action FROM audit_log WHERE id = ?').get(extra[0]);
    db.close();
    if (row) assert.equal(row.action, 'audit.compacted');
  }
  return extra;
}

async function bootServer(dbPath, env = {}) {
  const port = 55000 + Math.floor(Math.random() * 4000);
  const baseUrl = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['dist/index.js'], {
    cwd: serverRoot,
    env: {
      ...process.env,
      HATCHERY_PORT: String(port),
      HATCHERY_HOST: '127.0.0.1',
      HATCHERY_DB_PATH: dbPath,
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (chunk) => {
    output += chunk.toString();
  });
  child.stderr.on('data', (chunk) => {
    output += chunk.toString();
  });
  const deadline = Date.now() + 25000;
  let up = false;
  while (Date.now() < deadline && !up) {
    try {
      up = (await fetch(`${baseUrl}/api/health`)).ok;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 150));
    }
  }
  assert.ok(up, `server did not start:\n${output}`);
  return {
    baseUrl,
    output: () => output,
    async stop() {
      if (child.exitCode !== null) return;
      child.kill('SIGTERM');
      const exited = await new Promise((resolve) => {
        const timer = setTimeout(() => resolve(false), 3000);
        child.once('exit', () => {
          clearTimeout(timer);
          resolve(true);
        });
      });
      if (!exited) child.kill('SIGKILL');
    },
  };
}

/** Interrupt a compaction at a named step, the way a kill or a power cut would. */
function crashAt(dbPath, step, policy) {
  const db = open(dbPath);
  try {
    return compactAudit(db, {
      dbPath,
      policy,
      apply: true,
      hooks: (current) => {
        if (current === step) throw new Error(`simulated crash at ${step}`);
      },
    });
  } catch (error) {
    assert.match(String(error.message), /simulated crash/);
    return null;
  } finally {
    db.close();
  }
}

// ---------------------------------------------------------------------------

test('an interruption after the archive is written resumes without duplicating or losing a row', () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  seed(dbPath, 30);
  const policy = resolveRetentionPolicy({ maxRows: 10 });
  const before = rows(dbPath).map((row) => row.id);

  assert.equal(crashAt(dbPath, 'archive-written', policy), null);

  // The archive exists, the manifest does not (it is written last), and not one row
  // was deleted: the interrupted run is not a half-archived segment.
  assert.equal(rows(dbPath).length, 30);
  const names = archiveNames(dbPath);
  assert.equal(names.filter((name) => name.endsWith('.jsonl')).length, 1);
  assert.equal(names.filter((name) => name.endsWith('.manifest.json')).length, 0);
  assert.equal(meta(dbPath).archive_segments, undefined);

  // A second run completes it. The archive it finds is byte-identical and is reused,
  // not rewritten — so the evidence keeps the hash the first attempt gave it.
  const resumed = cliJson(dbPath, ['audit', 'compact', '--max-rows', '10', '--apply']);
  assert.equal(resumed.applied, true);
  assert.equal(resumed.archive.reused, true);
  assert.equal(resumed.resumed, true);

  assertNoRowLost(dbPath, before);
  assert.equal(allIds(dbPath).live.length, 10);
  assert.equal(cliJson(dbPath, ['audit', 'verify']).ok, true);
});

test('an interruption after the manifest is written resumes with the same manifest hash', () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  seed(dbPath, 24);
  const policy = resolveRetentionPolicy({ maxRows: 8 });
  const before = rows(dbPath).map((row) => row.id);

  assert.equal(crashAt(dbPath, 'manifest-written', policy), null);
  assert.equal(rows(dbPath).length, 24);

  const names = archiveNames(dbPath);
  const manifestName = names.find((name) => name.endsWith('.manifest.json'));
  assert.ok(manifestName, 'the manifest was written last');
  const manifestPath = path.join(archiveDir(dbPath), manifestName);
  const manifestHash = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const recordedTail = manifestHash.tail.entry_hash;

  const resumed = cliJson(dbPath, ['audit', 'compact', '--max-rows', '8', '--apply']);
  assert.equal(resumed.applied, true);
  assert.equal(resumed.manifest.reused, true);
  assert.equal(resumed.tail.entry_hash, recordedTail);

  // Exactly one archive and one manifest: a resume must not double-archive.
  assert.equal(archiveNames(dbPath).filter((name) => name.endsWith('.jsonl')).length, 1);
  assert.equal(archiveNames(dbPath).filter((name) => name.endsWith('.manifest.json')).length, 1);

  assertNoRowLost(dbPath, before);
  assert.equal(cliJson(dbPath, ['audit', 'verify']).ok, true);
});

test('an interruption inside the delete transaction rolls back and leaves no gap', () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  seed(dbPath, 18);
  const policy = resolveRetentionPolicy({ maxRows: 6 });
  const before = rows(dbPath).map((row) => row.id);

  assert.equal(crashAt(dbPath, 'row-appended', policy), null);

  // The transaction rolled back: every row is still there and the compaction record
  // was not written either. Nothing is half-deleted.
  assert.deepEqual(rows(dbPath).map((row) => row.id), before);
  const db = new Database(dbPath, { readonly: true });
  const compactionRows = db
    .prepare("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'audit.compacted'")
    .get().n;
  db.close();
  assert.equal(compactionRows, 0);

  const resumed = cliJson(dbPath, ['audit', 'compact', '--max-rows', '6', '--apply']);
  assert.equal(resumed.applied, true);
  assertNoRowLost(dbPath, before);
  assert.equal(cliJson(dbPath, ['audit', 'verify']).ok, true);
});

test('a concurrent append burst during a compaction produces one valid chain and loses nothing', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  seed(dbPath, 40);
  const server = await bootServer(dbPath);
  const BURST = 30;

  try {
    const before = meta(dbPath);
    const beforeTotal = Number(before.chained_rows_total);
    const beforeFailures = Number(before.append_failure_total ?? '0');

    const requests = Array.from({ length: BURST }, () => fetch(`${server.baseUrl}/api/tasks`));
    const compaction = Promise.resolve().then(() =>
      cliJson(dbPath, ['audit', 'compact', '--max-rows', '5', '--apply']),
    );

    const responses = await Promise.all(requests);
    const compacted = await compaction;
    assert.equal(compacted.applied, true);
    for (const response of responses) assert.equal(response.status, 200);

    // Every request was answered; wait for the last onResponse appends to land.
    const deadline = Date.now() + 15000;
    let after = meta(dbPath);
    while (
      Number(after.chained_rows_total) - beforeTotal < BURST &&
      Date.now() < deadline
    ) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      after = meta(dbPath);
    }

    const gained = Number(after.chained_rows_total) - beforeTotal;
    const failuresGained = Number(after.append_failure_total ?? '0') - beforeFailures;
    // One row per answered request, plus the `audit.compacted` row. If any append was
    // lost it is in the failure count, never silently missing.
    assert.equal(gained + failuresGained, BURST + 1, `gained=${gained} failures=${failuresGained}`);

    const report = cliJson(dbPath, ['audit', 'verify']);
    assert.equal(report.ok, true, JSON.stringify(report.first_broken));
    assert.equal(report.archive.checked, true);
    assert.equal(report.archive.join, 'proven');
    assert.equal(
      Number(after.chained_rows_total),
      rows(dbPath).length + Number(after.archived_row_total),
    );
  } finally {
    await server.stop();
  }
});

test('a failed audit append does not fail the request, and the count survives a restart', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  seed(dbPath, 12);
  const server = await bootServer(dbPath);

  try {
    // Simulate a storage failure that is not "busy": every insert into audit_log
    // aborts. The database itself stays readable, so the failure can be persisted.
    const db = new Database(dbPath);
    db.exec(
      "CREATE TRIGGER audit_boom BEFORE INSERT ON audit_log BEGIN " +
        "SELECT RAISE(ABORT, 'simulated disk full'); END;",
    );
    db.close();

    const response = await fetch(`${server.baseUrl}/api/tasks`);
    assert.equal(response.status, 200, 'D25: a failed audit append must not 500 the request');

    const deadline = Date.now() + 10000;
    let counts = meta(dbPath);
    while (Number(counts.append_failure_total ?? '0') < 1 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      counts = meta(dbPath);
    }
    assert.ok(Number(counts.append_failure_total) >= 1, 'the failure is recorded, not dropped');

    const repair = new Database(dbPath);
    repair.exec('DROP TRIGGER audit_boom');
    repair.close();
  } finally {
    await server.stop();
  }

  // A fresh process (the CLI) sees the persisted total and no failures *of its own*:
  // the counter is no longer forgotten by a restart.
  const report = cliJson(dbPath, ['audit', 'verify']);
  assert.equal(report.append_failures_since_start, 0);
  assert.ok(report.append_failures_total >= 1, JSON.stringify(report));
  assert.equal(report.append_failures_persisted, true);
  // The request that failed to be audited left a hole the chain cannot see; the count
  // is how the operator learns about it. Nothing was deleted to hide it.
  assert.equal(report.ok, true);
});
