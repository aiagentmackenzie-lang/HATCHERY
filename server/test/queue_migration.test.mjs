/**
 * The D27 migration is additive and test-covered.
 *
 * A database created before the queue has no `queue_job_id` column. `CREATE TABLE
 * IF NOT EXISTS` will not add it, so the server must ALTER it in on startup or
 * every insert naming the column fails at runtime. This boots the real built
 * server against a hand-built pre-queue database and asserts the column exists.
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');

async function waitForHealth(baseUrl, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/api/health`);
      if (response.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return false;
}

test('a database created before the queue gains the queue_job_id column', async () => {
  const port = 40000 + Math.floor(Math.random() * 10000);
  const baseUrl = `http://127.0.0.1:${port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-queue-migrate-'));
  const dbPath = path.join(dir, 'old.db');

  // Build the pre-D27 tasks table by hand: no queue_job_id.
  const old = new Database(dbPath);
  old.exec(`
    CREATE TABLE tasks (
      task_id TEXT PRIMARY KEY,
      file_name TEXT NOT NULL,
      file_path TEXT NOT NULL,
      file_size INTEGER NOT NULL DEFAULT 0,
      md5 TEXT, sha1 TEXT, sha256 TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      static_done INTEGER NOT NULL DEFAULT 0,
      sandbox_done INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      completed_at TEXT,
      error_message TEXT
    );
    CREATE TABLE static_results (task_id TEXT PRIMARY KEY);
    CREATE TABLE sandbox_results (task_id TEXT PRIMARY KEY);
  `);
  old.close();

  const child = spawn(process.execPath, ['dist/index.js'], {
    cwd: serverRoot,
    env: {
      ...process.env,
      HATCHERY_PORT: String(port),
      HATCHERY_HOST: '127.0.0.1',
      HATCHERY_DB_PATH: dbPath,
      HATCHERY_QUEUE_DB: path.join(dir, 'queue.db'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    assert.ok(await waitForHealth(baseUrl), 'server did not start against the old database');
    const migrated = new Database(dbPath, { readonly: true });
    const columns = migrated.prepare('PRAGMA table_info(tasks)').all();
    migrated.close();
    assert.ok(
      columns.some((column) => column.name === 'queue_job_id'),
      `queue_job_id missing after migration: ${columns.map((c) => c.name).join(', ')}`,
    );
  } finally {
    child.kill('SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 200));
    if (!child.killed) child.kill('SIGKILL');
  }
});
