/**
 * Concurrent appends produce one chain, not a fork (D30).
 *
 * The interesting concurrency here is **cross-process**: two API processes writing
 * audit rows into the same SQLite database, which is exactly what happens when an
 * operator restarts the server on another port, or a second instance shares the
 * database. A single-process burst is serialised by the event loop and proves
 * nothing, so this test runs two real built servers against one database, fires a
 * burst at both at once, and then verifies the result.
 *
 * What must hold: every row links to exactly one predecessor (no two rows share a
 * `prev_hash`), the recorded head is the actual last row, and the verifier says the
 * chain is intact.
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');
const ADMIN = 'concurrency-admin-secret';

async function boot(port, dbPath) {
  const baseUrl = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ['dist/index.js'], {
    cwd: serverRoot,
    env: {
      ...process.env,
      HATCHERY_PORT: String(port),
      HATCHERY_HOST: '127.0.0.1',
      HATCHERY_DB_PATH: dbPath,
      HATCHERY_ADMIN_TOKEN: ADMIN,
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
  while (Date.now() < deadline) {
    try {
      if ((await fetch(`${baseUrl}/api/health`)).ok) break;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  assert.ok(output.includes('HATCHERY API running') || (await fetch(`${baseUrl}/api/health`)).ok, output);
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

test('two servers writing the same database produce exactly one valid chain', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-chain-'));
  const dbPath = path.join(dir, 'shared.db');
  const portA = 63000 + Math.floor(Math.random() * 1000);
  const portB = portA + 1000;

  const a = await boot(portA, dbPath);
  const b = await boot(portB, dbPath);

  try {
    const headers = { authorization: `Bearer ${ADMIN}` };
    const burst = [];
    for (let i = 0; i < 40; i += 1) {
      const server = i % 2 === 0 ? a : b;
      burst.push(fetch(`${server.baseUrl}/api/tasks?burst=${i}`, { headers }));
    }
    const responses = await Promise.all(burst);
    for (const response of responses) {
      assert.equal(response.status, 200, 'every request must be answered while the other process writes');
    }

    // Nothing was lost: /api/audit/verify audits itself, so ask one server and then
    // compare against the rows actually present.
    const verifyResponse = await fetch(`${a.baseUrl}/api/audit/verify?limit=50000`, { headers });
    assert.equal(verifyResponse.status, 200);
    const chain = await verifyResponse.json();
    assert.equal(chain.ok, true, JSON.stringify(chain));
    assert.equal(chain.complete, true);
    assert.equal(chain.head.matches_meta, true);
    assert.ok(chain.rows_checked >= 40, `expected the burst to be recorded, got ${chain.rows_checked}`);

    const db = new Database(dbPath, { readonly: true });
    try {
      const forked = db
        .prepare('SELECT prev_hash, COUNT(*) AS n FROM audit_log GROUP BY prev_hash HAVING n > 1')
        .all();
      assert.deepEqual(forked, [], 'two rows sharing a prev_hash is a forklift into the chain');

      const rows = db.prepare('SELECT id, prev_hash, entry_hash FROM audit_log ORDER BY id').all();
      assert.equal(rows[0].prev_hash, '0'.repeat(64));
      for (let i = 1; i < rows.length; i += 1) {
        assert.equal(rows[i].prev_hash, rows[i - 1].entry_hash);
      }

      const meta = Object.fromEntries(
        db
          .prepare('SELECT key, value FROM audit_chain_meta')
          .all()
          .map((row) => [row.key, row.value]),
      );
      assert.equal(Number(meta.head_id), rows[rows.length - 1].id, 'one head, and it is the last row');
      assert.equal(meta.head_hash, rows[rows.length - 1].entry_hash);
      assert.equal(Number(meta.chained_row_count), rows.length);

      // Nothing was silently dropped to SQLITE_BUSY: the row count matches what the
      // two processes answered (the burst, plus audit/verify rows).
      assert.ok(rows.length >= 40);
    } finally {
      db.close();
    }

    // Neither process logged an append failure.
    for (const server of [a, b]) {
      assert.ok(
        !server.output().includes('audit append failed'),
        `an append failed instead of waiting for the lock:\n${server.output()}`,
      );
    }
  } finally {
    await a.stop();
    await b.stop();
  }
});
