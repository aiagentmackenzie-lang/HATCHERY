/**
 * A credential is not an unlimited budget (D43).
 *
 * D25/D30 answer "may this caller act?"; D41/D42 answer "what may a sample be?".
 * Neither answers "how much". Before this, an authenticated token could fill the
 * disk with accepted 256 MiB samples or queue work without bound, and the only cost
 * was patience.
 *
 * The ordering is the substance of the slice, so it is what these tests assert: a
 * submission **reserves the largest sample it could send before the body is read**,
 * and settles to the real size afterwards. A byte quota checked after the write is
 * the same defect D40 fixed one layer down. The stand-in engine records every
 * invocation, so "refused before the read" is proved by the log not growing — not
 * by a response that merely looks fast.
 *
 * The counters live in the API's SQLite database, so one test restarts the real
 * server and shows the budget survived; a test that only builds a second Fastify
 * instance would prove `getDb()` is a singleton, not that the budget is durable.
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';
import Fastify from 'fastify';
import multipart from '@fastify/multipart';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');

const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-admission-'));
const uploadsDir = path.join(workDir, 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });
const engineLog = path.join(workDir, 'engine.log');

process.env.HATCHERY_UPLOADS_DIR = uploadsDir;
process.env.HATCHERY_DB_PATH = path.join(workDir, 'hatchery.db');
process.env.HATCHERY_QUEUE_DB = path.join(workDir, 'queue.db');
process.env.HATCHERY_ENGINE_PYTHON = path.join(serverRoot, 'fixtures', 'fake-engine.mjs');
process.env.HATCHERY_TEST_ENGINE_LOG = engineLog;

const { MAX_UPLOAD_BYTES, submitRoutes } = await import('../dist/routes/submit.js');
const { readLimits } = await import('../dist/security/admission.js');

const BOUNDARY = 'HATCHERYADMIT';

function limits({ requests = 0, bytes = 0, jobs = 0, window = 600 } = {}) {
  process.env.HATCHERY_ADMIT_RATE = String(requests);
  process.env.HATCHERY_ADMIT_BYTES = String(bytes);
  process.env.HATCHERY_ADMIT_JOBS = String(jobs);
  process.env.HATCHERY_ADMIT_WINDOW = String(window);
  // readLimits() is called per request on purpose: an operator changes these with a
  // restart, and a test must be able to change them between cases.
  assert.deepEqual(readLimits(), {
    windowSeconds: window,
    requests,
    bytes,
    jobs,
  });
}

function multipartBody(data, filename = 'sample.bin') {
  return Buffer.concat([
    Buffer.from(
      `--${BOUNDARY}\r\n` +
        `Content-Disposition: form-data; name="sample"; filename="${filename}"\r\n` +
        'Content-Type: application/octet-stream\r\n\r\n',
    ),
    data,
    Buffer.from(`\r\n--${BOUNDARY}--\r\n`),
  ]);
}

async function withApp(run) {
  const app = Fastify({ logger: false });
  await app.register(multipart, { limits: { fileSize: MAX_UPLOAD_BYTES, files: 1, parts: 8 } });
  await app.register(submitRoutes);
  await app.listen({ port: 0, host: '127.0.0.1' });
  const address = app.server.address();
  try {
    return await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await app.close();
  }
}

async function submit(baseUrl, data = Buffer.from('MZ admission test')) {
  return fetch(`${baseUrl}/api/submit`, {
    method: 'POST',
    headers: { 'content-type': `multipart/form-data; boundary=${BOUNDARY}` },
    body: multipartBody(data),
    signal: AbortSignal.timeout(20000),
  });
}

function taskCount() {
  if (!fs.existsSync(process.env.HATCHERY_DB_PATH)) return 0;
  const db = new Database(process.env.HATCHERY_DB_PATH, { readonly: true, fileMustExist: true });
  try {
    return Number((db.prepare('SELECT COUNT(*) AS n FROM tasks').get() ?? { n: 0 }).n);
  } finally {
    db.close();
  }
}

function engineInvocations() {
  if (!fs.existsSync(engineLog)) return 0;
  return fs.readFileSync(engineLog, 'utf-8').trim().split('\n').filter(Boolean).length;
}

// ---------------------------------------------------------------------------
// 1. The three limits
// ---------------------------------------------------------------------------

test('the request rate is per caller, refused with Retry-After, and recorded', { timeout: 40000 }, async () => {
  limits({ requests: 2, window: 600 });

  await withApp(async (baseUrl) => {
    assert.equal((await submit(baseUrl)).status, 200);
    assert.equal((await submit(baseUrl)).status, 200);

    const refused = await submit(baseUrl);
    assert.equal(refused.status, 429);
    const retryAfter = Number(refused.headers.get('retry-after'));
    assert.ok(retryAfter > 0 && retryAfter <= 600, `Retry-After was ${refused.headers.get('retry-after')}`);

    const body = await refused.json();
    assert.equal(body.reason, 'admission-rate');
    assert.equal(body.limit, 2);
    assert.equal(body.used, 2);
    assert.equal(body.window_seconds, 600);
    assert.equal(body.retry_after, retryAfter);
    assert.match(
      String(refused.headers.get('x-hatchery-admission')),
      /^rate 2\/2$/,
      'the refusal must name the limit it hit',
    );
  });
});

test('a byte budget refuses before the body is read, not after it is stored', { timeout: 40000 }, async () => {
  // The reservation is the upload limit, so a 1 KiB byte budget refuses the very
  // first submission — and the engine is never asked to store anything.
  limits({ bytes: 1024 });

  const before = engineInvocations();
  const tasksBefore = taskCount();

  await withApp(async (baseUrl) => {
    const refused = await submit(baseUrl, Buffer.alloc(64 * 1024, 0x41));
    assert.equal(refused.status, 429);
    const body = await refused.json();
    assert.equal(body.reason, 'admission-bytes');
    assert.equal(body.limit, 1024);
  });

  assert.equal(
    engineInvocations(),
    before,
    'the engine was asked to store a sample the byte budget had already refused',
  );
  assert.equal(taskCount(), tasksBefore);
  assert.deepEqual(fs.readdirSync(uploadsDir), [], 'a refused submission left residue');
});

test('a caller may not exceed the queued-job cap', { timeout: 40000 }, async () => {
  limits({ jobs: 1 });

  // A minimal jobs table: this test is about the *reader* (the API counting what the
  // queue says), not about the engine's schema, which its own suite covers.
  const queue = new Database(process.env.HATCHERY_QUEUE_DB);
  queue.exec('CREATE TABLE IF NOT EXISTS jobs (job_id TEXT PRIMARY KEY, status TEXT NOT NULL, owner TEXT)');
  queue.prepare('INSERT OR REPLACE INTO jobs (job_id, status, owner) VALUES (?, ?, ?)').run(
    'already-queued',
    'queued',
    'anonymous',
  );
  queue.close();

  try {
    await withApp(async (baseUrl) => {
      const refused = await submit(baseUrl);
      assert.equal(refused.status, 429);
      const body = await refused.json();
      assert.equal(body.reason, 'admission-jobs');
      assert.equal(body.limit, 1);
      assert.equal(body.used, 1);
      assert.equal(
        Number(refused.headers.get('retry-after')),
        30,
        'a full job queue has no known drain time; Retry-After is a polling hint',
      );
    });
  } finally {
    fs.rmSync(process.env.HATCHERY_QUEUE_DB, { force: true });
  }
});

test('0 disables a dimension, and a disabled dimension writes nothing', { timeout: 40000 }, async () => {
  const counterRows = () => {
    const db = new Database(process.env.HATCHERY_DB_PATH, { readonly: true, fileMustExist: true });
    try {
      return Number((db.prepare('SELECT COUNT(*) AS n FROM admission_counters').get() ?? { n: 0 }).n);
    } finally {
      db.close();
    }
  };

  limits({ requests: 0, bytes: 0, jobs: 0 });
  const before = counterRows();

  await withApp(async (baseUrl) => {
    for (let i = 0; i < 3; i += 1) {
      assert.equal((await submit(baseUrl)).status, 200);
    }
  });

  assert.equal(
    counterRows(),
    before,
    'a disabled dimension must not write counters (earlier cases in this file wrote some)',
  );
});

// ---------------------------------------------------------------------------
// 2. Durability — a real restart, not a second object in one process
// ---------------------------------------------------------------------------

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

test('the budget survives a real server restart', { timeout: 90000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-admission-restart-'));
  const port = 42000 + Math.floor(Math.random() * 5000);
  const baseUrl = `http://127.0.0.1:${port}`;
  const env = {
    ...process.env,
    HATCHERY_HOST: '127.0.0.1',
    HATCHERY_PORT: String(port),
    HATCHERY_DB_PATH: path.join(dir, 'hatchery.db'),
    HATCHERY_QUEUE_DB: path.join(dir, 'queue.db'),
    HATCHERY_RESULTS_ROOT: path.join(dir, 'results'),
    HATCHERY_UPLOADS_DIR: path.join(dir, 'uploads'),
    HATCHERY_ENGINE_PYTHON: path.join(serverRoot, 'fixtures', 'fake-engine.mjs'),
    HATCHERY_ADMIT_RATE: '1',
    HATCHERY_ADMIT_BYTES: '0',
    HATCHERY_ADMIT_JOBS: '0',
    HATCHERY_ADMIT_WINDOW: '600',
  };
  fs.mkdirSync(env.HATCHERY_UPLOADS_DIR, { recursive: true });

  const start = () => spawn(process.execPath, [path.join(serverRoot, 'dist', 'index.js')], {
    cwd: serverRoot,
    env,
    stdio: 'ignore',
  });

  let server = start();
  try {
    assert.ok(await waitForHealth(baseUrl), 'the server did not start');
    assert.equal((await submit(baseUrl)).status, 200);
  } finally {
    server.kill('SIGKILL');
    await new Promise((resolve) => setTimeout(resolve, 300));
  }

  server = start();
  try {
    assert.ok(await waitForHealth(baseUrl), 'the server did not restart');
    const refused = await submit(baseUrl);
    assert.equal(
      refused.status,
      429,
      'the window was forgotten across a restart, so the budget is per process, not per caller',
    );
    assert.equal((await refused.json()).reason, 'admission-rate');

    // The refusal is a recorded fact, not a mystery (D43). Asserted against the real
    // server because the audit chain is wired in `index.ts`, not in the route module —
    // a route-only harness would be asserting a hook it never added.
    //
    // Polled, because the audit row is appended from `onResponse`: the caller receives
    // the 429 *before* the chain is written, so a verifier reading the log in the same
    // millisecond would see nothing and conclude, wrongly, that the refusal was
    // unrecorded.
    let row;
    const deadline = Date.now() + 3000;
    const audit = new Database(env.HATCHERY_DB_PATH, { readonly: true, fileMustExist: true });
    try {
      while (Date.now() < deadline) {
        row = audit
          .prepare('SELECT actor, status_code, action, detail FROM audit_log ORDER BY id DESC LIMIT 1')
          .get();
        if (row && Number(row.status_code) === 429) break;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      assert.ok(row, 'the throttled request produced no audit row');
      assert.equal(row.status_code, 429);
      assert.equal(
        row.action,
        'request.throttled',
        'a refused request must not be recorded as allowed just because 429 is below 500',
      );
      assert.equal(row.actor, 'anonymous');
      assert.match(String(row.detail), /rate 1\/1/, `the audit row must name the limit: ${row.detail}`);
    } finally {
      audit.close();
    }
  } finally {
    server.kill('SIGKILL');
  }
});
