/**
 * The API's sample boundary: one limit, one intake path, nothing written down (D41/D42).
 *
 * D40 bounded intake in the engine and recorded one gap: the API's multipart
 * route. It turned out the route *did* have a limit (50 MiB, set on the plugin)
 * but nothing tied it to the engine's 256 MiB, so a 100 MiB sample was refused by
 * the API and accepted by the engine; the JSON `filePath` branch had no limit at
 * all; and a refused upload left the partial file and its directory on disk. D41
 * made the limit one number, applied on both branches, with nothing left behind.
 *
 * D42 removed the file: the route used to stage up to 256 MiB of live malware as
 * PLAINTEXT under `uploads/<taskId>/`. It now streams the body into the encrypted
 * store and queues the address. That also fixed a defect D41 could not see from a
 * small fixture — the old route collected the file part and consumed it after the
 * loop, so busboy's backpressure deadlocked every upload above ~128 KiB (96 KiB
 * answered, 128 KiB never did).
 *
 * The engine is replaced by `fixtures/fake-engine.mjs` here: this job runs in
 * CI's `server-gate`, which has no Python and no engine. The real path — a real
 * store, a real encryption envelope, a real worker — is exercised by
 * `scripts/verify_setup.sh` and by the engine's own suite.
 *
 * Run with `npm test` (after `npm run build`).
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
const repoRoot = path.join(serverRoot, '..');

// Resolve the upload directory into a temp root *before* importing the route:
// the module reads the environment at load time, and a test that writes into
// the checkout cannot prove that a refused upload left nothing behind.
const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-upload-'));
const uploadsDir = path.join(workDir, 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });
process.env.HATCHERY_UPLOADS_DIR = uploadsDir;
process.env.HATCHERY_DB_PATH = path.join(workDir, 'hatchery.db');
process.env.HATCHERY_QUEUE_DB = path.join(workDir, 'queue.db');
// D42: a stand-in engine, so this suite needs no Python (see the file header).
// It lives outside `test/` because `node --test` runs every file under that
// directory, and a fixture is not a test.
process.env.HATCHERY_ENGINE_PYTHON = path.join(serverRoot, 'fixtures', 'fake-engine.mjs');

const { MAX_FILENAME_BYTES, MAX_UPLOAD_BYTES, safeFilename, submitRoutes } =
  await import('../dist/routes/submit.js');

const BOUNDARY = 'HATCHERYBOUNDARY';

function multipartBody(parts) {
  const chunks = [];
  for (const part of parts) {
    if (part.value !== undefined) {
      // A plain field: no filename and no Content-Type, or busboy treats it as
      // a file — which is how a test can accidentally prove the wrong thing.
      chunks.push(
        Buffer.from(
          `--${BOUNDARY}\r\n` +
            `Content-Disposition: form-data; name="${part.name}"\r\n\r\n`,
        ),
      );
      chunks.push(Buffer.from(part.value));
    } else {
      chunks.push(
        Buffer.from(
          `--${BOUNDARY}\r\n` +
            `Content-Disposition: form-data; name="${part.name}"; filename="${part.filename}"\r\n` +
            'Content-Type: application/octet-stream\r\n\r\n',
        ),
      );
      chunks.push(part.data);
    }
    chunks.push(Buffer.from('\r\n'));
  }
  chunks.push(Buffer.from(`--${BOUNDARY}--\r\n`));
  return Buffer.concat(chunks);
}

async function appWith(limits) {
  const app = Fastify({ logger: false });
  await app.register(multipart, { limits });
  await app.register(submitRoutes);
  return app;
}

/**
 * POST a multipart body over a real socket.
 *
 * `app.inject` never settles for a request whose body the server refuses
 * mid-stream (the fake request stream is not drained), and the test hangs
 * instead of failing. A real listener is also the honest shape: the client is
 * a browser or PhishHawk, not light-my-request.
 */
async function postMultipart(app, payload) {
  await app.listen({ port: 0, host: '127.0.0.1' });
  const address = app.server.address();
  try {
    return await fetch(`http://127.0.0.1:${address.port}/api/submit`, {
      method: 'POST',
      headers: { 'content-type': `multipart/form-data; boundary=${BOUNDARY}` },
      body: payload,
      signal: AbortSignal.timeout(15000),
    });
  } finally {
    await app.close();
  }
}

function residues() {
  return fs.readdirSync(uploadsDir).sort();
}

function taskRows() {
  // A refusal can happen before the route ever opens the database (the plugin
  // rejects the body first), so a missing file means "no tasks", not a failure.
  if (!fs.existsSync(process.env.HATCHERY_DB_PATH)) return [];
  const db = new Database(process.env.HATCHERY_DB_PATH, { readonly: true, fileMustExist: true });
  try {
    return db.prepare('SELECT task_id, file_name, file_path, sample_store_ref FROM tasks').all();
  } finally {
    db.close();
  }
}

test('the API limit is the engine limit, not a second opinion', () => {
  const source = fs.readFileSync(
    path.join(repoRoot, 'engine', 'store', 'store.py'),
    'utf-8',
  );
  const match = source.match(
    /^DEFAULT_MAX_SAMPLE_BYTES\s*=\s*(\d+)\s*\*\s*(\d+)\s*\*\s*(\d+)/m,
  );
  assert.ok(match, 'DEFAULT_MAX_SAMPLE_BYTES was not found in engine/store/store.py');
  const engineLimit = Number(match[1]) * Number(match[2]) * Number(match[3]);
  assert.equal(
    MAX_UPLOAD_BYTES,
    engineLimit,
    'the API and the engine disagree about the largest sample; a sample must not be ' +
      'refused by one and accepted by the other',
  );
});

test('an oversized multipart upload is 413 and queues nothing', { timeout: 30000 }, async () => {
  const app = await appWith({ fileSize: 1024, files: 1, parts: 8 });
  const before = residues();
  const tasksBefore = taskRows().length;

  const response = await postMultipart(
    app,
    multipartBody([
      { name: 'sample', filename: 'big.bin', data: Buffer.alloc(8 * 1024, 0x41) },
    ]),
  );

  assert.equal(response.status, 413);
  assert.match(await response.text(), /too large|file too large/i);
  assert.deepEqual(
    residues(),
    before,
    'a refused upload left a partial file or task directory behind',
  );
  assert.equal(
    taskRows().length,
    tasksBefore,
    'a truncated upload must not become a task — and therefore must not become a job',
  );
});

test('a multipart upload is stored through the engine, not written to a file', { timeout: 30000 }, async () => {
  const app = await appWith({ fileSize: MAX_UPLOAD_BYTES, files: 1, parts: 8 });
  const sample = Buffer.from('MZ\u0090\u0000hatchery-d42-streamed-upload');
  const expected = createHash('sha256').update(sample).digest('hex');
  const before = residues();

  const response = await postMultipart(
    app,
    multipartBody([
      { name: 'sample', filename: 'payload.docm', data: sample },
      // A field after the file: the route applies options only once the body is
      // fully read, which is why storing and queueing are two calls (D42).
      { name: 'noSandbox', value: Buffer.from('true') },
    ]),
  );
  const body = await response.json();

  assert.equal(response.status, 200, JSON.stringify(body));
  assert.equal(
    body.sample_store_ref,
    expected,
    'the response must name the address the engine stored, not a path',
  );
  assert.equal(body.file_name, 'payload.docm');
  assert.equal(body.no_sandbox, true, 'a field sent after the file must still apply');
  assert.deepEqual(
    residues(),
    before,
    'the sample must never be written under the uploads root',
  );

  const rows = taskRows().filter((row) => row.task_id === body.task_id);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].sample_store_ref, expected);
  assert.equal(
    rows[0].file_path,
    `store:${expected}`,
    'a path that does not exist must not be recorded as one',
  );
});

test('a second file part is refused and leaves nothing on disk', { timeout: 30000 }, async () => {
  const app = await appWith({ fileSize: MAX_UPLOAD_BYTES, files: 1, parts: 8 });
  const before = residues();

  const response = await postMultipart(
    app,
    multipartBody([
      { name: 'sample', filename: 'one.bin', data: Buffer.from('MZ') },
      { name: 'sample', filename: 'two.bin', data: Buffer.from('MZ') },
    ]),
  );

  assert.equal(response.status, 413);
  assert.match(await response.text(), /files limit/i);
  assert.deepEqual(residues(), before);
});

test('an oversized filePath is 413 before a task is enqueued', { timeout: 30000 }, async () => {
  const app = await appWith({ fileSize: MAX_UPLOAD_BYTES, files: 1, parts: 8 });
  const oversized = path.join(uploadsDir, 'oversized.bin');
  fs.writeFileSync(oversized, '');
  fs.truncateSync(oversized, MAX_UPLOAD_BYTES + 1);

  const response = await app.inject({
    method: 'POST',
    url: '/api/submit',
    payload: { filePath: oversized, noSandbox: true },
  });
  await app.close();

  assert.equal(response.statusCode, 413);
  const body = JSON.parse(response.body);
  assert.equal(body.error, 'sample too large');
  assert.equal(body.limit, MAX_UPLOAD_BYTES);

  fs.rmSync(oversized, { force: true });
  assert.deepEqual(
    residues(),
    [],
    'the refusal must not create a task upload directory',
  );
});

test('a client filename is bounded in bytes and keeps its extension', () => {
  const safe = safeFilename(`${'A'.repeat(400)}.docm`);
  assert.ok(Buffer.byteLength(safe) <= MAX_FILENAME_BYTES, safe);
  assert.ok(safe.endsWith('.docm'), safe);
  assert.equal(safeFilename('../../etc/passwd'), 'passwd');
  assert.match(safeFilename('..'), /^sample-[0-9a-f]{8}$/, 'a dots-only name is replaced, not used');
});
