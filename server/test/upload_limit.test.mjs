/**
 * The API refuses an oversized sample at the boundary (D41).
 *
 * D40 bounded intake in the engine and recorded one gap: the API's multipart
 * route. It turned out the route *did* have a limit (50 MiB, set on the plugin)
 * but nothing tied it to the engine's 256 MiB, so a 100 MiB sample was refused
 * by the API and accepted by the engine; the JSON `filePath` branch had no
 * limit at all; and a refused upload left the partial file and its directory on
 * disk. This file pins the three things that make the limit real: one number,
 * applied on both branches, with nothing left behind.
 *
 * Run with `npm test` (after `npm run build`); no engine and no database are
 * needed for the refusal paths, so this runs in server-gate.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

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

const { MAX_FILENAME_BYTES, MAX_UPLOAD_BYTES, safeFilename, submitRoutes } =
  await import('../dist/routes/submit.js');

const BOUNDARY = 'HATCHERYBOUNDARY';

function multipartBody(parts) {
  const chunks = [];
  for (const part of parts) {
    chunks.push(
      Buffer.from(
        `--${BOUNDARY}\r\n` +
          `Content-Disposition: form-data; name="${part.name}"; filename="${part.filename}"\r\n` +
          'Content-Type: application/octet-stream\r\n\r\n',
      ),
    );
    chunks.push(part.data);
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

test('an oversized multipart upload is 413 and leaves nothing on disk', { timeout: 30000 }, async () => {
  const app = await appWith({ fileSize: 1024, files: 1, parts: 8 });
  const before = residues();

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
