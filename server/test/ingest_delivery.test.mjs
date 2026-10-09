/**
 * Delivery-intake ingest tests.
 *
 * The engine writes the delivery block into `static.delivery`; the API is the
 * only writer of rows. This pins the bridge: without the `delivery_json`
 * column (and the migration that adds it to an older database), the delivery
 * section would be silently dropped on ingest and the API would render a
 * document as if nothing had been unpacked — the exact silent "no findings"
 * the engine half refuses to produce.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';

import { ingestBundle } from '../dist/db/ingest.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.join(here, '..', 'src', 'db', 'schema.sql');

const DELIVERY_BLOCK = {
  format: 'ooxml',
  format_detail: 'OOXML package (docm)',
  is_container: true,
  flags: ['ooxml-macro', 'ooxml-external-relationship'],
  children: [
    { name: 'word/vbaProject.bin', format: 'bin', size: 388, sha256: 'ab'.repeat(32) },
  ],
  unsupported: [{ path: 'doc.pdf', format: 'pdf', reason: 'not implemented in this revision' }],
  errors: [],
  truncated: false,
};

function seedTask(db) {
  db.prepare(
    'INSERT INTO tasks (task_id, file_name, file_path) VALUES (?, ?, ?)',
  ).run('t1', 'invoice.docm', '/x/invoice.docm');
}

test('delivery intake survives ingest and is exposed in static_results', () => {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  seedTask(db);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-ingest-'));
  const bundleDir = path.join(dir, 'bundle');
  fs.mkdirSync(bundleDir, { recursive: true });
  fs.writeFileSync(
    path.join(bundleDir, 'analysis.json'),
    JSON.stringify({
      task_id: 't1',
      sample: { file_name: 'invoice.docm', md5: 'a', sha1: 'b', sha256: 'c', file_size: 1 },
      static: {
        strings: {}, yara: { matches: [] }, capa: {}, packer: {},
        delivery: DELIVERY_BLOCK,
      },
      iocs: [], mitre: {}, limitations: [], sandbox: null,
    }),
  );
  fs.writeFileSync(path.join(bundleDir, 'events.jsonl'), '');

  const result = ingestBundle(db, 't1', dir);
  assert.equal(result.ok, true, result.error);

  const row = db.prepare('SELECT delivery_json FROM static_results WHERE task_id = ?').get('t1');
  assert.ok(row.delivery_json, 'delivery_json must be persisted');
  const parsed = JSON.parse(row.delivery_json);
  assert.equal(parsed.format, 'ooxml');
  assert.equal(parsed.children[0].name, 'word/vbaProject.bin');
  assert.equal(parsed.unsupported[0].format, 'pdf');
  assert.ok(parsed.flags.includes('ooxml-macro'));
});

test('schema declares delivery_json for a fresh database', () => {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  const columns = db.prepare('PRAGMA table_info(static_results)').all();
  assert.ok(columns.some((c) => c.name === 'delivery_json'));
});
