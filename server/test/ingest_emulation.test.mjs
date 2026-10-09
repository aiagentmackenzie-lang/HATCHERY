/**
 * Emulation ingest tests.
 *
 * The engine writes the emulation block as a top-level `emulation` key; the API
 * is the only writer of rows. This pins the bridge: without the `emulation_json`
 * column (and the migration that adds it to an older database), the emulation
 * section — its config, snapshots and capa_dynamic — would be silently dropped on
 * ingest and the API would show nothing for a run that actually emulated a PE.
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

const EMULATION_BLOCK = {
  available: true,
  status: 'completed',
  emulator: 'speakeasy-emulator',
  emulator_version: '2.0.0b6',
  schema_hash: 'ab'.repeat(32),
  api_calls: 4,
  events_written: 5,
  unsupported_apis: [],
  config: {
    network_endpoints: [{ server: 'c2.example', port: 80, protocol: 'tcp.http', kind: 'net_http' }],
    mutexes: ['HatcheryMutex'],
    registry_persistence: [],
  },
  capa_dynamic: { capabilities: [{ name: 'write file', namespace: 'file-system' }] },
  snapshots: { regions_selected: 3, regions_decoded: 2 },
};

function seedTask(db) {
  db.prepare(
    'INSERT INTO tasks (task_id, file_name, file_path) VALUES (?, ?, ?)',
  ).run('t1', 'packed.exe', '/x/packed.exe');
}

test('emulation block survives ingest and is exposed in static_results', () => {
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
      sample: { file_name: 'packed.exe', md5: 'a', sha1: 'b', sha256: 'c', file_size: 1 },
      static: { strings: {}, yara: { matches: [] }, capa: {}, packer: {} },
      emulation: EMULATION_BLOCK,
      iocs: [], mitre: {}, limitations: [], sandbox: null,
    }),
  );
  fs.writeFileSync(path.join(bundleDir, 'events.jsonl'), '');

  const result = ingestBundle(db, 't1', dir);
  assert.equal(result.ok, true, result.error);

  const row = db.prepare('SELECT emulation_json FROM static_results WHERE task_id = ?').get('t1');
  assert.ok(row.emulation_json, 'emulation_json must be persisted');
  const parsed = JSON.parse(row.emulation_json);
  assert.equal(parsed.emulator_version, '2.0.0b6');
  assert.equal(parsed.config.network_endpoints[0].server, 'c2.example');
  assert.equal(parsed.capa_dynamic.capabilities[0].name, 'write file');
  assert.equal(parsed.snapshots.regions_decoded, 2);
});

test('schema declares emulation_json for a fresh database', () => {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  const columns = db.prepare('PRAGMA table_info(static_results)').all().map((c) => c.name);
  assert.ok(columns.includes('emulation_json'));
});

test('a bundle without emulation leaves the column null', () => {
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
      sample: { file_name: 'x', md5: 'a', sha1: 'b', sha256: 'c', file_size: 1 },
      static: { strings: {}, yara: { matches: [] }, capa: {}, packer: {} },
      iocs: [], mitre: {}, limitations: [], sandbox: null,
    }),
  );
  fs.writeFileSync(path.join(bundleDir, 'events.jsonl'), '');

  const result = ingestBundle(db, 't1', dir);
  assert.equal(result.ok, true, result.error);
  const row = db.prepare('SELECT emulation_json FROM static_results WHERE task_id = ?').get('t1');
  assert.equal(row.emulation_json, null);
});
