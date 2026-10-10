/**
 * Triage ingest tests.
 *
 * The engine writes the advisory triage block as a top-level `triage` key; the
 * API is the only writer of rows. This pins the bridge: without the
 * `triage_json` column (and the migration that adds it to an older database),
 * the triage verdict and its grounded findings would be silently dropped on
 * ingest and the API would show nothing for a run that was triaged.
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

const TRIAGE_BLOCK = {
  available: true,
  status: 'completed',
  verdict: 'suspicious',
  confidence: 55,
  summary: 'Cron persistence plus an outbound URL.',
  findings: [{ claim: 'cron persistence', grounding: ['event:1'] }],
  findings_dropped: 2,
  not_established: ['payload purpose'],
  techniques: ['T1053.003'],
  model: 'mistral:7b',
  prompt_version: '1.0',
  contract_hash: 'ab'.repeat(32),
  evidence_ids: 12,
  inconclusive: false,
};

function seedTask(db) {
  db.prepare(
    'INSERT INTO tasks (task_id, file_name, file_path) VALUES (?, ?, ?)',
  ).run('t1', 'sample.bin', '/x/sample.bin');
}

function writeBundle(dir, extra) {
  const bundleDir = path.join(dir, 'bundle');
  fs.mkdirSync(bundleDir, { recursive: true });
  fs.writeFileSync(
    path.join(bundleDir, 'analysis.json'),
    JSON.stringify({
      task_id: 't1',
      sample: { file_name: 'sample.bin', md5: 'a', sha1: 'b', sha256: 'c', file_size: 1 },
      static: { strings: {}, yara: { matches: [] }, capa: {}, packer: {} },
      iocs: [],
      mitre: {},
      limitations: [],
      sandbox: null,
      ...extra,
    }),
  );
  fs.writeFileSync(path.join(bundleDir, 'events.jsonl'), '');
}

test('triage block survives ingest and is exposed in static_results', () => {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  seedTask(db);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-triage-'));
  writeBundle(dir, { triage: TRIAGE_BLOCK });

  const result = ingestBundle(db, 't1', dir);
  assert.equal(result.ok, true, result.error);

  const row = db.prepare('SELECT triage_json FROM static_results WHERE task_id = ?').get('t1');
  assert.ok(row.triage_json, 'triage_json must be persisted');
  const parsed = JSON.parse(row.triage_json);
  assert.equal(parsed.verdict, 'suspicious');
  assert.equal(parsed.model, 'mistral:7b');
  assert.equal(parsed.findings[0].grounding[0], 'event:1');
  assert.equal(parsed.findings_dropped, 2);
});

test('schema declares triage_json for a fresh database', () => {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  const columns = db.prepare('PRAGMA table_info(static_results)').all().map((c) => c.name);
  assert.ok(columns.includes('triage_json'));
});

test('a bundle without triage leaves the column null', () => {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  seedTask(db);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-triage-'));
  writeBundle(dir, {});

  const result = ingestBundle(db, 't1', dir);
  assert.equal(result.ok, true, result.error);
  const row = db.prepare('SELECT triage_json FROM static_results WHERE task_id = ?').get('t1');
  assert.equal(row.triage_json, null);
});
