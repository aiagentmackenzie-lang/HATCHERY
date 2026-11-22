/**
 * Binary-metadata ingest tests (D38).
 *
 * The engine now writes `static.pe` / `static.elf`. The API already had
 * `pe_json` / `elf_json` columns and `ingest.ts` already read those keys — but no
 * engine revision produced them, so both were always null and the dashboard's
 * PE panel and the report route had nothing to render. This pins the bridge so
 * a binary's structure cannot be silently dropped between bundle and report.
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

const PE_BLOCK = {
  is_valid_pe: true,
  machine_type: 'x64 (AMD64)',
  subsystem: 'Windows CUI (Console)',
  is_64bit: true,
  sections: [{ name: '.text', raw_size: 512 }],
  imports: [{ dll: 'KERNEL32.dll', function: 'ExitProcess' }],
  error: null,
};

const ELF_BLOCK = {
  is_valid_elf: true,
  arch: 'x86-64',
  bits: 64,
  elf_type: 'EXEC (executable)',
  sections: [{ name: '.text', size: 12 }],
  security: { is_pie: false, is_stripped: true },
  error: null,
};

function ingest(staticBlock) {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  db.prepare('INSERT INTO tasks (task_id, file_name, file_path) VALUES (?, ?, ?)').run(
    't1',
    'sample.bin',
    '/x/sample.bin',
  );

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-ingest-bin-'));
  const bundleDir = path.join(dir, 'bundle');
  fs.mkdirSync(bundleDir, { recursive: true });
  fs.writeFileSync(
    path.join(bundleDir, 'analysis.json'),
    JSON.stringify({
      schema_version: '1.1',
      task_id: 't1',
      sample: { file_name: 'sample.bin', md5: 'a', sha1: 'b', sha256: 'c', file_size: 1 },
      static: { strings: {}, yara: { matches: [] }, capa: {}, packer: {}, ...staticBlock },
      iocs: [],
      mitre: {},
      limitations: [],
      sandbox: null,
    }),
  );
  fs.writeFileSync(path.join(bundleDir, 'events.jsonl'), '');

  const result = ingestBundle(db, 't1', dir);
  assert.equal(result.ok, true, result.error);
  return db
    .prepare('SELECT pe_json, elf_json FROM static_results WHERE task_id = ?')
    .get('t1');
}

test('pe and elf sections survive ingest and keep their fields', () => {
  const row = ingest({ pe: PE_BLOCK, elf: null });
  assert.ok(row.pe_json, 'pe_json must be persisted');
  assert.equal(row.elf_json, null);
  const pe = JSON.parse(row.pe_json);
  assert.equal(pe.machine_type, 'x64 (AMD64)');
  assert.equal(pe.sections[0].name, '.text');

  const elfRow = ingest({ pe: null, elf: ELF_BLOCK });
  const elf = JSON.parse(elfRow.elf_json);
  assert.equal(elf.arch, 'x86-64');
  assert.equal(elf.security.is_stripped, true);
  assert.equal(elfRow.pe_json, null);
});

test('a run without binary sections leaves both columns null', () => {
  const row = ingest({ pe: null, elf: null });
  assert.equal(row.pe_json, null);
  assert.equal(row.elf_json, null);
});

test('schema declares pe_json and elf_json for a fresh database', () => {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  const columns = db.prepare('PRAGMA table_info(static_results)').all().map((c) => c.name);
  assert.ok(columns.includes('pe_json'));
  assert.ok(columns.includes('elf_json'));
});
