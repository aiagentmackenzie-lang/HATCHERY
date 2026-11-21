/**
 * Audit-log compaction and cross-segment verification, end to end (D32).
 *
 * The claim under test is not "a DELETE was added". It is that the audit log can be
 * **finite without becoming a lie**: a segment is archived, the chain is handed off
 * verifiably, every claim the verifier makes stays true across the boundary, and a
 * missing or tampered archive is a break rather than a pass.
 *
 * Everything here is the real built server (as a subprocess), the real CLI (as a
 * subprocess), real SQLite files and real archive files in throwaway directories.
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import zlib from 'node:zlib';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';

import {
  GENESIS_HASH,
  configureAuditKeyring,
  entryHash,
  initAuditChain,
  recordAudit,
} from '../dist/security/audit.js';
import { resolveAuditKeyring } from '../dist/security/auditKey.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');
const schemaPath = path.join(here, '..', 'src', 'db', 'schema.sql');

function tempRoot(prefix = 'hatchery-compact-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function nestedDb(root) {
  return path.join(root, 'data', 'hatchery.db');
}

function prepareDbPath(dbPath) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });
}

function cli(dbPath, args, extraEnv = {}) {
  return spawnSync(process.execPath, [`scripts/${args[0]}.mjs`, ...args.slice(1)], {
    cwd: serverRoot,
    env: { ...process.env, HATCHERY_DB_PATH: dbPath, ...extraEnv },
    encoding: 'utf-8',
    timeout: 120000,
  });
}

function cliJson(dbPath, args, extraEnv = {}) {
  const result = cli(dbPath, [...args, '--json'], extraEnv);
  assert.equal(result.status, 0, `${args.join(' ')} failed: ${result.stderr}`);
  return JSON.parse(result.stdout);
}

function mode(file) {
  return fs.statSync(file).mode & 0o777;
}

/**
 * Append real chained rows through the appender itself, against the real database
 * file and the real audit key ring. This is history, not a fixture: the same
 * `recordAudit` the server calls.
 */
function seed(dbPath, count, options = {}) {
  prepareDbPath(dbPath);
  const ring = options.noRing ? null : resolveAuditKeyring(dbPath);
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
          path: `/seed/${options.label ?? 'row'}/${index}`,
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

function meta(dbPath) {
  const db = new Database(dbPath, { readonly: true });
  try {
    const rows = db.prepare('SELECT key, value FROM audit_chain_meta').all();
    return Object.fromEntries(rows.map((row) => [row.key, row.value]));
  } finally {
    db.close();
  }
}

function rowCount(dbPath) {
  const db = new Database(dbPath, { readonly: true });
  try {
    return db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n;
  } finally {
    db.close();
  }
}

function ringOf(dbPath) {
  return JSON.parse(fs.readFileSync(path.join(path.dirname(dbPath), '.audit-keyring'), 'utf-8'));
}

function archiveFiles(dbPath) {
  const dir = path.join(path.dirname(dbPath), 'audit-archives');
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((name) => name.endsWith('.jsonl') || name.endsWith('.jsonl.gz'))
    .sort();
}

function archiveRows(file) {
  const text = file.endsWith('.gz')
    ? zlib.gunzipSync(fs.readFileSync(file)).toString('utf8')
    : fs.readFileSync(file, 'utf8');
  return text
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line));
}

function writeArchiveRows(file, rows) {
  fs.writeFileSync(file, `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`);
}

async function bootServer(dbPath, env = {}) {
  const port = 51000 + Math.floor(Math.random() * 4000);
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

/** Open the database the way a database-level attacker would and edit every digest. */
function forgeLiveRow(dbPath, rowId, field, value) {
  const db = new Database(dbPath);
  try {
    db.prepare(`UPDATE audit_log SET ${field} = ? WHERE id = ?`).run(value, rowId);
    const rows = db.prepare('SELECT * FROM audit_log ORDER BY id').all();
    let prev = rows[0].prev_hash ?? GENESIS_HASH;
    let last = null;
    for (const row of rows) {
      const hash = entryHash({ ...row, prev_hash: prev });
      db.prepare('UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE id = ?').run(
        prev,
        hash,
        row.id,
      );
      prev = hash;
      last = { id: row.id, hash };
    }
    db.prepare("UPDATE audit_chain_meta SET value = ? WHERE key = 'head_id'").run(String(last.id));
    db.prepare("UPDATE audit_chain_meta SET value = ? WHERE key = 'head_hash'").run(last.hash);
    return last;
  } finally {
    db.close();
  }
}

// ---------------------------------------------------------------------------

test('a compacted log verifies across the boundary: archived count, manifest hash, proven join', () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  seed(dbPath, 40);

  const firstRun = cliJson(dbPath, ['audit', 'compact', '--max-rows', '25', '--apply']);
  assert.equal(firstRun.applied, true);
  // 40 rows, `--max-rows 25`: the rule accounts for the compaction record it will
  // append, so 16 rows move and 25 live rows remain (24 kept + the record).
  assert.equal(firstRun.window.rows, 16);
  assert.equal(firstRun.window.first_id, 1);
  assert.equal(firstRun.window.last_id, 16);
  assert.equal(firstRun.join.proven, true);
  assert.equal(firstRun.remaining_eligible, 0);
  assert.ok(fs.existsSync(path.join(path.dirname(dbPath), firstRun.archive.path)));
  assert.equal(mode(path.join(path.dirname(dbPath), firstRun.archive.path)), 0o600);
  assert.equal(mode(path.join(path.dirname(dbPath), firstRun.manifest.path)), 0o600);

  // The live chain is shorter, keeps its assurance, and says what is archived.
  const one = cliJson(dbPath, ['audit', 'verify']);
  assert.equal(one.ok, true, JSON.stringify(one.first_broken));
  assert.equal(one.assurance, 'keyed');
  assert.equal(one.archive.recorded, true);
  assert.equal(one.archive.checked, true);
  assert.equal(one.archive.verified, true);
  assert.equal(one.archive.rows, 16);
  assert.equal(one.archive.segments, 1);
  assert.equal(one.archive.manifest_sha256, firstRun.manifest.sha256);
  assert.equal(one.archive.tail.entry_hash, firstRun.tail.entry_hash);
  assert.equal(one.archive.join, 'proven');
  assert.equal(one.segments.live_first_prev_hash, firstRun.tail.entry_hash);
  assert.equal(one.archive_verified, true);

  // The `audit.compacted` row is in the live chain and names the archive, the manifest
  // hash and the archived tail.
  const db = new Database(dbPath, { readonly: true });
  const compaction = db
    .prepare("SELECT * FROM audit_log WHERE action = 'audit.compacted' ORDER BY id DESC LIMIT 1")
    .get();
  db.close();
  assert.ok(compaction, 'the compaction is recorded in the chain');
  assert.ok(compaction.detail.includes(firstRun.manifest.sha256), compaction.detail);
  assert.ok(compaction.detail.includes(firstRun.tail.entry_hash), compaction.detail);
  assert.ok(compaction.detail.includes('audit-archives/'), compaction.detail);

  // A second compaction produces a second segment; the archives splice to each other
  // and the live chain still verifies.
  const secondRun = cliJson(dbPath, ['audit', 'compact', '--max-rows', '10', '--apply']);
  assert.equal(secondRun.applied, true);
  assert.equal(secondRun.window.first_id, 17);

  const two = cliJson(dbPath, ['audit', 'verify']);
  assert.equal(two.ok, true, JSON.stringify(two.first_broken));
  assert.equal(two.archive.segments, 2);
  assert.equal(two.archive.rows, 16 + secondRun.window.rows);
  assert.equal(two.archive.manifest_sha256, secondRun.manifest.sha256);
  assert.equal(two.archive.join, 'proven');

  // Every row that ever existed is either live or archived.
  const counts = meta(dbPath);
  assert.equal(
    Number(counts.chained_rows_total),
    rowCount(dbPath) + Number(counts.archived_row_total),
  );

  // A third run with the same policy has nothing to do and archives nothing twice.
  const again = cliJson(dbPath, ['audit', 'compact', '--max-rows', '10', '--apply']);
  assert.equal(again.applied, false);
  assert.equal(again.reason, 'nothing-to-archive');
});

test('an archive verifies offline; an edited, shortened or truncated one does not', () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  seed(dbPath, 30);
  const run = cliJson(dbPath, ['audit', 'compact', '--max-rows', '20', '--apply']);

  // "Offline": a copy of the archive and manifest in a directory with no database,
  // and the key ring handed over explicitly — a machine that never held HATCHERY.
  const offline = tempRoot('hatchery-offline-');
  const archivePath = path.join(path.dirname(dbPath), run.archive.path);
  const manifestPath = path.join(path.dirname(dbPath), run.manifest.path);
  const offlineArchive = path.join(offline, path.basename(archivePath));
  const offlineManifest = path.join(offline, path.basename(manifestPath));
  fs.copyFileSync(archivePath, offlineArchive);
  fs.copyFileSync(manifestPath, offlineManifest);

  // No `--db` at all: the offline path must not need a database.
  const offlineRun = spawnSync(
    process.execPath,
    ['scripts/audit.mjs', 'verify', '--archive', offlineArchive, '--keyring',
      path.join(path.dirname(dbPath), '.audit-keyring'), '--json'],
    { cwd: serverRoot, env: { ...process.env }, encoding: 'utf-8', timeout: 60000 },
  );
  assert.equal(offlineRun.status, 0, offlineRun.stderr);
  const offlineResult = JSON.parse(offlineRun.stdout);
  assert.equal(offlineResult.ok, true, JSON.stringify(offlineResult.first_broken));
  assert.equal(offlineResult.checked, true);
  assert.equal(offlineResult.rows, run.window.rows);
  assert.equal(offlineResult.manifest_sha256, run.manifest.sha256);
  assert.equal(offlineResult.archive_sha256, run.archive.sha256);
  assert.equal(offlineResult.tail.entry_hash, run.tail.entry_hash);
  assert.equal(offlineResult.first_prev_hash, GENESIS_HASH);
  assert.ok(!JSON.stringify(offlineResult).includes(ringOf(dbPath).keys[0].material));

  const verifyOffline = () =>
    spawnSync(
      process.execPath,
      ['scripts/audit.mjs', 'verify', '--archive', offlineArchive, '--keyring',
        path.join(path.dirname(dbPath), '.audit-keyring'), '--json'],
      { cwd: serverRoot, env: { ...process.env }, encoding: 'utf-8', timeout: 60000 },
    );

  const original = archiveRows(offlineArchive);

  // 1. One archived row edited: caught at that row, and the manifest hash mismatch is
  //    named in the same detail.
  const edited = original.map((row) => ({ ...row }));
  edited[4].path = '/api/forged';
  writeArchiveRows(offlineArchive, edited);
  const editedRun = verifyOffline();
  assert.equal(editedRun.status, 1);
  const editedReport = JSON.parse(editedRun.stdout);
  assert.equal(editedReport.ok, false);
  assert.equal(editedReport.first_broken.id, edited[4].id);
  assert.equal(editedReport.first_broken.classification, 'archive-modified');
  assert.match(editedReport.first_broken.detail, /no longer hashes/);
  assert.match(editedReport.first_broken.detail, /manifest records archive sha256/);

  // 2. One archived row deleted: the id gap is caught, and the hash mismatch named.
  const deleted = original.filter((_, index) => index !== 6);
  writeArchiveRows(offlineArchive, deleted);
  const deletedRun = verifyOffline();
  assert.equal(deletedRun.status, 1);
  const deletedReport = JSON.parse(deletedRun.stdout);
  assert.equal(deletedReport.ok, false);
  assert.equal(deletedReport.first_broken.classification, 'archive-truncated');
  assert.equal(deletedReport.first_broken.id, original[6].id);
  assert.match(deletedReport.first_broken.detail, /a row is missing from the archive/);

  // 3. The archive truncated: the count no longer matches the manifest.
  writeArchiveRows(offlineArchive, original.slice(0, -2));
  const truncatedRun = verifyOffline();
  assert.equal(truncatedRun.status, 1);
  const truncatedReport = JSON.parse(truncatedRun.stdout);
  assert.equal(truncatedReport.ok, false);
  assert.equal(truncatedReport.first_broken.classification, 'archive-truncated');
  assert.match(truncatedReport.first_broken.detail, /manifest records/);

  // 4. Restored: it passes again, so the detection is the edit and not the harness.
  fs.copyFileSync(archivePath, offlineArchive);
  assert.equal(verifyOffline().status, 0);

  // 5. The manifest is required: without it there is nothing to verify against.
  fs.unlinkSync(offlineManifest);
  const noManifestRun = verifyOffline();
  assert.equal(noManifestRun.status, 1);
  assert.equal(JSON.parse(noManifestRun.stdout).first_broken.classification, 'archive-missing');
});

test('a deleted archive is a break, not a shorter green history', () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  seed(dbPath, 20);
  const run = cliJson(dbPath, ['audit', 'compact', '--max-rows', '10', '--apply']);
  const archivePath = path.join(path.dirname(dbPath), run.archive.path);
  assert.equal(cli(dbPath, ['audit', 'verify']).status, 0);

  fs.unlinkSync(archivePath);

  const live = cli(dbPath, ['audit', 'verify', '--json']);
  assert.equal(live.status, 1, 'the CLI must exit non-zero');
  const report = JSON.parse(live.stdout);
  assert.equal(report.ok, false);
  assert.equal(report.first_broken.classification, 'archive-missing');
  assert.ok(report.first_broken.detail.includes(path.basename(archivePath)));
  assert.equal(report.archive.present, false);
  assert.equal(report.archive_verified, false);

  // The endpoint reports the same thing (it is the same verifier).
  // A deleted *manifest* is equally fatal.
  const second = tempRoot();
  const secondDb = nestedDb(second);
  seed(secondDb, 20);
  const secondRun = cliJson(secondDb, ['audit', 'compact', '--max-rows', '10', '--apply']);
  fs.unlinkSync(path.join(path.dirname(secondDb), secondRun.manifest.path));
  const noManifest = JSON.parse(cli(secondDb, ['audit', 'verify', '--json']).stdout);
  assert.equal(noManifest.ok, false);
  assert.equal(noManifest.first_broken.classification, 'archive-missing');
});

test('a head recorded before a compaction still verifies, and so does one after', () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  seed(dbPath, 24);
  const before = cliJson(dbPath, ['audit', 'head']);
  // More work happens — an anchor recorded on Monday, verified on Friday.
  seed(dbPath, 10, { label: 'later' });

  // Compact past the anchored row so the anchor itself is archived.
  cliJson(dbPath, ['audit', 'compact', '--max-rows', '6', '--apply']);

  // The anchored row is no longer the head — it lives in the archive now. That is what
  // a compaction does, and the anchor must survive it.
  const anchored = cliJson(dbPath, ['audit', 'verify', '--expect-head', before.anchor]);
  assert.equal(anchored.ok, true, JSON.stringify(anchored.first_broken));
  assert.equal(anchored.anchor.matches, true);
  assert.equal(anchored.anchor.found_in, 'archive');
  assert.equal(anchored.anchor.head_at_anchor, false);

  const after = cliJson(dbPath, ['audit', 'head']);
  const anchoredAfter = cliJson(dbPath, ['audit', 'verify', '--expect-head', after.anchor]);
  assert.equal(anchoredAfter.ok, true);
  assert.equal(anchoredAfter.anchor.matches, true);
  assert.equal(anchoredAfter.anchor.found_in, 'live');
  assert.equal(anchoredAfter.anchor.head_at_anchor, true);

  // An anchor that is in neither chain is still a break: compaction did not turn the
  // anchor into a no-op.
  const absent = cli(dbPath, [
    'audit', 'verify', '--expect-head', `${before.head.id}:${'a'.repeat(64)}`, '--json',
  ]);
  assert.equal(absent.status, 1);
  assert.equal(JSON.parse(absent.stdout).first_broken.classification, 'replaced');

  // With the archive deliberately not read, the answer is "unconfirmed", never a pass.
  const presence = cli(dbPath, ['audit', 'verify', '--no-archive', '--expect-head', before.anchor, '--json']);
  assert.equal(presence.status, 1, 'an unconfirmed anchor is not a pass');
  const presenceReport = JSON.parse(presence.stdout);
  assert.equal(presenceReport.anchor.matches, null);
  assert.equal(presenceReport.archive.checked, false);
  assert.equal(presenceReport.archive_verified, false);
  assert.match(presenceReport.archive.reason, /not read/);
});

test('retention policy: a dry run moves nothing, --apply removes exactly that, and an anchor row always stays', () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  seed(dbPath, 18);
  const before = rowCount(dbPath);

  const status = cliJson(dbPath, ['audit', 'status', '--max-rows', '8']);
  assert.equal(status.policy_off, false);
  assert.equal(status.rows.total, before);
  // `--max-rows 8` keeps 8 live rows *including* the compaction record it appends, so
  // 11 of the 18 rows move and the anchor row is 12.
  assert.equal(status.would_archive.rows, before - 8 + 1);
  assert.equal(status.would_archive.anchor_row.id, before - 8 + 2);

  const dry = cliJson(dbPath, ['audit', 'compact', '--max-rows', '8']);
  assert.equal(dry.applied, false);
  assert.equal(dry.reason, 'dry-run');
  assert.equal(dry.window.rows, before - 8 + 1);
  assert.equal(rowCount(dbPath), before, 'a dry run must not delete a row');
  assert.deepEqual(archiveFiles(dbPath), [], 'a dry run must not write an archive');

  const applied = cliJson(dbPath, ['audit', 'compact', '--max-rows', '8', '--apply']);
  assert.equal(applied.applied, true);
  assert.equal(applied.window.rows, dry.window.rows);
  assert.equal(applied.window.first_id, dry.window.first_id);
  assert.equal(applied.window.last_id, dry.window.last_id);
  // The rule keeps `--max-rows` live rows *including* the compaction record it
  // appends, so repeated runs settle instead of nibbling one row per run for ever.
  assert.equal(rowCount(dbPath), 8);

  // A policy of "remove everything" keeps the newest chained row as a documented
  // anchor instead of leaving an empty chain, and says that it clamped.
  const extreme = cliJson(dbPath, ['audit', 'status', '--max-rows', '0']);
  assert.match(extreme.would_archive.clamp, /--max-rows 0 is below --keep-rows 1/);
  assert.equal(extreme.would_archive.anchor_row.id, extreme.newest.id);

  const extremeRun = cliJson(dbPath, ['audit', 'compact', '--max-rows', '0', '--apply']);
  assert.equal(extremeRun.applied, true);
  assert.equal(extremeRun.clamped, true);
  assert.equal(extremeRun.window.last_id, extreme.newest.id - 1);
  assert.equal(rowCount(dbPath), 2, 'the anchor row and the compaction record remain');
  assert.equal(cliJson(dbPath, ['audit', 'verify']).ok, true);

  // A policy that would archive nothing is refused rather than guessing.
  const refused = cli(dbPath, ['audit', 'compact', '--max-rows', '1000', '--json']);
  assert.equal(refused.status, 0);
  assert.equal(JSON.parse(refused.stdout).applied, false);

  // No policy at all: retention is off, and a bare `compact` does not invent one.
  const bare = cli(dbPath, ['audit', 'compact', '--apply']);
  assert.equal(bare.status, 2);
  assert.match(bare.stderr, /retention is off by default/);
});

test('growth is visible in status, the verify response and the startup banner — and never deletes', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  seed(dbPath, 12);

  const env = { HATCHERY_AUDIT_WARN_ROWS: '5', HATCHERY_AUDIT_WARN_BYTES: '0' };

  const status = cliJson(dbPath, ['audit', 'status'], env);
  assert.equal(status.growth.over, true);
  assert.equal(status.growth.warn_rows, 5);
  assert.equal(status.growth.enforced, false);
  assert.match(status.growth.message, /warning threshold/);

  const verify = cliJson(dbPath, ['audit', 'verify'], env);
  assert.equal(verify.growth.over, true);
  assert.equal(verify.growth.warn_rows, 5);

  const rowsBefore = rowCount(dbPath);
  const server = await bootServer(dbPath, env);
  try {
    assert.match(server.output(), /AUDIT LOG GROWTH WARNING/);
    assert.match(server.output(), /Nothing was deleted/);
    // A real audited request (health checks are deliberately not audited).
    const tasks = await fetch(`${server.baseUrl}/api/tasks`);
    assert.equal(tasks.status, 200);
    // `onResponse` runs after the reply is flushed, so give it a moment.
    for (let i = 0; i < 40 && rowCount(dbPath) === rowsBefore; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(rowCount(dbPath) > rowsBefore, 'serving traffic appends; it never prunes');
  } finally {
    await server.stop();
  }

  // Over threshold is a warning, not an action: nothing was deleted by any of it.
  const statusAfter = cliJson(dbPath, ['audit', 'status'], env);
  assert.equal(statusAfter.rows.total, rowCount(dbPath));
  assert.equal(archiveFiles(dbPath).length, 0, 'the guard never archives on its own');
});

test('a compacted log still catches a forged live row and a keyed-to-unkeyed downgrade', () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  seed(dbPath, 20);
  cliJson(dbPath, ['audit', 'compact', '--max-rows', '10', '--apply']);
  const ring = resolveAuditKeyring(dbPath);

  const clean = cliJson(dbPath, ['audit', 'verify']);
  assert.equal(clean.ok, true);
  assert.equal(clean.assurance, 'keyed');

  // The D31 attack, re-run on the live segment after a compaction: edit a row, recompute
  // every digest and the stored head. With the key held, the MAC fails at the row.
  const db = new Database(dbPath, { readonly: true });
  const target = db.prepare('SELECT id FROM audit_log ORDER BY id ASC LIMIT 1 OFFSET 2').get();
  db.close();
  forgeLiveRow(dbPath, target.id, 'path', '/api/exfiltrate');

  const forged = cli(dbPath, ['audit', 'verify', '--json']);
  assert.equal(forged.status, 1);
  const forgedReport = JSON.parse(forged.stdout);
  assert.equal(forgedReport.ok, false);
  assert.equal(forgedReport.first_broken.id, target.id);
  assert.equal(forgedReport.first_broken.classification, 'forged');
  // The verifier stops at the first break, so the archive was not read after it — and
  // the response says exactly that rather than claiming a verified archive.
  assert.equal(forgedReport.archive.checked, false);
  assert.equal(forgedReport.archive_verified, false);
  assert.equal(forgedReport.archive.join, 'proven');

  // The archive's own MACs were never rewritten, so the archived segment still verifies.
  const archiveCheck = spawnSync(
    process.execPath,
    ['scripts/audit.mjs', 'verify', '--archive',
      path.join(path.dirname(dbPath), 'audit-archives', archiveFiles(dbPath)[0]), '--keyring',
      ring.path, '--json'],
    { cwd: serverRoot, env: { ...process.env }, encoding: 'utf-8', timeout: 60000 },
  );
  assert.equal(archiveCheck.status, 0, archiveCheck.stderr);

  // A stripped MAC after keyed rows is a downgrade, not "unkeyed history" — on a
  // fresh compacted log, so the forged row above cannot break first.
  const other = tempRoot();
  const otherDb = nestedDb(other);
  seed(otherDb, 14);
  cliJson(otherDb, ['audit', 'compact', '--max-rows', '7', '--apply']);
  const live = new Database(otherDb, { readonly: true });
  const victim = live.prepare('SELECT MIN(id) AS id FROM audit_log').get().id;
  live.close();
  const db2 = new Database(otherDb);
  db2.prepare('UPDATE audit_log SET entry_mac = NULL, key_id = NULL WHERE id = ?').run(victim + 1);
  db2.close();
  const downgraded = JSON.parse(cli(otherDb, ['audit', 'verify', '--json']).stdout);
  assert.equal(downgraded.ok, false);
  assert.equal(downgraded.first_broken.classification, 'unkeyed');
  assert.equal(downgraded.first_broken.id, victim + 1);
});

test('the archive contains exactly the stored fields — no token, header, body or key material', () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  const ring = seed(dbPath, 6);
  const run = cliJson(dbPath, ['audit', 'compact', '--max-rows', '2', '--apply']);

  const dir = path.dirname(dbPath);
  const archive = fs.readFileSync(path.join(dir, run.archive.path), 'utf8');
  const manifest = fs.readFileSync(path.join(dir, run.manifest.path), 'utf8');
  const material = ring.keys[0].material;

  for (const [name, content] of [
    ['archive', archive],
    ['manifest', manifest],
  ]) {
    assert.ok(!content.includes(material), `${name} must not contain key material`);
    assert.ok(!content.includes('Bearer '), `${name} must not contain a credential`);
    assert.ok(!content.includes('authorization'), `${name} must not contain a header`);
  }

  const rows = archiveRows(path.join(dir, run.archive.path));
  assert.ok(rows.length > 0);
  const allowed = new Set([
    'id', 'actor', 'role', 'authenticated', 'method', 'path', 'status_code',
    'action', 'detail', 'created_at', 'prev_hash', 'entry_hash', 'key_id', 'entry_mac',
  ]);
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      assert.ok(allowed.has(key), `archive row has an unexpected field: ${key}`);
    }
  }
  // The manifest records key ids only.
  const parsed = JSON.parse(manifest);
  assert.deepEqual(parsed.key_ids, [ring.active]);
  assert.ok(parsed.tail.entry_mac);
  assert.equal(
    createHash('sha256').update(fs.readFileSync(path.join(dir, run.archive.path))).digest('hex'),
    parsed.archive.sha256,
  );
});
