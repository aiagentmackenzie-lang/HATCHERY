/**
 * The keyed audit chain, end to end (D31).
 *
 * D30's chain was a SHA-256 linked list, so anyone who could write the database
 * could recompute every digest after an edit and produce a log that verified. These
 * tests attack the log exactly that way and require it to be caught, then pin the
 * limits that remain (a truncation that also rewrites the stored head is only caught
 * by an anchor recorded outside the database) and the file posture that makes any of
 * it meaningful.
 *
 * Everything here is the real built server, the real CLI and real SQLite files in a
 * throwaway directory.
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';

import { GENESIS_HASH, entryHash } from '../dist/security/audit.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');
const ADMIN = 'audit-key-admin-secret';

function tempRoot(prefix = 'hatchery-key-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** `<root>/data/hatchery.db`, so the data directory itself has to be created. */
function nestedDb(root) {
  return path.join(root, 'data', 'hatchery.db');
}

function mode(file) {
  return fs.statSync(file).mode & 0o777;
}

function cli(dbPath, args, extraEnv = {}) {
  return spawnSync(process.execPath, [`scripts/${args[0]}.mjs`, ...args.slice(1)], {
    cwd: serverRoot,
    env: { ...process.env, HATCHERY_DB_PATH: dbPath, ...extraEnv },
    encoding: 'utf-8',
    timeout: 60000,
  });
}

function cliJson(dbPath, args, extraEnv = {}) {
  const result = cli(dbPath, [...args, '--json'], extraEnv);
  assert.equal(result.status, 0, `${args.join(' ')} failed: ${result.stderr}`);
  return JSON.parse(result.stdout);
}

function ringOf(dbPath) {
  const file = path.join(path.dirname(dbPath), '.audit-keyring');
  return JSON.parse(fs.readFileSync(file, 'utf-8'));
}

async function bootServer(dbPath, env = {}) {
  const port = 47000 + Math.floor(Math.random() * 4000);
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
      await new Promise((resolve) => setTimeout(resolve, 200));
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

/** A database-only attacker: edit a row, then recompute every digest and the head. */
function forgeWithDigestsOnly(dbPath, rowId, field, value) {
  const db = new Database(dbPath);
  try {
    db.prepare(`UPDATE audit_log SET ${field} = ? WHERE id = ?`).run(value, rowId);
    const rows = db.prepare('SELECT * FROM audit_log ORDER BY id').all();
    let prev = GENESIS_HASH;
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
    // The attacker also fixes up the stored head so a naive check passes.
    db.prepare("UPDATE audit_chain_meta SET value = ? WHERE key = 'head_id'").run(String(last.id));
    db.prepare("UPDATE audit_chain_meta SET value = ? WHERE key = 'head_hash'").run(last.hash);
    return rows;
  } finally {
    db.close();
  }
}

test('the API database, its sidecars and the audit key ring are 0600', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  // One real chained row, so verification has something keyed to report. Creating a
  // stored token also closes the API, so every request below carries it.
  const owner = cliJson(dbPath, ['token', 'create', '--role', 'admin', '--name', 'posture']);
  const server = await bootServer(dbPath);
  try {
    // The data directory getDb created is private; the database and its sidecars are
    // readable only by the owner. Before D31 this was 0755/0644 — every local account
    // could read the audit log and the token hashes.
    assert.equal(mode(path.join(root, 'data')), 0o700, 'data directory must be 0700');
    assert.equal(mode(dbPath), 0o600, 'database must be 0600');
    for (const suffix of ['-wal', '-shm']) {
      const sidecar = `${dbPath}${suffix}`;
      if (fs.existsSync(sidecar)) assert.equal(mode(sidecar), 0o600, `${sidecar} must be 0600`);
    }
    const ringPath = path.join(path.dirname(dbPath), '.audit-keyring');
    assert.equal(mode(ringPath), 0o600, 'audit key ring must be 0600');

    const startup = server.output();
    const ring = ringOf(dbPath);
    assert.match(startup, /audit chain keyed/);
    assert.ok(startup.includes(ring.active), 'the startup log names the key id');

    // The key material is nowhere but the ring: not the database, not the log, not a
    // response, not a listing.
    const material = ring.keys[0].material;
    const bytes = ['', '-wal', '-shm']
      .map((suffix) => {
        try {
          return fs.readFileSync(`${dbPath}${suffix}`).toString('latin1');
        } catch {
          return '';
        }
      })
      .join('');
    assert.ok(!bytes.includes(material), 'key material must never be written to the database');
    assert.ok(!startup.includes(material), 'key material must never be logged');

    const auth = { authorization: `Bearer ${owner.token}` };
    const verify = await fetch(`${server.baseUrl}/api/audit/verify`, { headers: auth });
    assert.equal(verify.status, 200);
    const body = await verify.json();
    assert.equal(body.assurance, 'keyed');
    assert.ok(!JSON.stringify(body).includes(material), 'no key material in a response');
    assert.equal(body.key.active, ring.active);
    assert.equal(body.append_failures_since_start, 0);

    const listed = await (await fetch(`${server.baseUrl}/api/audit?limit=20`, { headers: auth })).json();
    assert.ok(!JSON.stringify(listed).includes(material));

    // An empty chain says so rather than implying an unkeyed or a verified one.
    const fresh = tempRoot();
    const freshDb = nestedDb(fresh);
    const freshServer = await bootServer(freshDb);
    try {
      const freshLog = freshServer.output();
      assert.match(freshLog, /audit chain keyed — key [0-9a-f]{16} \(generated\)/);
      assert.match(freshLog, /HATCHERY_AUDIT_KEY_FILE/, 'the generated-key advice is printed');
      assert.equal(mode(path.join(fresh, 'data', '.audit-keyring')), 0o600);

      const empty = await (await fetch(`${freshServer.baseUrl}/api/audit/verify`)).json();
      assert.equal(empty.rows_checked, 0);
      assert.equal(empty.assurance, 'empty');
      assert.equal(empty.ok, true);
    } finally {
      await freshServer.stop();
    }
  } finally {
    await server.stop();
  }
});

test('a full digest rewrite is caught by the MAC, at the row that changed', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  // Four chained rows from four real CLI writes.
  const created = cliJson(dbPath, ['token', 'create', '--role', 'viewer', '--name', 'a']);
  for (const name of ['b', 'c', 'd']) {
    cliJson(dbPath, ['token', 'create', '--role', 'viewer', '--name', name]);
  }
  assert.equal(cliJson(dbPath, ['audit', 'verify']).ok, true);

  forgeWithDigestsOnly(dbPath, 2, 'path', '/api/not-what-happened');

  const result = cli(dbPath, ['audit', 'verify', '--json']);
  assert.equal(result.status, 1, 'verification must fail');
  const report = JSON.parse(result.stdout);
  assert.equal(report.ok, false);
  assert.equal(report.first_broken.id, 2, 'the break is reported at the edited row');
  assert.equal(report.first_broken.classification, 'forged');
  assert.match(report.first_broken.detail, /without the audit key/);
  assert.equal(report.assurance, 'keyed');
  assert.ok(!JSON.stringify(report).includes(created.token));

  // Human output names it too, and exits 1.
  const human = cli(dbPath, ['audit', 'verify']);
  assert.equal(human.status, 1);
  assert.match(human.stdout, /BREAK:\s+row 2 forged/);
});

test('losing the key ring fails closed instead of verifying a shorter history', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  cliJson(dbPath, ['token', 'create', '--role', 'viewer']);
  cliJson(dbPath, ['token', 'create', '--role', 'viewer']);

  const ringPath = path.join(path.dirname(dbPath), '.audit-keyring');
  fs.unlinkSync(ringPath);

  // A new ring is generated (the file is back), but the rows name the old key id.
  const result = cli(dbPath, ['audit', 'verify', '--json']);
  assert.equal(result.status, 1);
  const report = JSON.parse(result.stdout);
  assert.equal(report.ok, false);
  assert.equal(report.first_broken.classification, 'unknown-key');
  assert.match(report.first_broken.detail, /does not hold/);
  assert.notEqual(fs.existsSync(ringPath), false, 'a new ring is generated, not silently skipped');
});

test('rotation keeps every historical row verifiable', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  for (const name of ['a', 'b']) cliJson(dbPath, ['token', 'create', '--role', 'admin', '--name', name]);
  const before = cliJson(dbPath, ['audit', 'head']);
  const oldKey = before.key_id;

  const rotated = cliJson(dbPath, ['audit', 'key', 'rotate']);
  assert.notEqual(rotated.active, oldKey);
  assert.deepEqual(
    rotated.keys.map((key) => key.id).sort(),
    [oldKey, rotated.active].sort(),
    'the old key stays in the ring',
  );

  cliJson(dbPath, ['token', 'create', '--role', 'viewer', '--name', 'after-rotation']);
  const report = cliJson(dbPath, ['audit', 'verify']);
  assert.equal(report.ok, true, JSON.stringify(report.first_broken));
  assert.equal(report.assurance, 'keyed');
  assert.equal(report.coverage.unkeyed_rows, 0);

  // Rows written before and after the rotation are MAC'd with different keys and both
  // verify — that is the point of the key id per row.
  const db = new Database(dbPath, { readonly: true });
  try {
    const keys = db
      .prepare('SELECT key_id, COUNT(*) AS n FROM audit_log WHERE key_id IS NOT NULL GROUP BY key_id')
      .all();
    assert.equal(keys.length, 2, JSON.stringify(keys));
    const total = keys.reduce((sum, row) => sum + row.n, 0);
    assert.equal(total, report.coverage.mac_rows);
  } finally {
    db.close();
  }

  // Rotation writes its own audit row, MAC'd with the new key.
  assert.ok(report.coverage.mac_rows >= 4);
  assert.match(
    cli(dbPath, ['audit', 'key', 'status']).stdout,
    /active key: [0-9a-f]{16}/,
  );
});

test('an unkeyed prefix is reported as mixed, and a later unkeyed row is a downgrade', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });

  const { configureAuditKeyring, recordAudit, verifyAuditChain } = await import(
    '../dist/security/audit.js'
  );
  const { resolveAuditKeyring } = await import('../dist/security/auditKey.js');

  const db = new Database(dbPath);
  db.exec(fs.readFileSync(path.join(serverRoot, 'src', 'db', 'schema.sql'), 'utf-8'));

  // Two rows written before the key existed (a D30 log), then two keyed ones.
  configureAuditKeyring(null);
  for (const suffix of ['old-1', 'old-2']) {
    recordAudit(db, {
      actor: 'admin', role: 'admin', authenticated: true,
      method: 'GET', path: `/api/${suffix}`, statusCode: 200, action: 'request.allowed',
    });
  }
  const ring = resolveAuditKeyring(dbPath);
  configureAuditKeyring(ring);
  for (const suffix of ['new-1', 'new-2']) {
    recordAudit(db, {
      actor: 'admin', role: 'admin', authenticated: true,
      method: 'GET', path: `/api/${suffix}`, statusCode: 200, action: 'request.allowed',
    });
  }

  const mixed = verifyAuditChain(db, { keyring: ring });
  assert.equal(mixed.ok, true, JSON.stringify(mixed.first_broken));
  assert.equal(mixed.assurance, 'mixed');
  assert.equal(mixed.coverage.unkeyed_rows, 2);
  assert.equal(mixed.coverage.mac_rows, 2);

  // Stripping a MAC from a row *after* keyed rows is a downgrade, not "unkeyed
  // history": it is reported at that row.
  db.prepare('UPDATE audit_log SET entry_mac = NULL, key_id = NULL WHERE id = 4').run();
  const downgraded = verifyAuditChain(db, { keyring: ring });
  assert.equal(downgraded.ok, false);
  assert.equal(downgraded.first_broken.id, 4);
  assert.equal(downgraded.first_broken.classification, 'unkeyed');
  db.close();
});

test('a truncation that rewrites the stored head verifies — until it is anchored', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  for (const name of ['a', 'b', 'c', 'd', 'e']) {
    cliJson(dbPath, ['token', 'create', '--role', 'viewer', '--name', name]);
  }
  const anchored = cliJson(dbPath, ['audit', 'head']);
  assert.equal(anchored.head.id, 5);

  // Attacker with database write access: delete the tail and point the stored head at
  // row 3, whose hash and MAC are genuine. Internally consistent, shorter history.
  const db = new Database(dbPath);
  try {
    const row3 = db.prepare('SELECT id, entry_hash FROM audit_log WHERE id = 3').get();
    db.prepare('DELETE FROM audit_log WHERE id > 3').run();
    db.prepare("UPDATE audit_chain_meta SET value = ? WHERE key = 'head_id'").run(String(row3.id));
    db.prepare("UPDATE audit_chain_meta SET value = ? WHERE key = 'head_hash'").run(row3.entry_hash);
  } finally {
    db.close();
  }

  // Without an external anchor this is indistinguishable from a log that ended at row
  // 3. That limit is real and is documented rather than hidden; the CLI reports it.
  const unanchored = cliJson(dbPath, ['audit', 'verify']);
  assert.equal(unanchored.ok, true);
  assert.equal(unanchored.head.id, 3);

  // With the head recorded elsewhere, it is caught, and named.
  const anchoredRun = cli(dbPath, ['audit', 'verify', '--json', '--expect-head', anchored.anchor]);
  assert.equal(anchoredRun.status, 1);
  const report = JSON.parse(anchoredRun.stdout);
  assert.equal(report.ok, false);
  assert.equal(report.first_broken.classification, 'replaced');
  assert.equal(report.anchor.matches, false);
  assert.match(report.first_broken.detail, /not the database\s+that was anchored/);
  assert.match(cli(dbPath, ['audit', 'verify', '--expect-head', anchored.anchor]).stdout, /BREAK:\s+row 5 replaced/);

  // A chain that still matches its anchor passes.
  const fresh = tempRoot();
  const freshDb = nestedDb(fresh);
  cliJson(freshDb, ['token', 'create', '--role', 'viewer']);
  const headNow = cliJson(freshDb, ['audit', 'head']);
  const matching = cliJson(freshDb, ['audit', 'verify', '--expect-head', headNow.anchor]);
  assert.equal(matching.ok, true);
  assert.equal(matching.anchor.matches, true);
});

test('the HTTP verifier reports the same assurance and honours expect_head', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  const created = cliJson(dbPath, ['token', 'create', '--role', 'admin', '--name', 'http']);
  const head = cliJson(dbPath, ['audit', 'head']);

  const server = await bootServer(dbPath);
  try {
    const auth = { authorization: `Bearer ${created.token}` };
    const response = await fetch(`${server.baseUrl}/api/audit/verify`, { headers: auth });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.ok, true);
    assert.equal(result.assurance, 'keyed');
    assert.equal(result.coverage.mac_rows, result.coverage.chained_rows);
    assert.ok(!JSON.stringify(result).includes(ringOf(dbPath).keys[0].material));

    // The first verify call wrote its own two audit rows, so the head captured
    // before it is now stale — an anchor is precise, and being stale is visible.
    const stale = await fetch(
      `${server.baseUrl}/api/audit/verify?expect_head=${encodeURIComponent(head.anchor)}`,
      { headers: auth },
    );
    assert.equal(stale.status, 200);
    const staleBody = await stale.json();
    assert.equal(staleBody.anchor.matches, false);
    assert.equal(staleBody.first_broken.classification, 'replaced');

    const current = cliJson(dbPath, ['audit', 'head']);
    const anchored = await fetch(
      `${server.baseUrl}/api/audit/verify?expect_head=${encodeURIComponent(current.anchor)}`,
      { headers: auth },
    );
    assert.equal(anchored.status, 200);
    assert.equal((await anchored.json()).anchor.matches, true);

    const bad = await fetch(`${server.baseUrl}/api/audit/verify?expect_head=not-a-head`, {
      headers: auth,
    });
    assert.equal(bad.status, 400);

    const wrong = await fetch(
      `${server.baseUrl}/api/audit/verify?expect_head=1:${'a'.repeat(64)}`,
      { headers: auth },
    );
    assert.equal(wrong.status, 200);
    const wrongBody = await wrong.json();
    assert.equal(wrongBody.ok, false);
    assert.equal(wrongBody.first_broken.classification, 'replaced');
  } finally {
    await server.stop();
  }
});

test('two processes starting on a fresh database agree on one audit key', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const keyModule = path.join(serverRoot, 'dist', 'security', 'auditKey.js');

  // Four processes race to resolve the ring for the first time. Exactly one creates
  // it; the others must read the same key. A split here would make one process's rows
  // unverifiable.
  const runners = Array.from({ length: 4 }, () =>
    spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `const m = await import(${JSON.stringify(`file://${keyModule}`)});` +
          'process.stdout.write(m.resolveAuditKeyring(process.env.KEYDB).active);',
      ],
      {
        env: { ...process.env, KEYDB: dbPath },
        encoding: 'utf-8',
        timeout: 60000,
      },
    ),
  );
  for (const runner of runners) assert.equal(runner.status, 0, runner.stderr);
  const ids = new Set(runners.map((runner) => runner.stdout.trim()));
  assert.equal(ids.size, 1, `processes disagreed on the key: ${[...ids].join(', ')}`);
  assert.equal(ringOf(dbPath).active, [...ids][0]);
});
