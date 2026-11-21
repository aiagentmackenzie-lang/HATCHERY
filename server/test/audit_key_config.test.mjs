/**
 * Audit key sources and the refusal to run without one (D31).
 *
 * A keyed chain that can be silently downgraded is worse than an honest unkeyed one:
 * the operator would read `ok: true` and believe the log was authenticated. These
 * tests pin the rules — which source wins, what is refused at startup, and that an
 * operator-supplied key never overwrites the ring that already holds history.
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');

function tempRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-auditkey-'));
}

function nestedDb(root) {
  return path.join(root, 'data', 'hatchery.db');
}

function material() {
  return randomBytes(32).toString('hex');
}

function cli(dbPath, args, env = {}) {
  return spawnSync(process.execPath, [`scripts/${args[0]}.mjs`, ...args.slice(1)], {
    cwd: serverRoot,
    env: { ...process.env, HATCHERY_DB_PATH: dbPath, ...env },
    encoding: 'utf-8',
    timeout: 60000,
  });
}

function cliJson(dbPath, args, env = {}) {
  const result = cli(dbPath, [...args, '--json'], env);
  assert.equal(result.status, 0, `${args.join(' ')}: ${result.stderr}`);
  return JSON.parse(result.stdout);
}

/** Start the server and wait for it to exit; a refusal is a zero-answer exit 1. */
async function expectStartupFailure(dbPath, env) {
  const port = 44000 + Math.floor(Math.random() * 3000);
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
  const result = await new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolve({ code: null, timedOut: true });
    }, 20000);
    child.once('exit', (code) => {
      clearTimeout(timer);
      resolve({ code, timedOut: false });
    });
  });
  return { ...result, output };
}

async function startServer(dbPath, env = {}) {
  const port = 45000 + Math.floor(Math.random() * 3000);
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
      await new Promise((resolve) => setTimeout(resolve, 300));
      if (child.exitCode === null) child.kill('SIGKILL');
    },
  };
}

test('HATCHERY_AUDIT_KEY is used as-is and is not copied beside the database', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  const key = material();

  const created = cliJson(dbPath, ['token', 'create', '--role', 'admin'], {
    HATCHERY_AUDIT_KEY: key,
  });
  const ringPath = path.join(path.dirname(dbPath), '.audit-keyring');
  assert.equal(fs.existsSync(ringPath), false, 'an operator key is not silently copied to disk');

  const report = cliJson(dbPath, ['audit', 'verify'], { HATCHERY_AUDIT_KEY: key });
  assert.equal(report.ok, true, JSON.stringify(report.first_broken));
  assert.equal(report.assurance, 'keyed');
  assert.equal(report.key.source, 'env');
  const { keyIdOf } = await import('../dist/security/auditKey.js');
  assert.equal(report.key.active, keyIdOf(key), 'the active key id derives from the env key');
  assert.equal(report.coverage.mac_rows, report.coverage.chained_rows);

  // The right key verifies; a different one fails closed instead of passing.
  const wrong = cli(dbPath, ['audit', 'verify', '--json'], { HATCHERY_AUDIT_KEY: material() });
  assert.equal(wrong.status, 1);
  const wrongReport = JSON.parse(wrong.stdout);
  assert.equal(wrongReport.ok, false);
  assert.equal(wrongReport.first_broken.classification, 'unknown-key');

  // The token is still usable — this test is about the chain, not the credential.
  assert.match(created.id, /^htk_[0-9a-f]{16}$/);
});

test('a malformed HATCHERY_AUDIT_KEY stops the API instead of downgrading the chain', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  const result = await expectStartupFailure(dbPath, { HATCHERY_AUDIT_KEY: 'not-64-hex' });
  assert.equal(result.timedOut, false, 'the server must exit, not keep running unkeyed');
  assert.notEqual(result.code, 0);
  assert.match(result.output, /audit key ring unusable/);
  assert.match(result.output, /64 hex characters/);
  assert.match(result.output, /refusing to start/);
});

test('a loose or symlinked key file is refused, a 0600 one is accepted', async () => {
  const root = tempRoot();
  const keyFile = path.join(root, 'audit.key');
  fs.writeFileSync(keyFile, `${material()}\n`, { mode: 0o600 });

  // Accepted: 0600, regular file.
  const good = cliJson(nestedDb(path.join(root, 'a')), ['token', 'create', '--role', 'viewer'], {
    HATCHERY_AUDIT_KEY_FILE: keyFile,
  });
  assert.match(good.id, /^htk_/);

  // Refused: readable by the group or others.
  fs.chmodSync(keyFile, 0o644);
  const loose = await expectStartupFailure(nestedDb(path.join(root, 'b')), {
    HATCHERY_AUDIT_KEY_FILE: keyFile,
  });
  assert.notEqual(loose.code, 0);
  assert.match(loose.output, /group\/other accessible/);

  // Refused: a symlink, even to a 0600 file.
  fs.chmodSync(keyFile, 0o600);
  const link = path.join(root, 'audit-link.key');
  fs.symlinkSync(keyFile, link);
  const symlinked = await expectStartupFailure(nestedDb(path.join(root, 'c')), {
    HATCHERY_AUDIT_KEY_FILE: link,
  });
  assert.notEqual(symlinked.code, 0);
  assert.match(symlinked.output, /symlink/);
});

test('the key ring is authoritative once it exists — an env key cannot replace history', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  // Establish a ring and one row.
  cliJson(dbPath, ['token', 'create', '--role', 'admin', '--name', 'first']);
  const head = cliJson(dbPath, ['audit', 'head']);
  const ringKey = head.key_id;

  // A different env key is configured afterwards. It must be reported and ignored,
  // otherwise rows would verify under a key that never wrote them.
  const envKey = material();
  const server = await startServer(dbPath, { HATCHERY_AUDIT_KEY: envKey });
  try {
    assert.match(server.output(), /HATCHERY_AUDIT_KEY is IGNORED/);
    const report = cliJson(dbPath, ['audit', 'verify'], { HATCHERY_AUDIT_KEY: envKey });
    assert.equal(report.ok, true, JSON.stringify(report.first_broken));
    assert.equal(report.key.active, ringKey);
    assert.equal(report.key.env_ignored, true);
  } finally {
    await server.stop();
  }
});

test('rotating a key configured from the environment materialises the ring first', () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  const envKey = material();
  cliJson(dbPath, ['token', 'create', '--role', 'viewer'], { HATCHERY_AUDIT_KEY: envKey });
  const before = cliJson(dbPath, ['audit', 'verify'], { HATCHERY_AUDIT_KEY: envKey });
  assert.equal(before.key.source, 'env');

  const rotated = cliJson(dbPath, ['audit', 'key', 'rotate'], { HATCHERY_AUDIT_KEY: envKey });
  assert.equal(rotated.source, 'ring');
  const ring = JSON.parse(
    fs.readFileSync(path.join(path.dirname(dbPath), '.audit-keyring'), 'utf-8'),
  );
  assert.equal(ring.keys.length, 2, 'the env key is preserved in the ring');
  assert.notEqual(ring.active, before.key.active);
  assert.ok(ring.keys.some((key) => key.id === before.key.active));

  // History still verifies, now via the ring, with no env key at all.
  const after = cliJson(dbPath, ['audit', 'verify']);
  assert.equal(after.ok, true, JSON.stringify(after.first_broken));
  assert.equal(after.assurance, 'keyed');
  assert.equal(after.coverage.unkeyed_rows, 0);
});

test('a corrupt or loose key ring is refused rather than replaced', async () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  cliJson(dbPath, ['token', 'create', '--role', 'viewer']);
  const ringPath = path.join(path.dirname(dbPath), '.audit-keyring');
  const original = fs.readFileSync(ringPath, 'utf-8');

  // Newer version than this build understands.
  const parsed = JSON.parse(original);
  fs.writeFileSync(ringPath, JSON.stringify({ ...parsed, version: 2 }), { mode: 0o600 });
  const newer = await expectStartupFailure(dbPath, {});
  assert.notEqual(newer.code, 0);
  assert.match(newer.output, /unsupported key-ring version 2/);

  // Tampered material (id no longer matches) is refused, not "repaired".
  const tampered = JSON.parse(original);
  tampered.keys[0].id = 'ffffffffffffffff';
  fs.writeFileSync(ringPath, JSON.stringify(tampered), { mode: 0o600 });
  const bad = await expectStartupFailure(dbPath, {});
  assert.notEqual(bad.code, 0);
  assert.match(bad.output, /key id does not match its material/);

  // Restoring the original ring makes it work again — nothing was overwritten.
  fs.writeFileSync(ringPath, original, { mode: 0o600 });
  const report = cliJson(dbPath, ['audit', 'verify']);
  assert.equal(report.ok, true);

  // A world-readable ring is refused even though its contents are valid.
  fs.chmodSync(ringPath, 0o644);
  const loose = await expectStartupFailure(dbPath, {});
  assert.notEqual(loose.code, 0);
  assert.match(loose.output, /key ring must be 0600/);
});

test('the audit key never appears in the token CLI or the audit CLI output', () => {
  const root = tempRoot();
  const dbPath = nestedDb(root);
  const key = material();
  const env = { HATCHERY_AUDIT_KEY: key };

  const outputs = [
    cli(dbPath, ['token', 'create', '--role', 'admin'], env),
    cli(dbPath, ['token', 'list'], env),
    cli(dbPath, ['audit', 'head'], env),
    cli(dbPath, ['audit', 'verify'], env),
    cli(dbPath, ['audit', 'key', 'status'], env),
  ];
  for (const result of outputs) {
    assert.ok(!result.stdout.includes(key), 'key material must not be printed on stdout');
    assert.ok(!result.stderr.includes(key), 'key material must not be printed on stderr');
  }

  // And it is not inside the database either.
  const db = new Database(dbPath, { readonly: true });
  try {
    const dump = JSON.stringify(
      db.prepare('SELECT * FROM audit_log').all(),
    );
    assert.ok(!dump.includes(key));
    assert.match(dump, /[0-9a-f]{16}/, 'key ids are recorded, not key material');
  } finally {
    db.close();
  }
});
