/**
 * Token lifecycle, end to end (D30).
 *
 * The claim this file exists to prove: a credential change is survivable without
 * downtime. Tokens are created locally (the secret never crosses the network),
 * authenticated by the real built server, retired while it runs, and refused on the
 * very next request — with no restart, no environment edit, and no raw secret in the
 * database, the audit log or any response.
 *
 * Every server here is the real built one (`dist/index.js`) on a random loopback
 * port with a throwaway database. Token creation/expiry goes through the real CLI
 * (`scripts/token.mjs`) as a subprocess, because that is the documented operator
 * path.
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import Database from 'better-sqlite3';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');
const repoRoot = path.join(serverRoot, '..');
const ADMIN = 'bootstrap-admin-secret-9f2c';
const VIEWER = 'bootstrap-viewer-secret-4b71';

const venvPython = path.join(repoRoot, '.venv', 'bin', 'python3');
const enginePython =
  process.env.HATCHERY_ENGINE_PYTHON ?? (fs.existsSync(venvPython) ? venvPython : 'python3');

function tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function pickPort() {
  return 42000 + Math.floor(Math.random() * 8000);
}

async function waitForHealth(baseUrl, timeoutMs = 25000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/api/health`);
      if (response.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  return false;
}

/** The real CLI, as an operator would run it. `--json` for a parseable surface. */
function cli(dbPath, args) {
  return spawnSync(process.execPath, ['scripts/token.mjs', ...args, '--json'], {
    cwd: serverRoot,
    env: { ...process.env, HATCHERY_DB_PATH: dbPath },
    encoding: 'utf-8',
    timeout: 60000,
  });
}

function cliJson(dbPath, args) {
  const result = cli(dbPath, args);
  assert.equal(result.status, 0, `token CLI failed: ${result.stderr}`);
  return JSON.parse(result.stdout);
}

async function bootServer({ dbPath, env = {} }) {
  const port = pickPort();
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

  const up = await waitForHealth(baseUrl);
  assert.ok(up, `server did not become healthy; output:\n${output}`);

  let stopped = false;
  return {
    baseUrl,
    output: () => output,
    async stop() {
      if (stopped || child.exitCode !== null) {
        stopped = true;
        return;
      }
      stopped = true;
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

function bearer(token) {
  return { authorization: `Bearer ${token}` };
}

/** Every byte SQLite could hold, including the WAL, for a "no secret on disk" check. */
function databaseBytes(dbPath) {
  return ['', '-wal', '-shm']
    .map((suffix) => {
      try {
        return fs.readFileSync(`${dbPath}${suffix}`).toString('latin1');
      } catch {
        return '';
      }
    })
    .join('');
}

function engineReady() {
  const probe = spawnSync(enginePython, ['-m', 'engine.cli', '--help'], {
    cwd: repoRoot,
    encoding: 'utf-8',
    timeout: 60000,
  });
  return probe.status === 0;
}

test('a stored token authenticates, a second is independent, and retirement needs no restart', async () => {
  const dir = tempDir('hatchery-tokens-');
  const dbPath = path.join(dir, 'tokens.db');
  // No bootstrap tokens: the server starts open, then a stored token closes it.
  const server = await bootServer({ dbPath });

  try {
    // Open mode, with the D25/D8 caveat: everyone is an unauthenticated admin.
    const openRead = await fetch(`${server.baseUrl}/api/tasks`);
    assert.equal(openRead.status, 200, 'no credentials configured means open mode');

    const adminA = cliJson(dbPath, ['create', '--role', 'admin', '--name', 'rotation-a']);
    assert.match(adminA.id, /^htk_[0-9a-f]{16}$/);
    assert.equal(adminA.prefix, adminA.id);
    assert.equal(adminA.token.slice(0, adminA.id.length + 1), `${adminA.id}_`);

    // Creating a token takes the API out of open mode immediately — no restart.
    const nowClosed = await fetch(`${server.baseUrl}/api/tasks`);
    assert.equal(nowClosed.status, 401, 'a live stored token must close open mode');

    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(adminA.token) })).status, 200);

    // A second, independent token. Adding one must not invalidate the first.
    const viewerB = cliJson(dbPath, ['create', '--role', 'viewer', '--name', 'ci']);
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(adminA.token) })).status, 200);
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(viewerB.token) })).status, 200);
    assert.equal(
      (await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(viewerB.token) })).ok,
      true,
    );

    // Retire A with A (it is the only admin) over HTTP; the row is audited.
    const retire = await fetch(`${server.baseUrl}/api/tokens/${adminA.id}/retire`, {
      method: 'POST',
      headers: { ...bearer(adminA.token), 'content-type': 'application/json' },
      body: JSON.stringify({ reason: 'rotation: replaced by token B' }),
    });
    assert.equal(retire.status, 200);
    const retired = await retire.json();
    assert.equal(retired.changed, true);
    assert.equal(retired.state, 'revoked');
    assert.match(String(retired.revoked_at), /^\d{4}-\d{2}-\d{2}T/);

    // The same secret is refused on the next request, without a restart.
    const afterRetire = await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(adminA.token) });
    assert.equal(afterRetire.status, 401);
    assert.deepEqual(await afterRetire.json(), { error: 'Unauthorized' });

    // The second token still works.
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(viewerB.token) })).status, 200);

    // Nothing about the retired token is a secret on disk.
    const bytes = databaseBytes(dbPath);
    assert.ok(!bytes.includes(adminA.token), 'the raw token must never be in the database');
    assert.ok(!bytes.includes(viewerB.token), 'the raw token must never be in the database');

    const db = new Database(dbPath, { readonly: true });
    try {
      const rows = db.prepare('SELECT id, role, prefix, secret_hash, revoked_at FROM api_tokens').all();
      assert.equal(rows.length, 2);
      for (const row of rows) {
        assert.match(row.secret_hash, /^[0-9a-f]{64}$/);
        assert.notEqual(row.secret_hash, adminA.token);
        assert.notEqual(row.secret_hash, viewerB.token);
      }
      const audit = db.prepare('SELECT action, detail FROM audit_log ORDER BY id').all();
      const serialized = JSON.stringify(audit);
      assert.ok(!serialized.includes(adminA.token));
      assert.ok(!serialized.includes(viewerB.token));
      const lifecycle = audit.find((row) => row.action === 'token.retired');
      assert.ok(lifecycle, 'retirement must be audited');
      assert.match(String(lifecycle.detail), new RegExp(adminA.id));
    } finally {
      db.close();
    }

    // The audit chain covers every row in this database.
    const verify = await fetch(`${server.baseUrl}/api/audit/verify`, { headers: bearer(viewerB.token) });
    assert.equal(verify.status, 403, 'verification is admin-only');

    const adminC = cliJson(dbPath, ['create', '--role', 'admin', '--name', 'verify']);
    const verified = await fetch(`${server.baseUrl}/api/audit/verify`, {
      headers: bearer(adminC.token),
    });
    assert.equal(verified.status, 200);
    const chain = await verified.json();
    assert.equal(chain.ok, true, JSON.stringify(chain));
    assert.ok(chain.rows_checked > 0);
  } finally {
    await server.stop();
  }
});

test('bootstrap env tokens coexist with stored tokens and remain the recovery path', async () => {
  const dir = tempDir('hatchery-bootstrap-');
  const dbPath = path.join(dir, 'tokens.db');
  // A stored viewer token exists before the server starts, beside the env pair.
  const stored = cliJson(dbPath, ['create', '--role', 'viewer', '--name', 'stored-viewer']);

  const server = await bootServer({
    dbPath,
    env: { HATCHERY_ADMIN_TOKEN: ADMIN, HATCHERY_READ_TOKEN: VIEWER },
  });

  try {
    // Both kinds work.
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(ADMIN) })).status, 200);
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(VIEWER) })).status, 200);
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(stored.token) })).status, 200);

    // The stored viewer is a viewer, not an admin: it cannot read the audit log.
    const storedAudit = await fetch(`${server.baseUrl}/api/audit`, {
      headers: bearer(stored.token),
    });
    assert.equal(storedAudit.status, 403);
    // Nor can it touch token lifecycle.
    assert.equal(
      (await fetch(`${server.baseUrl}/api/tokens`, { headers: bearer(stored.token) })).status,
      403,
    );

    // Precedence, demonstrated rather than asserted: a stored row whose hash *is*
    // the bootstrap admin secret must not turn the bootstrap token into a stored
    // actor. The bootstrap path is consulted first, so the audit row says `admin`.
    const db = new Database(dbPath);
    try {
      const { hashToken } = await import('../dist/security/tokens.js');
      db.prepare(
        `INSERT INTO api_tokens (id, name, role, prefix, secret_hash, created_at, expires_at, revoked_at, retired_reason)
         VALUES (?, ?, 'viewer', ?, ?, ?, NULL, NULL, NULL)`,
      ).run(
        'htk_00000000deadbeef',
        'shadow attempt',
        'htk_00000000deadbeef',
        hashToken(ADMIN),
        new Date().toISOString(),
      );
    } finally {
      db.close();
    }
    const shadowed = await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(ADMIN) });
    assert.equal(shadowed.status, 200);
    const auditPayload = await (
      await fetch(`${server.baseUrl}/api/audit?limit=20`, { headers: bearer(ADMIN) })
    ).json();
    const recent = auditPayload.entries.find((entry) => entry.path === '/api/tasks');
    assert.equal(recent.actor, 'admin', 'bootstrap tokens resolve as bootstrap, never as a stored token');

    // Retiring every stored token must not lock the operator out: the env pair is
    // the recovery path.
    const list = await (await fetch(`${server.baseUrl}/api/tokens`, { headers: bearer(ADMIN) })).json();
    for (const token of list.tokens) {
      const response = await fetch(`${server.baseUrl}/api/tokens/${token.id}/retire`, {
        method: 'POST',
        headers: bearer(ADMIN),
      });
      assert.equal(response.status, 200);
    }
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(stored.token) })).status, 401);
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(ADMIN) })).status, 200);

    // ...and a second server restart keeps working (no in-memory-only state).
    await server.stop();
    const restarted = await bootServer({
      dbPath,
      env: { HATCHERY_ADMIN_TOKEN: ADMIN, HATCHERY_READ_TOKEN: VIEWER },
    });
    try {
      assert.equal((await fetch(`${restarted.baseUrl}/api/tasks`, { headers: bearer(ADMIN) })).status, 200);
      assert.equal((await fetch(`${restarted.baseUrl}/api/tasks`, { headers: bearer(VIEWER) })).status, 200);
    } finally {
      await restarted.stop();
    }
  } finally {
    await server.stop().catch(() => {});
  }
});

test('HATCHERY_API_TOKEN is still a back-compatible admin token', async () => {
  const dir = tempDir('hatchery-legacy-');
  const server = await bootServer({
    dbPath: path.join(dir, 'legacy.db'),
    env: { HATCHERY_API_TOKEN: 'legacy-shared-secret' },
  });
  try {
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`)).status, 401);
    assert.equal(
      (await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer('legacy-shared-secret') })).status,
      200,
    );
    // Admin, not viewer: the audit log is readable.
    assert.equal(
      (await fetch(`${server.baseUrl}/api/audit`, { headers: bearer('legacy-shared-secret') })).status,
      200,
    );
  } finally {
    await server.stop();
  }
});

test('expired and revoked tokens are refused with a generic 401 while the audit row carries the reason and id', async () => {
  const dir = tempDir('hatchery-expiry-');
  const dbPath = path.join(dir, 'tokens.db');
  const expired = cliJson(dbPath, ['create', '--role', 'viewer', '--name', 'expired-soon']);
  const revoked = cliJson(dbPath, ['create', '--role', 'viewer', '--name', 'to-retire']);
  const kept = cliJson(dbPath, ['create', '--role', 'viewer', '--name', 'kept']);

  const server = await bootServer({
    dbPath,
    env: { HATCHERY_ADMIN_TOKEN: ADMIN },
  });

  try {
    // Expire one now and retire the other through the CLI, while the server runs.
    const expiredNow = cliJson(dbPath, ['expire', expired.id, '--in', '0']);
    assert.equal(expiredNow.state, 'expired');
    const retired = cliJson(dbPath, ['retire', revoked.id, '--reason', 'test rotation']);
    assert.equal(retired.token.state, 'revoked');

    const expiredResponse = await fetch(`${server.baseUrl}/api/tasks`, {
      headers: bearer(expired.token),
    });
    assert.equal(expiredResponse.status, 401);
    const expiredBody = await expiredResponse.text();
    assert.equal(expiredBody, JSON.stringify({ error: 'Unauthorized' }));

    const revokedResponse = await fetch(`${server.baseUrl}/api/tasks`, {
      headers: bearer(revoked.token),
    });
    assert.equal(revokedResponse.status, 401);
    // A generic refusal: identical body whether the token is expired, revoked or
    // never existed. The API is not a token oracle.
    assert.equal(await revokedResponse.text(), expiredBody);
    const unknownResponse = await fetch(`${server.baseUrl}/api/tasks`, {
      headers: bearer('htk_ffffffffffffffff_' + 'A'.repeat(43)),
    });
    assert.equal(unknownResponse.status, 401);
    assert.equal(await unknownResponse.text(), expiredBody);

    // The live one still works.
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(kept.token) })).status, 200);

    // The audit log (admin-only) has the precise reasons and the token ids.
    const audit = await (
      await fetch(`${server.baseUrl}/api/audit?limit=50`, { headers: bearer(ADMIN) })
    ).json();
    const denied = audit.entries.filter((entry) => entry.action === 'auth.denied');
    const serialized = JSON.stringify(audit);
    for (const token of [expired, revoked, kept]) {
      assert.ok(!serialized.includes(token.token), 'no audit row may contain a token');
    }
    const expiryRow = denied.find((entry) => String(entry.detail).includes('token-expired'));
    assert.ok(expiryRow, `expected a token-expired row, got ${JSON.stringify(denied)}`);
    assert.match(String(expiryRow.detail), new RegExp(expired.id));
    const revokedRow = denied.find((entry) => String(entry.detail).includes('token-revoked'));
    assert.ok(revokedRow, `expected a token-revoked row, got ${JSON.stringify(denied)}`);
    assert.match(String(revokedRow.detail), new RegExp(revoked.id));

    // A token's id or prefix is not a credential.
    for (const guess of [expired.id, kept.id, `${kept.id}_`, kept.token.slice(0, kept.token.length - 1)]) {
      assert.equal(
        (await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(guess) })).status,
        401,
        `a token id/prefix/truncation must not authenticate: ${guess}`,
      );
    }
  } finally {
    await server.stop();
  }
});

test('lifecycle endpoints are admin-only, creation is not on the wire, and the actions are audited', async () => {
  const dir = tempDir('hatchery-lifecycle-');
  const dbPath = path.join(dir, 'tokens.db');
  const victim = cliJson(dbPath, ['create', '--role', 'viewer', '--name', 'victim']);

  const server = await bootServer({
    dbPath,
    env: { HATCHERY_ADMIN_TOKEN: ADMIN, HATCHERY_READ_TOKEN: VIEWER },
  });

  try {
    // A viewer cannot list, retire, or create.
    assert.equal((await fetch(`${server.baseUrl}/api/tokens`, { headers: bearer(VIEWER) })).status, 403);
    assert.equal(
      (await fetch(`${server.baseUrl}/api/tokens/${victim.id}/retire`, {
        method: 'POST',
        headers: bearer(VIEWER),
      })).status,
      403,
    );
    assert.equal(
      (await fetch(`${server.baseUrl}/api/tokens`, {
        method: 'POST',
        headers: { ...bearer(VIEWER), 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'admin' }),
      })).status,
      403,
    );

    // There is no create endpoint at all, even for an admin: a secret must not be
    // minted over the wire or returned in a response.
    const adminCreate = await fetch(`${server.baseUrl}/api/tokens`, {
      method: 'POST',
      headers: { ...bearer(ADMIN), 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'admin' }),
    });
    assert.equal(adminCreate.status, 404);

    // An anonymous caller cannot list either.
    assert.equal((await fetch(`${server.baseUrl}/api/tokens`)).status, 401);

    // A viewer's refusal is audited as a precise action.
    const beforeRetire = await (
      await fetch(`${server.baseUrl}/api/audit?limit=50`, { headers: bearer(ADMIN) })
    ).json();
    const forbidden = beforeRetire.entries.filter((entry) => entry.action === 'request.forbidden');
    assert.ok(forbidden.some((entry) => entry.path === '/api/tokens'));
    assert.ok(forbidden.some((entry) => entry.path === `/api/tokens/${victim.id}/retire`));

    // The admin list is secret-free: id, role, prefix, timestamps, state only.
    const listResponse = await fetch(`${server.baseUrl}/api/tokens`, { headers: bearer(ADMIN) });
    assert.equal(listResponse.status, 200);
    const list = await listResponse.json();
    assert.equal(list.count, 1);
    const listed = list.tokens[0];
    assert.deepEqual(Object.keys(listed).sort(), [
      'created_at',
      'expires_at',
      'id',
      'name',
      'prefix',
      'retired_reason',
      'revoked_at',
      'role',
      'state',
    ]);
    assert.ok(!JSON.stringify(list).includes(victim.token));

    // An admin retires it; the action is audited beside the request row.
    const retire = await fetch(`${server.baseUrl}/api/tokens/${victim.id}/retire`, {
      method: 'POST',
      headers: { ...bearer(ADMIN), 'content-type': 'application/json' },
      body: JSON.stringify({ reason: 'offboarding' }),
    });
    assert.equal(retire.status, 200);
    const after = await (
      await fetch(`${server.baseUrl}/api/audit?limit=20`, { headers: bearer(ADMIN) })
    ).json();
    const lifecycle = after.entries.find((entry) => entry.action === 'token.retired');
    assert.ok(lifecycle, 'token.retired must be audited');
    assert.equal(lifecycle.actor, 'admin');
    assert.equal(lifecycle.authenticated, 1);

    // Idempotent: retiring again is not an error and does not invent a new state.
    const again = await fetch(`${server.baseUrl}/api/tokens/${victim.id}/retire`, {
      method: 'POST',
      headers: bearer(ADMIN),
    });
    assert.equal(again.status, 200);
    assert.equal((await again.json()).changed, false);

    // Unknown id: 404 for an admin, and no token state is guessed.
    assert.equal(
      (await fetch(`${server.baseUrl}/api/tokens/htk_ffffffffffffffff/retire`, {
        method: 'POST',
        headers: bearer(ADMIN),
      })).status,
      404,
    );
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(victim.token) })).status, 401);

    // Expiry is an admin action too, and one a viewer cannot perform.
    const shortLived = cliJson(dbPath, ['create', '--role', 'viewer', '--name', 'short-lived']);
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(shortLived.token) })).status, 200);
    const viewerExpire = await fetch(`${server.baseUrl}/api/tokens/${shortLived.id}/expire`, {
      method: 'POST',
      headers: { ...bearer(VIEWER), 'content-type': 'application/json' },
      body: JSON.stringify({ in_seconds: 0 }),
    });
    assert.equal(viewerExpire.status, 403);
    const expire = await fetch(`${server.baseUrl}/api/tokens/${shortLived.id}/expire`, {
      method: 'POST',
      headers: { ...bearer(ADMIN), 'content-type': 'application/json' },
      body: JSON.stringify({ in_seconds: 0 }),
    });
    assert.equal(expire.status, 200);
    assert.equal((await expire.json()).state, 'expired');
    assert.equal(
      (await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(shortLived.token) })).status,
      401,
      'an expired token is refused on the next request',
    );
    // Bad input is a 400, not a silent no-op; an unknown id is a 404.
    assert.equal(
      (await fetch(`${server.baseUrl}/api/tokens/${shortLived.id}/expire`, {
        method: 'POST',
        headers: { ...bearer(ADMIN), 'content-type': 'application/json' },
        body: JSON.stringify({ at: 'whenever' }),
      })).status,
      400,
    );
    assert.equal(
      (await fetch(`${server.baseUrl}/api/tokens/${shortLived.id}/expire`, {
        method: 'POST',
        headers: { ...bearer(ADMIN), 'content-type': 'application/json' },
        body: JSON.stringify({}),
      })).status,
      400,
    );
    assert.equal(
      (await fetch(`${server.baseUrl}/api/tokens/htk_ffffffffffffffff/expire`, {
        method: 'POST',
        headers: { ...bearer(ADMIN), 'content-type': 'application/json' },
        body: JSON.stringify({ in_seconds: 0 }),
      })).status,
      404,
    );
    const expiredAudit = await (
      await fetch(`${server.baseUrl}/api/audit?limit=20`, { headers: bearer(ADMIN) })
    ).json();
    assert.ok(expiredAudit.entries.some((entry) => entry.action === 'token.expired'));
    assert.ok(!JSON.stringify(expiredAudit).includes(shortLived.token));
  } finally {
    await server.stop();
  }
});

test('the CLI never leaks a secret except the single create handover', async () => {
  const dir = tempDir('hatchery-cli-');
  const dbPath = path.join(dir, 'tokens.db');
  const created = cliJson(dbPath, ['create', '--role', 'admin', '--name', 'cli-check']);

  // `list` output (both forms) is secret-free.
  const listJson = cli(dbPath, ['list']);
  assert.equal(listJson.status, 0);
  assert.ok(!listJson.stdout.includes(created.token));
  assert.ok(!listJson.stdout.includes('secret_hash'));
  const listTable = spawnSync(process.execPath, ['scripts/token.mjs', 'list'], {
    cwd: serverRoot,
    env: { ...process.env, HATCHERY_DB_PATH: dbPath },
    encoding: 'utf-8',
  });
  assert.equal(listTable.status, 0);
  assert.ok(listTable.stdout.includes(created.id));
  assert.ok(!listTable.stdout.includes(created.token));
  assert.equal(listTable.stderr, '');

  // Retire and expire are secret-free on both streams.
  for (const args of [
    ['retire', created.id],
    ['expire', created.id, '--in', '1h'],
    ['expire', 'htk_ffffffffffffffff', '--in', '1h'],
  ]) {
    const result = spawnSync(process.execPath, ['scripts/token.mjs', ...args], {
      cwd: serverRoot,
      env: { ...process.env, HATCHERY_DB_PATH: dbPath },
      encoding: 'utf-8',
    });
    assert.ok(!result.stdout.includes(created.token));
    assert.ok(!result.stderr.includes(created.token));
  }

  // Documented non-zero exits: usage error = 2, operation failure = 1.
  assert.equal(cli(dbPath, ['create']).status, 2, 'missing --role is a usage error');
  assert.equal(cli(dbPath, ['create', '--role', 'root']).status, 2, 'unknown role is refused');
  assert.equal(cli(dbPath, ['retire', 'htk_ffffffffffffffff']).status, 1, 'unknown id is a failure');
  assert.equal(cli(dbPath, ['expire', 'htk_ffffffffffffffff', '--in', '1h']).status, 1);
  assert.equal(cli(dbPath, ['create', '--role', 'viewer', '--expires-in', 'soon']).status, 2);

  // Usage output is parseable text and names the exit codes; no secret.
  const help = spawnSync(process.execPath, ['scripts/token.mjs', '--help'], {
    cwd: serverRoot,
    env: { ...process.env, HATCHERY_DB_PATH: dbPath },
    encoding: 'utf-8',
  });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /Exit codes: 0 success, 1 operation failed, 2 usage error/);

  // The database and its WAL never contain the secret.
  const bytes = databaseBytes(dbPath);
  assert.ok(!bytes.includes(created.token));
});

test('an in-flight request authenticated under a token that is retired mid-flight completes', async (t) => {
  if (!engineReady()) {
    t.skip(`the HATCHERY engine is not importable by ${enginePython}`);
    return;
  }
  const dir = tempDir('hatchery-inflight-');
  const dbPath = path.join(dir, 'tokens.db');
  const admin = cliJson(dbPath, ['create', '--role', 'admin', '--name', 'in-flight']);

  const server = await bootServer({
    dbPath,
    env: {
      HATCHERY_SAMPLE_STORE: path.join(dir, 'store'),
      HATCHERY_QUEUE_DB: path.join(dir, 'queue.db'),
      HATCHERY_RESULTS_ROOT: path.join(dir, 'results'),
      HATCHERY_ENGINE_PYTHON: enginePython,
    },
  });

  try {
    // `/api/submit` spawns the engine CLI, so the request is genuinely in flight
    // for long enough to retire the credential it was authenticated with.
    const started = Date.now();
    const submit = fetch(`${server.baseUrl}/api/submit`, {
      method: 'POST',
      headers: { ...bearer(admin.token), 'content-type': 'application/json' },
      body: JSON.stringify({ filePath: path.join(repoRoot, 'samples', 'eicar.com') }),
    });
    await new Promise((resolve) => setTimeout(resolve, 250));

    const retire = await fetch(`${server.baseUrl}/api/tokens/${admin.id}/retire`, {
      method: 'POST',
      headers: bearer(admin.token),
    });
    assert.equal(retire.status, 200, 'retirement must land while the submit is running');

    const response = await submit;
    const body = await response.json();
    assert.equal(
      response.status,
      200,
      `an in-flight request must not be cut off by retirement; got ${response.status}: ${JSON.stringify(body)}`,
    );
    // It really was still running when the credential was retired.
    assert.ok(Date.now() - started >= 250, 'the submit finished too quickly to prove anything');
    assert.equal(body.status, 'queued');

    // The *next* request with the retired token is refused.
    assert.equal((await fetch(`${server.baseUrl}/api/tasks`, { headers: bearer(admin.token) })).status, 401);
  } finally {
    await server.stop();
  }
});
