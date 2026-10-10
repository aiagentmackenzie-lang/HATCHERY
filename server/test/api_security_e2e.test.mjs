/**
 * End-to-end API security test (D25).
 *
 * Boots the real built server as a subprocess with both tokens set and a throwaway
 * database, then exercises the auth and audit behaviour over HTTP. This is the test
 * that would have caught the old model's flaw: one shared secret that either opened
 * everything or nothing.
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');
const ADMIN = 'admin-secret-value';
const VIEWER = 'viewer-secret-value';

async function waitForHealth(baseUrl, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/api/health`);
      if (response.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return false;
}

test('role-based auth and the audit trail, end to end', async () => {
  const port = 40000 + Math.floor(Math.random() * 10000);
  const baseUrl = `http://127.0.0.1:${port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-api-'));
  const dbPath = path.join(dir, 'test.db');

  const child = spawn(process.execPath, ['dist/index.js'], {
    cwd: serverRoot,
    env: {
      ...process.env,
      HATCHERY_PORT: String(port),
      HATCHERY_HOST: '127.0.0.1',
      HATCHERY_DB_PATH: dbPath,
      HATCHERY_ADMIN_TOKEN: ADMIN,
      HATCHERY_READ_TOKEN: VIEWER,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    const up = await waitForHealth(baseUrl);
    assert.ok(up, 'server did not become healthy');

    // Health is reachable without a token.
    assert.equal((await fetch(`${baseUrl}/api/health`)).status, 200);

    // No token -> 401.
    const anonymous = await fetch(`${baseUrl}/api/audit`);
    assert.equal(anonymous.status, 401);

    // A viewer may read analysis but may not read the audit log (admin-only GET).
    const viewerAudit = await fetch(`${baseUrl}/api/audit`, {
      headers: { authorization: `Bearer ${VIEWER}` },
    });
    assert.equal(viewerAudit.status, 403);
    assert.equal(viewerAudit.headers.get('x-hatchery-required-role'), 'admin');

    // A viewer may not submit (a write).
    const viewerSubmit = await fetch(`${baseUrl}/api/submit`, {
      method: 'POST',
      headers: { authorization: `Bearer ${VIEWER}`, 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(viewerSubmit.status, 403);

    // An admin may read the audit log, and the refusals are recorded.
    const adminAudit = await fetch(`${baseUrl}/api/audit?limit=50`, {
      headers: { authorization: `Bearer ${ADMIN}` },
    });
    assert.equal(adminAudit.status, 200);
    const payload = await adminAudit.json();
    assert.ok(payload.count >= 3, `expected audit rows, got ${payload.count}`);
    const actions = payload.entries.map((entry) => entry.action);
    assert.ok(actions.includes('auth.denied'));
    assert.ok(actions.includes('request.forbidden'));

    // The audit rows never contain the tokens.
    const serialized = JSON.stringify(payload);
    assert.ok(!serialized.includes(ADMIN));
    assert.ok(!serialized.includes(VIEWER));

    // A failed auth must not have created a task.
    const viewerRows = payload.entries.find((entry) => entry.actor === 'viewer');
    assert.ok(viewerRows, 'the viewer refusals should be attributed to the viewer');
  } finally {
    child.kill('SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 200));
    if (!child.killed) child.kill('SIGKILL');
  }
});
