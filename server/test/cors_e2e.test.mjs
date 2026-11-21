/**
 * CORS allow-list, end to end (D30).
 *
 * D8 shipped `origin: true`, which reflects any Origin a browser sends. These tests
 * boot the real built server and pin the replacement: an exact allow-list, never a
 * reflection, with the documented dashboard origin still working and non-browser
 * clients untouched.
 *
 * CORS is a browser-side read restriction, not authentication. These tests assert
 * the header behaviour, not that an unlisted origin cannot reach the API — it can,
 * and it gets the same 401 as anyone without a token. That distinction is stated in
 * D30 rather than papered over.
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

async function bootServer(env = {}) {
  const port = 52000 + Math.floor(Math.random() * 6000);
  const baseUrl = `http://127.0.0.1:${port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-cors-'));
  const child = spawn(process.execPath, ['dist/index.js'], {
    cwd: serverRoot,
    env: {
      ...process.env,
      HATCHERY_PORT: String(port),
      HATCHERY_HOST: '127.0.0.1',
      HATCHERY_DB_PATH: path.join(dir, 'cors.db'),
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
  assert.ok(up, `server did not become healthy:\n${output}`);
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

test('an allowed origin gets the CORS header, an unlisted origin is never reflected', async () => {
  const server = await bootServer();
  try {
    for (const origin of ['http://localhost:5173', 'http://127.0.0.1:5173']) {
      const response = await fetch(`${server.baseUrl}/api/health`, {
        headers: { origin },
      });
      assert.equal(response.status, 200);
      assert.equal(
        response.headers.get('access-control-allow-origin'),
        origin,
        `the documented dashboard origin ${origin} must be allowed`,
      );
      assert.match(String(response.headers.get('vary')), /Origin/i);
    }

    const unlisted = [
      'https://evil.example',
      'http://localhost:5174',
      'http://localhost:5173.evil.example',
      'null',
    ];
    for (const origin of unlisted) {
      const response = await fetch(`${server.baseUrl}/api/health`, { headers: { origin } });
      assert.equal(response.status, 200, 'the request is served; the browser is what is told not to read it');
      assert.equal(
        response.headers.get('access-control-allow-origin'),
        null,
        `origin ${origin} must not be reflected`,
      );
      assert.equal(response.headers.get('access-control-allow-credentials'), null);
    }

    // The dashboard origin still works on a real API route, not just /api/health.
    const apiAllowed = await fetch(`${server.baseUrl}/api/tasks`, {
      headers: { origin: 'http://localhost:5173' },
    });
    assert.equal(apiAllowed.headers.get('access-control-allow-origin'), 'http://localhost:5173');
    const apiDenied = await fetch(`${server.baseUrl}/api/tasks`, {
      headers: { origin: 'https://evil.example' },
    });
    assert.equal(apiDenied.headers.get('access-control-allow-origin'), null);

    // Preflight: allowed origin is granted with bounded methods and no credentials;
    // an unlisted origin is not granted anything.
    const preflight = await fetch(`${server.baseUrl}/api/tasks`, {
      method: 'OPTIONS',
      headers: {
        origin: 'http://localhost:5173',
        'access-control-request-method': 'GET',
      },
    });
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get('access-control-allow-origin'), 'http://localhost:5173');
    assert.match(String(preflight.headers.get('access-control-allow-methods')), /GET/);
    assert.equal(preflight.headers.get('access-control-allow-credentials'), null);
    assert.ok(Number(preflight.headers.get('access-control-max-age')) > 0);

    const deniedPreflight = await fetch(`${server.baseUrl}/api/tasks`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://evil.example',
        'access-control-request-method': 'GET',
      },
    });
    assert.equal(deniedPreflight.headers.get('access-control-allow-origin'), null);

    // No Origin header (curl, the worker, the CLI, a server-side integration):
    // unaffected, and no CORS header is invented.
    const plain = await fetch(`${server.baseUrl}/api/health`);
    assert.equal(plain.status, 200);
    assert.equal(plain.headers.get('access-control-allow-origin'), null);
    const plainApi = await fetch(`${server.baseUrl}/api/tasks`);
    assert.equal(plainApi.status, 200);
    assert.equal(plainApi.headers.get('access-control-allow-origin'), null);
  } finally {
    await server.stop();
  }
});

test('HATCHERY_ALLOWED_ORIGINS adds exact origins and refuses wildcards', async () => {
  const server = await bootServer({
    HATCHERY_ALLOWED_ORIGINS: 'https://ops.example, https://ops.example/, *',
  });
  try {
    // Configured origins (trailing slash normalised) are allowed.
    const ops = await fetch(`${server.baseUrl}/api/health`, {
      headers: { origin: 'https://ops.example' },
    });
    assert.equal(ops.headers.get('access-control-allow-origin'), 'https://ops.example');

    // The dashboard default survives: the env var adds, it does not replace.
    const dashboard = await fetch(`${server.baseUrl}/api/health`, {
      headers: { origin: 'http://localhost:5173' },
    });
    assert.equal(dashboard.headers.get('access-control-allow-origin'), 'http://localhost:5173');

    // `*` is refused rather than honoured: no origin becomes a wildcard.
    for (const origin of ['https://arbitrary.example', 'https://ops.example.evil.example']) {
      const response = await fetch(`${server.baseUrl}/api/health`, { headers: { origin } });
      assert.equal(response.headers.get('access-control-allow-origin'), null);
    }

    // The refusal is explained at startup, without echoing anything secret.
    const startup = server.output();
    assert.match(startup, /CORS allow-list/);
    assert.match(startup, /wildcards are not supported/);
  } finally {
    await server.stop();
  }
});

test('a path or a bare host in the allow-list is rejected, not reinterpreted', async () => {
  const server = await bootServer({
    HATCHERY_ALLOWED_ORIGINS: 'https://ok.example, https://path.example/ui, localhost:1234',
  });
  try {
    const ok = await fetch(`${server.baseUrl}/api/health`, {
      headers: { origin: 'https://ok.example' },
    });
    assert.equal(ok.headers.get('access-control-allow-origin'), 'https://ok.example');

    for (const origin of ['https://path.example', 'localhost:1234']) {
      const response = await fetch(`${server.baseUrl}/api/health`, { headers: { origin } });
      assert.equal(response.headers.get('access-control-allow-origin'), null);
    }
    const startup = server.output();
    assert.match(startup, /must be scheme:\/\/host\[:port\] with no path/);
  } finally {
    await server.stop();
  }
});
