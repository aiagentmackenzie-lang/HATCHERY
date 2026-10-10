/**
 * The queue, end to end through the real API (D27).
 *
 * Boots the real built server with throwaway server/queue databases, submits a
 * sample, and asserts the task is *queued* rather than spawned-and-forgotten.
 * Then it runs a real `hatchery worker --once`, and asserts the next read
 * reflects the completed job and has ingested the bundle. This is the test that
 * proves the old behaviour is gone: a server death no longer leaves a task
 * `running` forever, because the queue owns job state and a worker recovers it.
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');
const repoRoot = path.join(serverRoot, '..');
const venvPython = path.join(repoRoot, '.venv', 'bin', 'python3');

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

function runWorker(queueDb) {
  return spawnSync(
    venvPython,
    ['-m', 'engine.cli', 'worker', '--once', '--concurrency', '1', '--queue', queueDb],
    {
      cwd: repoRoot,
      env: { ...process.env, PYTHONPATH: repoRoot, HATCHERY_QUEUE_DB: queueDb },
      encoding: 'utf-8',
      timeout: 300000,
    },
  );
}

test('a submission is queued, and a worker completes it into the API', async () => {
  const port = 40000 + Math.floor(Math.random() * 10000);
  const baseUrl = `http://127.0.0.1:${port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-queue-api-'));
  const dbPath = path.join(dir, 'test.db');
  const queueDb = path.join(dir, 'queue.db');
  const resultsRoot = path.join(dir, 'results');
  const samplesDir = path.join(dir, 'samples');
  fs.mkdirSync(samplesDir, { recursive: true });
  const samplePath = path.join(samplesDir, 'queued-sample.txt');
  fs.writeFileSync(samplePath, 'hello hatchery queue\n');

  const child = spawn(process.execPath, ['dist/index.js'], {
    cwd: serverRoot,
    env: {
      ...process.env,
      HATCHERY_PORT: String(port),
      HATCHERY_HOST: '127.0.0.1',
      HATCHERY_DB_PATH: dbPath,
      HATCHERY_QUEUE_DB: queueDb,
      HATCHERY_RESULTS_ROOT: resultsRoot,
      HATCHERY_ALLOWED_SAMPLE_ROOTS: samplesDir,
      HATCHERY_ENGINE_PYTHON: venvPython,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    const up = await waitForHealth(baseUrl);
    assert.ok(up, 'server did not become healthy');

    const submitted = await fetch(`${baseUrl}/api/submit`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ filePath: samplePath, noSandbox: true }),
    });
    const submittedText = await submitted.text();
    assert.equal(submitted.status, 200, submittedText);
    const submission = JSON.parse(submittedText);
    assert.equal(submission.status, 'queued');
    assert.ok(submission.queue_job_id, 'the response must name the queued job');
    const taskId = submission.task_id;

    // The queue row is real and the task is NOT running.
    const pending = await (await fetch(`${baseUrl}/api/tasks/${taskId}`)).json();
    assert.equal(pending.task.status, 'queued');
    assert.ok(pending.queue, 'the task response must reflect queue state');
    assert.equal(pending.queue.status, 'queued');
    assert.equal(pending.queue.job_id, taskId);

    // A real worker executes the real submit pipeline.
    const worked = runWorker(queueDb);
    assert.equal(worked.status, 0, worked.stdout + worked.stderr);

    const completed = await (await fetch(`${baseUrl}/api/tasks/${taskId}`)).json();
    assert.equal(completed.task.status, 'completed', JSON.stringify(completed.task));
    assert.equal(completed.queue.status, 'completed');
    assert.equal(completed.queue.attempts, 1);
    assert.ok(completed.task.sha256, 'the bundle must have been ingested');
    assert.ok(completed.static_results, 'static results must exist after ingest');

    // The list endpoint also reflects the completed state.
    const listed = await (await fetch(`${baseUrl}/api/tasks`)).json();
    const row = listed.tasks.find((task) => task.task_id === taskId);
    assert.equal(row.status, 'completed');
    assert.equal(row.queue_job_id, taskId);
  } finally {
    child.kill('SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 200));
    if (!child.killed) child.kill('SIGKILL');
  }
});

test('a job that cannot produce a bundle is reflected as failed, not running', async () => {
  const port = 40000 + Math.floor(Math.random() * 10000);
  const baseUrl = `http://127.0.0.1:${port}`;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hatchery-queue-fail-'));
  const dbPath = path.join(dir, 'test.db');
  const queueDb = path.join(dir, 'queue.db');
  const resultsRoot = path.join(dir, 'results');
  const samplesDir = path.join(dir, 'samples');
  fs.mkdirSync(samplesDir, { recursive: true });
  const samplePath = path.join(samplesDir, 'vanishing.txt');
  fs.writeFileSync(samplePath, 'here for now\n');

  const child = spawn(process.execPath, ['dist/index.js'], {
    cwd: serverRoot,
    env: {
      ...process.env,
      HATCHERY_PORT: String(port),
      HATCHERY_HOST: '127.0.0.1',
      HATCHERY_DB_PATH: dbPath,
      HATCHERY_QUEUE_DB: queueDb,
      HATCHERY_RESULTS_ROOT: resultsRoot,
      HATCHERY_ALLOWED_SAMPLE_ROOTS: samplesDir,
      HATCHERY_ENGINE_PYTHON: venvPython,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    assert.ok(await waitForHealth(baseUrl), 'server did not become healthy');

    const submitted = await fetch(`${baseUrl}/api/submit`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ filePath: samplePath, noSandbox: true }),
    });
    const submittedText = await submitted.text();
    assert.equal(submitted.status, 200, submittedText);
    const taskId = JSON.parse(submittedText).task_id;

    // The sample disappears before a worker sees it: submit cannot produce a
    // bundle, so the job must fail rather than sit "running" forever.
    fs.unlinkSync(samplePath);
    const worked = runWorker(queueDb);
    assert.notEqual(
      worked.status,
      0,
      'a job that produced no bundle must make `worker --once` exit non-zero',
    );

    const failed = await (await fetch(`${baseUrl}/api/tasks/${taskId}`)).json();
    assert.equal(failed.task.status, 'failed');
    assert.equal(failed.queue.status, 'failed');
    assert.ok(failed.task.error_message, 'the real reason must be recorded');
  } finally {
    child.kill('SIGTERM');
    await new Promise((resolve) => setTimeout(resolve, 200));
    if (!child.killed) child.kill('SIGKILL');
  }
});
