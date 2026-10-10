/**
 * The engine-side durable job queue, seen from the API (D27).
 *
 * The queue is the **single producer of job state**, and it lives in the Python
 * engine so it works headless — no Node server required to enqueue or execute a
 * job. The API therefore does two narrow things here:
 *
 *   1. enqueue by shelling out to `hatchery submit --enqueue` (a short-lived
 *      process that writes one row), and
 *   2. **read** the queue database to reflect job state, read-only.
 *
 * It never writes job state itself. The `tasks` table remains the API's own
 * projection of a job's outcome, written only by the server, so the dashboard's
 * existing queries keep working.
 */

import Database from 'better-sqlite3';
import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** Repo root: server/src/db and server/dist/db both climb three levels. */
export const ENGINE_ROOT = path.join(__dirname, '..', '..', '..');
export const RESULTS_ROOT =
  process.env.HATCHERY_RESULTS_ROOT ?? path.join(ENGINE_ROOT, 'results');

/** The queue database the engine and the server must agree on. */
export const QUEUE_DB = process.env.HATCHERY_QUEUE_DB ?? path.join(ENGINE_ROOT, 'data', 'queue.db');

/** The interpreter the engine runs under (override for a packaged deployment). */
export function enginePython(): string {
  if (process.env.HATCHERY_ENGINE_PYTHON) return process.env.HATCHERY_ENGINE_PYTHON;
  const venv = path.join(ENGINE_ROOT, '.venv', 'bin', 'python3');
  return fs.existsSync(venv) ? venv : 'python3';
}

export interface QueueJob {
  job_id: string;
  status: string;
  sample_path: string;
  output_dir: string;
  attempts: number;
  max_attempts: number;
  worker_id: string | null;
  lease_expires_at: number | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  updated_at: string;
  exit_code: number | null;
  error: string | null;
  run_dir: string | null;
  task_id: string | null;
}

export interface EnqueueRequest {
  jobId: string;
  filePath: string;
  outputDir: string;
  timeout: number;
  noSandbox: boolean;
  requeue?: boolean;
}

export interface EnqueueResult {
  ok: boolean;
  jobId?: string;
  error?: string;
}

/**
 * Enqueue a job through the engine CLI.
 *
 * Shelling out keeps one producer of job state (D4): the API does not open the
 * queue database for writing. The CLI validates the sample exists and prints one
 * JSON object; a non-zero exit or unparseable output is an honest failure.
 */
export function enqueueJob(request: EnqueueRequest): EnqueueResult {
  const args = [
    '-m', 'engine.cli', 'submit', request.filePath,
    '--enqueue',
    '--queue', QUEUE_DB,
    '--job-id', request.jobId,
    '--timeout', String(request.timeout),
    '-o', request.outputDir,
  ];
  if (request.noSandbox) args.push('--no-sandbox');
  if (request.requeue) args.push('--requeue');

  const completed = spawnSync(enginePython(), args, {
    cwd: ENGINE_ROOT,
    env: { ...process.env, PYTHONPATH: ENGINE_ROOT, HATCHERY_QUEUE_DB: QUEUE_DB },
    encoding: 'utf-8',
    timeout: 60000,
  });

  if (completed.error) {
    return { ok: false, error: `could not enqueue: ${completed.error.message}` };
  }
  if (completed.status !== 0) {
    const detail = (completed.stderr || completed.stdout || '').trim().slice(-500);
    return { ok: false, error: detail || `hatchery submit --enqueue exited ${completed.status}` };
  }

  const stdout = completed.stdout ?? '';
  const lines = stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('{'));
  if (lines.length === 0) {
    return { ok: false, error: `enqueue printed no job object: ${stdout.slice(-300)}` };
  }
  try {
    const payload = JSON.parse(lines[lines.length - 1]) as { job_id?: string };
    if (!payload.job_id) return { ok: false, error: 'enqueue output had no job_id' };
    return { ok: true, jobId: payload.job_id };
  } catch (error) {
    return { ok: false, error: `unparseable enqueue output: ${String(error)}` };
  }
}

/** Read one job from the queue database, read-only. `null` if it is not there. */
export function readQueueJob(jobId: string): QueueJob | null {
  if (!fs.existsSync(QUEUE_DB)) return null;
  let queue: Database.Database | null = null;
  try {
    queue = new Database(QUEUE_DB, { readonly: true, fileMustExist: true });
    queue.pragma('busy_timeout = 5000');
    const row = queue
      .prepare(
        `SELECT job_id, status, sample_path, output_dir, attempts, max_attempts,
                worker_id, lease_expires_at, created_at, started_at, finished_at,
                updated_at, exit_code, error, run_dir, task_id
         FROM jobs WHERE job_id = ?`,
      )
      .get(jobId) as QueueJob | undefined;
    return row ?? null;
  } catch {
    // A queue that has not been created yet, or a database locked by a
    // heartbeat, is not an error: the task simply has no queue detail yet.
    return null;
  } finally {
    if (queue) queue.close();
  }
}

/** The queue database path, exposed for tests and the dashboard. */
export function queueDbPath(): string {
  return QUEUE_DB;
}
