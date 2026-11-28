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
import { spawn, spawnSync } from 'child_process';
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
  sample_sha256: string | null;
  /** D28: the content address the worker executes (null for a pre-D28 job). */
  sample_store_ref: string | null;
  /** D42: the sample's display name (a stream-supplied sample has no path). */
  sample_name: string | null;
  /** D43: the actor that submitted the job. */
  owner: string | null;
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
  /** D43: the actor that submitted the job, recorded in the queue. */
  owner?: string;
}

/** Queue an address that is already in the encrypted store (D42). */
export interface EnqueueStoredRequest {
  jobId: string;
  sha256: string;
  fileName: string;
  outputDir: string;
  timeout: number;
  noSandbox: boolean;
  /** D43: the actor that submitted the job, recorded in the queue. */
  owner?: string;
}

export interface EnqueueResult {
  ok: boolean;
  jobId?: string;
  error?: string;
  /** D42: the engine's own refusal code (`too-large`, `empty`, `not-found`, ...). */
  reason?: string;
  /** The store's byte limit, present on a `too-large` refusal. */
  limit?: number;
  storeRef?: string;
  sha256?: string;
  size?: number;
}

/**
 * The one JSON object a machine-readable engine command prints (D42).
 *
 * `submit --enqueue` prints it on **stdout**; the `store` group prints refusals
 * on **stderr** by its own contract ("stdout is the machine-readable object").
 * Both are one object and both are parsed here, so the route never has to know
 * which convention a refusal came from, and never has to pattern-match a human
 * sentence to pick a status code.
 */
function engineJson(stdout: string, stderr: string): Record<string, unknown> | null {
  for (const stream of [stdout, stderr]) {
    const lines = (stream ?? '')
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.startsWith('{'));
    for (let i = lines.length - 1; i >= 0; i -= 1) {
      try {
        const parsed = JSON.parse(lines[i]) as Record<string, unknown>;
        if (typeof parsed === 'object' && parsed !== null) return parsed;
      } catch {
        // Not the object; keep looking. A log line that starts with '{' is not
        // evidence of a refusal.
      }
    }
  }
  return null;
}

function refusalFrom(
  stdout: string,
  stderr: string,
  fallback: string,
): EnqueueResult {
  const payload = engineJson(stdout, stderr);
  if (payload && payload.ok === false) {
    return {
      ok: false,
      reason: typeof payload.reason === 'string' ? payload.reason : undefined,
      limit: typeof payload.limit === 'number' ? payload.limit : undefined,
      error:
        typeof payload.message === 'string'
          ? payload.message
          : fallback,
    };
  }
  return { ok: false, error: fallback };
}

function successFrom(payload: Record<string, unknown> | null, fallback: string): EnqueueResult {
  if (!payload) return { ok: false, error: fallback };
  const jobId = typeof payload.job_id === 'string' ? payload.job_id : undefined;
  if (!jobId) return { ok: false, error: 'the engine accepted the sample but printed no job_id' };
  return {
    ok: true,
    jobId,
    storeRef: typeof payload.sample_store_ref === 'string' ? payload.sample_store_ref : undefined,
    sha256: typeof payload.sha256 === 'string' ? payload.sha256 : undefined,
    size: typeof payload.size === 'number' ? payload.size : undefined,
  };
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
  if (request.owner) args.push(`--owner=${request.owner}`);

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
    return refusalFrom(
      completed.stdout ?? '',
      completed.stderr ?? '',
      detail || `hatchery submit --enqueue exited ${completed.status}`,
    );
  }

  const stdout = completed.stdout ?? '';
  const lines = stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('{'));
  if (lines.length === 0) {
    return { ok: false, error: `enqueue printed no job object: ${stdout.slice(-300)}` };
  }
  return successFrom(engineJson(stdout, completed.stderr ?? ''), 'unparseable enqueue output');
}

/**
 * Store a sample that arrives on a stream, and return its content address (D42).
 *
 * The bytes go into the engine's encrypted store through a pipe. They are never
 * written to a filesystem: the API used to stage up to 256 MiB of live malware as
 * a plaintext file under `uploads/`, which was the one place the store's
 * encryption-at-rest claim was not true.
 *
 * The call is asynchronous on purpose. `spawnSync` cannot take a stream, and the
 * multipart body must be consumed *as it arrives* — the route used to collect the
 * file part and pipe it after the loop, which deadlocked above roughly 100 KiB
 * because busboy applies backpressure to an unread part.
 */
export function storeSampleFromStream(
  stream: NodeJS.ReadableStream,
  options: { jobId: string; fileName: string; timeoutSeconds?: number },
): Promise<EnqueueResult> {
  const args = [
    '-m', 'engine.cli', 'store', 'put', '--stdin', '--json',
    // `--name=<value>`: a client filename may begin with `-`, and a separate
    // argument would be parsed as an option.
    `--name=${options.fileName}`,
  ];

  return new Promise<EnqueueResult>((resolve) => {
    let settled = false;
    const finish = (result: EnqueueResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(cap);
      resolve(result);
    };

    const child = spawn(enginePython(), args, {
      cwd: ENGINE_ROOT,
      env: { ...process.env, PYTHONPATH: ENGINE_ROOT },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    child.stdout?.setEncoding('utf-8');
    child.stderr?.setEncoding('utf-8');
    child.stdout?.on('data', (chunk: string) => { stdout += chunk; });
    child.stderr?.on('data', (chunk: string) => { stderr += chunk; });

    // A stalled body must not pin a Python process forever. This is a total cap,
    // not an inactivity timer: 256 MiB of encryption and one fsync is seconds.
    const cap = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      finish({ ok: false, error: 'the engine did not finish storing the sample in time' });
    }, (options.timeoutSeconds ?? 300) * 1000);

    child.on('error', (error) => {
      finish({ ok: false, error: `could not start the engine: ${error.message}` });
    });

    child.on('close', (code, signal) => {
      if (signal) {
        // SIGKILL is ours (the cap) or the route's (client gone). Nothing was
        // queued: the store writes a blob before any job row exists, so a kill
        // here can leave a prunable orphan blob, never a job pointing at nothing.
        finish({ ok: false, error: `the engine was killed (${signal}) before it accepted the sample` });
        return;
      }
      if (code !== 0) {
        finish(refusalFrom(stdout, stderr, `hatchery store put exited ${code}`));
        return;
      }
      const payload = engineJson(stdout, stderr);
      const sha256 = typeof payload?.sha256 === 'string' ? payload.sha256 : undefined;
      const size = typeof payload?.size === 'number' ? payload.size : undefined;
      if (!sha256 || size === undefined) {
        finish({ ok: false, error: 'the engine stored the sample but printed no address' });
        return;
      }
      finish({ ok: true, sha256, size, storeRef: sha256 });
    });

    // A refusal (413 from the plugin, a disconnect, the engine's own limit) ends
    // the pipe; EPIPE on stdin is expected and is not the caller's error.
    child.stdin?.on('error', () => { /* reported through close/exit */ });
    stream.on('error', (error: Error) => {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      finish({ ok: false, error: `the upload stream failed: ${error.message}` });
    });
    stream.pipe(child.stdin);
  });
}

/**
 * Queue an address that is already in the store (D42).
 *
 * The second half of the intake boundary: `store put` took the bytes, this queues
 * the address. Splitting them is what lets the route read the body before it knows
 * the form's `timeout` and `noSandbox` — a stream cannot be held without being
 * written down, and not writing it down is the entire point.
 */
export function enqueueStored(request: EnqueueStoredRequest): EnqueueResult {
  const args = [
    '-m', 'engine.cli', 'submit',
    '--from-store', request.sha256,
    '--enqueue',
    `--name=${request.fileName}`,
    '--queue', QUEUE_DB,
    '--job-id', request.jobId,
    '--timeout', String(request.timeout),
    '-o', request.outputDir,
  ];
  if (request.noSandbox) args.push('--no-sandbox');
  if (request.owner) args.push(`--owner=${request.owner}`);

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
    return refusalFrom(
      completed.stdout ?? '',
      completed.stderr ?? '',
      `hatchery submit --enqueue exited ${completed.status}`,
    );
  }
  return successFrom(
    engineJson(completed.stdout ?? '', completed.stderr ?? ''),
    'unparseable enqueue output',
  );
}

/**
 * How many queued or running jobs this owner has (D43).
 *
 * A reader, not a counter: job state belongs to the engine (D27), so the per-caller
 * job cap is enforced by counting what the queue already says rather than by
 * keeping a second tally that could drift. Returns `null` when the queue cannot be
 * read — a missing queue file on a fresh install is "no jobs", not "a full queue",
 * and refusing every submission because a file does not exist is the kind of
 * control an operator switches off.
 */
export function countActiveJobs(owner: string): number | null {
  if (!fs.existsSync(QUEUE_DB)) return 0;
  let queue: Database.Database | null = null;
  try {
    queue = new Database(QUEUE_DB, { readonly: true, fileMustExist: true });
    queue.pragma('busy_timeout = 5000');
    const row = queue
      .prepare(
        `SELECT COUNT(*) AS n FROM jobs WHERE owner = ? AND status IN ('queued', 'running')`,
      )
      .get(owner) as { n: number } | undefined;
    return row ? Number(row.n) : 0;
  } catch {
    return null;
  } finally {
    if (queue) queue.close();
  }
}

/**
 * Re-queue a job from what the row already records (D42).
 *
 * A retry must not depend on a path: a sample that arrived on a stream never had
 * one, and an operator may have deleted the original of any job. The engine keeps
 * the store reference, display name, output directory and arguments, so a retry
 * runs the same job rather than a lookalike.
 */
export function requeueJob(jobId: string): EnqueueResult {
  const completed = spawnSync(
    enginePython(),
    ['-m', 'engine.cli', 'queue', jobId, '--requeue', '--json', '--queue', QUEUE_DB],
    {
      cwd: ENGINE_ROOT,
      env: { ...process.env, PYTHONPATH: ENGINE_ROOT, HATCHERY_QUEUE_DB: QUEUE_DB },
      encoding: 'utf-8',
      timeout: 60000,
    },
  );
  if (completed.error) {
    return { ok: false, error: `could not re-queue: ${completed.error.message}` };
  }
  if (completed.status !== 0) {
    return refusalFrom(
      completed.stdout ?? '',
      completed.stderr ?? '',
      `hatchery queue --requeue exited ${completed.status}`,
    );
  }
  const payload = engineJson(completed.stdout ?? '', completed.stderr ?? '');
  const job = typeof payload?.job_id === 'string' ? payload.job_id : undefined;
  if (!job) return { ok: false, error: 're-queue printed no job object' };
  return { ok: true, jobId: job };
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
        `SELECT job_id, status, sample_path, sample_sha256, sample_store_ref, sample_name,
                owner, output_dir, attempts, max_attempts,
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
