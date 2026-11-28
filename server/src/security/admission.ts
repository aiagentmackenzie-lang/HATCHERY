/**
 * Admission control: a credential is not an unlimited budget (D43).
 *
 * D25/D30 answer "may this caller act?" and D41/D42 answer "what may a sample be?".
 * Neither answers **"how much"**. Before this module an authenticated token could
 * fill the disk with accepted 256 MiB samples, or queue work without bound, and the
 * only cost was patience. Authentication is not availability.
 *
 * Three limits, all per caller and all counted in the API's own SQLite database so
 * a restart does not forget them:
 *
 *   1. requests per window                (`HATCHERY_ADMIT_RATE`,   default 60 / 10 min)
 *   2. accepted bytes per window         (`HATCHERY_ADMIT_BYTES`,  default 2 GiB / 10 min)
 *   3. queued + running jobs, right now  (`HATCHERY_ADMIT_JOBS`,   default 8)
 *
 * **A submission reserves the largest sample it could send**, before the body is
 * read, and settles to the real size when it is known. That ordering is the whole
 * point: a byte quota checked after the bytes have been written protects nothing,
 * which is exactly the defect D40 fixed one layer down (a limit applied after the
 * allocation it was meant to prevent). A 300 MiB upload that would break the quota
 * is refused before a single byte is staged.
 *
 * What it is not: this is single-host, per-process accounting with a fixed window,
 * and it stops accident and casual abuse — a loop, a runaway client, a leaked token
 * used politely. It does not stop a determined attacker holding a valid **admin**
 * token, who already owns the input path and can simply retry inside the budget.
 * The honest claim is "bounded", not "safe".
 */

import type Database from 'better-sqlite3';

export interface AdmissionLimits {
  windowSeconds: number;
  requests: number;
  bytes: number;
  jobs: number;
}

export interface Reservation {
  owner: string;
  /** Fixed-window start (epoch seconds). Settling must land in the same window. */
  windowStart: number;
  /** What was counted against the byte quota up front. */
  reservedBytes: number;
}

export type RefusalCode = 'rate' | 'bytes' | 'jobs';

export interface Refusal {
  ok: false;
  code: RefusalCode;
  limit: number;
  used: number;
  retryAfter: number;
}

export interface Granted {
  ok: true;
  reservation: Reservation;
}

export type AdmissionDecision = Granted | Refusal;

const DEFAULT_WINDOW_SECONDS = 600;
const DEFAULT_REQUESTS = 60;
const DEFAULT_BYTES = 2 * 1024 * 1024 * 1024;
const DEFAULT_JOBS = 8;

/** `Retry-After` for a full job queue: a polling hint, not a promise (D43). */
export const JOB_RETRY_HINT_SECONDS = 30;

function integerEnv(value: string | undefined, fallback: number): number {
  if (value === undefined || value.trim() === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return parsed;
}

/**
 * Read the limits. `0` disables a dimension, which is documented as the operator's
 * deliberate choice — a limit nobody can turn off is a limit somebody will work
 * around by patching the source.
 */
export function readLimits(env: NodeJS.ProcessEnv = process.env): AdmissionLimits {
  const windowSeconds = Math.max(1, integerEnv(env.HATCHERY_ADMIT_WINDOW, DEFAULT_WINDOW_SECONDS));
  return {
    windowSeconds,
    requests: integerEnv(env.HATCHERY_ADMIT_RATE, DEFAULT_REQUESTS),
    bytes: integerEnv(env.HATCHERY_ADMIT_BYTES, DEFAULT_BYTES),
    jobs: integerEnv(env.HATCHERY_ADMIT_JOBS, DEFAULT_JOBS),
  };
}

/** One line for the startup banner: what an operator is actually allowed. */
export function describeLimits(limits: AdmissionLimits): string {
  const perWindow = `per ${limits.windowSeconds}s`;
  const parts = [
    limits.requests > 0 ? `${limits.requests} requests ${perWindow}` : 'requests unlimited',
    limits.bytes > 0 ? `${limits.bytes} bytes ${perWindow}` : 'bytes unlimited',
    limits.jobs > 0 ? `${limits.jobs} queued+running jobs` : 'jobs unlimited',
  ];
  return parts.join(', ');
}

export function windowStartFor(nowSeconds: number, limits: AdmissionLimits): number {
  return Math.floor(nowSeconds / limits.windowSeconds) * limits.windowSeconds;
}

export interface ActiveJobCounter {
  /** How many queued/running jobs the owner has, or null when it cannot be read. */
  count(owner: string): number | null;
}

/**
 * Reserve one submission against the caller's budget.
 *
 * `reservedBytes` is the largest sample this request could store. For a multipart
 * body that is the upload limit, because the size is not known until the body has
 * been read — and reading it is the thing the quota exists to prevent. The caller
 * settles the difference afterwards with {@link settle}.
 *
 * `jobs` is a reader, not a counter: job state belongs to the engine (D27), so the
 * cap is enforced by counting what the queue already says rather than by keeping a
 * second tally that could drift. An unreadable queue returns null and the cap is not
 * applied — "I could not look" is not evidence of a full queue, and refusing every
 * submission because the queue file is absent would break a fresh install.
 */
export function reserve(
  db: Database.Database,
  owner: string,
  reservedBytes: number,
  limits: AdmissionLimits,
  jobs: ActiveJobCounter | null = null,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): AdmissionDecision {
  const windowStart = windowStartFor(nowSeconds, limits);
  const retryAfter = Math.max(1, windowStart + limits.windowSeconds - nowSeconds);

  // Read-then-write inside one transaction: better-sqlite3 is synchronous, but a
  // settle from another request must not interleave between the read and the write.
  // A refusal never consumes the resource it refused — the counters are untouched.
  const run = db.transaction((): AdmissionDecision => {
    const row = db
      .prepare('SELECT requests, bytes FROM admission_counters WHERE owner = ? AND window_start = ?')
      .get(owner, windowStart) as { requests: number; bytes: number } | undefined;
    const requests = row?.requests ?? 0;
    const bytes = row?.bytes ?? 0;

    if (limits.requests > 0 && requests >= limits.requests) {
      return {
        ok: false, code: 'rate', limit: limits.requests, used: requests, retryAfter,
      };
    }
    if (limits.bytes > 0 && bytes + reservedBytes > limits.bytes) {
      return {
        ok: false,
        code: 'bytes',
        limit: limits.bytes,
        used: bytes,
        retryAfter,
      };
    }
    if (limits.jobs > 0 && jobs) {
      const active = jobs.count(owner);
      if (active !== null && active >= limits.jobs) {
        return {
          ok: false,
          code: 'jobs',
          limit: limits.jobs,
          used: active,
          retryAfter: JOB_RETRY_HINT_SECONDS,
        };
      }
    }

    db.prepare(
      `INSERT INTO admission_counters (owner, window_start, requests, bytes)
       VALUES (?, ?, 1, ?)
       ON CONFLICT(owner, window_start)
       DO UPDATE SET requests = requests + 1, bytes = bytes + excluded.bytes`,
    ).run(owner, windowStart, reservedBytes);

    // The table must stay finite without a timer: anything older than the previous
    // window is not evidence about this one.
    db.prepare('DELETE FROM admission_counters WHERE window_start < ?').run(
      windowStart - limits.windowSeconds,
    );

    return { ok: true, reservation: { owner, windowStart, reservedBytes } };
  });

  return run();
}

/**
 * Settle a reservation to the bytes the caller actually caused to be stored.
 *
 * A refusal or a disconnect settles to 0: the reservation was the request's
 * *intent*, and intent that never became a stored sample must not be charged back
 * to the operator forever. If the window has rolled over (a long upload), the old
 * row may be gone and nothing is adjusted — the honest outcome, since the new
 * window's budget is about the new window.
 */
export function settle(
  db: Database.Database,
  reservation: Reservation,
  actualBytes: number,
): void {
  const delta = reservation.reservedBytes - Math.max(0, Math.trunc(actualBytes));
  if (delta <= 0) return;
  db.prepare(
    `UPDATE admission_counters SET bytes = MAX(0, bytes - ?)
     WHERE owner = ? AND window_start = ?`,
  ).run(delta, reservation.owner, reservation.windowStart);
}

/** What a 429 says. The shape is deliberate: a client can act on it without parsing prose. */
export interface AdmissionRefusalBody {
  error: string;
  reason: string;
  limit: number;
  used: number;
  window_seconds: number;
  retry_after: number;
}

export function refusalBody(
  refusal: Refusal,
  limits: AdmissionLimits,
): AdmissionRefusalBody {
  const messages: Record<RefusalCode, string> = {
    rate: 'too many submissions in this window',
    bytes: 'accepted-sample budget for this window is exhausted',
    jobs: 'too many queued or running jobs for this caller',
  };
  return {
    error: `submission refused: ${messages[refusal.code]}`,
    reason: `admission-${refusal.code}`,
    limit: refusal.limit,
    used: refusal.used,
    window_seconds: refusal.code === 'jobs' ? 0 : limits.windowSeconds,
    retry_after: refusal.retryAfter,
  };
}
