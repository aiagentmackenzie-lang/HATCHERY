/**
 * The audit log's disk-growth guard (D32).
 *
 * An always-on API whose audit log grows silently is a defect, but an API that prunes
 * its own evidence is a worse one. So the guard **measures** and **warns** — in
 * `npm run audit -- status`, in every verify response and in the startup banner — and
 * it never deletes anything. The only thing that removes audit rows is an operator
 * running `npm run audit -- compact --apply`.
 *
 * The thresholds are row-count and database-bytes based, configurable, and `0`
 * disables a dimension:
 *
 * | Variable | Default | Meaning |
 * |:--|:--|:--|
 * | `HATCHERY_AUDIT_WARN_ROWS` | 500 000 | warn at this many audit rows |
 * | `HATCHERY_AUDIT_WARN_BYTES` | 256 MiB | warn at this database size (db + WAL) |
 */

import fs from 'fs';
import type Database from 'better-sqlite3';

export const DEFAULT_WARN_ROWS = 500_000;
export const DEFAULT_WARN_BYTES = 256 * 1024 * 1024;

export interface GrowthThresholds {
  warn_rows: number;
  warn_bytes: number;
}

export interface DatabaseSizes {
  bytes: number;
  database_bytes: number;
  wal_bytes: number;
  shm_bytes: number;
}

export interface GrowthReport {
  rows: number;
  bytes: number;
  warn_rows: number;
  warn_bytes: number;
  over: boolean;
  reasons: string[];
  message: string;
  /** The guard never deletes; this is false by construction and stated in the API. */
  enforced: false;
}

function numberOrNull(value: unknown): number | null {
  if (value === undefined || value === null || value === '') return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return null;
  return Math.floor(parsed);
}

export function growthThresholds(env: NodeJS.ProcessEnv = process.env): GrowthThresholds {
  const rows = numberOrNull(env.HATCHERY_AUDIT_WARN_ROWS);
  const bytes = numberOrNull(env.HATCHERY_AUDIT_WARN_BYTES);
  return {
    warn_rows: rows === null ? DEFAULT_WARN_ROWS : rows,
    warn_bytes: bytes === null ? DEFAULT_WARN_BYTES : bytes,
  };
}

export function databaseSizes(dbPath: string): DatabaseSizes {
  const size = (file: string) => {
    try {
      return fs.statSync(file).size;
    } catch {
      return 0;
    }
  };
  const database_bytes = size(dbPath);
  const wal_bytes = size(`${dbPath}-wal`);
  const shm_bytes = size(`${dbPath}-shm`);
  return { bytes: database_bytes + wal_bytes + shm_bytes, database_bytes, wal_bytes, shm_bytes };
}

/**
 * Measure the log against the warning thresholds. Read-only, always: a guard that
 * "fixes" growth by deleting evidence is the thing this project exists to avoid.
 */
export function growthReport(
  db: Database.Database,
  dbPath: string,
  env: NodeJS.ProcessEnv = process.env,
): GrowthReport {
  const thresholds = growthThresholds(env);
  let rows = 0;
  try {
    rows = (db.prepare('SELECT COUNT(*) AS n FROM audit_log').get() as { n: number }).n;
  } catch {
    rows = 0;
  }
  const sizes = databaseSizes(dbPath);
  const reasons: string[] = [];
  if (thresholds.warn_rows > 0 && rows >= thresholds.warn_rows) {
    reasons.push(`${rows} audit rows (warning at ${thresholds.warn_rows})`);
  }
  if (thresholds.warn_bytes > 0 && sizes.bytes >= thresholds.warn_bytes) {
    reasons.push(`${sizes.bytes} database bytes (warning at ${thresholds.warn_bytes})`);
  }
  const over = reasons.length > 0;
  return {
    rows,
    bytes: sizes.bytes,
    warn_rows: thresholds.warn_rows,
    warn_bytes: thresholds.warn_bytes,
    over,
    reasons,
    message: over
      ? `audit log is over its warning threshold: ${reasons.join(', ')}; run ` +
        '`npm run audit -- status` and `npm run audit -- compact --apply`'
      : 'audit log is below its warning threshold',
    enforced: false,
  };
}
