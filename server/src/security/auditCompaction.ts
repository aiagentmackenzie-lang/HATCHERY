/**
 * Retention policy, compaction and the disk-growth guard (D32).
 *
 * `audit_log` grows for the life of the deployment and nothing in the serving process
 * prunes it. Deleting old rows is exactly what a hash chain cannot survive, so a
 * compaction **archives** a segment (see `auditArchive.ts`) and hands the chain off.
 *
 * The rules this module enforces:
 *
 * - **Nothing is deleted at runtime.** Retention is applied only by
 *   `npm run audit -- compact`, and only with `--apply`. There is no timer, no
 *   scheduled task and no code path from a request to this module.
 * - **The policy always leaves a live anchor row** (`--keep-rows`, default 1). A policy
 *   that would archive the newest chained row is clamped, and the clamp is reported
 *   rather than hidden.
 * - **A run archives a bounded segment** (`--max-segment-rows`, default 50 000), so the
 *   archive file, the verification cost and the time the write lock is held stay
 *   bounded. `status` says how many rows are still eligible afterwards.
 * - **A crash resumes.** The archive and the manifest are written before any row is
 *   deleted, both are deterministic, and an interrupted run re-uses the files it left
 *   behind. A second `compact` either completes the deletion or reports that there is
 *   nothing left to do.
 * - **Concurrency is safe.** The deletion and the `audit.compacted` record are one
 *   `BEGIN IMMEDIATE` transaction, re-checking the archived window inside the lock. A
 *   concurrent append cannot be lost; a concurrent compaction either wins the lock or
 *   observes the rows already gone and aborts having deleted nothing.
 * - **Fail closed.** An archive that cannot be written, a manifest that does not match,
 *   a join that cannot be proven or a window that changed under us refuses and deletes
 *   nothing.
 */

import { createHash } from 'crypto';
import fs from 'fs';
import path from 'path';
import type Database from 'better-sqlite3';

import {
  appendAuditRowStrict,
  auditChainMeta,
  setAuditChainMeta,
  type AuditEntry,
} from './audit.js';
import type { AuditKeyring } from './auditKey.js';
import {
  databaseSizes,
  growthReport,
  type GrowthReport,
} from './auditGrowth.js';
import {
  DEFAULT_MAX_SEGMENT_ROWS,
  MANIFEST_VERSION,
  defaultArchiveDir,
  describeArchivePath,
  ensureArchiveDir,
  readArchiveSegments,
  segmentFromManifest,
  sha256,
  sha256Buffer,
  writeArchive,
  writeManifest,
  type ArchiveRow,
  type ArchiveSegment,
} from './auditArchive.js';

export interface RetentionPolicy {
  /** Archive rows created more than this many seconds ago. `null` = no age rule. */
  older_than_seconds: number | null;
  /** Archive everything beyond the newest N chained rows. `null` = no count rule. */
  max_rows: number | null;
  /** Always keep this many of the newest chained rows live (the anchor). Minimum 1. */
  keep_rows: number;
  /** At most this many rows per run. */
  max_segment_rows: number;
}

export const DEFAULT_KEEP_ROWS = 1;

/** `30d`, `24h`, `90m`, `45s` or a bare number of seconds. */
export function parseDuration(value: string): number {
  const match = /^(\d+(?:\.\d+)?)(s|m|h|d|w)?$/i.exec(String(value).trim());
  if (!match) throw new Error(`not a duration: ${value} (use 30d, 12h, 90m or seconds)`);
  const amount = Number(match[1]);
  const unit = (match[2] ?? 's').toLowerCase();
  const factor = unit === 's' ? 1 : unit === 'm' ? 60 : unit === 'h' ? 3600 : unit === 'd' ? 86400 : 604800;
  const seconds = Math.floor(amount * factor);
  if (!Number.isFinite(seconds) || seconds < 0) throw new Error(`not a duration: ${value}`);
  return seconds;
}

function numberOrNull(value: unknown): number | null {
  if (value === undefined || value === null || value === '') return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return null;
  return Math.floor(parsed);
}

/**
 * Resolve the policy from explicit arguments and the environment.
 *
 * The environment only supplies **defaults for the command**. Retention is still off
 * unless a rule is configured *and* an operator runs `compact --apply`; the serving
 * process never reads this.
 */
export function resolveRetentionPolicy(
  args: { olderThan?: string; maxRows?: number | string; keepRows?: number | string; maxSegmentRows?: number | string } = {},
  env: NodeJS.ProcessEnv = process.env,
): RetentionPolicy {
  const envDays = env.HATCHERY_AUDIT_RETENTION_DAYS;
  let olderThan = args.olderThan === undefined ? (envDays ? `${envDays}d` : undefined) : String(args.olderThan);
  const older_than_seconds = olderThan === undefined ? null : parseDuration(olderThan);

  const maxRowsRaw = args.maxRows ?? env.HATCHERY_AUDIT_RETENTION_MAX_ROWS ?? null;
  const max_rows = numberOrNull(maxRowsRaw);

  const keepRaw = args.keepRows ?? env.HATCHERY_AUDIT_KEEP_ROWS ?? DEFAULT_KEEP_ROWS;
  const keep_rows = Math.max(1, numberOrNull(keepRaw) ?? DEFAULT_KEEP_ROWS);

  const segmentRaw = args.maxSegmentRows ?? env.HATCHERY_AUDIT_MAX_SEGMENT_ROWS ?? DEFAULT_MAX_SEGMENT_ROWS;
  const max_segment_rows = Math.max(1, numberOrNull(segmentRaw) ?? DEFAULT_MAX_SEGMENT_ROWS);

  return { older_than_seconds, max_rows, keep_rows, max_segment_rows };
}

export function policyIsOff(policy: RetentionPolicy): boolean {
  return policy.older_than_seconds === null && policy.max_rows === null;
}

export function describePolicy(policy: RetentionPolicy): Record<string, unknown> {
  return {
    older_than_seconds: policy.older_than_seconds,
    older_than: policy.older_than_seconds === null ? null : `${policy.older_than_seconds}s`,
    max_rows: policy.max_rows,
    keep_rows: policy.keep_rows,
    max_segment_rows: policy.max_segment_rows,
  };
}

const ROW_COLUMNS = `id, actor, role, authenticated, method, path, status_code, action,
                    detail, created_at, prev_hash, entry_hash, key_id, entry_mac`;

function nthNewestChainedId(db: Database.Database, offset: number): number | null {
  const row = db
    .prepare(
      `SELECT id FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1 OFFSET ?`,
    )
    .get(offset) as { id: number } | undefined;
  return row?.id ?? null;
}

export interface CompactionPlan {
  policy: RetentionPolicy;
  /** Rows that satisfy the policy before the per-run segment cap. */
  eligible_rows: number;
  /** Rows this run would archive (capped). */
  rows: number;
  first_id: number | null;
  last_id: number | null;
  /** The newest chained row that would be archived is clamped by `keep_rows`. */
  clamped: boolean;
  /** Rows still eligible after this run. */
  remaining_after: number;
  /** The row that will remain live immediately after the archived window. */
  anchor: { id: number; entry_hash: string; prev_hash: string } | null;
  /** The id below which everything eligible lies. */
  cutoff_id: number | null;
}

/**
 * Decide which rows a run would archive. Pure read: nothing is written, and a dry run
 * and an `--apply` run compute the same window (the `--apply` run re-checks it under
 * the write lock).
 */
export function planCompaction(db: Database.Database, policy: RetentionPolicy): CompactionPlan {
  const empty: CompactionPlan = {
    policy,
    eligible_rows: 0,
    rows: 0,
    first_id: null,
    last_id: null,
    clamped: false,
    remaining_after: 0,
    anchor: null,
    cutoff_id: null,
  };
  if (policyIsOff(policy)) return empty;

  const chained = db
    .prepare('SELECT COUNT(*) AS n FROM audit_log WHERE entry_hash IS NOT NULL')
    .get() as { n: number };

  // The hard floor: the newest `keep_rows` chained rows are never archived, so the
  // live chain always keeps a row for the next append to link to.
  const keepNewestId = nthNewestChainedId(db, policy.keep_rows - 1);
  if (keepNewestId === null) return empty; // fewer rows than the floor

  // What the policy alone would take, before the floor is applied.
  let policyCutoff: number | null = null;
  if (policy.max_rows !== null) {
    if (chained.n <= policy.max_rows) {
      // Already within the count budget: the count rule contributes nothing. The
      // compaction record is itself a chained row, so the rule archives
      // `live - max_rows + 1` rows rather than nibbling one row per run for ever.
      if (policy.older_than_seconds === null) return empty;
    } else {
      const offset = Math.max(0, policy.max_rows - 1);
      const beyond = nthNewestChainedId(db, offset);
      if (beyond === null) return empty;
      policyCutoff = beyond;
    }
  }
  if (policy.older_than_seconds !== null) {
    const cutoffIso = new Date(Date.now() - policy.older_than_seconds * 1000)
      .toISOString()
      .slice(0, 19)
      .replace('T', ' ');
    const aged = db
      .prepare(
        `SELECT MAX(id) AS id FROM audit_log
          WHERE entry_hash IS NOT NULL AND datetime(created_at) < datetime(?)`,
      )
      .get(cutoffIso) as { id: number | null };
    if (aged.id === null) return empty; // nothing is old enough
    policyCutoff = policyCutoff === null ? aged.id : Math.min(policyCutoff, aged.id);
  }
  if (policyCutoff === null) return empty;

  const floor = keepNewestId - 1;
  const cutoff = Math.min(policyCutoff, floor);
  const clamped = policyCutoff > floor;
  if (cutoff < 0) return empty;

  const first = db
    .prepare(
      `SELECT id, created_at, prev_hash, entry_hash FROM audit_log
        WHERE entry_hash IS NOT NULL AND id <= ? ORDER BY id ASC LIMIT 1`,
    )
    .get(cutoff) as { id: number; entry_hash: string; prev_hash: string } | undefined;
  if (!first) return empty;

  const eligible = db
    .prepare(
      `SELECT COUNT(*) AS n FROM audit_log WHERE entry_hash IS NOT NULL AND id <= ?`,
    )
    .get(cutoff) as { n: number };
  if (eligible.n === 0) return empty;

  const rows = Math.min(eligible.n, policy.max_segment_rows);
  const last = db
    .prepare(
      `SELECT id FROM audit_log WHERE entry_hash IS NOT NULL AND id <= ?
        ORDER BY id ASC LIMIT 1 OFFSET ?`,
    )
    .get(cutoff, rows - 1) as { id: number } | undefined;
  if (!last) return empty;

  const anchor = db
    .prepare(
      `SELECT id, entry_hash, prev_hash FROM audit_log
        WHERE entry_hash IS NOT NULL AND id > ? ORDER BY id ASC LIMIT 1`,
    )
    .get(last.id) as { id: number; entry_hash: string; prev_hash: string } | undefined;
  if (!anchor) return empty;

  return {
    policy,
    eligible_rows: eligible.n,
    rows,
    first_id: first.id,
    last_id: last.id,
    clamped,
    remaining_after: Math.max(0, eligible.n - rows),
    anchor,
    cutoff_id: cutoff,
  };
}

export type CompactionStep =
  | 'archive-written'
  | 'manifest-written'
  | 'row-appended'
  | 'rows-deleted'
  | 'committed';

export interface CompactOptions {
  dbPath: string;
  policy: RetentionPolicy;
  apply: boolean;
  gzip?: boolean;
  outDir?: string;
  now?: Date;
  keyring?: AuditKeyring | null;
  /** Test-only: run a callback at each step so an interruption can be simulated. */
  hooks?: (step: CompactionStep) => void;
}

export interface CompactionReport {
  compacted: boolean;
  applied: boolean;
  reason: string | null;
  policy: Record<string, unknown>;
  archive_dir: string;
  window: { first_id: number; last_id: number; rows: number; from: string | null; to: string | null } | null;
  archive: { path: string; sha256: string; size: number; compression: string; reused: boolean } | null;
  manifest: { path: string; sha256: string; reused: boolean } | null;
  tail: { id: number; entry_hash: string; entry_mac: string | null; key_id: string | null } | null;
  join: { anchor_id: number; anchor_prev_hash: string; proven: boolean } | null;
  remaining_eligible: number;
  clamped: boolean;
  segment: ArchiveSegment | null;
  resumed: boolean;
  warnings: string[];
}

function isBusy(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /SQLITE_BUSY|database is locked|database table is locked/i.test(message);
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function loadRows(db: Database.Database, lastId: number, limit: number): ArchiveRow[] {
  return db
    .prepare(
      `SELECT ${ROW_COLUMNS} FROM audit_log
        WHERE entry_hash IS NOT NULL AND id <= ?
        ORDER BY id ASC
        LIMIT ?`,
    )
    .all(lastId, limit) as ArchiveRow[];
}

/**
 * Archive a segment and delete it, handing the chain off.
 *
 * Without `apply` this is a dry run: it writes no file and deletes no row, and it
 * reports exactly what an `--apply` run would move.
 */
export function compactAudit(db: Database.Database, options: CompactOptions): CompactionReport {
  const now = options.now ?? new Date();
  const createdAt = now.toISOString();
  const archiveDir = options.outDir
    ? path.resolve(options.outDir)
    : defaultArchiveDir(options.dbPath);

  const report: CompactionReport = {
    compacted: false,
    applied: false,
    reason: null,
    policy: describePolicy(options.policy),
    archive_dir: archiveDir,
    window: null,
    archive: null,
    manifest: null,
    tail: null,
    join: null,
    remaining_eligible: 0,
    clamped: false,
    segment: null,
    resumed: false,
    warnings: [],
  };

  const plan = planCompaction(db, options.policy);
  report.remaining_eligible = plan.remaining_after;
  report.clamped = plan.clamped;
  if (policyIsOff(options.policy)) {
    report.reason = 'retention-policy-off';
    return report;
  }
  if (plan.rows === 0 || plan.first_id === null || plan.last_id === null) {
    report.reason = 'nothing-to-archive';
    return report;
  }

  const rows = loadRows(db, plan.last_id, plan.rows);
  if (rows.length !== plan.rows) {
    throw new Error(
      `the compaction window changed while it was read (expected ${plan.rows} rows, ` +
        `found ${rows.length}) — nothing was written`,
    );
  }
  const tail = rows[rows.length - 1];
  report.window = {
    first_id: rows[0].id,
    last_id: tail.id,
    rows: rows.length,
    from: rows[0].created_at,
    to: tail.created_at,
  };
  report.tail = {
    id: tail.id,
    entry_hash: tail.entry_hash,
    entry_mac: tail.entry_mac,
    key_id: tail.key_id,
  };

  // The join must be provable **before** anything is archived: the row that will
  // remain live has to link to the last archived row's hash.
  if (!plan.anchor || plan.anchor.prev_hash !== tail.entry_hash) {
    throw new Error(
      `refusing to compact: the row after the window (${plan.anchor ? plan.anchor.id : 'none'}) ` +
        `does not link to the archived tail ${tail.id}:${tail.entry_hash} — the join could ` +
        'not be proven, so nothing was archived',
    );
  }
  report.join = {
    anchor_id: plan.anchor.id,
    anchor_prev_hash: plan.anchor.prev_hash,
    proven: true,
  };

  if (!options.apply) {
    report.reason = 'dry-run';
    return report;
  }

  ensureArchiveDir(archiveDir);
  const gzip = Boolean(options.gzip);
  const written = writeArchive(archiveDir, rows[0].id, tail.id, rows, gzip);
  const archiveSha = sha256Buffer(written.bytes);
  report.archive = {
    path: describeArchivePath(options.dbPath, written.file),
    sha256: archiveSha,
    size: written.bytes.length,
    compression: gzip ? 'gzip' : 'none',
    reused: !written.written,
  };
  if (!written.written) report.resumed = true;
  options.hooks?.('archive-written');

  const meta = auditChainMeta(db);
  const manifest = writeManifest({
    dbPath: options.dbPath,
    dir: archiveDir,
    firstId: rows[0].id,
    lastId: tail.id,
    rows,
    archiveFile: written.file,
    archiveSha256: archiveSha,
    archiveSize: written.bytes.length,
    compression: gzip ? 'gzip' : 'none',
    policy: describePolicy(options.policy),
    headId: meta.head_id ? Number(meta.head_id) : null,
    headHash: meta.head_hash ?? null,
    now: createdAt,
  });
  report.manifest = {
    path: describeArchivePath(options.dbPath, manifest.file),
    sha256: manifest.sha256,
    reused: !manifest.written,
  };
  if (!manifest.written) report.resumed = true;
  options.hooks?.('manifest-written');

  const existing = readArchiveSegments(db);
  if (existing.error) {
    throw new Error(`refusing to compact: ${existing.error}`);
  }
  const sequence = existing.segments.length + 1;
  const segment = segmentFromManifest(
    options.dbPath,
    sequence,
    manifest.document,
    manifest.sha256,
    archiveSha,
    createdAt,
  );

  const detail =
    `archived ${rows[0].id}-${tail.id} (${rows.length} rows) -> ${report.archive?.path} ` +
    `manifest sha256:${manifest.sha256} tail ${tail.id}:${tail.entry_hash}`;

  const run = () => {
    // Re-read the window under the write lock. Rows in it are immutable, so anything
    // other than "exactly what we archived" means another compaction got there first
    // (or something removed rows) — abort, having deleted nothing.
    const current = loadRows(db, tail.id, rows.length + 1);
    if (
      current.length !== rows.length ||
      current[0].id !== rows[0].id ||
      current[current.length - 1].entry_hash !== tail.entry_hash
    ) {
      throw new Error(
        `compaction window changed between the archive write and the delete ` +
          `(expected ${rows.length} rows ending at ${tail.id}:${tail.entry_hash}) — ` +
          'another compaction or a deletion got there first; nothing was deleted',
      );
    }
    const anchorNow = db
      .prepare(
        `SELECT id, prev_hash FROM audit_log
          WHERE entry_hash IS NOT NULL AND id > ? ORDER BY id ASC LIMIT 1`,
      )
      .get(tail.id) as { id: number; prev_hash: string } | undefined;
    if (!anchorNow || anchorNow.prev_hash !== tail.entry_hash) {
      throw new Error(
        'refusing to compact: the live row after the window no longer links to the ' +
          'archived tail — nothing was deleted',
      );
    }

    const entry: AuditEntry = {
      actor: 'operator:cli',
      role: 'admin',
      authenticated: false,
      method: 'CLI',
      path: 'audit.compacted',
      statusCode: null,
      action: 'audit.compacted',
      detail,
    };
    appendAuditRowStrict(db, entry);
    options.hooks?.('row-appended');

    const deleted = db
      .prepare('DELETE FROM audit_log WHERE id <= ? AND entry_hash IS NOT NULL')
      .run(tail.id);
    if (deleted.changes !== rows.length) {
      throw new Error(
        `refusing to compact: ${deleted.changes} row(s) would be deleted but ${rows.length} ` +
          'were archived — rolling back',
      );
    }
    options.hooks?.('rows-deleted');

    const live = db
      .prepare('SELECT COUNT(*) AS n FROM audit_log WHERE entry_hash IS NOT NULL')
      .get() as { n: number };

    // `chained_rows_total` is maintained by the appender (the `audit.compacted` row is
    // itself chained), so a compaction must not rewrite it. `chained_row_count` is the
    // live count and does shrink.
    setAuditChainMeta(db, 'archive_segments', JSON.stringify([...existing.segments, segment]));
    setAuditChainMeta(db, 'archived_row_total', String(Number(meta.archived_row_total ?? '0') + rows.length));
    setAuditChainMeta(db, 'archive_last_tail_id', String(tail.id));
    setAuditChainMeta(db, 'archive_last_tail_hash', tail.entry_hash);
    setAuditChainMeta(db, 'archive_last_manifest_sha256', manifest.sha256);
    setAuditChainMeta(db, 'archive_last_archive_sha256', archiveSha);
    setAuditChainMeta(db, 'chained_row_count', String(live.n));
    setAuditChainMeta(db, 'last_compacted_at', createdAt);
    options.hooks?.('committed');
  };

  for (let attempt = 0; ; attempt += 1) {
    try {
      if (db.inTransaction) run();
      else db.transaction(run).immediate();
      break;
    } catch (error) {
      if (!isBusy(error) || attempt >= 4) throw error;
      sleepSync(50 * 2 ** attempt);
    }
  }

  report.compacted = true;
  report.applied = true;
  report.segment = segment;
  report.remaining_eligible = Math.max(0, plan.eligible_rows - rows.length);
  report.reason = null;
  return report;
}

export interface AuditStatusReport {
  database: { path: string; bytes: number; database_bytes: number; wal_bytes: number };
  rows: { total: number; chained: number; legacy: number };
  oldest: { id: number; created_at: string } | null;
  newest: { id: number; created_at: string } | null;
  chained_rows_total: number;
  archived: {
    segments: number;
    rows: number;
    last_manifest: string | null;
    last_manifest_sha256: string | null;
    last_archive: string | null;
    last_compacted_at: string | null;
    error: string | null;
  };
  policy: Record<string, unknown>;
  policy_off: boolean;
  would_archive: {
    rows: number;
    first_id: number | null;
    last_id: number | null;
    eligible_rows: number;
    remaining_after: number;
    clamp: string;
    anchor_row: { id: number; entry_hash: string } | null;
  };
  growth: GrowthReport;
  append_failures: { since_start: number; total: number; persisted: boolean };
  served_by_api: false;
}

/**
 * `npm run audit -- status`: what is in the log, how big it is, what a run would
 * remove, whether growth is over the warning threshold, and what is archived.
 */
export function auditStatus(
  db: Database.Database,
  dbPath: string,
  policy: RetentionPolicy,
  options: {
    env?: NodeJS.ProcessEnv;
    appendFailures?: { since_start: number; total: number; persisted: boolean };
  } = {},
): AuditStatusReport {
  const env = options.env ?? process.env;
  const meta = auditChainMeta(db);
  const total = (db.prepare('SELECT COUNT(*) AS n FROM audit_log').get() as { n: number }).n;
  const chained = (
    db.prepare('SELECT COUNT(*) AS n FROM audit_log WHERE entry_hash IS NOT NULL').get() as { n: number }
  ).n;
  const oldest = db
    .prepare('SELECT id, created_at FROM audit_log ORDER BY id ASC LIMIT 1')
    .get() as { id: number; created_at: string } | undefined;
  const newest = db
    .prepare('SELECT id, created_at FROM audit_log ORDER BY id DESC LIMIT 1')
    .get() as { id: number; created_at: string } | undefined;

  const segments = readArchiveSegments(db);
  const plan = planCompaction(db, policy);
  const sizes = databaseSizes(dbPath);

  let clamp = 'none';
  if (policy.max_rows !== null && policy.max_rows < policy.keep_rows) {
    clamp = `--max-rows ${policy.max_rows} is below --keep-rows ${policy.keep_rows}; ` +
      `${policy.keep_rows} newest row(s) are kept as the anchor`;
  } else if (plan.eligible_rows > plan.rows) {
    clamp = `the run is capped at ${policy.max_segment_rows} rows; ${plan.remaining_after} more ` +
      'remain eligible for a later run';
  }

  return {
    database: {
      path: dbPath,
      bytes: sizes.bytes,
      database_bytes: sizes.database_bytes,
      wal_bytes: sizes.wal_bytes,
    },
    rows: { total, chained, legacy: total - chained },
    oldest: oldest ?? null,
    newest: newest ?? null,
    chained_rows_total: Number(meta.chained_rows_total ?? chained),
    archived: {
      segments: segments.segments.length,
      rows: Number(
        meta.archived_row_total ??
          segments.segments.reduce((sum, segment) => sum + Number(segment.window.rows), 0),
      ),
      last_manifest: segments.segments.at(-1)?.manifest.path ?? null,
      last_manifest_sha256: segments.segments.at(-1)?.manifest.sha256 ?? null,
      last_archive: segments.segments.at(-1)?.archive.path ?? null,
      last_compacted_at: meta.last_compacted_at ?? null,
      error: segments.error,
    },
    policy: describePolicy(policy),
    policy_off: policyIsOff(policy),
    would_archive: {
      rows: plan.rows,
      first_id: plan.first_id,
      last_id: plan.last_id,
      eligible_rows: plan.eligible_rows,
      remaining_after: plan.remaining_after,
      clamp,
      anchor_row: plan.anchor ? { id: plan.anchor.id, entry_hash: plan.anchor.entry_hash } : null,
    },
    growth: growthReport(db, dbPath, env),
    append_failures: options.appendFailures ?? { since_start: 0, total: 0, persisted: true },
    served_by_api: false,
  };
}

/** Manifest-version guard used by the CLI before it trusts a `--archive` path. */
export function assertManifestVersion(document: any): void {
  if (document?.manifest_version !== MANIFEST_VERSION) {
    throw new Error(
      `manifest version ${String(document?.manifest_version)} is not ${MANIFEST_VERSION}`,
    );
  }
}

/** A stable, non-secret id for an archive file, used in reports. */
export function archiveLabel(file: string): string {
  return createHash('sha256').update(path.basename(file)).digest('hex').slice(0, 12);
}

export { sha256 };
