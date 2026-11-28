/**
 * Append-only access audit log (D25), a hash chain (D30) and a keyed chain (D31).
 *
 * Every request the API answers is recorded: who (actor + role, and whether they
 * authenticated), what (method + path), and the outcome (status + action). What is
 * **not** recorded is as deliberate as what is: no token, no `Authorization`
 * header, no request body and no sample bytes. An audit log that leaks the
 * credential it is auditing is worse than no audit log.
 *
 * Three layers, each of which answers a different question:
 *
 * 1. **Append-only under concurrency.** Each row carries `prev_hash` (the previous
 *    row's `entry_hash`, or the documented genesis constant) and `entry_hash`
 *    (SHA-256 over a canonical encoding of the stored fields). The head read and the
 *    insert share one `BEGIN IMMEDIATE` transaction, so two API processes or the API
 *    plus the CLI produce one chain, not a fork.
 * 2. **Tamper-evidence.** `entry_mac` is HMAC-SHA-256 over the same canonical form,
 *    keyed by a local key ring (D31). Without the key, an attacker with write access
 *    can recompute digests but cannot produce a matching MAC — so "rewrite the whole
 *    chain" stops working. `key_id` names the key per row, so rotation never
 *    invalidates history.
 * 3. **Honesty about the gaps.** Verification reports its own strength
 *    (`assurance`, `coverage`) instead of a bare `ok`. A deliberate truncation that
 *    also rewrites the recorded head, or a whole-database rollback, is only
 *    detectable against a head recorded **outside** the database — that is what
 *    `expectHead` is for, and what the docs say plainly.
 */

import fs from 'fs';
import type Database from 'better-sqlite3';
import {
  CHAIN_ALGORITHM,
  GENESIS_HASH,
  canonical,
  entryHash,
  hexEqual,
  type ChainBreak,
  type ChainBreakClass,
  type HashableFields,
} from './auditChain.js';
import {
  activeKey,
  auditMac,
  findKey,
  type AuditKeyring,
} from './auditKey.js';
import {
  readArchiveSegments,
  resolveArchivePath,
  verifyArchive,
  type ArchiveSegment,
} from './auditArchive.js';
import { growthReport } from './auditGrowth.js';

export { CHAIN_ALGORITHM, GENESIS_HASH, canonical, entryHash } from './auditChain.js';
export type { ChainBreak, ChainBreakClass } from './auditChain.js';

export type AuditAction =
  | 'auth.denied'
  | 'request.forbidden'
  | 'request.allowed'
  | 'request.failed'
  // D43: a throttled request was refused, not served. Recording it as `allowed`
  // because 429 is below 500 would make the trail disagree with the response.
  | 'request.throttled'
  | 'token.created'
  | 'token.retired'
  | 'token.expired'
  | 'audit.verified'
  | 'audit.key-rotated'
  | 'audit.compacted';

export interface AuditEntry {
  actor: string;
  role: string;
  authenticated: boolean;
  method: string;
  path: string;
  statusCode?: number | null;
  action: AuditAction;
  detail?: string | null;
}

export interface AuditRow {
  id: number;
  actor: string;
  role: string;
  authenticated: number;
  method: string;
  path: string;
  status_code: number | null;
  action: string | null;
  detail: string | null;
  created_at: string;
  prev_hash: string | null;
  entry_hash: string | null;
  key_id: string | null;
  entry_mac: string | null;
}

/** Routes that are not worth an audit row (liveness probes, the websocket upgrade). */
const NOT_AUDITED = new Set(['/api/health', '/ws']);

export function shouldAudit(url: string): boolean {
  return !NOT_AUDITED.has(url.split('?')[0]);
}

const MAX_DETAIL = 300;

interface ChainFields extends HashableFields {
  entry_hash: string;
  key_id: string | null;
  entry_mac: string | null;
}


export function auditChainMeta(db: Database.Database): Record<string, string> {
  try {
    const rows = db.prepare('SELECT key, value FROM audit_chain_meta').all() as Array<{
      key: string;
      value: string;
    }>;
    return Object.fromEntries(rows.map((row) => [row.key, row.value]));
  } catch {
    return {};
  }
}

function setMeta(db: Database.Database, key: string, value: string): void {
  db.prepare(
    'INSERT INTO audit_chain_meta (key, value) VALUES (?, ?) ' +
      'ON CONFLICT(key) DO UPDATE SET value = excluded.value',
  ).run(key, value);
}

/**
 * Write one `audit_chain_meta` key. Exported for the compaction path (D32), which
 * records the archive boundary in the same transaction that deletes the segment.
 */
export function setAuditChainMeta(db: Database.Database, key: string, value: string): void {
  setMeta(db, key, value);
}

/**
 * The process's chain key ring (D31).
 *
 * `getDb()` always resolves one (generating a `0600` ring beside the database when
 * nothing is configured), so the server cannot silently write an unkeyed row. A unit
 * test that has no ring gets unkeyed rows and verification says so — the reduced
 * assurance is reported, never hidden.
 */
let chainKeyring: AuditKeyring | null = null;

export function configureAuditKeyring(ring: AuditKeyring | null): void {
  chainKeyring = ring;
}

export function auditKeyring(): AuditKeyring | null {
  return chainKeyring;
}

/** Appends that failed and were logged instead of written. Surfaced by verification. */
let appendFailures = 0;
/** The persisted count read at startup, so a restart does not forget the total. */
let appendFailuresBeforeStart = 0;
/** Whether this process managed to persist its failures to `audit_chain_meta`. */
let appendFailuresPersisted = true;

export function auditAppendFailures(): number {
  return appendFailures;
}

export function resetAuditAppendFailures(): void {
  appendFailures = 0;
}

/**
 * Seed the persisted failure total from the database at startup (D32).
 *
 * The counter used to be per process, so a restart forgot it. Persisting it in
 * `audit_chain_meta` is the same store the chain already uses — no second database,
 * no second daemon. It is **best effort by design**: a failure is usually caused by a
 * disk that is full or a lock that cannot be taken, and in exactly that case the
 * write that records the failure can fail too. When it does, `persisted` is false and
 * the server log remains the record — that limitation is stated, not hidden.
 */
export function loadAuditAppendFailures(db: Database.Database): void {
  appendFailures = 0;
  try {
    const meta = auditChainMeta(db);
    appendFailuresBeforeStart = Number(meta.append_failure_total ?? '0') || 0;
    appendFailuresPersisted = true;
  } catch {
    appendFailuresBeforeStart = 0;
    appendFailuresPersisted = false;
  }
}

function persistAppendFailure(db: Database.Database): void {
  try {
    const meta = auditChainMeta(db);
    const total = (Number(meta.append_failure_total ?? '0') || 0) + 1;
    setMeta(db, 'append_failure_total', String(total));
    setMeta(db, 'append_failure_last_at', new Date().toISOString());
    appendFailuresPersisted = true;
  } catch {
    // The database is the thing that just failed. The in-memory count and the server
    // log are what is left, and the report says the total is not persisted.
    appendFailuresPersisted = false;
  }
}

export function auditAppendFailureTotals(): {
  since_start: number;
  total: number;
  persisted: boolean;
} {
  return {
    since_start: appendFailures,
    total: appendFailuresBeforeStart + appendFailures,
    persisted: appendFailuresPersisted,
  };
}

/**
 * Record the migration boundary once (D30).
 *
 * `legacy_row_count`/`legacy_max_id` describe the rows that existed before the
 * chain did. They are written with `INSERT OR IGNORE` so a restart never moves the
 * anchor, and so a later deletion of a pre-chain row is visible as a count
 * mismatch instead of being silently absorbed. Those rows are **not** backfilled:
 * they were not tamper-evident when they were written, and pretending otherwise
 * would be a retroactive claim the evidence cannot support.
 */
export function initAuditChain(db: Database.Database): void {
  try {
    const meta = auditChainMeta(db);
    if (meta.chain_version) return;
    const row = db
      .prepare(
        'SELECT COUNT(*) AS n, MAX(id) AS max_id FROM audit_log WHERE entry_hash IS NULL',
      )
      .get() as { n: number; max_id: number | null };
    db.transaction(() => {
      setMeta(db, 'chain_version', '1');
      setMeta(db, 'legacy_row_count', String(row.n));
      setMeta(db, 'legacy_max_id', String(row.max_id ?? 0));
      setMeta(db, 'chained_row_count', '0');
      setMeta(db, 'chained_rows_total', '0');
      setMeta(db, 'archived_row_total', '0');
    }).immediate();
  } catch {
    // A database without the table yet (an older schema mid-migration) is handled
    // by the next call; the server refuses to append rather than guessing.
  }
}

/** Synchronous sleep, used only for the bounded retry of a busy append. */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function isBusy(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /SQLITE_BUSY|database is locked|database table is locked/i.test(message);
}

/**
 * Insert one audit row and advance the chain.
 *
 * The head read, the insert and the MAC all happen inside one `BEGIN IMMEDIATE`
 * transaction, so two writers cannot claim the same `prev_hash`. A busy database is
 * retried a bounded number of times (a *lost* audit row is worse than 120 ms of
 * latency); after that it throws and the caller logs the failure and counts it.
 */
function appendChained(db: Database.Database, entry: AuditEntry): {
  id: number;
  entryHash: string;
  prevHash: string;
} {
  const created = new Date().toISOString();
  const stored = {
    actor: entry.actor || 'anonymous',
    role: entry.role || 'anonymous',
    authenticated: entry.authenticated ? 1 : 0,
    method: entry.method,
    path: entry.path,
    status_code: entry.statusCode ?? null,
    action: entry.action,
    detail: entry.detail ? entry.detail.slice(0, MAX_DETAIL) : null,
    created_at: created,
  };

  const run = () => {
    const key = chainKeyring ? activeKey(chainKeyring) : null;
    const head = db
      .prepare(
        'SELECT id, entry_hash FROM audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1',
      )
      .get() as { id: number; entry_hash: string } | undefined;
    const prevHash = head?.entry_hash ?? GENESIS_HASH;

    const info = db
      .prepare(
        `INSERT INTO audit_log
           (actor, role, authenticated, method, path, status_code, action, detail,
            created_at, prev_hash, entry_hash, key_id, entry_mac)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL)`,
      )
      .run(
        stored.actor,
        stored.role,
        stored.authenticated,
        stored.method,
        stored.path,
        stored.status_code,
        stored.action,
        stored.detail,
        stored.created_at,
        prevHash,
        key?.id ?? null,
      );

    const id = Number(info.lastInsertRowid);
    const hash = entryHash({ id, prev_hash: prevHash, ...stored });
    const mac = key ? auditMac(key.material, key.id, canonical({ id, prev_hash: prevHash, ...stored })) : null;
    // Both cover the row id, which SQLite assigns on insert; they are filled in
    // inside the same transaction so no reader and no later appender can observe
    // or link to an unfilled row.
    db.prepare('UPDATE audit_log SET entry_hash = ?, entry_mac = ? WHERE id = ?').run(hash, mac, id);

    const meta = auditChainMeta(db);
    if (!meta.chain_first_id) setMeta(db, 'chain_first_id', String(id));
    setMeta(db, 'head_id', String(id));
    setMeta(db, 'head_hash', hash);
    setMeta(db, 'chained_row_count', String(Number(meta.chained_row_count ?? '0') + 1));
    // The cumulative count is what lets verification prove that every row that ever
    // existed is either live or archived (D32); it only ever grows.
    const previousTotal = Number(
      meta.chained_rows_total ?? meta.chained_row_count ?? '0',
    );
    setMeta(db, 'chained_rows_total', String(previousTotal + 1));
    return { id, entryHash: hash, prevHash };
  };

  for (let attempt = 0; ; attempt += 1) {
    try {
      // A caller already inside a transaction keeps its lock instead of nesting one
      // (and cannot be retried: its transaction is the one holding the write).
      if (db.inTransaction) return run();
      return db.transaction(run).immediate();
    } catch (error) {
      if (!isBusy(error) || attempt >= 2) throw error;
      sleepSync(40 * 3 ** attempt);
    }
  }
}

/**
 * Insert one audit row. Never throws: auditing must not break the request path
 * (D25). A failure is logged **without** any credential, counted, and reported by
 * `GET /api/audit/verify` as `append_failures_since_start` — so a hole caused by a
 * full disk or an exhausted busy timeout is visible instead of silent.
 */
export function recordAudit(db: Database.Database, entry: AuditEntry): boolean {
  try {
    appendChained(db, entry);
    return true;
  } catch (error) {
    appendFailures += 1;
    const message = error instanceof Error ? error.message : String(error);
    console.error(
      `[hatchery] audit append failed (chain not advanced, ${appendFailures} this process, ` +
        `${appendFailuresBeforeStart + appendFailures} total): ${message}`,
    );
    persistAppendFailure(db);
    return false;
  }
}

/**
 * Append one row and let a failure propagate. Used where an append is part of a
 * larger transaction that must roll back rather than continue (the `audit.compacted`
 * record, D32). The request path uses `recordAudit`, which never throws.
 */
export function appendAuditRowStrict(db: Database.Database, entry: AuditEntry): void {
  appendChained(db, entry);
}

/** Read the log, newest first. */
export function listAudit(
  db: Database.Database,
  options: { limit?: number; actor?: string } = {},
): AuditRow[] {
  const limit = Math.min(Math.max(options.limit ?? 100, 1), 1000);
  if (options.actor) {
    return db
      .prepare(
        'SELECT * FROM audit_log WHERE actor = ? ORDER BY id DESC LIMIT ?',
      )
      .all(options.actor, limit) as AuditRow[];
  }
  return db
    .prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?')
    .all(limit) as AuditRow[];
}

export function countAudit(db: Database.Database): number {
  const row = db.prepare('SELECT COUNT(*) AS n FROM audit_log').get() as { n: number };
  return row.n;
}

/**
 * What the verifier was actually able to check. `ok` must be read with this:
 * `empty` (nothing chained yet), `unkeyed` (no MACs at all), `mixed` (a keyed suffix
 * over unkeyed history) or `keyed` (every chained row authenticated).
 *
 * D32 does not change what `assurance` means: it is the strength of the check **on the
 * live chain**. A compacted-but-intact log reports the same assurance it had before the
 * compaction and says separately what is archived and whether the archive was read —
 * history moving to an archive must never silently weaken the claim.
 */
export type Assurance = 'empty' | 'unkeyed' | 'mixed' | 'keyed';

/** What is known about the archived history behind the live segment (D32). */
export interface ArchiveReport {
  /** The chain metadata records at least one archived segment. */
  recorded: boolean;
  /** Every recorded segment's archive file and manifest exist. */
  present: boolean;
  /** The archives were read and recomputed — not merely observed to exist. */
  checked: boolean;
  /** `checked` and nothing was wrong with them. */
  verified: boolean;
  mode: 'full' | 'presence' | 'none';
  segments: number;
  rows: number;
  first_id: number | null;
  last_id: number | null;
  /** The newest archived segment's manifest hash (of the manifest file itself). */
  manifest_sha256: string | null;
  archive_sha256: string | null;
  tail: {
    id: number;
    entry_hash: string;
    entry_mac: string | null;
    key_id: string | null;
  } | null;
  /** Whether the live chain's first `prev_hash` links to the archived tail. */
  join: 'none' | 'proven' | 'mismatch' | 'unchecked';
  missing: string[];
  error: string | null;
  /** Why the archives were not read, when they were not. */
  reason: string | null;
}

export interface ChainVerification {
  ok: boolean;
  algorithm: string;
  genesis: string;
  /** How strong the checks were: no MACs, a keyed suffix, or a fully keyed chain. */
  assurance: Assurance;
  coverage: {
    chained_rows: number;
    mac_rows: number;
    unkeyed_rows: number;
    legacy_rows: number;
  };
  /** Live rows vs archived rows, and whether the two chains splice (D32). */
  segments: {
    live_rows: number;
    archived_rows: number;
    archived_segments: number;
    live_first_prev_hash: string | null;
    archived_tail_hash: string | null;
    join: 'none' | 'proven' | 'mismatch' | 'unchecked';
  };
  archive: ArchiveReport;
  /** Convenience: `archive.verified`. A verifier that did not read the archive says false. */
  archive_verified: boolean;
  key: {
    active: string | null;
    id: string | null;
    source: string | null;
    env_ignored: boolean;
  };
  anchor: {
    expected: { id: number; hash: string } | null;
    /**
     * `true` when the anchored row is present with the anchored hash, wherever it is
     * now (live or archived). An anchor says "the log I recorded is still a prefix of
     * this log" — it is not a demand that nothing has happened since (D32 corrected
     * D31 here; a strict head equality made an anchor unusable after a single append).
     */
    matches: boolean | null;
    found_in: 'live' | 'archive' | null;
    /** Whether the anchored row is still the newest live row. Staleness is visible. */
    head_at_anchor: boolean | null;
  };
  rows_checked: number;
  complete: boolean;
  next_after_id: number | null;
  first_broken: ChainBreak | null;
  head: { id: number | null; hash: string | null; matches_meta: boolean };
  legacy: {
    rows: number;
    covered: false;
    anchor_row_count: number;
    altered: boolean;
  };
  /** Appends that failed in this process, and the persisted total (D32). */
  append_failures_since_start: number;
  append_failures_total: number;
  append_failures_persisted: boolean;
  /** The disk-growth guard: measured and warned, never enforced by deletion. */
  growth: {
    rows: number;
    bytes: number;
    warn_rows: number;
    warn_bytes: number;
    over: boolean;
    reasons: string[];
    message: string;
  } | null;
}

const MAX_VERIFY_ROWS = 50000;

/**
 * Recompute the chain and report the first row that does not verify.
 *
 * Bounded by `limitRows` so a large log cannot hang the endpoint; when the page is
 * exhausted the caller continues with `after`. Classification is causal:
 *
 * - `modified`   — the row's own `entry_hash` no longer matches its stored fields.
 * - `deleted`    — a row links to a hash that is not the previous row's, and the
 *                  ids skip, so row(s) were removed.
 * - `inserted`   — a row links to a hash the chain never produced (contiguous ids).
 * - `forged`     — the digest is self-consistent but the MAC is not: the row was
 *                  rewritten by something without the key.
 * - `unkeyed`    — a keyed row is followed by an unkeyed one: the chain was
 *                  downgraded after D31.
 * - `unknown-key`— a row names a key id the key ring does not hold (fail closed).
 * - `truncated`  — the recorded head is not at the end of the chain.
 * - `replaced`   — the anchored head is not in this chain (live or archived).
 * - `unhashed`   — a row inside the chained region has no `entry_hash` at all.
 * - `archive-missing`  — a recorded archive's file or manifest is gone (D32).
 * - `archive-mismatch` — the archive file is not the one the manifest recorded.
 * - `archive-modified` — an archived row was edited (digest or MAC).
 * - `archive-truncated`— archived rows are missing or the tail moved.
 * - `archive-invalid`  — the archive or its manifest cannot be parsed.
 * - `join-mismatch`    — the live chain does not link to the archived tail.
 */
export function verifyAuditChain(
  db: Database.Database,
  options: {
    limitRows?: number;
    afterId?: number;
    /** A head recorded outside the database, from `npm run audit -- head`. */
    expectHead?: { id: number; hash: string } | null;
    keyring?: AuditKeyring | null;
    /** Where the database lives, so a recorded archive path can be resolved. */
    dbPath?: string | null;
    /** `full` reads and recomputes the archives; `presence` only stats them. */
    archiveMode?: 'full' | 'presence';
    env?: NodeJS.ProcessEnv;
  } = {},
): ChainVerification {
  const limit = Math.min(Math.max(options.limitRows ?? 5000, 1), MAX_VERIFY_ROWS);
  const afterId = Math.max(options.afterId ?? 0, 0);
  const ring = options.keyring === undefined ? chainKeyring : options.keyring;
  const dbPath = options.dbPath ?? null;
  const env = options.env ?? process.env;
  const wantedArchiveMode = options.archiveMode ?? 'full';
  const meta = auditChainMeta(db);
  const metaHeadId = meta.head_id ? Number(meta.head_id) : null;
  const metaHeadHash = meta.head_hash ?? null;
  const anchorRows = Number(meta.legacy_row_count ?? '0');
  const chainFirstId = meta.chain_first_id ? Number(meta.chain_first_id) : null;
  const expectedHead = options.expectHead ?? null;

  const segmentsRead = readArchiveSegments(db);
  const segments: ArchiveSegment[] = segmentsRead.segments;
  const lastSegment = segments.length > 0 ? segments[segments.length - 1] : null;
  const archivedRowsRecorded = Number(
    meta.archived_row_total ??
      segments.reduce((sum, segment) => sum + Number(segment.window.rows ?? 0), 0),
  );
  const failures = auditAppendFailureTotals();
  const growth = dbPath ? growthReport(db, dbPath, env) : null;

  const archive: ArchiveReport = {
    recorded: segments.length > 0,
    present: false,
    checked: false,
    verified: false,
    mode: segments.length === 0 ? 'none' : wantedArchiveMode,
    segments: segments.length,
    rows: archivedRowsRecorded,
    first_id: segments[0]?.window.first_id ?? null,
    last_id: lastSegment?.window.last_id ?? null,
    manifest_sha256: lastSegment?.manifest.sha256 ?? null,
    archive_sha256: lastSegment?.archive.sha256 ?? null,
    tail: lastSegment
      ? {
          id: lastSegment.tail.id,
          entry_hash: lastSegment.tail.entry_hash,
          entry_mac: lastSegment.tail.entry_mac,
          key_id: lastSegment.tail.key_id,
        }
      : null,
    join: segments.length === 0 ? 'none' : 'unchecked',
    missing: [],
    error: segmentsRead.error,
    reason: null,
  };

  const result: ChainVerification = {
    ok: true,
    algorithm: CHAIN_ALGORITHM,
    genesis: GENESIS_HASH,
    assurance: 'empty',
    coverage: { chained_rows: 0, mac_rows: 0, unkeyed_rows: 0, legacy_rows: 0 },
    segments: {
      live_rows: 0,
      archived_rows: archivedRowsRecorded,
      archived_segments: segments.length,
      live_first_prev_hash: null,
      archived_tail_hash: lastSegment?.tail.entry_hash ?? null,
      join: segments.length === 0 ? 'none' : 'unchecked',
    },
    archive,
    archive_verified: false,
    key: {
      active: ring?.active ?? null,
      id: ring?.active ?? null,
      source: ring?.source ?? null,
      env_ignored: ring?.env_ignored ?? false,
    },
    anchor: { expected: expectedHead, matches: null, found_in: null, head_at_anchor: null },
    rows_checked: 0,
    complete: false,
    next_after_id: null,
    first_broken: null,
    head: { id: null, hash: null, matches_meta: false },
    legacy: { rows: 0, covered: false, anchor_row_count: anchorRows, altered: false },
    append_failures_since_start: failures.since_start,
    append_failures_total: failures.total,
    append_failures_persisted: failures.persisted,
    growth,
  };

  // Rows that predate the chain must be a prefix. Count them by id, which is
  // cheap on SQLite's rowid, instead of scanning the table.
  if (chainFirstId !== null) {
    const legacy = db
      .prepare('SELECT COUNT(*) AS n FROM audit_log WHERE id < ? AND entry_hash IS NULL')
      .get(chainFirstId) as { n: number };
    result.legacy.rows = legacy.n;
    result.legacy.altered = legacy.n !== anchorRows;
  } else {
    result.legacy.rows = anchorRows;
  }
  result.coverage.legacy_rows = result.legacy.rows;

  if (result.legacy.altered) {
    result.ok = false;
    result.first_broken = {
      id: null,
      classification: 'deleted',
      detail:
        `pre-chain rows changed since the anchor: ${anchorRows} at migration, ` +
        `${result.legacy.rows} now. Those rows were never tamper-evident (D30).`,
    };
    return result;
  }

  // Archive metadata that cannot be parsed is a break, not a shorter green history.
  if (segmentsRead.error) {
    result.ok = false;
    result.first_broken = {
      id: null,
      classification: 'archive-invalid',
      detail: `the archive metadata is unusable: ${segmentsRead.error}`,
    };
    return result;
  }

  // A NULL hash inside the chained region is a stripped hash, not a legacy row.
  if (chainFirstId !== null) {
    const stray = db
      .prepare(
        'SELECT id FROM audit_log WHERE entry_hash IS NULL AND id > ? ORDER BY id ASC LIMIT 1',
      )
      .get(chainFirstId) as { id: number } | undefined;
    if (stray) {
      result.ok = false;
      result.first_broken = {
        id: stray.id,
        classification: 'unhashed',
        detail: 'a row inside the chained region has no entry_hash',
      };
      return result;
    }
  }

  // With an archive behind the live segment, the chain must resume from the archived
  // tail, not from genesis. Without one, genesis is still the documented anchor.
  let expectedPrev = GENESIS_HASH;
  let prevId: number | null = null;
  let seenMac = false;
  let keyedSeen = false;

  /** Assurance reflects what was observed, including on a break at the first MAC'd row. */
  const finish = (): ChainVerification => {
    if (result.coverage.chained_rows === 0 && result.legacy.rows === 0) {
      result.assurance = 'empty';
    } else if (!keyedSeen) {
      result.assurance = 'unkeyed';
    } else {
      result.assurance = result.coverage.unkeyed_rows === 0 ? 'keyed' : 'mixed';
    }
    result.segments.live_rows = result.coverage.chained_rows;
    result.segments.join = result.archive.join;
    result.archive_verified = result.archive.verified;
    return result;
  };

  if (afterId > 0) {
    const anchor = db
      .prepare('SELECT id, entry_hash, entry_mac FROM audit_log WHERE id = ?')
      .get(afterId) as { id: number; entry_hash: string | null; entry_mac: string | null } | undefined;
    if (!anchor || !anchor.entry_hash) {
      result.ok = false;
      result.first_broken = {
        id: afterId,
        classification: 'deleted',
        detail: 'the row used to resume verification no longer exists or has no entry_hash',
      };
      return finish();
    }
    expectedPrev = anchor.entry_hash;
    prevId = anchor.id;
    seenMac = Boolean(anchor.entry_mac);
    result.head = { id: anchor.id, hash: anchor.entry_hash, matches_meta: false };
  } else if (lastSegment) {
    expectedPrev = lastSegment.tail.entry_hash;
  }

  const rows = db
    .prepare(
      `SELECT id, actor, role, authenticated, method, path, status_code, action,
              detail, created_at, prev_hash, entry_hash, key_id, entry_mac
         FROM audit_log
        WHERE entry_hash IS NOT NULL AND id > ?
        ORDER BY id ASC
        LIMIT ?`,
    )
    .all(afterId, limit) as ChainFields[];

  let firstWalked = true;
  for (const row of rows) {
    result.rows_checked += 1;
    result.coverage.chained_rows += 1;
    if (firstWalked && afterId === 0) {
      result.segments.live_first_prev_hash = row.prev_hash;
      if (lastSegment) {
        result.archive.join =
          row.prev_hash === lastSegment.tail.entry_hash ? 'proven' : 'mismatch';
        if (result.archive.join === 'mismatch') {
          result.ok = false;
          result.first_broken = {
            id: row.id,
            classification: 'join-mismatch',
            detail:
              `the live chain starts at row ${row.id} linking to ${String(row.prev_hash)}, ` +
              `but the archived segment ends at ${lastSegment.tail.id}:` +
              `${lastSegment.tail.entry_hash} — the two chains do not splice`,
          };
          return finish();
        }
      }
    }

    if (row.prev_hash !== expectedPrev) {
      const contiguous = prevId !== null ? row.id === prevId + 1 : true;
      result.ok = false;
      result.first_broken = {
        id: row.id,
        classification: contiguous ? 'inserted' : 'deleted',
        detail: contiguous
          ? `row ${row.id} links to a hash the chain never produced (prev_hash mismatch)`
          : `row ${row.id} does not follow row ${prevId} — row(s) were deleted`,
      };
      return finish();
    }

    if (row.entry_hash !== entryHash(row)) {
      result.ok = false;
      result.first_broken = {
        id: row.id,
        classification: 'modified',
        detail: `row ${row.id} no longer hashes to its stored entry_hash`,
      };
      return finish();
    }

    if (row.entry_mac) {
      keyedSeen = true;
      const key = findKey(ring, row.key_id);
      if (!key) {
        result.ok = false;
        result.first_broken = {
          id: row.id,
          classification: 'unknown-key',
          detail:
            `row ${row.id} is MAC'd with key ${String(row.key_id)}, which the key ring ` +
            'does not hold — cannot verify',
        };
        return finish();
      }
      const expected = auditMac(key.material, key.id, canonical(row));
      if (!hexEqual(expected, row.entry_mac)) {
        result.ok = false;
        result.first_broken = {
          id: row.id,
          classification: 'forged',
          detail:
            `row ${row.id} is internally consistent but its MAC does not verify — ` +
            'it was rewritten without the audit key',
        };
        return finish();
      }
      result.coverage.mac_rows += 1;
      seenMac = true;
    } else {
      if (seenMac) {
        result.ok = false;
        result.first_broken = {
          id: row.id,
          classification: 'unkeyed',
          detail: `row ${row.id} has no MAC after keyed rows — the chain was downgraded`,
        };
        return finish();
      }
      result.coverage.unkeyed_rows += 1;
    }

    expectedPrev = row.entry_hash as string;
    prevId = row.id;
    firstWalked = false;
    result.head = {
      id: row.id,
      hash: row.entry_hash,
      matches_meta: metaHeadId === row.id && metaHeadHash === row.entry_hash,
    };
  }

  result.complete = rows.length < limit;
  result.next_after_id = result.complete ? null : prevId;
  if (result.complete) {
    // The tail must be exactly where the appender left it; otherwise rows were
    // removed from the end, which no forward link can reveal. With the key held by
    // the operator, a truncation that also rewrites this metadata is caught by the
    // `expectHead` anchor instead — and only by it.
    const headId = result.head.id;
    const headHash = result.head.hash;
    result.head.matches_meta =
      metaHeadId !== null && headId === metaHeadId && headHash === metaHeadHash;
    if (metaHeadId !== null && (headId !== metaHeadId || headHash !== metaHeadHash)) {
      result.ok = false;
      result.first_broken = {
        id: metaHeadId,
        classification: 'truncated',
        detail:
          `the chain ends at row ${headId ?? 'none'} but the recorded head is row ` +
          `${metaHeadId} — rows were removed from the end`,
      };
    } else if (metaHeadId === null && result.head.id !== null) {
      result.ok = false;
      result.first_broken = {
        id: result.head.id,
        classification: 'truncated',
        detail: 'chained rows exist but no head is recorded — the chain metadata is missing or was cleared',
      };
    }
  }

  // --- the archived segments (D32) -----------------------------------------
  if (segments.length > 0 && afterId === 0 && dbPath) {
    let expectedArchivePrev = GENESIS_HASH;
    let anchorFound: 'live' | 'archive' | null = null;
    let anchorMismatched = false;

    const liveHas = (expected: { id: number; hash: string }): 'match' | 'conflict' | 'absent' => {
      const row = db
        .prepare('SELECT id, entry_hash FROM audit_log WHERE id = ?')
        .get(expected.id) as { id: number; entry_hash: string | null } | undefined;
      if (!row) return 'absent';
      return row.entry_hash === expected.hash ? 'match' : 'conflict';
    };

    if (expectedHead) {
      const state = liveHas(expectedHead);
      if (state === 'match') anchorFound = 'live';
      else if (state === 'conflict') anchorMismatched = true;
    }

    let allPresent = true;
    for (const [index, segment] of segments.entries()) {
      const archiveFile = resolveArchivePath(dbPath, segment.archive.path);
      const manifestFile = resolveArchivePath(dbPath, segment.manifest.path);
      for (const file of [archiveFile, manifestFile]) {
        if (!fs.existsSync(file)) {
          allPresent = false;
          result.archive.missing.push(file);
        }
      }
      if (result.archive.missing.length > 0) continue;

      if (wantedArchiveMode === 'presence') {
        if (!anchorFound && expectedHead && !anchorMismatched) {
          // The manifest records the tail, not every row; a presence check cannot say
          // whether an old anchor is archived, and must not guess.
        }
        continue;
      }

      const verified = verifyArchive({
        archiveFile,
        manifestFile,
        keyring: ring,
        expectedFirstPrev: expectedArchivePrev,
        expectContains:
          expectedHead && !anchorFound && !anchorMismatched
            ? { id: expectedHead.id, hash: expectedHead.hash }
            : undefined,
      });
      result.archive.checked = true;
      if (verified.contains) {
        if (verified.contains.found) anchorFound = 'archive';
        else if (verified.contains.mismatched) anchorMismatched = true;
      }
      if (!verified.ok) {
        result.ok = false;
        result.archive.error = verified.error;
        result.first_broken = verified.first_broken;
        return finish();
      }
      const tail = verified.tail;
      if (!tail) {
        result.ok = false;
        result.first_broken = {
          id: null,
          classification: 'archive-truncated',
          detail: `archived segment ${segment.sequence} has no tail`,
        };
        return finish();
      }
      expectedArchivePrev = tail.entry_hash;
      if (index === segments.length - 1) {
        result.archive.tail = {
          id: tail.id,
          entry_hash: tail.entry_hash,
          entry_mac: tail.entry_mac,
          key_id: tail.key_id,
        };
      }
    }

    result.archive.present = allPresent && result.archive.missing.length === 0;
    if (!result.archive.present) {
      result.ok = false;
      result.first_broken = {
        id: result.archive.tail?.id ?? null,
        classification: 'archive-missing',
        detail:
          `the chain records ${segments.length} archived segment(s) but ` +
          `${result.archive.missing.length} file(s) are missing: ` +
          `${result.archive.missing.join(', ')} — history has been removed, not archived`,
      };
      return finish();
    }

    result.archive.verified = result.archive.checked;
    if (expectedHead) {
      if (anchorFound) {
        result.anchor.matches = true;
        result.anchor.found_in = anchorFound;
        result.anchor.head_at_anchor =
          anchorFound === 'live' ? result.head.id === expectedHead.id : false;
      } else if (anchorMismatched) {
        result.anchor.matches = false;
        result.anchor.found_in = anchorFound;
      } else if (!result.archive.checked) {
        // The archive was not read, so whether the anchor is in it is unknown. Say so
        // rather than implying a pass.
        result.anchor.matches = null;
        result.archive.reason =
          'the archive was not read (presence check only), so an anchor older than the ' +
          'live segment cannot be confirmed';
      } else {
        result.anchor.matches = false;
      }
      if (result.anchor.matches === false) {
        result.ok = false;
        result.first_broken = {
          id: expectedHead.id,
          classification: 'replaced',
          detail:
            `the anchored head ${expectedHead.id}:${expectedHead.hash} is not in this chain ` +
            '(live or archived) — this is not the database that was anchored ' +
            '(restored backup, truncated tail, or a replaced log)',
        };
      }
    }
  } else if (segments.length > 0) {
    result.archive.reason =
      afterId > 0
        ? 'verification resumed mid-chain, so the archive was not read on this page'
        : 'no database path was supplied, so the archive files cannot be resolved';
  }

  // An anchor that must be checked on a *complete, unanchored-at-the-start* pass when
  // there is no archived history: the row is either in the live chain or nowhere.
  if (expectedHead && result.complete && afterId === 0 && segments.length === 0) {
    const row = db
      .prepare('SELECT id, entry_hash FROM audit_log WHERE id = ?')
      .get(expectedHead.id) as { id: number; entry_hash: string | null } | undefined;
    if (row && row.entry_hash === expectedHead.hash) {
      result.anchor.matches = true;
      result.anchor.found_in = 'live';
      result.anchor.head_at_anchor = row.id === result.head.id;
    } else {
      result.anchor.matches = false;
      result.ok = false;
      result.first_broken = {
        id: expectedHead.id,
        classification: 'replaced',
        detail:
          `the chain head is ${result.head.id ?? 'none'}:${result.head.hash ?? 'none'} but the ` +
          `anchored head is ${expectedHead.id}:${expectedHead.hash} — this is not the database ` +
          'that was anchored (restored backup, truncated tail, or a replaced log)',
      };
    }
  }

  // Accounting: every chained row that ever existed is either live or archived. A row
  // that is in neither was deleted outside a compaction. Only checked when the totals
  // are known (a pre-D32 database does not record them).
  if (result.ok && result.complete && afterId === 0 && meta.chained_rows_total) {
    const totalEver = Number(meta.chained_rows_total);
    const accounted = result.coverage.chained_rows + archivedRowsRecorded;
    if (accounted !== totalEver) {
      result.ok = false;
      result.first_broken = {
        id: result.head.id,
        classification: 'deleted',
        detail:
          `${totalEver} chained row(s) were ever written, but ${result.coverage.chained_rows} ` +
          `live + ${archivedRowsRecorded} archived = ${accounted} are accounted for — ` +
          'rows were deleted outside a compaction',
      };
    }
  }

  return finish();
}
