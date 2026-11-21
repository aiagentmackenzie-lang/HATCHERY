/**
 * Append-only access audit log (D25) with a tamper-evident hash chain (D30).
 *
 * Every request the API answers is recorded: who (actor + role, and whether they
 * authenticated), what (method + path), and the outcome (status + action). What is
 * **not** recorded is as deliberate as what is: no token, no `Authorization`
 * header, no request body and no sample bytes. An audit log that leaks the
 * credential it is auditing is worse than no audit log.
 *
 * D30 makes the table append-only in practice, not just in intent. Each row
 * carries `prev_hash` (the previous row's `entry_hash`, or the documented genesis
 * constant) and `entry_hash` (SHA-256 over a canonical encoding of the stored
 * fields). Reading the head and inserting happen inside one `BEGIN IMMEDIATE`
 * transaction, so concurrent writers — two API processes, the API and the CLI —
 * produce one chain rather than a fork.
 *
 * What the chain is and is not: it detects a modified row, a deleted row, a row
 * that does not link, and truncation of the tail. It is **not** authenticated with
 * a secret, so an attacker with write access who recomputes every hash from the
 * edit onwards (and the recorded head) produces a chain that verifies. There is no
 * KMS/HSM here, deliberately. See D30.
 */

import { createHash } from 'crypto';
import type Database from 'better-sqlite3';

export type AuditAction =
  | 'auth.denied'
  | 'request.forbidden'
  | 'request.allowed'
  | 'request.failed'
  | 'token.created'
  | 'token.retired'
  | 'token.expired'
  | 'audit.verified';

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
}

/** Routes that are not worth an audit row (liveness probes, the websocket upgrade). */
const NOT_AUDITED = new Set(['/api/health', '/ws']);

export function shouldAudit(url: string): boolean {
  return !NOT_AUDITED.has(url.split('?')[0]);
}

const MAX_DETAIL = 300;

/**
 * The chain's canonical encoding, versioned.
 *
 * A JSON array is used rather than a delimited string because `JSON.stringify`
 * escapes every field deterministically — a path containing the delimiter cannot
 * forge a different row's encoding. The domain string and the fixed field order
 * make an `entry_hash` from another purpose unusable here.
 */
const CHAIN_DOMAIN = 'hatchery.audit.v1';

/** The documented genesis value: 32 zero bytes, hex. The first chained row links to it. */
export const GENESIS_HASH = '0'.repeat(64);

/** How the chain is computed, reported by the verify endpoint so it is never a guess. */
export const CHAIN_ALGORITHM = 'sha256(json-array-v1)';

interface HashableFields {
  id: number;
  prev_hash: string | null;
  actor: string;
  role: string;
  authenticated: number;
  method: string;
  path: string;
  status_code: number | null;
  action: string | null;
  detail: string | null;
  created_at: string;
}

interface ChainFields extends HashableFields {
  entry_hash: string | null;
}

function canonical(row: HashableFields): string {
  return JSON.stringify([
    CHAIN_DOMAIN,
    row.id,
    row.prev_hash,
    row.actor,
    row.role,
    row.authenticated,
    row.method,
    row.path,
    row.status_code,
    row.action,
    row.detail,
    row.created_at,
  ]);
}

/** SHA-256 over the canonical encoding of exactly the fields the table stores. */
export function entryHash(row: HashableFields): string {
  return createHash('sha256').update(canonical(row), 'utf8').digest('hex');
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
    }).immediate();
  } catch {
    // A database without the table yet (an older schema mid-migration) is handled
    // by the next call; the server refuses to append rather than guessing.
  }
}

interface AppendResult {
  id: number;
  entryHash: string;
  prevHash: string;
}

/**
 * Insert one audit row and advance the chain.
 *
 * The head read and the insert are one `BEGIN IMMEDIATE` transaction, so two
 * writers cannot both claim the same `prev_hash`. It throws on failure; the
 * caller decides whether that is survivable.
 */
function appendChained(db: Database.Database, entry: AuditEntry): AppendResult {
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
            created_at, prev_hash, entry_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
        // Placeholder: the hash covers the row id, which SQLite assigns on insert.
        // It is filled in below inside the same transaction, so no reader and no
        // later appender can observe or link to the unfilled row.
        null,
      );

    const id = Number(info.lastInsertRowid);
    const hash = entryHash({ id, prev_hash: prevHash, ...stored });
    db.prepare('UPDATE audit_log SET entry_hash = ? WHERE id = ?').run(hash, id);

    const meta = auditChainMeta(db);
    if (!meta.chain_first_id) setMeta(db, 'chain_first_id', String(id));
    setMeta(db, 'head_id', String(id));
    setMeta(db, 'head_hash', hash);
    setMeta(
      db,
      'chained_row_count',
      String(Number(meta.chained_row_count ?? '0') + 1),
    );
    return { id, entryHash: hash, prevHash };
  };

  // `BEGIN IMMEDIATE` takes the write lock before the head is read, so two
  // processes cannot read the same head and then both insert. A caller already
  // inside a transaction keeps its lock instead of nesting one.
  const result = db.inTransaction ? run() : db.transaction(run).immediate();
  return result;
}

/**
 * Insert one audit row. Never throws: auditing must not break the request path
 * (D25). A failure is logged **without** any credential — the log line names the
 * error and that the chain did not advance, nothing else.
 */
export function recordAudit(db: Database.Database, entry: AuditEntry): boolean {
  try {
    appendChained(db, entry);
    return true;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[hatchery] audit append failed (chain not advanced): ${message}`);
    return false;
  }
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

export type ChainBreakClass =
  | 'modified'
  | 'deleted'
  | 'inserted'
  | 'truncated'
  | 'unhashed';

export interface ChainBreak {
  id: number | null;
  classification: ChainBreakClass;
  detail: string;
}

export interface ChainVerification {
  ok: boolean;
  algorithm: string;
  genesis: string;
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
}

const MAX_VERIFY_ROWS = 50000;

/**
 * Recompute the chain and report the first row that does not verify.
 *
 * Bounded by `limitRows` so a large log cannot hang the endpoint; when the page is
 * exhausted the caller continues with `after`. Classification is causal rather than
 * cosmetic:
 *
 * - `modified`   — the row's own `entry_hash` no longer matches its stored fields.
 * - `deleted`    — a row links to a hash that is not the previous row's, and the
 *                  ids skip, so row(s) were removed.
 * - `inserted`   — a row links to a hash the chain never produced (and the ids are
 *                  contiguous), so it was written by something other than the
 *                  appender.
 * - `truncated`  — the recorded head no longer exists at the end of the chain.
 * - `unhashed`   — a row inside the chained region has no `entry_hash` at all.
 */
export function verifyAuditChain(
  db: Database.Database,
  options: { limitRows?: number; afterId?: number } = {},
): ChainVerification {
  const limit = Math.min(Math.max(options.limitRows ?? 5000, 1), MAX_VERIFY_ROWS);
  const afterId = Math.max(options.afterId ?? 0, 0);
  const meta = auditChainMeta(db);
  const metaHeadId = meta.head_id ? Number(meta.head_id) : null;
  const metaHeadHash = meta.head_hash ?? null;
  const anchorRows = Number(meta.legacy_row_count ?? '0');
  const chainFirstId = meta.chain_first_id ? Number(meta.chain_first_id) : null;

  const result: ChainVerification = {
    ok: true,
    algorithm: CHAIN_ALGORITHM,
    genesis: GENESIS_HASH,
    rows_checked: 0,
    complete: false,
    next_after_id: null,
    first_broken: null,
    head: { id: null, hash: null, matches_meta: false },
    legacy: { rows: 0, covered: false, anchor_row_count: anchorRows, altered: false },
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

  let expectedPrev = GENESIS_HASH;
  let prevId: number | null = null;
  if (afterId > 0) {
    const anchor = db
      .prepare('SELECT id, entry_hash FROM audit_log WHERE id = ?')
      .get(afterId) as { id: number; entry_hash: string | null } | undefined;
    if (!anchor || !anchor.entry_hash) {
      result.ok = false;
      result.first_broken = {
        id: afterId,
        classification: 'deleted',
        detail: 'the row used to resume verification no longer exists or has no entry_hash',
      };
      return result;
    }
    expectedPrev = anchor.entry_hash;
    prevId = anchor.id;
    result.head = { id: anchor.id, hash: anchor.entry_hash, matches_meta: false };
  }

  const rows = db
    .prepare(
      `SELECT id, actor, role, authenticated, method, path, status_code, action,
              detail, created_at, prev_hash, entry_hash
         FROM audit_log
        WHERE entry_hash IS NOT NULL AND id > ?
        ORDER BY id ASC
        LIMIT ?`,
    )
    .all(afterId, limit) as ChainFields[];

  for (const row of rows) {
    result.rows_checked += 1;

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
      return result;
    }

    if (row.entry_hash !== entryHash(row)) {
      result.ok = false;
      result.first_broken = {
        id: row.id,
        classification: 'modified',
        detail: `row ${row.id} no longer hashes to its stored entry_hash`,
      };
      return result;
    }

    expectedPrev = row.entry_hash as string;
    prevId = row.id;
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
    // removed from the end, which no forward link can reveal.
    const headId = result.head.id;
    const headHash = result.head.hash;
    // A resumed page that ends exactly on the recorded head (rows.length === 0)
    // must report a match, not the placeholder set when the anchor was read.
    result.head.matches_meta = metaHeadId !== null && headId === metaHeadId && headHash === metaHeadHash;
    if (metaHeadId !== null && (headId !== metaHeadId || headHash !== metaHeadHash)) {
      result.ok = false;
      result.head.matches_meta = false;
      result.first_broken = {
        id: metaHeadId,
        classification: 'truncated',
        detail:
          `the chain ends at row ${headId ?? 'none'} but the recorded head is row ` +
          `${metaHeadId} — rows were removed from the end`,
      };
    } else if (metaHeadId === null && result.head.id !== null) {
      // Chained rows with no recorded head: the chain metadata was cleared or is
      // missing. Fail closed rather than reporting a chain nobody anchored.
      result.ok = false;
      result.first_broken = {
        id: result.head.id,
        classification: 'truncated',
        detail: 'chained rows exist but no head is recorded — the chain metadata is missing or was cleared',
      };
    }
  }

  return result;
}
