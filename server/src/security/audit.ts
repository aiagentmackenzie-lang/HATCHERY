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

import { createHash, timingSafeEqual } from 'crypto';
import type Database from 'better-sqlite3';
import {
  activeKey,
  auditMac,
  findKey,
  type AuditKeyring,
} from './auditKey.js';

export type AuditAction =
  | 'auth.denied'
  | 'request.forbidden'
  | 'request.allowed'
  | 'request.failed'
  | 'token.created'
  | 'token.retired'
  | 'token.expired'
  | 'audit.verified'
  | 'audit.key-rotated';

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

/**
 * The chain's canonical encoding, versioned.
 *
 * A JSON array is used rather than a delimited string because `JSON.stringify`
 * escapes every field deterministically — a path containing the delimiter cannot
 * forge a different row's encoding. The domain string and the fixed field order
 * make an `entry_hash` from another purpose unusable here. D31 does **not** change
 * this: the digest and the MAC cover the same bytes, so a D30 log stays verifiable.
 */
const CHAIN_DOMAIN = 'hatchery.audit.v1';

/** The documented genesis value: 32 zero bytes, hex. The first chained row links to it. */
export const GENESIS_HASH = '0'.repeat(64);

/** How the chain is computed, reported by the verify endpoint so it is never a guess. */
export const CHAIN_ALGORITHM = 'sha256(json-array-v1)+hmac-sha256(json-array-v1,v2)';

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
  key_id: string | null;
  entry_mac: string | null;
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

function hexEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  if (left.length !== 32 || right.length !== 32) return false;
  return timingSafeEqual(left, right);
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

export function auditAppendFailures(): number {
  return appendFailures;
}

export function resetAuditAppendFailures(): void {
  appendFailures = 0;
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
      `[hatchery] audit append failed (chain not advanced, ${appendFailures} this process): ${message}`,
    );
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
  | 'unhashed'
  | 'forged'
  | 'unkeyed'
  | 'unknown-key'
  | 'replaced';

export interface ChainBreak {
  id: number | null;
  classification: ChainBreakClass;
  detail: string;
}

/**
 * What the verifier was actually able to check. `ok` must be read with this:
 * `empty` (nothing chained yet), `unkeyed` (no MACs at all), `mixed` (a keyed suffix
 * over unkeyed history) or `keyed` (every chained row authenticated).
 */
export type Assurance = 'empty' | 'unkeyed' | 'mixed' | 'keyed';

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
  key: {
    active: string | null;
    id: string | null;
    source: string | null;
    env_ignored: boolean;
  };
  anchor: {
    expected: { id: number; hash: string } | null;
    matches: boolean | null;
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
  /** Appends that failed and were logged in this process. A hole the chain cannot see. */
  append_failures_since_start: number;
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
 * - `replaced`   — the head does not match a caller-supplied `expectHead`: the
 *                  database is not the one that was anchored.
 * - `unhashed`   — a row inside the chained region has no `entry_hash` at all.
 */
export function verifyAuditChain(
  db: Database.Database,
  options: {
    limitRows?: number;
    afterId?: number;
    /** A head recorded outside the database, from `npm run audit -- head`. */
    expectHead?: { id: number; hash: string } | null;
    keyring?: AuditKeyring | null;
  } = {},
): ChainVerification {
  const limit = Math.min(Math.max(options.limitRows ?? 5000, 1), MAX_VERIFY_ROWS);
  const afterId = Math.max(options.afterId ?? 0, 0);
  const ring = options.keyring === undefined ? chainKeyring : options.keyring;
  const meta = auditChainMeta(db);
  const metaHeadId = meta.head_id ? Number(meta.head_id) : null;
  const metaHeadHash = meta.head_hash ?? null;
  const anchorRows = Number(meta.legacy_row_count ?? '0');
  const chainFirstId = meta.chain_first_id ? Number(meta.chain_first_id) : null;
  const expectedHead = options.expectHead ?? null;

  const result: ChainVerification = {
    ok: true,
    algorithm: CHAIN_ALGORITHM,
    genesis: GENESIS_HASH,
    assurance: 'empty',
    coverage: { chained_rows: 0, mac_rows: 0, unkeyed_rows: 0, legacy_rows: 0 },
    key: {
      active: ring?.active ?? null,
      id: ring?.active ?? null,
      source: ring?.source ?? null,
      env_ignored: ring?.env_ignored ?? false,
    },
    anchor: { expected: expectedHead, matches: null },
    rows_checked: 0,
    complete: false,
    next_after_id: null,
    first_broken: null,
    head: { id: null, hash: null, matches_meta: false },
    legacy: { rows: 0, covered: false, anchor_row_count: anchorRows, altered: false },
    append_failures_since_start: appendFailures,
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
      return result;
    }
    expectedPrev = anchor.entry_hash;
    prevId = anchor.id;
    seenMac = Boolean(anchor.entry_mac);
    result.head = { id: anchor.id, hash: anchor.entry_hash, matches_meta: false };
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

  for (const row of rows) {
    result.rows_checked += 1;
    result.coverage.chained_rows += 1;

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

    if (expectedHead) {
      const matches = headId === expectedHead.id && headHash === expectedHead.hash;
      result.anchor.matches = matches;
      if (!matches) {
        result.ok = false;
        result.first_broken = {
          id: expectedHead.id,
          classification: 'replaced',
          detail:
            `the chain head is ${headId ?? 'none'}:${headHash ?? 'none'} but the anchored ` +
            `head is ${expectedHead.id}:${expectedHead.hash} — this is not the database ` +
            'that was anchored (restored backup, truncated tail, or a replaced log)',
        };
      }
    }
  }

  return finish();
}
