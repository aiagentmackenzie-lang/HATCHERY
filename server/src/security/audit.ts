/**
 * Append-only access audit log (D25).
 *
 * Every request the API answers is recorded: who (actor + role, and whether they
 * authenticated), what (method + path), and the outcome (status + action). What is
 * **not** recorded is as deliberate as what is: no token, no `Authorization`
 * header, no request body and no sample bytes. An audit log that leaks the
 * credential it is auditing is worse than no audit log.
 */

import type Database from 'better-sqlite3';

export type AuditAction = 'auth.denied' | 'request.forbidden' | 'request.allowed' | 'request.failed';

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
}

/** Routes that are not worth an audit row (liveness probes, the websocket upgrade). */
const NOT_AUDITED = new Set(['/api/health', '/ws']);

export function shouldAudit(url: string): boolean {
  return !NOT_AUDITED.has(url.split('?')[0]);
}

const MAX_DETAIL = 300;

/** Insert one audit row. Never throws: auditing must not break the request path. */
export function recordAudit(db: Database.Database, entry: AuditEntry): void {
  try {
    db.prepare(
      `INSERT INTO audit_log
         (actor, role, authenticated, method, path, status_code, action, detail)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      entry.actor || 'anonymous',
      entry.role || 'anonymous',
      entry.authenticated ? 1 : 0,
      entry.method,
      entry.path,
      entry.statusCode ?? null,
      entry.action,
      entry.detail ? entry.detail.slice(0, MAX_DETAIL) : null,
    );
  } catch {
    // Intentionally swallowed: a full disk or locked database must not turn an
    // otherwise successful analysis into a 500.
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
