/**
 * API token lifecycle (D30).
 *
 * D25 gave the API roles but left the credential model at two long-lived
 * environment variables: no expiry, no revocation, and no way to rotate without
 * editing the environment and restarting. This module is the missing half — named
 * tokens with an id, a role, a non-secret prefix, a creation/expiry time and a
 * revocation stamp, stored in the existing SQLite database.
 *
 * Three properties shape the design:
 *
 * 1. **The raw token is never stored, printed, logged, audited or returned.** The
 *    database holds `sha256(domain || token)`, and only the CLI's `create`
 *    handover prints the value once. No HTTP response ever carries a secret, which
 *    is why token creation is a local operator action rather than an endpoint.
 * 2. **An id or prefix cannot authenticate.** Verification is a constant-time
 *    comparison of the stored hash with the hash of the presented token, after a
 *    strict format check.
 * 3. **Bootstrap env tokens are the recovery path.** `HATCHERY_ADMIN_TOKEN`,
 *    `HATCHERY_READ_TOKEN` and the back-compatible `HATCHERY_API_TOKEN` are
 *    resolved **first**, before the store is consulted. Creating or retiring a
 *    stored token therefore can never lock an operator out of a host they can
 *    already reach, and no stored token can shadow a bootstrap credential.
 */

import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import type Database from 'better-sqlite3';

/** Every stored token starts with this. */
const TOKEN_PREFIX = 'htk_';
const ID_HEX = 16; // 8 random bytes, hex — the token's first segment and its id
const SECRET_CHARS = 43; // 32 random bytes, base64url
/** `htk_` + id + `_` + secret. Strict, so a malformed token never reaches the store. */
const TOKEN_LENGTH = TOKEN_PREFIX.length + ID_HEX + 1 + SECRET_CHARS;

/**
 * Domain separation. A hash from another purpose (or a raw SHA-256 of a token
 * computed elsewhere) cannot be replayed as a token hash here.
 */
export const TOKEN_HASH_DOMAIN = 'hatchery/api-token/v1';

export type TokenRole = 'admin' | 'viewer';

export interface StoredTokenRow {
  id: string;
  name: string | null;
  role: string;
  prefix: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  retired_reason: string | null;
}

/** What a listing may show: no secret, no hash. */
export interface TokenListing extends StoredTokenRow {
  state: 'live' | 'expired' | 'revoked';
}

export interface CreatedToken {
  id: string;
  name: string | null;
  role: TokenRole;
  prefix: string;
  created_at: string;
  expires_at: string | null;
  /** The secret. Returned exactly once, to the operator who created it. */
  token: string;
}

const ID_PATTERN = /^htk_[0-9a-f]{16}$/;

/** A well-formed hash that no token produces; used to equalise the unknown-id path. */
const DUMMY_HASH = 'f'.repeat(64);

/** `sha256(domain || token)`, hex. One-way; the token is not recoverable from it. */
export function hashToken(token: string): string {
  return createHash('sha256').update(`${TOKEN_HASH_DOMAIN}\u0000${token}`, 'utf8').digest('hex');
}

/**
 * Pull the token id out of a presented token, or `null` if it is not one of ours.
 *
 * The format is fixed-length, so the id is at a known offset and a base64url secret
 * containing `_` or `-` cannot confuse the parse. This is a shape check only: a
 * well-formed token that was never issued still has to fail the hash comparison.
 */
export function tokenIdOf(token: string): string | null {
  if (token.length !== TOKEN_LENGTH) return null;
  const id = token.slice(0, TOKEN_PREFIX.length + ID_HEX);
  if (!ID_PATTERN.test(id)) return null;
  if (token[TOKEN_PREFIX.length + ID_HEX] !== '_') return null;
  return id;
}

/** Generate a token locally. The secret exists in this process and nowhere else. */
export function generateToken(): { token: string; id: string; prefix: string; secretHash: string } {
  const id = `${TOKEN_PREFIX}${randomBytes(ID_HEX / 2).toString('hex')}`;
  const secret = randomBytes(32).toString('base64url');
  const token = `${id}_${secret}`;
  return { token, id, prefix: id, secretHash: hashToken(token) };
}

function constantTimeHashEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  if (left.length !== 32 || right.length !== 32) return false;
  return timingSafeEqual(left, right);
}

function nowIso(): string {
  return new Date().toISOString();
}

function normaliseIso(value: string | null | undefined, field: string): string | null {
  if (value === null || value === undefined || value === '') return null;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    throw new Error(`invalid ${field}: not an ISO-8601 timestamp`);
  }
  return new Date(parsed).toISOString();
}

/** Create a token row. Returns the secret-bearing record; the caller hands it over once. */
export function createToken(
  db: Database.Database,
  options: { role: TokenRole; name?: string | null; expiresAt?: string | null },
): CreatedToken {
  if (options.role !== 'admin' && options.role !== 'viewer') {
    throw new Error(`invalid role: ${String(options.role)}`);
  }
  const generated = generateToken();
  const createdAt = nowIso();
  const expiresAt = normaliseIso(options.expiresAt ?? null, 'expires_at');
  db.prepare(
    `INSERT INTO api_tokens
       (id, name, role, prefix, secret_hash, created_at, expires_at, revoked_at, retired_reason)
     VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)`,
  ).run(
    generated.id,
    options.name ?? null,
    options.role,
    generated.prefix,
    generated.secretHash,
    createdAt,
    expiresAt,
  );
  return {
    id: generated.id,
    name: options.name ?? null,
    role: options.role,
    prefix: generated.prefix,
    created_at: createdAt,
    expires_at: expiresAt,
    token: generated.token,
  };
}

/** Every row, newest first, without the hash. Callers never see a secret. */
export function listTokens(db: Database.Database): TokenListing[] {
  const rows = db
    .prepare(
      `SELECT id, name, role, prefix, created_at, expires_at, revoked_at, retired_reason
         FROM api_tokens ORDER BY created_at DESC, id ASC`,
    )
    .all() as StoredTokenRow[];
  const now = Date.now();
  return rows.map((row) => ({ ...row, state: tokenState(row, now) }));
}

export function tokenState(
  row: Pick<StoredTokenRow, 'expires_at' | 'revoked_at'>,
  now = Date.now(),
): 'live' | 'expired' | 'revoked' {
  if (row.revoked_at) return 'revoked';
  if (row.expires_at) {
    const expires = Date.parse(row.expires_at);
    if (Number.isNaN(expires)) return 'expired'; // malformed expiry: never treated as live
    if (expires <= now) return 'expired';
  }
  return 'live';
}

/**
 * Any stored token exists: the API is not in open mode.
 *
 * Deliberately *any*, not *live*. Retiring the last token must not silently
 * re-open the API to a browser on the network — that would make a routine
 * credential change a security regression. Once a token has been created, the API
 * stays closed; recovery is the bootstrap env pair or the local CLI (host access),
 * never an implicit "no live token means open".
 */
export function hasStoredTokens(db: Database.Database): boolean {
  // `LIMIT 1` on the primary key: O(1), and it does not materialise every row's
  // hash on every request the way `SELECT *` did.
  const row = db.prepare('SELECT 1 AS present FROM api_tokens LIMIT 1').get();
  return row !== undefined;
}

export function countTokens(db: Database.Database): { total: number; live: number } {
  const total = (db.prepare('SELECT COUNT(*) AS n FROM api_tokens').get() as { n: number }).n;
  // Only the two fields liveness depends on, and the same `tokenState` rule the
  // authenticator uses, so a "live" count can never disagree with what is accepted.
  const rows = db
    .prepare('SELECT expires_at, revoked_at FROM api_tokens')
    .all() as Array<Pick<StoredTokenRow, 'expires_at' | 'revoked_at'>>;
  const now = Date.now();
  return { total, live: rows.filter((row) => tokenState(row, now) === 'live').length };
}

/**
 * Retire (revoke) a token. Effective on the next request: the store is read per
 * request, so no restart is involved, and a request already authenticated keeps
 * running (its actor was resolved when it arrived).
 */
export function retireToken(
  db: Database.Database,
  id: string,
  reason = 'retired by operator',
): { changed: boolean; token: TokenListing | null } {
  const row = db
    .prepare(
      `SELECT id, name, role, prefix, created_at, expires_at, revoked_at, retired_reason
         FROM api_tokens WHERE id = ?`,
    )
    .get(id) as StoredTokenRow | undefined;
  if (!row) return { changed: false, token: null };
  if (row.revoked_at) {
    return { changed: false, token: { ...row, state: tokenState(row) } };
  }
  const revokedAt = nowIso();
  db.prepare('UPDATE api_tokens SET revoked_at = ?, retired_reason = ? WHERE id = ?').run(
    revokedAt,
    reason.slice(0, 200),
    id,
  );
  return {
    changed: true,
    token: { ...row, revoked_at: revokedAt, retired_reason: reason.slice(0, 200), state: 'revoked' },
  };
}

/** Move a token's expiry. `at` in the past expires it now, which is checked per request. */
export function expireToken(
  db: Database.Database,
  id: string,
  at: string,
): TokenListing | null {
  const expiresAt = normaliseIso(at, 'expires_at');
  const row = db
    .prepare(
      `SELECT id, name, role, prefix, created_at, expires_at, revoked_at, retired_reason
         FROM api_tokens WHERE id = ?`,
    )
    .get(id) as StoredTokenRow | undefined;
  if (!row) return null;
  db.prepare('UPDATE api_tokens SET expires_at = ? WHERE id = ?').run(expiresAt, id);
  const updated = { ...row, expires_at: expiresAt };
  return { ...updated, state: tokenState(updated) };
}

export interface TokenCheck {
  ok: boolean;
  /** Precise reason for the audit row. Never sent to the client and never a secret. */
  reason: string;
  tokenId: string | null;
  role: TokenRole | null;
}

/**
 * Verify a presented token against the store.
 *
 * Fail-closed on every ambiguity: a shape that is not ours, an unknown id, a hash
 * mismatch, malformed timestamps, a role this build does not understand, or an
 * unreadable table all refuse. The reasons are distinct so the audit row can be
 * precise, but the HTTP response is always the same generic 401 — the API is not a
 * token oracle.
 */
export function checkStoredToken(db: Database.Database, presented: string): TokenCheck {
  const id = tokenIdOf(presented);
  if (!id) return { ok: false, reason: 'token-malformed', tokenId: null, role: null };

  // Hash before the lookup so an unknown id and a known one do the same hashing
  // work. The response is uniform either way; this only narrows the timing gap so
  // existence is not trivially probeable by a local caller. It is not a formal
  // constant-time guarantee, and the audit row is admin-only, so nothing here is
  // relied on for secrecy.
  const presentedHash = hashToken(presented);

  let row: (StoredTokenRow & { secret_hash: string }) | undefined;
  try {
    row = db
      .prepare('SELECT * FROM api_tokens WHERE id = ?')
      .get(id) as (StoredTokenRow & { secret_hash: string }) | undefined;
  } catch {
    return { ok: false, reason: 'token-store-unreadable', tokenId: id, role: null };
  }
  if (!row) {
    // Compare against a value that cannot match, so the "missing row" path is not
    // measurably cheaper than "wrong secret".
    constantTimeHashEqual(presentedHash, DUMMY_HASH);
    return { ok: false, reason: 'token-unknown', tokenId: id, role: null };
  }

  if (!constantTimeHashEqual(presentedHash, String(row.secret_hash ?? ''))) {
    return { ok: false, reason: 'token-hash-mismatch', tokenId: id, role: null };
  }
  if (row.revoked_at) {
    return { ok: false, reason: 'token-revoked', tokenId: id, role: null };
  }
  if (row.expires_at !== null && row.expires_at !== undefined && row.expires_at !== '') {
    const expires = Date.parse(row.expires_at);
    if (Number.isNaN(expires)) {
      return { ok: false, reason: 'token-malformed', tokenId: id, role: null };
    }
    if (expires <= Date.now()) {
      return { ok: false, reason: 'token-expired', tokenId: id, role: null };
    }
  }
  if (row.role !== 'admin' && row.role !== 'viewer') {
    return { ok: false, reason: 'token-invalid-role', tokenId: id, role: null };
  }
  return { ok: true, reason: 'token-valid', tokenId: id, role: row.role };
}
