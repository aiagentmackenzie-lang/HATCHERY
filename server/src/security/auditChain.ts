/**
 * The audit chain's canonical encoding (D30/D31), kept in one place so the appender,
 * the live verifier and the archive verifier cannot drift apart.
 *
 * A JSON array is used rather than a delimited string because `JSON.stringify`
 * escapes every field deterministically — a path containing the delimiter cannot
 * forge a different row's encoding. The domain string and the fixed field order make
 * an `entry_hash` from another purpose unusable here. D31 does **not** change this:
 * the digest and the MAC cover the same bytes, so a D30 log stays verifiable.
 */

import { createHash, timingSafeEqual } from 'crypto';

const CHAIN_DOMAIN = 'hatchery.audit.v1';

/** The documented genesis value: 32 zero bytes, hex. The first chained row links to it. */
export const GENESIS_HASH = '0'.repeat(64);

/** How the chain is computed, reported by the verifier so it is never a guess. */
export const CHAIN_ALGORITHM = 'sha256(json-array-v1)+hmac-sha256(json-array-v1,v2)';

/**
 * Every way a chain can be wrong, including the ways a **compacted** chain can be
 * wrong (D32). The classification is causal, not cosmetic: it says what happened,
 * not merely that something did.
 */
export type ChainBreakClass =
  | 'modified'
  | 'deleted'
  | 'inserted'
  | 'truncated'
  | 'unhashed'
  | 'forged'
  | 'unkeyed'
  | 'unknown-key'
  | 'replaced'
  // D32: the boundary between the live segment and an archive.
  | 'archive-missing'
  | 'archive-modified'
  | 'archive-truncated'
  | 'archive-mismatch'
  | 'archive-invalid'
  | 'join-mismatch';

export interface ChainBreak {
  id: number | null;
  classification: ChainBreakClass;
  detail: string;
}

export interface HashableFields {
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

export function canonical(row: HashableFields): string {
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

/** Constant-time comparison of two 32-byte hex digests. */
export function hexEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'hex');
  const right = Buffer.from(b, 'hex');
  if (left.length !== 32 || right.length !== 32) return false;
  return timingSafeEqual(left, right);
}
