/**
 * Role-based access for the API (D25/D30).
 *
 * Before D25 the API had one optional shared secret: either you had it and could
 * do everything, or the API was open and everyone could. That is not a permission
 * model. This module resolves a request's **actor and role** and decides what role
 * an endpoint needs, so a read-only integration can be given a viewer token that
 * cannot submit samples.
 *
 * D30 adds stored, rotatable tokens beside the bootstrap environment variables.
 * **Bootstrap env tokens are checked first** — they are the recovery path, so no
 * stored-token change (including retiring every stored admin token) can lock an
 * operator out, and a stored token can never shadow or impersonate a bootstrap
 * credential.
 *
 * The default remains open when nothing at all is configured (no bootstrap token
 * *and* no live stored token), because the local dashboard depends on it, and the
 * operator is told plainly at startup. When any credential exists, tokens are
 * compared in constant time and an unauthenticated request is refused.
 */

import type Database from 'better-sqlite3';
import { timingSafeEqual } from 'crypto';
import { checkStoredToken, hasStoredTokens } from './tokens.js';

export type Role = 'anonymous' | 'viewer' | 'admin';

export interface Tokens {
  admin: string;
  viewer: string;
}

export interface Actor {
  name: string;
  role: Role;
  authenticated: boolean;
}

/** Where an actor came from. Used for logging; never for authorization. */
export type ActorSource = 'open' | 'bootstrap' | 'store';

export interface Resolution {
  actor: Actor | null;
  /** Precise refusal reason for the audit row (`auth.denied`). Never a secret. */
  reason: string;
  source: ActorSource | null;
  /** The stored token id, when one was presented and recognised. */
  tokenId: string | null;
  /** True when the API has no credential configured at all. */
  open: boolean;
}

const ROLE_RANK: Record<Role, number> = { anonymous: 0, viewer: 1, admin: 2 };

/**
 * Read configured bootstrap tokens.
 *
 * `HATCHERY_API_TOKEN` is kept as a back-compatible *admin* token so existing
 * deployments do not break; `HATCHERY_ADMIN_TOKEN` / `HATCHERY_READ_TOKEN` are the
 * explicit pair.
 */
export function readTokens(env: NodeJS.ProcessEnv = process.env): Tokens {
  const admin = (env.HATCHERY_ADMIN_TOKEN ?? env.HATCHERY_API_TOKEN ?? '').trim();
  const viewer = (env.HATCHERY_READ_TOKEN ?? '').trim();
  return { admin, viewer };
}

/** True when no bootstrap token is configured. */
export function isOpen(tokens: Tokens, db?: Database.Database | null): boolean {
  if (tokens.admin || tokens.viewer) return false;
  // With a store, "open" also requires that no token has ever been created:
  // creating one takes the API out of open mode immediately, with no restart, and
  // retiring the last one does not re-open it.
  if (db) {
    try {
      return !hasStoredTokens(db);
    } catch {
      return false; // an unreadable store is not open mode; it is refused
    }
  }
  return true;
}

function constantTimeEqual(provided: string, expected: string): boolean {
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length || a.length === 0) return false;
  return timingSafeEqual(a, b);
}

/** Pull the presented token from the Authorization or X-HATCHERY-Token header. */
export function presentedToken(headers: Record<string, unknown>): string {
  const authorization = headers['authorization'];
  if (typeof authorization === 'string' && authorization.startsWith('Bearer ')) {
    return authorization.slice(7);
  }
  const custom = headers['x-hatchery-token'];
  return typeof custom === 'string' ? custom : '';
}

/**
 * Resolve the actor for a request, with the reason it was refused.
 *
 * Order matters and is the documented precedence:
 *  1. no credential configured anywhere -> open mode, unauthenticated `anonymous`;
 *  2. a bootstrap env token (constant time) -> `admin`/`viewer`, authenticated;
 *  3. a stored token (format check, id lookup, constant-time hash compare,
 *     revocation/expiry/role checks) -> `token:<id>`, authenticated;
 *  4. otherwise refuse.
 */
export function resolveRequest(
  headers: Record<string, unknown>,
  tokens: Tokens,
  db?: Database.Database | null,
): Resolution {
  const base: Resolution = { actor: null, reason: 'no-credential', source: null, tokenId: null, open: false };

  let open = false;
  if (!tokens.admin && !tokens.viewer) {
    if (!db) {
      open = true;
    } else {
      try {
        open = !hasStoredTokens(db);
      } catch {
        // Fail closed: an unreadable token store is refused, never "open".
        return { ...base, reason: 'token-store-unreadable' };
      }
    }
  }
  if (open) {
    return {
      actor: { name: 'anonymous', role: 'admin', authenticated: false },
      reason: 'open-mode',
      source: 'open',
      tokenId: null,
      open: true,
    };
  }

  const provided = presentedToken(headers);
  if (!provided) return { ...base, reason: 'no-credential' };

  // Bootstrap first: the env pair is the operator's recovery path.
  if (tokens.admin && constantTimeEqual(provided, tokens.admin)) {
    return {
      actor: { name: 'admin', role: 'admin', authenticated: true },
      reason: 'bootstrap-admin',
      source: 'bootstrap',
      tokenId: null,
      open: false,
    };
  }
  if (tokens.viewer && constantTimeEqual(provided, tokens.viewer)) {
    return {
      actor: { name: 'viewer', role: 'viewer', authenticated: true },
      reason: 'bootstrap-viewer',
      source: 'bootstrap',
      tokenId: null,
      open: false,
    };
  }

  if (db) {
    const checked = checkStoredToken(db, provided);
    if (checked.ok && checked.role && checked.tokenId) {
      return {
        actor: {
          name: `token:${checked.tokenId}`,
          role: checked.role,
          authenticated: true,
        },
        reason: 'stored-token',
        source: 'store',
        tokenId: checked.tokenId,
        open: false,
      };
    }
    return { ...base, reason: checked.reason, tokenId: checked.tokenId };
  }

  return base;
}

/**
 * Resolve the actor for a request, or `null` when it must be refused.
 *
 * Kept as the D25 signature (and return shape) so existing callers and tests are
 * unchanged; `resolveRequest` is the reason-carrying form the server uses.
 *
 * Open mode yields an unauthenticated `anonymous` actor with admin rights, and
 * `authenticated` is false so the audit log records that the action happened
 * without a credential rather than pretending it was verified.
 */
export function resolveActor(
  headers: Record<string, unknown>,
  tokens: Tokens,
  db?: Database.Database | null,
): Actor | null {
  return resolveRequest(headers, tokens, db).actor;
}

/** The role an endpoint requires. Reads need viewer; anything that changes state needs admin. */
export function requiredRole(method: string, url: string): Role {
  const path = url.split('?')[0];
  if (path === '/api/health') return 'anonymous';
  // The audit log names who did what, and the token list names the credentials that
  // can: both are admin actions even though they are GETs (D25/D30).
  if (path === '/api/audit' || path.startsWith('/api/audit/')) return 'admin';
  if (path === '/api/tokens' || path.startsWith('/api/tokens/')) return 'admin';
  const upper = method.toUpperCase();
  if (upper === 'GET' || upper === 'HEAD' || upper === 'OPTIONS') return 'viewer';
  return 'admin';
}

export function roleSatisfies(role: Role, required: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[required];
}
