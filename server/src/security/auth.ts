/**
 * Role-based access for the API (D25).
 *
 * Before this, the API had one optional shared secret: either you had it and
 * could do everything, or the API was open and everyone could. That is not a
 * permission model. This module resolves a request's **actor and role** and
 * decides what role an endpoint needs, so a read-only integration can be given a
 * viewer token that cannot submit samples.
 *
 * The default remains open (no tokens configured) because the local dashboard
 * depends on it, and the operator is told plainly at startup. When tokens are
 * configured, they are compared in constant time and an unauthenticated request
 * is refused.
 */

import { timingSafeEqual } from 'crypto';

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

const ROLE_RANK: Record<Role, number> = { anonymous: 0, viewer: 1, admin: 2 };

/**
 * Read configured tokens.
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

/** True when no token is configured, so the API runs unauthenticated. */
export function isOpen(tokens: Tokens): boolean {
  return !tokens.admin && !tokens.viewer;
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
 * Resolve the actor for a request, or `null` when it must be refused.
 *
 * Open mode yields an unauthenticated `anonymous` actor with admin rights, and
 * `authenticated` is false so the audit log records that the action happened
 * without a credential rather than pretending it was verified.
 */
export function resolveActor(headers: Record<string, unknown>, tokens: Tokens): Actor | null {
  if (isOpen(tokens)) {
    return { name: 'anonymous', role: 'admin', authenticated: false };
  }
  const provided = presentedToken(headers);
  if (!provided) return null;
  if (tokens.admin && constantTimeEqual(provided, tokens.admin)) {
    return { name: 'admin', role: 'admin', authenticated: true };
  }
  if (tokens.viewer && constantTimeEqual(provided, tokens.viewer)) {
    return { name: 'viewer', role: 'viewer', authenticated: true };
  }
  return null;
}

/** The role an endpoint requires. Reads need viewer; anything that changes state needs admin. */
export function requiredRole(method: string, url: string): Role {
  const path = url.split('?')[0];
  if (path === '/api/health') return 'anonymous';
  // The audit log names who did what: reading it is an admin action, not a read.
  if (path === '/api/audit' || path.startsWith('/api/audit/')) return 'admin';
  const upper = method.toUpperCase();
  if (upper === 'GET' || upper === 'HEAD' || upper === 'OPTIONS') return 'viewer';
  return 'admin';
}

export function roleSatisfies(role: Role, required: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[required];
}
