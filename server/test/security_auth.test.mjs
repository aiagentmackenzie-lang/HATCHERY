/**
 * Role-based access tests (D25).
 *
 * The previous model was one optional shared secret: hold it and do anything, or
 * hold nothing and the API was open. These pin the replacement — resolved roles,
 * constant-time comparison, and a read/admin split.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  isOpen,
  presentedToken,
  readTokens,
  requiredRole,
  resolveActor,
  roleSatisfies,
} from '../dist/security/auth.js';

test('no tokens configured means the API is open', () => {
  const tokens = readTokens({});
  assert.equal(isOpen(tokens), true);
  const actor = resolveActor({}, tokens);
  assert.deepEqual(actor, { name: 'anonymous', role: 'admin', authenticated: false });
});

test('HATCHERY_API_TOKEN is still accepted as a back-compatible admin token', () => {
  assert.deepEqual(readTokens({ HATCHERY_API_TOKEN: 'legacy' }), {
    admin: 'legacy',
    viewer: '',
  });
});

test('explicit admin and viewer tokens are read', () => {
  const tokens = readTokens({ HATCHERY_ADMIN_TOKEN: 'a', HATCHERY_READ_TOKEN: 'v' });
  assert.deepEqual(tokens, { admin: 'a', viewer: 'v' });
  assert.equal(isOpen(tokens), false);
});

test('an admin token resolves to the admin role', () => {
  const tokens = readTokens({ HATCHERY_ADMIN_TOKEN: 'a', HATCHERY_READ_TOKEN: 'v' });
  assert.deepEqual(resolveActor({ authorization: 'Bearer a' }, tokens), {
    name: 'admin',
    role: 'admin',
    authenticated: true,
  });
});

test('a viewer token resolves to the viewer role', () => {
  const tokens = readTokens({ HATCHERY_ADMIN_TOKEN: 'a', HATCHERY_READ_TOKEN: 'v' });
  assert.deepEqual(resolveActor({ authorization: 'Bearer v' }, tokens), {
    name: 'viewer',
    role: 'viewer',
    authenticated: true,
  });
});

test('the x-hatchery-token header is accepted as well as Bearer', () => {
  const tokens = readTokens({ HATCHERY_READ_TOKEN: 'v' });
  assert.equal(presentedToken({ 'x-hatchery-token': 'v' }), 'v');
  assert.equal(resolveActor({ 'x-hatchery-token': 'v' }, tokens)?.role, 'viewer');
});

test('a wrong or missing token is refused when tokens are configured', () => {
  const tokens = readTokens({ HATCHERY_ADMIN_TOKEN: 'a', HATCHERY_READ_TOKEN: 'v' });
  assert.equal(resolveActor({}, tokens), null);
  assert.equal(resolveActor({ authorization: 'Bearer nope' }, tokens), null);
  assert.equal(resolveActor({ authorization: 'a' }, tokens), null); // no Bearer prefix
  assert.equal(resolveActor({ authorization: 'Bearer a-extra' }, tokens), null);
});

test('reads need viewer and writes need admin', () => {
  assert.equal(requiredRole('GET', '/api/tasks/abc/report'), 'viewer');
  assert.equal(requiredRole('POST', '/api/submit'), 'admin');
  assert.equal(requiredRole('DELETE', '/api/tasks/abc'), 'admin');
  assert.equal(requiredRole('GET', '/api/health'), 'anonymous');
});

test('the audit log is admin-only even though it is a GET', () => {
  assert.equal(requiredRole('GET', '/api/audit'), 'admin');
  assert.equal(requiredRole('GET', '/api/audit?limit=5'), 'admin');
});

test('role ranking is monotonic', () => {
  assert.equal(roleSatisfies('admin', 'viewer'), true);
  assert.equal(roleSatisfies('admin', 'admin'), true);
  assert.equal(roleSatisfies('viewer', 'viewer'), true);
  assert.equal(roleSatisfies('viewer', 'admin'), false);
  assert.equal(roleSatisfies('anonymous', 'viewer'), false);
});
